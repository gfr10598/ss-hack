CXXFLAGS= $(WXXFLAGS) -std=c++11 -pthread -O2

SSOBJ=ss.o ssfilter.o
POLLING_OBJ=poll_tcpinfo_base.o ssfilter.o poll_tcpinfo.o printing.o
LNSTATOBJ=lnstat.o lnstat_util.o

TARGETS=poll_tcpinfo_base ss nstat ifstat rtacct lnstat printing.o

# Config defined CC, so we override below.
include ../Config
CXX := g++

ifeq ($(HAVE_BERKELEY_DB),y)
	TARGETS += arpd
endif

ifeq ($(HAVE_SELINUX),y)
	LDLIBS += $(shell $(PKG_CONFIG) --libs libselinux)
	CFLAGS += $(shell $(PKG_CONFIG) --cflags libselinux) -DHAVE_SELINUX
endif

ifeq ($(IP_CONFIG_SETNS),y)
	CFLAGS += -DHAVE_SETNS
endif

all: $(TARGETS)

poll_tcpinfo_base.o: structs.h poll_tcpinfo_base.c

poll_tcpinfo.o: structs.h poll_tcpinfo.cc

poll_tcpinfo_base: $(POLLING_OBJ)
	$(QUIET_LINK)$(CXX) $^ $(LDFLAGS) $(LDLIBS) $(LOADLIBES) -std=c++11 -o $@

ss: $(SSOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

nstat: nstat.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o nstat nstat.c $(LIBNETLINK) -lm

ifstat: ifstat.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o ifstat ifstat.c $(LIBNETLINK) -lm

rtacct: rtacct.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o rtacct rtacct.c $(LIBNETLINK) -lm

arpd: arpd.c
	$(QUIET_CC)$(CC) $(CFLAGS) -I$(DBM_INCLUDE) $(LDFLAGS) -o arpd arpd.c $(LIBNETLINK) -ldb -lpthread

ssfilter.c: ssfilter.y
	$(QUIET_YACC)bison ssfilter.y -o ssfilter.c

lnstat: $(LNSTATOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)
	ln -sf lnstat $(DESTDIR)$(SBINDIR)/rtstat
	ln -sf lnstat $(DESTDIR)$(SBINDIR)/ctstat

clean:
	rm -f *.o $(TARGETS) ssfilter.c
