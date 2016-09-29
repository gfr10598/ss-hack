CXXFLAGS=-std=c++11

SSOBJ=ss.o ssfilter.o
GFROBJ=gfr.o ssfilter.o gfr2.o
LNSTATOBJ=lnstat.o lnstat_util.o

TARGETS=gfr ss nstat ifstat rtacct lnstat

include ../Config

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

gfr: $(GFROBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

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
