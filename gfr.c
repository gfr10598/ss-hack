/*
 * ss.c		"sockstat", socket statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

/*
 * Strategy:
 * Keep a map from local port to small slot number.
 * For each active slow, keep the remote port, data, and state.
 *
 * For each cycle, use generic_record_read to read the record.  Parse the local
 * and remote port and state.  Look up the slot number in the map.  If new,
 * allocate a new slot.  If old, check the state.  If the state is one of the
 *
 *
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include "utils.h"
#include "rt_names.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "namespace.h"
#include "SNAPSHOT.h"

#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>
#include <linux/netdevice.h>	/* for MAX_ADDR_LEN */
#include <linux/filter.h>
#include <linux/packet_diag.h>
#include <linux/netlink_diag.h>

//#define LOG(fmt, ...) fprintf(stderr, "%d "+fmt, __LINE__, __VA_ARGS__)
#define MAGIC_SEQ 123456

#define DIAG_REQUEST(_req, _r)						    \
	struct {							    \
		struct nlmsghdr nlh;					    \
		_r;							    \
	} _req = {							    \
		.nlh = {						    \
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,		    \
			.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST,\
			.nlmsg_seq = MAGIC_SEQ,				    \
			.nlmsg_len = sizeof(_req),			    \
		},							    \
	}

#define SUPPRESS 0
#define STASH_DATA 0

int resolve_hosts;
static int resolve_services = 1;
int preferred_family = AF_UNSPEC;
static int show_options;
int show_details;
static int show_mem;
static int show_tcpinfo;
static int show_bpf;
static int show_header = 1;
static int follow_events;
       
static int netid_width;
static int state_width;
static int addrp_width;
static int addr_width;
static int serv_width;
static int screen_width;

static const char *TCP_PROTO = "tcp";
static const char *UDP_PROTO = "udp";
static const char *RAW_PROTO = "raw";
static const char *dg_proto;

enum {
	TCP_DB,
	DCCP_DB,
	UDP_DB,
	RAW_DB,
	UNIX_DG_DB,
	UNIX_ST_DB,
	UNIX_SQ_DB,
	PACKET_DG_DB,
	PACKET_R_DB,
	NETLINK_DB,
	MAX_DB
};

#define PACKET_DBM ((1<<PACKET_DG_DB)|(1<<PACKET_R_DB))
#define UNIX_DBM ((1<<UNIX_DG_DB)|(1<<UNIX_ST_DB)|(1<<UNIX_SQ_DB))
#define ALL_DB ((1<<MAX_DB)-1)
#define INET_DBM ((1<<TCP_DB)|(1<<UDP_DB)|(1<<DCCP_DB)|(1<<RAW_DB))

enum {
	SS_UNKNOWN,
	SS_ESTABLISHED,
	SS_SYN_SENT,
	SS_SYN_RECV,
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,
	SS_CLOSE,
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,
	SS_CLOSING,
	SS_MAX
};

#define SS_ALL ((1 << SS_MAX) - 1)
#define SS_CONN (SS_ALL & ~((1<<SS_LISTEN)|(1<<SS_CLOSE)|(1<<SS_TIME_WAIT)|(1<<SS_SYN_RECV)))

#include "ssfilter.h"

struct filter {
	int dbs;
	int states;
	int families;
	struct ssfilter *f;
	bool kill;
};

static const struct filter default_dbs[MAX_DB] = {
	[TCP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[DCCP_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[UDP_DB] = {
		.states   = (1 << SS_ESTABLISHED),
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[RAW_DB] = {
		.states   = (1 << SS_ESTABLISHED),
		.families = (1 << AF_INET) | (1 << AF_INET6),
	},
	[UNIX_DG_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_UNIX),
	},
	[UNIX_ST_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_UNIX),
	},
	[UNIX_SQ_DB] = {
		.states   = SS_CONN,
		.families = (1 << AF_UNIX),
	},
	[PACKET_DG_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_PACKET),
	},
	[PACKET_R_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_PACKET),
	},
	[NETLINK_DB] = {
		.states   = (1 << SS_CLOSE),
		.families = (1 << AF_NETLINK),
	},
};

static const struct filter default_afs[AF_MAX] = {
	[AF_INET] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
	[AF_INET6] = {
		.dbs    = INET_DBM,
		.states = SS_CONN,
	},
	[AF_UNIX] = {
		.dbs    = UNIX_DBM,
		.states = SS_CONN,
	},
	[AF_PACKET] = {
		.dbs    = PACKET_DBM,
		.states = (1 << SS_CLOSE),
	},
	[AF_NETLINK] = {
		.dbs    = (1 << NETLINK_DB),
		.states = (1 << SS_CLOSE),
	},
};

static int do_default = 1;
// This is for the YACC filter in ssfilter.*.
// It is used to ...
static struct filter current_filter;

static void filter_db_set(struct filter *f, int db)
{
	f->states   |= default_dbs[db].states;
	f->dbs	    |= 1 << db;
	do_default   = 0;
}

static void filter_af_set(struct filter *f, int af)
{
	f->states	   |= default_afs[af].states;
	f->families	   |= 1 << af;
	do_default	    = 0;
	preferred_family    = af;
}

static int filter_af_get(struct filter *f, int af)
{
	return f->families & (1 << af);
}

static void filter_states_set(struct filter *f, int states)
{
	if (states)
		f->states = states;
}

static void filter_merge_defaults(struct filter *f)
{
	int db;
	int af;

	for (db = 0; db < MAX_DB; db++) {
		if (!(f->dbs & (1 << db)))
			continue;

		if (!(default_dbs[db].families & f->families))
			f->families |= default_dbs[db].families;
	}
	for (af = 0; af < AF_MAX; af++) {
		if (!(f->families & (1 << af)))
			continue;

		if (!(default_afs[af].dbs & f->dbs))
			f->dbs |= default_afs[af].dbs;
	}
}

static FILE *generic_proc_open(const char *env, const char *name)
{
	const char *p = getenv(env);
	char store[128];

	if (!p) {
		p = getenv("PROC_ROOT") ? : "/proc";
		snprintf(store, sizeof(store)-1, "%s/%s", p, name);
		p = store;
	}

	return fopen(p, "r");
}

static FILE *net_tcp_open(void)
{
	return generic_proc_open("PROC_NET_TCP", "net/tcp");
}

static FILE *net_tcp6_open(void)
{
	return generic_proc_open("PROC_NET_TCP6", "net/tcp6");
}

static FILE *net_udp_open(void)
{
	return generic_proc_open("PROC_NET_UDP", "net/udp");
}

static FILE *net_udp6_open(void)
{
	return generic_proc_open("PROC_NET_UDP6", "net/udp6");
}

static FILE *net_raw_open(void)
{
	return generic_proc_open("PROC_NET_RAW", "net/raw");
}

static FILE *net_raw6_open(void)
{
	return generic_proc_open("PROC_NET_RAW6", "net/raw6");
}

static FILE *net_unix_open(void)
{
	return generic_proc_open("PROC_NET_UNIX", "net/unix");
}

static FILE *net_packet_open(void)
{
	return generic_proc_open("PROC_NET_PACKET", "net/packet");
}

static FILE *net_netlink_open(void)
{
	return generic_proc_open("PROC_NET_NETLINK", "net/netlink");
}

static FILE *slabinfo_open(void)
{
	return generic_proc_open("PROC_SLABINFO", "slabinfo");
}

static FILE *ephemeral_ports_open(void)
{
	return generic_proc_open("PROC_IP_LOCAL_PORT_RANGE", "sys/net/ipv4/ip_local_port_range");
}

enum entry_types {
	USERS,
	PROC_CTX,
	PROC_SOCK_CTX
};


/* Get stats from slab */

struct slabstat {
	int socks;
	int tcp_ports;
	int tcp_tws;
	int tcp_syns;
	int skbs;
};

static struct slabstat slabstat;

static const char *slabstat_ids[] = {

	"sock",
	"tcp_bind_bucket",
	"tcp_tw_bucket",
	"tcp_open_request",
	"skbuff_head_cache",
};

static int get_slabstat(struct slabstat *s)
{
	char buf[256];
	FILE *fp;
	int cnt;
	static int slabstat_valid;

	if (slabstat_valid)
		return 0;

	memset(s, 0, sizeof(*s));

	fp = slabinfo_open();
	if (!fp)
		return -1;

	cnt = sizeof(*s)/sizeof(int);

	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		int i;

		for (i = 0; i < ARRAY_SIZE(slabstat_ids); i++) {
			if (memcmp(buf, slabstat_ids[i], strlen(slabstat_ids[i])) == 0) {
				sscanf(buf, "%*s%d", ((int *)s) + i);
				cnt--;
				break;
			}
		}
		if (cnt <= 0)
			break;
	}

	slabstat_valid = 1;

	fclose(fp);
	return 0;
}

static unsigned long long cookie_sk_get(const uint32_t *cookie)
{
	return (((unsigned long long)cookie[1] << 31) << 1) | cookie[0];
}

static const char *sstate_name[] = {
	"UNKNOWN",
	[SS_ESTABLISHED] = "ESTAB",
	[SS_SYN_SENT] = "SYN-SENT",
	[SS_SYN_RECV] = "SYN-RECV",
	[SS_FIN_WAIT1] = "FIN-WAIT-1",
	[SS_FIN_WAIT2] = "FIN-WAIT-2",
	[SS_TIME_WAIT] = "TIME-WAIT",
	[SS_CLOSE] = "UNCONN",
	[SS_CLOSE_WAIT] = "CLOSE-WAIT",
	[SS_LAST_ACK] = "LAST-ACK",
	[SS_LISTEN] =	"LISTEN",
	[SS_CLOSING] = "CLOSING",
};

struct sockstat {
	struct sockstat	   *next;
	unsigned int	    type;
	uint16_t	    prot;
	inet_prefix	    local;
	inet_prefix	    remote;
	int		    lport;
	int		    rport;
	int		    state;
	int		    rq, wq;
	unsigned int ino;
	unsigned int uid;
	int		    refcnt;
	unsigned int	    iface;
	unsigned long long  sk;
	char *name;
	char *peer_name;
	__u32		    mark;
};

struct dctcpstat {
	unsigned int	ce_state;
	unsigned int	alpha;
	unsigned int	ab_ecn;
	unsigned int	ab_tot;
	bool		enabled;
};

struct tcpstat {
	struct sockstat	    ss;
	int		    timer;
	int		    timeout;
	int		    probes;
	char		    cong_alg[16];
	double		    rto, ato, rtt, rttvar;
	int		    qack, ssthresh, backoff;
	double		    send_bps;
	int		    snd_wscale;
	int		    rcv_wscale;
	int		    mss;
	unsigned int	    cwnd;
	unsigned int	    lastsnd;
	unsigned int	    lastrcv;
	unsigned int	    lastack;
	double		    pacing_rate;
	double		    pacing_rate_max;
	unsigned long long  bytes_acked;
	unsigned long long  bytes_received;
	unsigned int	    segs_out;
	unsigned int	    segs_in;
	unsigned int	    data_segs_out;
	unsigned int	    data_segs_in;
	unsigned int	    unacked;
	unsigned int	    retrans;
	unsigned int	    retrans_total;
	unsigned int	    lost;
	unsigned int	    sacked;
	unsigned int	    fackets;
	unsigned int	    reordering;
	unsigned int	    not_sent;
	double		    rcv_rtt;
	double		    min_rtt;
	int		    rcv_space;
	bool		    has_ts_opt;
	bool		    has_sack_opt;
	bool		    has_ecn_opt;
	bool		    has_ecnseen_opt;
	bool		    has_fastopen_opt;
	bool		    has_wscale_opt;
	struct dctcpstat    *dctcp;
	struct tcp_bbr_info *bbr_info;
};

static void sock_state_print(struct sockstat *s, const char *sock_name)
{
	if (netid_width)
		printf("%-*s ", netid_width, sock_name);
	if (state_width)
		printf("%-*s ", state_width, sstate_name[s->state]);

	printf("%-6d %-6d ", s->rq, s->wq);
}

static void sock_details_print(struct sockstat *s)
{
	if (s->uid)
		printf(" uid:%u", s->uid);

	printf(" ino:%u", s->ino);
	printf(" sk:%llx", s->sk);

	if (s->mark)
		printf(" fwmark:0x%x", s->mark);
}

static void sock_addr_print_width(int addr_len, const char *addr, char *delim,
		int port_len, const char *port, const char *ifname)
{
	if (ifname) {
		printf("%*s%%%s%s%-*s ", addr_len, addr, ifname, delim,
				port_len, port);
	} else {
		printf("%*s%s%-*s ", addr_len, addr, delim, port_len, port);
	}
}

static void sock_addr_print(const char *addr, char *delim, const char *port,
		const char *ifname)
{
	sock_addr_print_width(addr_width, addr, delim, serv_width, port, ifname);
}

static const char *tmr_name[] = {
	"off",
	"on",
	"keepalive",
	"timewait",
	"persist",
	"unknown"
};

static const char *print_ms_timer(int timeout)
{
	static char buf[64];
	int secs, msecs, minutes;

	if (timeout < 0)
		timeout = 0;
	secs = timeout/1000;
	minutes = secs/60;
	secs = secs%60;
	msecs = timeout%1000;
	buf[0] = 0;
	if (minutes) {
		msecs = 0;
		snprintf(buf, sizeof(buf)-16, "%dmin", minutes);
		if (minutes > 9)
			secs = 0;
	}
	if (secs) {
		if (secs > 9)
			msecs = 0;
		sprintf(buf+strlen(buf), "%d%s", secs, msecs ? "." : "sec");
	}
	if (msecs)
		sprintf(buf+strlen(buf), "%03dms", msecs);
	return buf;
}

struct scache {
	struct scache *next;
	int port;
	char *name;
	const char *proto;
};

struct scache *rlist;

/* Even do not try default linux ephemeral port ranges:
 * default /etc/services contains so much of useless crap
 * wouldbe "allocated" to this area that resolution
 * is really harmful. I shrug each time when seeing
 * "socks" or "cfinger" in dumps.
 */
static int is_ephemeral(int port)
{
	static int min = 0, max;

	if (!min) {
		FILE *f = ephemeral_ports_open();

		if (!f || fscanf(f, "%d %d", &min, &max) < 2) {
			min = 1024;
			max = 4999;
		}
		if (f)
			fclose(f);
	}
	return port >= min && port <= max;
}


static const char *__resolve_service(int port)
{
	struct scache *c;

	for (c = rlist; c; c = c->next) {
		if (c->port == port && c->proto == dg_proto)
			return c->name;
	}

	if (!is_ephemeral(port)) {
		static int notfirst;
		struct servent *se;

		if (!notfirst) {
			setservent(1);
			notfirst = 1;
		}
		se = getservbyport(htons(port), dg_proto);
		if (se)
			return se->s_name;
	}

	return NULL;
}

#define SCACHE_BUCKETS 1024
static struct scache *cache_htab[SCACHE_BUCKETS];

static const char *resolve_service(int port)
{
	static char buf[128];
	struct scache *c;
	const char *res;
	int hash;

	if (port == 0) {
		buf[0] = '*';
		buf[1] = 0;
		return buf;
	}

	if (!resolve_services)
		goto do_numeric;

	if (dg_proto == RAW_PROTO)
		return inet_proto_n2a(port, buf, sizeof(buf));


	hash = (port^(((unsigned long)dg_proto)>>2)) % SCACHE_BUCKETS;

	for (c = cache_htab[hash]; c; c = c->next) {
		if (c->port == port && c->proto == dg_proto)
			goto do_cache;
	}

	c = malloc(sizeof(*c));
	if (!c)
		goto do_numeric;
	res = __resolve_service(port);
	c->port = port;
	c->name = res ? strdup(res) : NULL;
	c->proto = dg_proto;
	c->next = cache_htab[hash];
	cache_htab[hash] = c;

do_cache:
	if (c->name)
		return c->name;

do_numeric:
	sprintf(buf, "%u", port);
	return buf;
}

static void inet_addr_print(const inet_prefix *a, int port, unsigned int ifindex)
{
	char buf[1024];
	const char *ap = buf;
	int est_len = addr_width;
	const char *ifname = NULL;

	if (a->family == AF_INET) {
		if (a->data[0] == 0) {
			buf[0] = '*';
			buf[1] = 0;
		} else {
			ap = format_host(AF_INET, 4, a->data);
		}
	} else {
		ap = format_host(a->family, 16, a->data);
		est_len = strlen(ap);
		if (est_len <= addr_width)
			est_len = addr_width;
		else
			est_len = addr_width + ((est_len-addr_width+3)/4)*4;
	}

	if (ifindex) {
		ifname   = ll_index_to_name(ifindex);
		est_len -= strlen(ifname) + 1;  /* +1 for percent char */
		if (est_len < 0)
			est_len = 0;
	}

	sock_addr_print_width(est_len, ap, ":", serv_width, resolve_service(port),
			ifname);
}

struct aafilter {
	inet_prefix	addr;
	int		port;
	unsigned int	iface;
	__u32		mark;
	__u32		mask;
	struct aafilter *next;
};

static int inet2_addr_match(const inet_prefix *a, const inet_prefix *p,
			    int plen)
{
	if (!inet_addr_match(a, p, plen))
		return 0;

	/* Cursed "v4 mapped" addresses: v4 mapped socket matches
	 * pure IPv4 rule, but v4-mapped rule selects only v4-mapped
	 * sockets. Fair? */
	if (p->family == AF_INET && a->family == AF_INET6) {
		if (a->data[0] == 0 && a->data[1] == 0 &&
		    a->data[2] == htonl(0xffff)) {
			inet_prefix tmp = *a;

			tmp.data[0] = a->data[3];
			return inet_addr_match(&tmp, p, plen);
		}
	}
	return 1;
}

static int unix_match(const inet_prefix *a, const inet_prefix *p)
{
	char *addr, *pattern;

	memcpy(&addr, a->data, sizeof(addr));
	memcpy(&pattern, p->data, sizeof(pattern));
	if (pattern == NULL)
		return 1;
	if (addr == NULL)
		addr = "";
	return !fnmatch(pattern, addr, 0);
}

static int run_ssfilter(struct ssfilter *f, struct sockstat *s)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
		if (s->local.family == AF_UNIX) {
			char *p;

			memcpy(&p, s->local.data, sizeof(p));
			return p == NULL || (p[0] == '@' && strlen(p) == 6 &&
					     strspn(p+1, "0123456789abcdef") == 5);
		}
		if (s->local.family == AF_PACKET)
			return s->lport == 0 && s->local.data[0] == 0;
		if (s->local.family == AF_NETLINK)
			return s->lport < 0;

		return is_ephemeral(s->lport);
	}
		case SSF_DCOND:
	{
		struct aafilter *a = (void *)f->pred;

		if (a->addr.family == AF_UNIX)
			return unix_match(&s->remote, &a->addr);
		if (a->port != -1 && a->port != s->rport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->remote, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_SCOND:
	{
		struct aafilter *a = (void *)f->pred;

		if (a->addr.family == AF_UNIX)
			return unix_match(&s->local, &a->addr);
		if (a->port != -1 && a->port != s->lport)
			return 0;
		if (a->addr.bitlen) {
			do {
				if (!inet2_addr_match(&s->local, &a->addr, a->addr.bitlen))
					return 1;
			} while ((a = a->next) != NULL);
			return 0;
		}
		return 1;
	}
		case SSF_D_GE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->rport >= a->port;
	}
		case SSF_D_LE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->rport <= a->port;
	}
		case SSF_S_GE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->lport >= a->port;
	}
		case SSF_S_LE:
	{
		struct aafilter *a = (void *)f->pred;

		return s->lport <= a->port;
	}
		case SSF_DEVCOND:
	{
		struct aafilter *a = (void *)f->pred;

		return s->iface == a->iface;
	}
		case SSF_MARKMASK:
	{
		struct aafilter *a = (void *)f->pred;

		return (s->mark & a->mask) == a->mark;
	}
		/* Yup. It is recursion. Sorry. */
		case SSF_AND:
		return run_ssfilter(f->pred, s) && run_ssfilter(f->post, s);
		case SSF_OR:
		return run_ssfilter(f->pred, s) || run_ssfilter(f->post, s);
		case SSF_NOT:
		return !run_ssfilter(f->pred, s);
		default:
		abort();
	}
}

/* Relocate external jumps by reloc. */
static void ssfilter_patch(char *a, int len, int reloc)
{
	while (len > 0) {
		struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)a;

		if (op->no == len+4)
			op->no += reloc;
		len -= op->yes;
		a += op->yes;
	}
	if (len < 0)
		abort();
}

static int ssfilter_bytecompile(struct ssfilter *f, char **bytecode)
{
	switch (f->type) {
		case SSF_S_AUTO:
	{
		if (!(*bytecode = malloc(4))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_AUTO, 4, 8 };
		return 4;
	}
		case SSF_DCOND:
		case SSF_SCOND:
	{
		struct aafilter *a = (void *)f->pred;
		struct aafilter *b;
		char *ptr;
		int  code = (f->type == SSF_DCOND ? INET_DIAG_BC_D_COND : INET_DIAG_BC_S_COND);
		int len = 0;

		for (b = a; b; b = b->next) {
			len += 4 + sizeof(struct inet_diag_hostcond);
			if (a->addr.family == AF_INET6)
				len += 16;
			else
				len += 4;
			if (b->next)
				len += 4;
		}
		if (!(ptr = malloc(len))) abort();
		*bytecode = ptr;
		for (b = a; b; b = b->next) {
			struct inet_diag_bc_op *op = (struct inet_diag_bc_op *)ptr;
			int alen = (a->addr.family == AF_INET6 ? 16 : 4);
			int oplen = alen + 4 + sizeof(struct inet_diag_hostcond);
			struct inet_diag_hostcond *cond = (struct inet_diag_hostcond *)(ptr+4);

			*op = (struct inet_diag_bc_op){ code, oplen, oplen+4 };
			cond->family = a->addr.family;
			cond->port = a->port;
			cond->prefix_len = a->addr.bitlen;
			memcpy(cond->addr, a->addr.data, alen);
			ptr += oplen;
			if (b->next) {
				op = (struct inet_diag_bc_op *)ptr;
				*op = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, len - (ptr-*bytecode)};
				ptr += 4;
			}
		}
		return ptr - *bytecode;
	}
		case SSF_D_GE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_GE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_D_LE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_D_LE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_GE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_GE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}
		case SSF_S_LE:
	{
		struct aafilter *x = (void *)f->pred;

		if (!(*bytecode = malloc(8))) abort();
		((struct inet_diag_bc_op *)*bytecode)[0] = (struct inet_diag_bc_op){ INET_DIAG_BC_S_LE, 8, 12 };
		((struct inet_diag_bc_op *)*bytecode)[1] = (struct inet_diag_bc_op){ 0, 0, x->port };
		return 8;
	}

		case SSF_AND:
	{
		char *a1 = NULL, *a2 = NULL, *a;
		int l1, l2;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!l1 || !l2) {
			free(a1);
			free(a2);
			return 0;
		}
		if (!(a = malloc(l1+l2))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1, a2, l2);
		free(a1); free(a2);
		ssfilter_patch(a, l1, l2);
		*bytecode = a;
		return l1+l2;
	}
		case SSF_OR:
	{
		char *a1 = NULL, *a2 = NULL, *a;
		int l1, l2;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		l2 = ssfilter_bytecompile(f->post, &a2);
		if (!l1 || !l2) {
			free(a1);
			free(a2);
			return 0;
		}
		if (!(a = malloc(l1+l2+4))) abort();
		memcpy(a, a1, l1);
		memcpy(a+l1+4, a2, l2);
		free(a1); free(a2);
		*(struct inet_diag_bc_op *)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, l2+4 };
		*bytecode = a;
		return l1+l2+4;
	}
		case SSF_NOT:
	{
		char *a1 = NULL, *a;
		int l1;

		l1 = ssfilter_bytecompile(f->pred, &a1);
		if (!l1) {
			free(a1);
			return 0;
		}
		if (!(a = malloc(l1+4))) abort();
		memcpy(a, a1, l1);
		free(a1);
		*(struct inet_diag_bc_op *)(a+l1) = (struct inet_diag_bc_op){ INET_DIAG_BC_JMP, 4, 8 };
		*bytecode = a;
		return l1+4;
	}
		case SSF_DEVCOND:
	{
		/* bytecompile for SSF_DEVCOND not supported yet */
		return 0;
	}
		case SSF_MARKMASK:
	{
		struct aafilter *a = (void *)f->pred;
		struct instr {
			struct inet_diag_bc_op op;
			struct inet_diag_markcond cond;
		};
		int inslen = sizeof(struct instr);

		if (!(*bytecode = malloc(inslen))) abort();
		((struct instr *)*bytecode)[0] = (struct instr) {
			{ INET_DIAG_BC_MARK_COND, inslen, inslen + 4 },
			{ a->mark, a->mask},
		};

		return inslen;
	}
		default:
		abort();
	}
}

static int remember_he(struct aafilter *a, struct hostent *he)
{
	char **ptr = he->h_addr_list;
	int cnt = 0;
	int len;

	if (he->h_addrtype == AF_INET)
		len = 4;
	else if (he->h_addrtype == AF_INET6)
		len = 16;
	else
		return 0;

	while (*ptr) {
		struct aafilter *b = a;

		if (a->addr.bitlen) {
			if ((b = malloc(sizeof(*b))) == NULL)
				return cnt;
			*b = *a;
			b->next = a->next;
			a->next = b;
		}
		memcpy(b->addr.data, *ptr, len);
		b->addr.bytelen = len;
		b->addr.bitlen = len*8;
		b->addr.family = he->h_addrtype;
		ptr++;
		cnt++;
	}
	return cnt;
}

static int get_dns_host(struct aafilter *a, const char *addr, int fam)
{
	static int notfirst;
	int cnt = 0;
	struct hostent *he;

	a->addr.bitlen = 0;
	if (!notfirst) {
		sethostent(1);
		notfirst = 1;
	}
	he = gethostbyname2(addr, fam == AF_UNSPEC ? AF_INET : fam);
	if (he)
		cnt = remember_he(a, he);
	if (fam == AF_UNSPEC) {
		he = gethostbyname2(addr, AF_INET6);
		if (he)
			cnt += remember_he(a, he);
	}
	return !cnt;
}

static int xll_initted;

static void xll_init(void)
{
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	ll_init_map(&rth);
	rtnl_close(&rth);
	xll_initted = 1;
}

static const char *xll_index_to_name(int index)
{
	if (!xll_initted)
		xll_init();
	return ll_index_to_name(index);
}

static int xll_name_to_index(const char *dev)
{
	if (!xll_initted)
		xll_init();
	return ll_name_to_index(dev);
}

void *parse_devcond(char *name)
{
	struct aafilter a = { .iface = 0 };
	struct aafilter *res;

	a.iface = xll_name_to_index(name);
	if (a.iface == 0) {
		char *end;
		unsigned long n;

		n = strtoul(name, &end, 0);
		if (!end || end == name || *end || n > UINT_MAX)
			return NULL;

		a.iface = n;
	}

	res = malloc(sizeof(*res));
	*res = a;

	return res;
}

void *parse_hostcond(char *addr, bool is_port)
{
	char *port = NULL;
	struct aafilter a = { .port = -1 };
	struct aafilter *res;
	int fam = preferred_family;
	struct filter *f = &current_filter;

	if (fam == AF_UNIX || strncmp(addr, "unix:", 5) == 0) {
		char *p;

		a.addr.family = AF_UNIX;
		if (strncmp(addr, "unix:", 5) == 0)
			addr += 5;
		p = strdup(addr);
		a.addr.bitlen = 8*strlen(p);
		memcpy(a.addr.data, &p, sizeof(p));
		fam = AF_UNIX;
		goto out;
	}

	if (fam == AF_PACKET || strncmp(addr, "link:", 5) == 0) {
		a.addr.family = AF_PACKET;
		a.addr.bitlen = 0;
		if (strncmp(addr, "link:", 5) == 0)
			addr += 5;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if ((a.port = xll_name_to_index(port+1)) <= 0)
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			unsigned short tmp;

			a.addr.bitlen = 32;
			if (ll_proto_a2n(&tmp, addr))
				return NULL;
			a.addr.data[0] = ntohs(tmp);
		}
		fam = AF_PACKET;
		goto out;
	}

	if (fam == AF_NETLINK || strncmp(addr, "netlink:", 8) == 0) {
		a.addr.family = AF_NETLINK;
		a.addr.bitlen = 0;
		if (strncmp(addr, "netlink:", 8) == 0)
			addr += 8;
		port = strchr(addr, ':');
		if (port) {
			*port = 0;
			if (port[1] && strcmp(port+1, "*")) {
				if (get_integer(&a.port, port+1, 0)) {
					if (strcmp(port+1, "kernel") == 0)
						a.port = 0;
					else
						return NULL;
				}
			}
		}
		if (addr[0] && strcmp(addr, "*")) {
			a.addr.bitlen = 32;
			if (nl_proto_a2n(&a.addr.data[0], addr) == -1)
				return NULL;
		}
		fam = AF_NETLINK;
		goto out;
	}

	if (fam == AF_INET || !strncmp(addr, "inet:", 5)) {
		fam = AF_INET;
		if (!strncmp(addr, "inet:", 5))
			addr += 5;
	} else if (fam == AF_INET6 || !strncmp(addr, "inet6:", 6)) {
		fam = AF_INET6;
		if (!strncmp(addr, "inet6:", 6))
			addr += 6;
	}

	/* URL-like literal [] */
	if (addr[0] == '[') {
		addr++;
		if ((port = strchr(addr, ']')) == NULL)
			return NULL;
		*port++ = 0;
	} else if (addr[0] == '*') {
		port = addr+1;
	} else {
		port = strrchr(strchr(addr, '/') ? : addr, ':');
	}

	if (is_port)
		port = addr;

	if (port && *port) {
		if (*port == ':')
			*port++ = 0;

		if (*port && *port != '*') {
			if (get_integer(&a.port, port, 0)) {
				struct servent *se1 = NULL;
				struct servent *se2 = NULL;

				if (current_filter.dbs&(1<<UDP_DB))
					se1 = getservbyname(port, UDP_PROTO);
				if (current_filter.dbs&(1<<TCP_DB))
					se2 = getservbyname(port, TCP_PROTO);
				if (se1 && se2 && se1->s_port != se2->s_port) {
					fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
					return NULL;
				}
				if (!se1)
					se1 = se2;
				if (se1) {
					a.port = ntohs(se1->s_port);
				} else {
					struct scache *s;

					for (s = rlist; s; s = s->next) {
						if ((s->proto == UDP_PROTO &&
						     (current_filter.dbs&(1<<UDP_DB))) ||
						    (s->proto == TCP_PROTO &&
						     (current_filter.dbs&(1<<TCP_DB)))) {
							if (s->name && strcmp(s->name, port) == 0) {
								if (a.port > 0 && a.port != s->port) {
									fprintf(stderr, "Error: ambiguous port \"%s\".\n", port);
									return NULL;
								}
								a.port = s->port;
							}
						}
					}
					if (a.port <= 0) {
						fprintf(stderr, "Error: \"%s\" does not look like a port.\n", port);
						return NULL;
					}
				}
			}
		}
	}
	if (!is_port && addr && *addr && *addr != '*') {
		if (get_prefix_1(&a.addr, addr, fam)) {
			if (get_dns_host(&a, addr, fam)) {
				fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", addr);
				return NULL;
			}
		}
	}

out:
	if (fam != AF_UNSPEC) {
		int states = f->states;
		f->families = 0;
		filter_af_set(f, fam);
		filter_states_set(f, states);
	}

	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

void *parse_markmask(const char *markmask)
{
	struct aafilter a, *res;

	if (strchr(markmask, '/')) {
		if (sscanf(markmask, "%i/%i", &a.mark, &a.mask) != 2)
			return NULL;
	} else {
		a.mask = 0xffffffff;
		if (sscanf(markmask, "%i", &a.mark) != 1)
			return NULL;
	}

	res = malloc(sizeof(*res));
	if (res)
		memcpy(res, &a, sizeof(a));
	return res;
}

static char *proto_name(int protocol)
{
	switch (protocol) {
	case 0:
		return "raw";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_DCCP:
		return "dccp";
	}

	return "???";
}

static void inet_stats_print(struct sockstat *s, int protocol)
{
	sock_state_print(s, proto_name(protocol));

	inet_addr_print(&s->local, s->lport, s->iface);
	inet_addr_print(&s->remote, s->rport, 0);
}

static int proc_parse_inet_addr(char *loc, char *rem, int family, struct
		sockstat * s)
{
	s->local.family = s->remote.family = family;
	if (family == AF_INET) {
		sscanf(loc, "%x:%x", s->local.data, (unsigned *)&s->lport);
		sscanf(rem, "%x:%x", s->remote.data, (unsigned *)&s->rport);
		s->local.bytelen = s->remote.bytelen = 4;
		return 0;
	} else {
		sscanf(loc, "%08x%08x%08x%08x:%x",
		       s->local.data,
		       s->local.data + 1,
		       s->local.data + 2,
		       s->local.data + 3,
		       &s->lport);
		sscanf(rem, "%08x%08x%08x%08x:%x",
		       s->remote.data,
		       s->remote.data + 1,
		       s->remote.data + 2,
		       s->remote.data + 3,
		       &s->rport);
		s->local.bytelen = s->remote.bytelen = 16;
		return 0;
	}
	return -1;
}

static int proc_inet_split_line(char *line, char **loc, char **rem, char **data)
{
	char *p;

	if ((p = strchr(line, ':')) == NULL)
		return -1;

	*loc = p+2;
	if ((p = strchr(*loc, ':')) == NULL)
		return -1;

	p[5] = 0;
	*rem = p+6;
	if ((p = strchr(*rem, ':')) == NULL)
		return -1;

	p[5] = 0;
	*data = p+6;
	return 0;
}

static char *sprint_bw(char *buf, double bw)
{
	if (bw > 1000000.)
		sprintf(buf, "%.1fM", bw / 1000000.);
	else if (bw > 1000.)
		sprintf(buf, "%.1fK", bw / 1000.);
	else
		sprintf(buf, "%g", bw);

	return buf;
}

static void tcp_stats_print(struct tcpstat *s)
{
	char b1[64];

	if (s->has_ts_opt)
		printf(" ts");
	if (s->has_sack_opt)
		printf(" sack");
	if (s->has_ecn_opt)
		printf(" ecn");
	if (s->has_ecnseen_opt)
		printf(" ecnseen");
	if (s->has_fastopen_opt)
		printf(" fastopen");
	if (s->cong_alg[0])
		printf(" %s", s->cong_alg);
	if (s->has_wscale_opt)
		printf(" wscale:%d,%d", s->snd_wscale, s->rcv_wscale);
	if (s->rto)
		printf(" rto:%g", s->rto);
	if (s->backoff)
		printf(" backoff:%u", s->backoff);
	if (s->rtt)
		printf(" rtt:%g/%g", s->rtt, s->rttvar);
	if (s->ato)
		printf(" ato:%g", s->ato);

	if (s->qack)
		printf(" qack:%d", s->qack);
	if (s->qack & 1)
		printf(" bidir");

	if (s->mss)
		printf(" mss:%d", s->mss);
	if (s->cwnd)
		printf(" cwnd:%u", s->cwnd);
	if (s->ssthresh)
		printf(" ssthresh:%d", s->ssthresh);

	if (s->bytes_acked)
		printf(" bytes_acked:%llu", s->bytes_acked);
	if (s->bytes_received)
		printf(" bytes_received:%llu", s->bytes_received);
	if (s->segs_out)
		printf(" segs_out:%u", s->segs_out);
	if (s->segs_in)
		printf(" segs_in:%u", s->segs_in);
	if (s->data_segs_out)
		printf(" data_segs_out:%u", s->data_segs_out);
	if (s->data_segs_in)
		printf(" data_segs_in:%u", s->data_segs_in);

	if (s->dctcp && s->dctcp->enabled) {
		struct dctcpstat *dctcp = s->dctcp;

		printf(" dctcp:(ce_state:%u,alpha:%u,ab_ecn:%u,ab_tot:%u)",
				dctcp->ce_state, dctcp->alpha, dctcp->ab_ecn,
				dctcp->ab_tot);
	} else if (s->dctcp) {
		printf(" dctcp:fallback_mode");
	}

	if (s->bbr_info) {
		__u64 bw;

		bw = s->bbr_info->bbr_bw_hi;
		bw <<= 32;
		bw |= s->bbr_info->bbr_bw_lo;

		printf(" bbr:(bw:%sbps,mrtt:%g",
		       sprint_bw(b1, bw * 8.0),
		       (double)s->bbr_info->bbr_min_rtt / 1000.0);
		if (s->bbr_info->bbr_pacing_gain)
			printf(",pacing_gain:%g",
			       (double)s->bbr_info->bbr_pacing_gain / 256.0);
		if (s->bbr_info->bbr_cwnd_gain)
			printf(",cwnd_gain:%g",
			       (double)s->bbr_info->bbr_cwnd_gain / 256.0);
		printf(")");
	}

	if (s->send_bps)
		printf(" send %sbps", sprint_bw(b1, s->send_bps));
	if (s->lastsnd)
		printf(" lastsnd:%u", s->lastsnd);
	if (s->lastrcv)
		printf(" lastrcv:%u", s->lastrcv);
	if (s->lastack)
		printf(" lastack:%u", s->lastack);

	if (s->pacing_rate) {
		printf(" pacing_rate %sbps", sprint_bw(b1, s->pacing_rate));
		if (s->pacing_rate_max)
				printf("/%sbps", sprint_bw(b1,
							s->pacing_rate_max));
	}

	if (s->unacked)
		printf(" unacked:%u", s->unacked);
	if (s->retrans || s->retrans_total)
		printf(" retrans:%u/%u", s->retrans, s->retrans_total);
	if (s->lost)
		printf(" lost:%u", s->lost);
	if (s->sacked && s->ss.state != SS_LISTEN)
		printf(" sacked:%u", s->sacked);
	if (s->fackets)
		printf(" fackets:%u", s->fackets);
	if (s->reordering != 3)
		printf(" reordering:%d", s->reordering);
	if (s->rcv_rtt)
		printf(" rcv_rtt:%g", s->rcv_rtt);
	if (s->rcv_space)
		printf(" rcv_space:%d", s->rcv_space);
	if (s->not_sent)
		printf(" notsent:%u", s->not_sent);
	if (s->min_rtt)
		printf(" minrtt:%g", s->min_rtt);
}

static void tcp_timer_print(struct tcpstat *s)
{
	if (s->timer) {
		if (s->timer > 4)
			s->timer = 5;
		printf(" timer:(%s,%s,%d)",
				tmr_name[s->timer],
				print_ms_timer(s->timeout),
				s->retrans);
	}
}

static int tcp_show_data(char *loc, char* rem, char* data, const struct filter *f, int family)
{
	int rto = 0, ato = 0;
	struct tcpstat s = {};
	char opt[256];
	int n;
	int hz = get_user_hz();

        // Hex(?) state value, e.g. C:
	int state = (data[1] >= 'A') ? (data[1] - 'A' + 10) : (data[1] - '0');

        // Filter out any states we don't care about.
	if (!(f->states & (1 << state)))
		return 0;

	proc_parse_inet_addr(loc, rem, family, &s.ss);

	if (f->f && run_ssfilter(f->f, &s.ss) == 0)
		return 0;

	opt[0] = 0;
	n = sscanf(data, "%x %x:%x %x:%x %x %d %d %u %d %llx %d %d %d %u %d %[^\n]\n",
		   &s.ss.state, &s.ss.wq, &s.ss.rq,
		   &s.timer, &s.timeout, &s.retrans, &s.ss.uid, &s.probes,
		   &s.ss.ino, &s.ss.refcnt, &s.ss.sk, &rto, &ato, &s.qack, &s.cwnd,
		   &s.ssthresh, opt);

	if (n < 17)
		opt[0] = 0;

	if (n < 12) {
		rto = 0;
		s.cwnd = 2;
		s.ssthresh = -1;
		ato = s.qack = 0;
	}

	s.retrans   = s.timer != 1 ? s.probes : s.retrans;
	s.timeout   = (s.timeout * 1000 + hz - 1) / hz;
	s.ato	    = (double)ato / hz;
	s.qack	   /= 2;
	s.rto	    = (double)rto;
	s.ssthresh  = s.ssthresh == -1 ? 0 : s.ssthresh;
	s.rto	    = s.rto != 3 * hz  ? s.rto / hz : 0;

        printf("%s ::: ", data);

	inet_stats_print(&s.ss, IPPROTO_TCP);  // OUTPUT

	if (show_options)
		tcp_timer_print(&s);

	if (show_details) {
		sock_details_print(&s.ss);
		if (opt[0])
			printf(" opt:\"%s\"", opt);
	}

	if (show_tcpinfo)
		tcp_stats_print(&s);  // OUTPUT

	printf("\n");  // OUTPUT
	return 0;
}

int stash_data(char *loc, char* rem, char* data, int family);

// GFR: For each connection, we need to capture its data and save it, and mark
// it as updated.  Then, we need to go through all entries that were NOT
// updated, and output them.
static int tcp_show_line(char *line, const struct filter *f, int family)
{
	char *loc, *rem, *data;

	if (proc_inet_split_line(line, &loc, &rem, &data))
		return -1;

        // Hex(?) state value, e.g. C:
	int state = (data[1] >= 'A') ? (data[1] - 'A' + 10) : (data[1] - '0');

        // Filter out any states we don't care about.
	if (!(f->states & (1 << state)))
		return 0;

        // Filter out any other lines we don't care about.
	struct sockstat ss = {};
	proc_parse_inet_addr(loc, rem, family, &ss);

	if (f->f && run_ssfilter(f->f, &ss) == 0)
		return 0;

        stash_data(loc, rem, data, family);

        return tcp_show_data(loc, rem, data, f, family);
}

static int generic_record_read(FILE *fp,
			       int (*worker)(char*, const struct filter *, int),
			       const struct filter *f, int fam)
{
	char line[256];

	/* skip header */
	if (fgets(line, sizeof(line), fp) == NULL)
		goto outerr;

	while (fgets(line, sizeof(line), fp) != NULL) {
		int n = strlen(line);

		if (n == 0 || line[n-1] != '\n') {
			errno = -EINVAL;
			return -1;
		}
		line[n-1] = 0;

		if (worker(line, f, fam) < 0)
			return 0;
	}
outerr:

	return ferror(fp) ? -1 : 0;
}

static void print_skmeminfo(struct rtattr *tb[], int attrtype)
{
	const __u32 *skmeminfo;

	if (!tb[attrtype]) {
		if (attrtype == INET_DIAG_SKMEMINFO) {
			if (!tb[INET_DIAG_MEMINFO])
				return;

			const struct inet_diag_meminfo *minfo =
				RTA_DATA(tb[INET_DIAG_MEMINFO]);

			printf(" mem:(r%u,w%u,f%u,t%u)",
					minfo->idiag_rmem,
					minfo->idiag_wmem,
					minfo->idiag_fmem,
					minfo->idiag_tmem);
		}
		return;
	}

	skmeminfo = RTA_DATA(tb[attrtype]);

	printf(" skmem:(r%u,rb%u,t%u,tb%u,f%u,w%u,o%u",
	       skmeminfo[SK_MEMINFO_RMEM_ALLOC],
	       skmeminfo[SK_MEMINFO_RCVBUF],
	       skmeminfo[SK_MEMINFO_WMEM_ALLOC],
	       skmeminfo[SK_MEMINFO_SNDBUF],
	       skmeminfo[SK_MEMINFO_FWD_ALLOC],
	       skmeminfo[SK_MEMINFO_WMEM_QUEUED],
	       skmeminfo[SK_MEMINFO_OPTMEM]);

	if (RTA_PAYLOAD(tb[attrtype]) >=
		(SK_MEMINFO_BACKLOG + 1) * sizeof(__u32))
		printf(",bl%u", skmeminfo[SK_MEMINFO_BACKLOG]);

	if (RTA_PAYLOAD(tb[attrtype]) >=
		(SK_MEMINFO_DROPS + 1) * sizeof(__u32))
		printf(",d%u", skmeminfo[SK_MEMINFO_DROPS]);

	printf(")");
}

#define TCPI_HAS_OPT(info, opt) !!(info->tcpi_options & (opt))

static void tcp_show_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r,
		struct rtattr *tb[])
{
  if (SUPPRESS) {
    //LOG("tcp_show_info suppressed.\n");
    fprintf(stderr, "tcp_show_info suppressed.\n");
    return;
  }
	double rtt = 0;
	struct tcpstat s = {};

	s.ss.state = r->idiag_state;

	print_skmeminfo(tb, INET_DIAG_SKMEMINFO);

	if (tb[INET_DIAG_INFO]) {
		struct tcp_info *info;
		int len = RTA_PAYLOAD(tb[INET_DIAG_INFO]);

		/* workaround for older kernels with less fields */
		if (len < sizeof(*info)) {
			info = alloca(sizeof(*info));
			memcpy(info, RTA_DATA(tb[INET_DIAG_INFO]), len);
			memset((char *)info + len, 0, sizeof(*info) - len);
		} else
			info = RTA_DATA(tb[INET_DIAG_INFO]);

		if (show_options) {
			s.has_ts_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_TIMESTAMPS);
			s.has_sack_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_SACK);
			s.has_ecn_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_ECN);
			s.has_ecnseen_opt  = TCPI_HAS_OPT(info, TCPI_OPT_ECN_SEEN);
			s.has_fastopen_opt = TCPI_HAS_OPT(info, TCPI_OPT_SYN_DATA);
		}

		if (tb[INET_DIAG_CONG])
			strncpy(s.cong_alg,
				rta_getattr_str(tb[INET_DIAG_CONG]),
				sizeof(s.cong_alg) - 1);

		if (TCPI_HAS_OPT(info, TCPI_OPT_WSCALE)) {
			s.has_wscale_opt  = true;
			s.snd_wscale	  = info->tcpi_snd_wscale;
			s.rcv_wscale	  = info->tcpi_rcv_wscale;
		}

		if (info->tcpi_rto && info->tcpi_rto != 3000000)
			s.rto = (double)info->tcpi_rto / 1000;

		s.backoff	 = info->tcpi_backoff;
		s.rtt		 = (double)info->tcpi_rtt / 1000;
		s.rttvar	 = (double)info->tcpi_rttvar / 1000;
		s.ato		 = (double)info->tcpi_ato / 1000;
		s.mss		 = info->tcpi_snd_mss;
		s.rcv_space	 = info->tcpi_rcv_space;
		s.rcv_rtt	 = (double)info->tcpi_rcv_rtt / 1000;
		s.lastsnd	 = info->tcpi_last_data_sent;
		s.lastrcv	 = info->tcpi_last_data_recv;
		s.lastack	 = info->tcpi_last_ack_recv;
		s.unacked	 = info->tcpi_unacked;
		s.retrans	 = info->tcpi_retrans;
		s.retrans_total  = info->tcpi_total_retrans;
		s.lost		 = info->tcpi_lost;
		s.sacked	 = info->tcpi_sacked;
		s.reordering	 = info->tcpi_reordering;
		s.rcv_space	 = info->tcpi_rcv_space;
		s.cwnd		 = info->tcpi_snd_cwnd;

		if (info->tcpi_snd_ssthresh < 0xFFFF)
			s.ssthresh = info->tcpi_snd_ssthresh;

		rtt = (double) info->tcpi_rtt;
		if (tb[INET_DIAG_VEGASINFO]) {
			const struct tcpvegas_info *vinfo
				= RTA_DATA(tb[INET_DIAG_VEGASINFO]);

			if (vinfo->tcpv_enabled &&
					vinfo->tcpv_rtt && vinfo->tcpv_rtt != 0x7fffffff)
				rtt =  vinfo->tcpv_rtt;
		}

		if (tb[INET_DIAG_DCTCPINFO]) {
			struct dctcpstat *dctcp = malloc(sizeof(struct
						dctcpstat));

			const struct tcp_dctcp_info *dinfo
				= RTA_DATA(tb[INET_DIAG_DCTCPINFO]);

			dctcp->enabled	= !!dinfo->dctcp_enabled;
			dctcp->ce_state = dinfo->dctcp_ce_state;
			dctcp->alpha	= dinfo->dctcp_alpha;
			dctcp->ab_ecn	= dinfo->dctcp_ab_ecn;
			dctcp->ab_tot	= dinfo->dctcp_ab_tot;
			s.dctcp		= dctcp;
		}

		if (tb[INET_DIAG_BBRINFO]) {
			const void *bbr_info = RTA_DATA(tb[INET_DIAG_BBRINFO]);
			int len = min(RTA_PAYLOAD(tb[INET_DIAG_BBRINFO]),
				      sizeof(*s.bbr_info));

			s.bbr_info = calloc(1, sizeof(*s.bbr_info));
			if (s.bbr_info && bbr_info)
				memcpy(s.bbr_info, bbr_info, len);
		}

		if (rtt > 0 && info->tcpi_snd_mss && info->tcpi_snd_cwnd) {
			s.send_bps = (double) info->tcpi_snd_cwnd *
				(double)info->tcpi_snd_mss * 8000000. / rtt;
		}

		if (info->tcpi_pacing_rate &&
				info->tcpi_pacing_rate != ~0ULL) {
			s.pacing_rate = info->tcpi_pacing_rate * 8.;

			if (info->tcpi_max_pacing_rate &&
					info->tcpi_max_pacing_rate != ~0ULL)
				s.pacing_rate_max = info->tcpi_max_pacing_rate * 8.;
		}
		s.bytes_acked = info->tcpi_bytes_acked;
		s.bytes_received = info->tcpi_bytes_received;
		s.segs_out = info->tcpi_segs_out;
		s.segs_in = info->tcpi_segs_in;
		s.data_segs_out = info->tcpi_data_segs_out;
		s.data_segs_in = info->tcpi_data_segs_in;
		s.not_sent = info->tcpi_notsent_bytes;
		if (info->tcpi_min_rtt && info->tcpi_min_rtt != ~0U)
			s.min_rtt = (double) info->tcpi_min_rtt / 1000;
		tcp_stats_print(&s);  // OUTPUT
		free(s.dctcp);
		free(s.bbr_info);
	}
}

static void parse_diag_msg(struct nlmsghdr *nlh, struct sockstat *s)
{
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	s->state	= r->idiag_state;
	s->local.family	= s->remote.family = r->idiag_family;
	s->lport	= ntohs(r->id.idiag_sport);
	s->rport	= ntohs(r->id.idiag_dport);
	s->wq		= r->idiag_wqueue;
	s->rq		= r->idiag_rqueue;
	s->ino		= r->idiag_inode;
	s->uid		= r->idiag_uid;
	s->iface	= r->id.idiag_if;
	s->sk		= cookie_sk_get(&r->id.idiag_cookie[0]);

	s->mark = 0;
	if (tb[INET_DIAG_MARK])
		s->mark = *(__u32 *) RTA_DATA(tb[INET_DIAG_MARK]);

	if (s->local.family == AF_INET)
		s->local.bytelen = s->remote.bytelen = 4;
	else
		s->local.bytelen = s->remote.bytelen = 16;

	memcpy(s->local.data, r->id.idiag_src, s->local.bytelen);
	memcpy(s->remote.data, r->id.idiag_dst, s->local.bytelen);
}

// This is called indirectly by rtnl_dump_filter to do the printing.
// INTERCEPT - modify this to stash the data!!
static int inet_show_sock(struct nlmsghdr *nlh,
			  struct sockstat *s,
			  int protocol)
{
  // STASH THE DATA HERE.
  if (STASH_DATA) {
    static int count = 0;
    count++;
    if (count % 10 == 0)
      fprintf(stderr, "inet_show_sock suppressed.  Data size = %ld\n",
              sizeof(struct nlmsghdr) + sizeof(struct sockstat) + sizeof(int));
    return 0;
  }
        // GFR
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[INET_DIAG_PROTOCOL])
		protocol = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);

        if (STASH_DATA) return 0;  // THIS TRAPS ALL OUTPUT FROM THIS FUNCTION
	inet_stats_print(s, protocol);  // OUTPUT

	if (show_options) {
		struct tcpstat t = {};

		t.timer = r->idiag_timer;
		t.timeout = r->idiag_expires;
		t.retrans = r->idiag_retrans;
		tcp_timer_print(&t);
	}

	if (show_details) {
		sock_details_print(s);
		if (s->local.family == AF_INET6 && tb[INET_DIAG_SKV6ONLY]) {
			unsigned char v6only;

			v6only = *(__u8 *)RTA_DATA(tb[INET_DIAG_SKV6ONLY]);
			printf(" v6only:%u", v6only);
		}
		if (tb[INET_DIAG_SHUTDOWN]) {
			unsigned char mask;

			mask = *(__u8 *)RTA_DATA(tb[INET_DIAG_SHUTDOWN]);
			printf(" %c-%c", mask & 1 ? '-' : '<', mask & 2 ? '-' : '>');
		}
	}

	if (show_mem || show_tcpinfo) {
		printf("\n\t");  // OUTPUT
		tcp_show_info(nlh, r, tb);
	}

	printf("\n");  // OUTPUT
	return 0;
}

static int tcpdiag_send(int fd, int protocol, struct filter *f)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req r;
	} req = {
		.nlh.nlmsg_len = sizeof(req),
		.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
		.nlh.nlmsg_seq = MAGIC_SEQ,
		.r.idiag_family = AF_INET,
		.r.idiag_states = f->states,
	};
	char    *bc = NULL;
	int	bclen;
	struct msghdr msg;
	struct rtattr rta;
	struct iovec iov[3];
	int iovlen = 1;

	if (protocol == IPPROTO_UDP)
		return -1;

	if (protocol == IPPROTO_TCP)
		req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
	else
		req.nlh.nlmsg_type = DCCPDIAG_GETSOCK;
	if (show_mem) {
		req.r.idiag_ext |= (1<<(INET_DIAG_MEMINFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_SKMEMINFO-1));
	}

	if (show_tcpinfo) {
		req.r.idiag_ext |= (1<<(INET_DIAG_INFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_CONG-1));
	}

	iov[0] = (struct iovec){
		.iov_base = &req,
		.iov_len = sizeof(req)
	};
	if (f->f) {
		bclen = ssfilter_bytecompile(f->f, &bc);
		if (bclen) {
			rta.rta_type = INET_DIAG_REQ_BYTECODE;
			rta.rta_len = RTA_LENGTH(bclen);
			iov[1] = (struct iovec){ &rta, sizeof(rta) };
			iov[2] = (struct iovec){ bc, bclen };
			req.nlh.nlmsg_len += RTA_LENGTH(bclen);
			iovlen = 3;
		}
	}

	msg = (struct msghdr) {
		.msg_name = (void *)&nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};

	if (sendmsg(fd, &msg, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int sockdiag_send(int family, int fd, int protocol, struct filter *f)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	DIAG_REQUEST(req, struct inet_diag_req_v2 r);
	char    *bc = NULL;
	int	bclen;
	struct msghdr msg;
	struct rtattr rta;
	struct iovec iov[3];
	int iovlen = 1;

	if (family == PF_UNSPEC)
		return tcpdiag_send(fd, protocol, f);

	memset(&req.r, 0, sizeof(req.r));
	req.r.sdiag_family = family;
	req.r.sdiag_protocol = protocol;
	req.r.idiag_states = f->states;
	if (show_mem) {
		req.r.idiag_ext |= (1<<(INET_DIAG_MEMINFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_SKMEMINFO-1));
	}

	if (show_tcpinfo) {
		req.r.idiag_ext |= (1<<(INET_DIAG_INFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
		req.r.idiag_ext |= (1<<(INET_DIAG_CONG-1));
	}

	iov[0] = (struct iovec){
		.iov_base = &req,
		.iov_len = sizeof(req)
	};
	if (f->f) {
		bclen = ssfilter_bytecompile(f->f, &bc);
		if (bclen) {
			rta.rta_type = INET_DIAG_REQ_BYTECODE;
			rta.rta_len = RTA_LENGTH(bclen);
			iov[1] = (struct iovec){ &rta, sizeof(rta) };
			iov[2] = (struct iovec){ bc, bclen };
			req.nlh.nlmsg_len += RTA_LENGTH(bclen);
			iovlen = 3;
		}
	}

	msg = (struct msghdr) {
		.msg_name = (void *)&nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};

	if (sendmsg(fd, &msg, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

struct inet_diag_arg {
	struct filter *f;
	int protocol;
	struct rtnl_handle *rth;
};

static int kill_inet_sock(struct nlmsghdr *h, void *arg)
{
	struct inet_diag_msg *d = NLMSG_DATA(h);
	struct inet_diag_arg *diag_arg = arg;
	struct rtnl_handle *rth = diag_arg->rth;

	DIAG_REQUEST(req, struct inet_diag_req_v2 r);

	req.nlh.nlmsg_type = SOCK_DESTROY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = ++rth->seq;
	req.r.sdiag_family = d->idiag_family;
	req.r.sdiag_protocol = diag_arg->protocol;
	req.r.id = d->id;

	return rtnl_talk(rth, &req.nlh, NULL, 0);
}

// INTERCEPT
// stash the data instead of printing.
static int show_one_inet_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *h, void *arg)
{
	int err;
	struct inet_diag_arg *diag_arg = arg;
	struct inet_diag_msg *r = NLMSG_DATA(h);
	struct sockstat s = {};

	if (!(diag_arg->f->families & (1 << r->idiag_family)))
		return 0;

	parse_diag_msg(h, &s);

	if (diag_arg->f->f && run_ssfilter(diag_arg->f->f, &s) == 0)
		return 0;

	if (diag_arg->f->kill && kill_inet_sock(h, arg) != 0) {
		if (errno == EOPNOTSUPP || errno == ENOENT) {
			/* Socket can't be closed, or is already closed. */
			return 0;
		} else {
			perror("SOCK_DESTROY answers");
			return -1;
		}
	}

        // STASH DATA HERE.
        if (STASH_DATA) {
          static int count = 0;
          count++;
          if (count % 10 == 0)
             fprintf(stderr, "show_one_inet_sock suppressed.  data size = %ld not including filter!\n",
                     h->nlmsg_len + sizeof(struct inet_diag_arg));
          return 0;
        }
	err = inet_show_sock(h, &s, diag_arg->protocol);
	if (err < 0)
		return err;

	return 0;
}

// This generates majority, but not all, of the output for
// misc/gfr -t -i -H -e -u -x -a -m
static int inet_show_netlink(struct filter *f, FILE *dump_fp, int protocol)
{
  if (SUPPRESS) {
    fprintf(stderr, "inet_show_netlink suppressed.\n");
    return 0;
  } else {
    fprintf(stderr, "inet_show_netlink\n");
  }
  fprintf(stderr, "protocol = %d\n", protocol);  // TCP is 6
	int err = 0;
	struct rtnl_handle rth, rth2;
	int family = PF_INET;
	struct inet_diag_arg arg = { .f = f, .protocol = protocol };

	if (rtnl_open_byproto(&rth, 0, NETLINK_SOCK_DIAG))
		return -1;

	if (f->kill) {
		if (rtnl_open_byproto(&rth2, 0, NETLINK_SOCK_DIAG)) {
			rtnl_close(&rth);
			return -1;
		}
		arg.rth = &rth2;
	}

	rth.dump = MAGIC_SEQ;
	rth.dump_fp = dump_fp;
	if (preferred_family == PF_INET6)
		family = PF_INET6;

again:
	if ((err = sockdiag_send(family, rth.fd, protocol, f)))
		goto Exit;

        //GFR this is where show_one_inet_sock is passed...
	if ((err = rtnl_dump_filter(&rth, show_one_inet_sock, &arg))) {
		if (family != PF_UNSPEC) {
			family = PF_UNSPEC;
			goto again;
		}
		goto Exit;
	}
	if (family == PF_INET && preferred_family != PF_INET) {
		family = PF_INET6;
		goto again;
	}

Exit:
	rtnl_close(&rth);
	if (arg.rth)
		rtnl_close(arg.rth);
	return err;
}

static int tcp_show_netlink_file(struct filter *f)
{
  if (SUPPRESS) {
    fprintf(stderr, "tcp_show_netlink_file suppressed\n");
    return 0;
  }
	FILE	*fp;
	char	buf[16384];

	if ((fp = fopen(getenv("TCPDIAG_FILE"), "r")) == NULL) {
		perror("fopen($TCPDIAG_FILE)");
		return -1;
	}

	while (1) {
		int status, err;
		struct nlmsghdr *h = (struct nlmsghdr *)buf;
		struct sockstat s = {};

		status = fread(buf, 1, sizeof(*h), fp);
		if (status < 0) {
			perror("Reading header from $TCPDIAG_FILE");
			return -1;
		}
		if (status != sizeof(*h)) {
			perror("Unexpected EOF reading $TCPDIAG_FILE");
			return -1;
		}

		status = fread(h+1, 1, NLMSG_ALIGN(h->nlmsg_len-sizeof(*h)), fp);

		if (status < 0) {
			perror("Reading $TCPDIAG_FILE");
			return -1;
		}
		if (status + sizeof(*h) < h->nlmsg_len) {
			perror("Unexpected EOF reading $TCPDIAG_FILE");
			return -1;
		}

		/* The only legal exit point */
		if (h->nlmsg_type == NLMSG_DONE)
			return 0;

		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
				fprintf(stderr, "ERROR truncated\n");
			} else {
				errno = -err->error;
				perror("TCPDIAG answered");
			}
			return -1;
		}

		parse_diag_msg(h, &s);

		if (f && f->f && run_ssfilter(f->f, &s) == 0)
			continue;

		err = inet_show_sock(h, &s, IPPROTO_TCP);
		if (err < 0)
			return err;
	}
}

static int tcp_show(struct filter *f, int socktype)
{
	FILE *fp = NULL;
	char *buf = NULL;
	int bufsize = 64*1024;

	if (!filter_af_get(f, AF_INET) && !filter_af_get(f, AF_INET6)) {
                printf("AF_INET path:\n");
		return 0;
        }

	dg_proto = TCP_PROTO;

	if (getenv("TCPDIAG_FILE")) {
		return tcp_show_netlink_file(f);
        }

	if (!getenv("PROC_NET_TCP") && !getenv("PROC_ROOT")
	    && inet_show_netlink(f, NULL, socktype) == 0) {
		return 0;
        }

	/* Sigh... We have to parse /proc/net/tcp... */

	/* Estimate amount of sockets and try to allocate
	 * huge buffer to read all the table at one read.
	 * Limit it by 16MB though. The assumption is: as soon as
	 * kernel was able to hold information about N connections,
	 * it is able to give us some memory for snapshot.
	 */
	if (1) {
		get_slabstat(&slabstat);

		int guess = slabstat.socks+slabstat.tcp_syns;

		if (f->states&(1<<SS_TIME_WAIT))
			guess += slabstat.tcp_tws;
		if (guess > (16*1024*1024)/128)
			guess = (16*1024*1024)/128;
		guess *= 128;
		if (guess > bufsize)
			bufsize = guess;
	}
	while (bufsize >= 64*1024) {
		if ((buf = malloc(bufsize)) != NULL)
			break;
		bufsize /= 2;
	}
	if (buf == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (f->families & (1<<AF_INET)) {
		if ((fp = net_tcp_open()) == NULL)
			goto outerr;

		setbuffer(fp, buf, bufsize);
		if (generic_record_read(fp, tcp_show_line, f, AF_INET))
			goto outerr;
		fclose(fp);
	}

	if ((f->families & (1<<AF_INET6)) &&
	    (fp = net_tcp6_open()) != NULL) {
		setbuffer(fp, buf, bufsize);
		if (generic_record_read(fp, tcp_show_line, f, AF_INET6))
			goto outerr;
		fclose(fp);
	}

	free(buf);
	return 0;

outerr:
	do {
		int saved_errno = errno;

		free(buf);
		if (fp)
			fclose(fp);
		errno = saved_errno;
		return -1;
	} while (0);
}


// INTERCEPT
static int dgram_show_line(char *line, const struct filter *f, int family)
{
	struct sockstat s = {};
	char *loc, *rem, *data;
	char opt[256];
	int n;

  if (STASH_DATA) {
    static int count = 0;
    count++;
    if (count % 40 == 0)
      fprintf(stderr, "dgram_show_line suppressed.  Data size = %ld not including subfilters\n",
              strlen(line) + sizeof(struct filter) + sizeof(int));
    return 0;
  }
	if (proc_inet_split_line(line, &loc, &rem, &data))
		return -1;

	int state = (data[1] >= 'A') ? (data[1] - 'A' + 10) : (data[1] - '0');

	if (!(f->states & (1 << state)))
		return 0;

	proc_parse_inet_addr(loc, rem, family, &s);

	if (f->f && run_ssfilter(f->f, &s) == 0)
		return 0;

	opt[0] = 0;
	n = sscanf(data, "%x %x:%x %*x:%*x %*x %d %*d %u %d %llx %[^\n]\n",
	       &s.state, &s.wq, &s.rq,
	       &s.uid, &s.ino,
	       &s.refcnt, &s.sk, opt);

	if (n < 9)
		opt[0] = 0;

	inet_stats_print(&s, dg_proto == UDP_PROTO ? IPPROTO_UDP : 0);

	if (show_details && opt[0])
		printf(" opt:\"%s\"", opt);

	printf("\n");
	return 0;
}

static int udp_show(struct filter *f)
{
  if (SUPPRESS) {
    fprintf(stderr, "udp_show suppressed\n");
    return 0;
  } else {
    fprintf(stderr, "udp_show\n");
  }

	FILE *fp = NULL;

	if (!filter_af_get(f, AF_INET) && !filter_af_get(f, AF_INET6))
		return 0;

	dg_proto = UDP_PROTO;

	if (!getenv("PROC_NET_UDP") && !getenv("PROC_ROOT")
	    && inet_show_netlink(f, NULL, IPPROTO_UDP) == 0)
		return 0;

	if (f->families&(1<<AF_INET)) {
		if ((fp = net_udp_open()) == NULL)
			goto outerr;
		if (generic_record_read(fp, dgram_show_line, f, AF_INET))
			goto outerr;
		fclose(fp);
	}

	if ((f->families&(1<<AF_INET6)) &&
	    (fp = net_udp6_open()) != NULL) {
		if (generic_record_read(fp, dgram_show_line, f, AF_INET6))
			goto outerr;
		fclose(fp);
	}
	return 0;

outerr:
	do {
		int saved_errno = errno;

		if (fp)
			fclose(fp);
		errno = saved_errno;
		return -1;
	} while (0);
}

static int raw_show(struct filter *f)
{
  if (SUPPRESS) {
    fprintf(stderr, "raw_show suppressed\n");
    return 0;
  } else {
    fprintf(stderr, "raw_show\n");
  }
	FILE *fp = NULL;

	if (!filter_af_get(f, AF_INET) && !filter_af_get(f, AF_INET6))
		return 0;

	dg_proto = RAW_PROTO;

	if (f->families&(1<<AF_INET)) {
		if ((fp = net_raw_open()) == NULL)
			goto outerr;
		if (generic_record_read(fp, dgram_show_line, f, AF_INET))
			goto outerr;
		fclose(fp);
	}

	if ((f->families&(1<<AF_INET6)) &&
	    (fp = net_raw6_open()) != NULL) {
		if (generic_record_read(fp, dgram_show_line, f, AF_INET6))
			goto outerr;
		fclose(fp);
	}
	return 0;

outerr:
	do {
		int saved_errno = errno;

		if (fp)
			fclose(fp);
		errno = saved_errno;
		return -1;
	} while (0);
}

int unix_state_map[] = { SS_CLOSE, SS_SYN_SENT,
			 SS_ESTABLISHED, SS_CLOSING };

#define MAX_UNIX_REMEMBER (1024*1024/sizeof(struct sockstat))

static void unix_list_free(struct sockstat *list)
{
	while (list) {
		struct sockstat *s = list;

		list = list->next;
		free(s->name);
		free(s);
	}
}

static const char *unix_netid_name(int type)
{
	const char *netid;

	switch (type) {
	case SOCK_STREAM:
		netid = "u_str";
		break;
	case SOCK_SEQPACKET:
		netid = "u_seq";
		break;
	case SOCK_DGRAM:
	default:
		netid = "u_dgr";
		break;
	}
	return netid;
}

static bool unix_type_skip(struct sockstat *s, struct filter *f)
{
	if (s->type == SOCK_STREAM && !(f->dbs&(1<<UNIX_ST_DB)))
		return true;
	if (s->type == SOCK_DGRAM && !(f->dbs&(1<<UNIX_DG_DB)))
		return true;
	if (s->type == SOCK_SEQPACKET && !(f->dbs&(1<<UNIX_SQ_DB)))
		return true;
	return false;
}

static bool unix_use_proc(void)
{
	return getenv("PROC_NET_UNIX") || getenv("PROC_ROOT");
}

static void unix_stats_print(struct sockstat *list, struct filter *f)
{
	struct sockstat *s;
	char *peer;
	bool use_proc = unix_use_proc();
	char port_name[30] = {};

	for (s = list; s; s = s->next) {
		if (!(f->states & (1 << s->state)))
			continue;
		if (unix_type_skip(s, f))
			continue;

		peer = "*";
		if (s->peer_name)
			peer = s->peer_name;

		if (s->rport && use_proc) {
			struct sockstat *p;

			for (p = list; p; p = p->next) {
				if (s->rport == p->lport)
					break;
			}

			if (!p) {
				peer = "?";
			} else {
				peer = p->name ? : "*";
			}
		}

		if (use_proc && f->f) {
			struct sockstat st = {
				.local.family = AF_UNIX,
				.remote.family = AF_UNIX,
			};

			memcpy(st.local.data, &s->name, sizeof(s->name));
			if (strcmp(peer, "*"))
				memcpy(st.remote.data, &peer, sizeof(peer));
			if (run_ssfilter(f->f, &st) == 0)
				continue;
		}

		sock_state_print(s, unix_netid_name(s->type));

		sock_addr_print(s->name ?: "*", " ",
				int_to_str(s->lport, port_name), NULL);
		sock_addr_print(peer, " ", int_to_str(s->rport, port_name),
				NULL);

		printf("\n");
	}
}

// INTERCEPT
// instead of printing stuff here, stash it away and only print when the socket
// disappears.
static int unix_show_sock(const struct sockaddr_nl *addr, struct nlmsghdr *nlh,
		void *arg)
{
  if (STASH_DATA) {
    static int count = 0;
    count++;
    if (count % 40 == 0)
      fprintf(stderr, "unix_show_sock suppressed.  Data size = %ld not including subfilters\n",
              sizeof(*addr) + nlh->nlmsg_len + sizeof(struct filter));
    return 0;
  }
	struct filter *f = (struct filter *)arg;
	struct unix_diag_msg *r = NLMSG_DATA(nlh);
	struct rtattr *tb[UNIX_DIAG_MAX+1];
	char name[128];
	struct sockstat stat = { .name = "*", .peer_name = "*" };

	parse_rtattr(tb, UNIX_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	stat.type  = r->udiag_type;
	stat.state = r->udiag_state;
	stat.ino   = stat.lport = r->udiag_ino;
	stat.local.family = stat.remote.family = AF_UNIX;

	if (unix_type_skip(&stat, f))
		return 0;

	if (tb[UNIX_DIAG_RQLEN]) {
		struct unix_diag_rqlen *rql = RTA_DATA(tb[UNIX_DIAG_RQLEN]);

		stat.rq = rql->udiag_rqueue;
		stat.wq = rql->udiag_wqueue;
	}
	if (tb[UNIX_DIAG_NAME]) {
		int len = RTA_PAYLOAD(tb[UNIX_DIAG_NAME]);

		memcpy(name, RTA_DATA(tb[UNIX_DIAG_NAME]), len);
		name[len] = '\0';
		if (name[0] == '\0')
			name[0] = '@';
		stat.name = &name[0];
		memcpy(stat.local.data, &stat.name, sizeof(stat.name));
	}
	if (tb[UNIX_DIAG_PEER])
		stat.rport = rta_getattr_u32(tb[UNIX_DIAG_PEER]);

	if (f->f && run_ssfilter(f->f, &stat) == 0)
		return 0;

        // STASH DATA HERE.  (200 bytes)
	unix_stats_print(&stat, f);

	if (show_mem) {
		printf("\t");
		print_skmeminfo(tb, UNIX_DIAG_MEMINFO);
	}
	if (show_details) {
		if (tb[UNIX_DIAG_SHUTDOWN]) {
			unsigned char mask;

			mask = *(__u8 *)RTA_DATA(tb[UNIX_DIAG_SHUTDOWN]);
			printf(" %c-%c", mask & 1 ? '-' : '<', mask & 2 ? '-' : '>');
		}
	}
	if (show_mem || show_details)
		printf("\n");

	return 0;
}

static int handle_netlink_request(struct filter *f, struct nlmsghdr *req,
		size_t size, rtnl_filter_t show_one_sock)
{
  fprintf(stderr, "handle_netlink_request.\n");
	int ret = -1;
	struct rtnl_handle rth;

	if (rtnl_open_byproto(&rth, 0, NETLINK_SOCK_DIAG))
		return -1;

	rth.dump = MAGIC_SEQ;

	if (rtnl_send(&rth, req, size) < 0)
		goto Exit;

	if (rtnl_dump_filter(&rth, show_one_sock, f))
		goto Exit;

	ret = 0;
Exit:
	rtnl_close(&rth);
        fprintf(stderr, "handle_netlink_request complete.\n");
	return ret;
}

static int unix_show_netlink(struct filter *f)
{
	DIAG_REQUEST(req, struct unix_diag_req r);

	req.r.sdiag_family = AF_UNIX;
	req.r.udiag_states = f->states;
	req.r.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_RQLEN;
	if (show_mem)
		req.r.udiag_show |= UDIAG_SHOW_MEMINFO;

        // INTERCEPT ALL OF THE line printers.
        fprintf(stderr, "Calling handle_netlink_request. %d\n", __LINE__);
	return handle_netlink_request(f, &req.nlh, sizeof(req), unix_show_sock);
}

// With environment variables set, all the output comes from here.
static int unix_show(struct filter *f)
{
  if (SUPPRESS) {
    // This shows about 1/4 of the content.
    static int count = 0;
    count++;
    if (count % 40 == 0)
    fprintf(stderr, "unix_show suppressed\n");
    return 0;
  }
	FILE *fp;
	char buf[256];
	char name[128];
	int  newformat = 0;
	int  cnt;

	if (!filter_af_get(f, AF_UNIX))
		return 0;

	if (!unix_use_proc() && unix_show_netlink(f) == 0)
		return 0;

        fprintf(stderr, "%4d Using net_unix_open().\n", __LINE__);
        // TODO(gfr) Consider dropping this code.
	if ((fp = net_unix_open()) == NULL)
		return -1;
	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return -1;
	}

	if (memcmp(buf, "Peer", 4) == 0)
		newformat = 1;
	cnt = 0;

        // Collect all results into list.
	struct sockstat *list = NULL;
	while (fgets(buf, sizeof(buf), fp)) {
		struct sockstat *u, **insp;
		int flags;

		if (!(u = calloc(1, sizeof(*u))))
			break;
		u->name = NULL;
		u->peer_name = NULL;

		if (sscanf(buf, "%x: %x %x %x %x %x %d %s",
			   &u->rport, &u->rq, &u->wq, &flags, &u->type,
			   &u->state, &u->ino, name) < 8)
			name[0] = 0;

		u->lport = u->ino;
		u->local.family = u->remote.family = AF_UNIX;

		if (flags & (1 << 16)) {
			u->state = SS_LISTEN;
		} else {
			u->state = unix_state_map[u->state-1];
			if (u->type == SOCK_DGRAM && u->state == SS_CLOSE && u->rport)
				u->state = SS_ESTABLISHED;
		}

		if (!newformat) {
			u->rport = 0;
			u->rq = 0;
			u->wq = 0;
		}

		insp = &list;
		while (*insp) {
			if (u->type < (*insp)->type ||
			    (u->type == (*insp)->type &&
			     u->ino < (*insp)->ino))
				break;
			insp = &(*insp)->next;
		}
		u->next = *insp;
		*insp = u;

		if (name[0]) {
			if ((u->name = malloc(strlen(name)+1)) == NULL)
				break;
			strcpy(u->name, name);
		}
		if (++cnt > MAX_UNIX_REMEMBER) {
			unix_stats_print(list, f);
			unix_list_free(list);
			list = NULL;
			cnt = 0;
		}
	}
	fclose(fp);

        // Output list contents.
	if (list) {
		unix_stats_print(list, f);
		unix_list_free(list);
		list = NULL;
		cnt = 0;
	}

	return 0;
}

static int packet_stats_print(struct sockstat *s, const struct filter *f)
{
	const char *addr, *port;
	char ll_name[16];

	if (f->f) {
		s->local.family = AF_PACKET;
		s->remote.family = AF_PACKET;
		s->local.data[0] = s->prot;
		if (run_ssfilter(f->f, s) == 0)
			return 1;
	}

	sock_state_print(s, s->type == SOCK_RAW ? "p_raw" : "p_dgr");

	if (s->prot == 3)
		addr = "*";
	else
		addr = ll_proto_n2a(htons(s->prot), ll_name, sizeof(ll_name));

	if (s->iface == 0)
		port = "*";
	else
		port = xll_index_to_name(s->iface);

	sock_addr_print(addr, ":", port, NULL);
	sock_addr_print("", "*", "", NULL);

	if (show_details)
		sock_details_print(s);

	return 0;
}

static void packet_show_ring(struct packet_diag_ring *ring)
{
	printf("blk_size:%d", ring->pdr_block_size);
	printf(",blk_nr:%d", ring->pdr_block_nr);
	printf(",frm_size:%d", ring->pdr_frame_size);
	printf(",frm_nr:%d", ring->pdr_frame_nr);
	printf(",tmo:%d", ring->pdr_retire_tmo);
	printf(",features:0x%x", ring->pdr_features);
}

static int packet_show_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg)
{
	const struct filter *f = arg;
	struct packet_diag_msg *r = NLMSG_DATA(nlh);
	struct packet_diag_info *pinfo = NULL;
	struct packet_diag_ring *ring_rx = NULL, *ring_tx = NULL;
	struct rtattr *tb[PACKET_DIAG_MAX+1];
	struct sockstat stat = {};
	uint32_t fanout = 0;
	bool has_fanout = false;

	parse_rtattr(tb, PACKET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	/* use /proc/net/packet if all info are not available */
	if (!tb[PACKET_DIAG_MEMINFO])
		return -1;

	stat.type   = r->pdiag_type;
	stat.prot   = r->pdiag_num;
	stat.ino    = r->pdiag_ino;
	stat.state  = SS_CLOSE;
	stat.sk	    = cookie_sk_get(&r->pdiag_cookie[0]);

	if (tb[PACKET_DIAG_MEMINFO]) {
		__u32 *skmeminfo = RTA_DATA(tb[PACKET_DIAG_MEMINFO]);

		stat.rq = skmeminfo[SK_MEMINFO_RMEM_ALLOC];
	}

	if (tb[PACKET_DIAG_INFO]) {
		pinfo = RTA_DATA(tb[PACKET_DIAG_INFO]);
		stat.lport = stat.iface = pinfo->pdi_index;
	}

	if (tb[PACKET_DIAG_UID])
		stat.uid = *(__u32 *)RTA_DATA(tb[PACKET_DIAG_UID]);

	if (tb[PACKET_DIAG_RX_RING])
		ring_rx = RTA_DATA(tb[PACKET_DIAG_RX_RING]);

	if (tb[PACKET_DIAG_TX_RING])
		ring_tx = RTA_DATA(tb[PACKET_DIAG_TX_RING]);

	if (tb[PACKET_DIAG_FANOUT]) {
		has_fanout = true;
		fanout = *(uint32_t *)RTA_DATA(tb[PACKET_DIAG_FANOUT]);
	}

	if (packet_stats_print(&stat, f))
		return 0;

	if (show_details) {
		if (pinfo) {
			printf("\n\tver:%d", pinfo->pdi_version);
			printf(" cpy_thresh:%d", pinfo->pdi_copy_thresh);
			printf(" flags( ");
			if (pinfo->pdi_flags & PDI_RUNNING)
				printf("running");
			if (pinfo->pdi_flags & PDI_AUXDATA)
				printf(" auxdata");
			if (pinfo->pdi_flags & PDI_ORIGDEV)
				printf(" origdev");
			if (pinfo->pdi_flags & PDI_VNETHDR)
				printf(" vnethdr");
			if (pinfo->pdi_flags & PDI_LOSS)
				printf(" loss");
			if (!pinfo->pdi_flags)
				printf("0");
			printf(" )");
		}
		if (ring_rx) {
			printf("\n\tring_rx(");
			packet_show_ring(ring_rx);
			printf(")");
		}
		if (ring_tx) {
			printf("\n\tring_tx(");
			packet_show_ring(ring_tx);
			printf(")");
		}
		if (has_fanout) {
			uint16_t type = (fanout >> 16) & 0xffff;

			printf("\n\tfanout(");
			printf("id:%d,", fanout & 0xffff);
			printf("type:");

			if (type == 0)
				printf("hash");
			else if (type == 1)
				printf("lb");
			else if (type == 2)
				printf("cpu");
			else if (type == 3)
				printf("roll");
			else if (type == 4)
				printf("random");
			else if (type == 5)
				printf("qm");
			else
				printf("0x%x", type);

			printf(")");
		}
	}

	if (show_bpf && tb[PACKET_DIAG_FILTER]) {
		struct sock_filter *fil =
		       RTA_DATA(tb[PACKET_DIAG_FILTER]);
		int num = RTA_PAYLOAD(tb[PACKET_DIAG_FILTER]) /
			  sizeof(struct sock_filter);

		printf("\n\tbpf filter (%d): ", num);
		while (num) {
			printf(" 0x%02x %u %u %u,",
			      fil->code, fil->jt, fil->jf, fil->k);
			num--;
			fil++;
		}
	}
	printf("\n");
	return 0;
}

static int packet_show_netlink(struct filter *f)
{
	DIAG_REQUEST(req, struct packet_diag_req r);

	req.r.sdiag_family = AF_PACKET;
	req.r.pdiag_show = PACKET_SHOW_INFO | PACKET_SHOW_MEMINFO |
		PACKET_SHOW_FILTER | PACKET_SHOW_RING_CFG | PACKET_SHOW_FANOUT;

        // INTERCEPT
        fprintf(stderr, "Calling handle_netlink_request. %d\n", __LINE__);
	return handle_netlink_request(f, &req.nlh, sizeof(req), packet_show_sock);
}

static int packet_show_line(char *buf, const struct filter *f, int fam)
{
  printf("......");
	unsigned long long sk;
	struct sockstat stat = {};
	int type, prot, iface, state, rq, uid, ino;

	sscanf(buf, "%llx %*d %d %x %d %d %u %u %u",
			&sk,
			&type, &prot, &iface, &state,
			&rq, &uid, &ino);

	if (stat.type == SOCK_RAW && !(f->dbs&(1<<PACKET_R_DB)))
		return 0;
	if (stat.type == SOCK_DGRAM && !(f->dbs&(1<<PACKET_DG_DB)))
		return 0;

	stat.type  = type;
	stat.prot  = prot;
	stat.lport = stat.iface = iface;
	stat.state = state;
	stat.rq    = rq;
	stat.uid   = uid;
	stat.ino   = ino;
	stat.state = SS_CLOSE;

	if (packet_stats_print(&stat, f))
		return 0;

	printf("\n");
	return 0;
}

static int packet_show(struct filter *f)
{
	FILE *fp;
	int rc = 0;

	if (!filter_af_get(f, AF_PACKET) || !(f->states & (1 << SS_CLOSE)))
		return 0;

	if (!getenv("PROC_NET_PACKET") && !getenv("PROC_ROOT") &&
			packet_show_netlink(f) == 0)
		return 0;

	if ((fp = net_packet_open()) == NULL)
		return -1;
	if (generic_record_read(fp, packet_show_line, f, AF_PACKET))
		rc = -1;

	fclose(fp);
	return rc;
}

static int netlink_show_one(struct filter *f,
				int prot, int pid, unsigned int groups,
				int state, int dst_pid, unsigned int dst_group,
				int rq, int wq,
				unsigned long long sk, unsigned long long cb)
{
	struct sockstat st;

	SPRINT_BUF(prot_buf) = {};
	const char *prot_name;
	char procname[64] = {};

	st.state = SS_CLOSE;
	st.rq	 = rq;
	st.wq	 = wq;

	if (f->f) {
		st.local.family = AF_NETLINK;
		st.remote.family = AF_NETLINK;
		st.rport = -1;
		st.lport = pid;
		st.local.data[0] = prot;
		if (run_ssfilter(f->f, &st) == 0)
			return 1;
	}

	sock_state_print(&st, "nl");

	if (resolve_services)
		prot_name = nl_proto_n2a(prot, prot_buf, sizeof(prot_buf));
	else
		prot_name = int_to_str(prot, prot_buf);

	if (pid == -1) {
		procname[0] = '*';
	} else if (resolve_services) {
		int done = 0;

		if (!pid) {
			done = 1;
			strncpy(procname, "kernel", 6);
		} else if (pid > 0) {
			FILE *fp;

			snprintf(procname, sizeof(procname), "%s/%d/stat",
				getenv("PROC_ROOT") ? : "/proc", pid);
			if ((fp = fopen(procname, "r")) != NULL) {
				if (fscanf(fp, "%*d (%[^)])", procname) == 1) {
					snprintf(procname+strlen(procname),
						sizeof(procname)-strlen(procname),
						"/%d", pid);
					done = 1;
				}
				fclose(fp);
			}
		}
		if (!done)
			int_to_str(pid, procname);
	} else {
		int_to_str(pid, procname);
	}

	sock_addr_print(prot_name, ":", procname, NULL);

	if (state == NETLINK_CONNECTED) {
		char dst_group_buf[30];
		char dst_pid_buf[30];

		sock_addr_print(int_to_str(dst_group, dst_group_buf), ":",
				int_to_str(dst_pid, dst_pid_buf), NULL);
	} else {
		sock_addr_print("", "*", "", NULL);
	}

	if (show_details) {
		printf(" sk=%llx cb=%llx groups=0x%08x", sk, cb, groups);
	}
	printf("\n");

	return 0;
}

static int netlink_show_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg)
{
	struct filter *f = (struct filter *)arg;
	struct netlink_diag_msg *r = NLMSG_DATA(nlh);
	struct rtattr *tb[NETLINK_DIAG_MAX+1];
	int rq = 0, wq = 0;
	unsigned long groups = 0;

	parse_rtattr(tb, NETLINK_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[NETLINK_DIAG_GROUPS] && RTA_PAYLOAD(tb[NETLINK_DIAG_GROUPS]))
		groups = *(unsigned long *) RTA_DATA(tb[NETLINK_DIAG_GROUPS]);

	if (tb[NETLINK_DIAG_MEMINFO]) {
		const __u32 *skmeminfo;

		skmeminfo = RTA_DATA(tb[NETLINK_DIAG_MEMINFO]);

		rq = skmeminfo[SK_MEMINFO_RMEM_ALLOC];
		wq = skmeminfo[SK_MEMINFO_WMEM_ALLOC];
	}

	if (netlink_show_one(f, r->ndiag_protocol, r->ndiag_portid, groups,
			 r->ndiag_state, r->ndiag_dst_portid, r->ndiag_dst_group,
			 rq, wq, 0, 0)) {
		return 0;
	}

	if (show_mem) {
		printf("\t");
		print_skmeminfo(tb, NETLINK_DIAG_MEMINFO);
		printf("\n");
	}

	return 0;
}

static int netlink_show_netlink(struct filter *f)
{
	DIAG_REQUEST(req, struct netlink_diag_req r);

	req.r.sdiag_family = AF_NETLINK;
	req.r.sdiag_protocol = NDIAG_PROTO_ALL;
	req.r.ndiag_show = NDIAG_SHOW_GROUPS | NDIAG_SHOW_MEMINFO;

        // INTERCEPT
        fprintf(stderr, "Calling handle_netlink_request. %d\n", __LINE__);
	return handle_netlink_request(f, &req.nlh, sizeof(req), netlink_show_sock);
}

static int netlink_show(struct filter *f)
{
	FILE *fp;
	char buf[256];
	int prot, pid;
	unsigned int groups;
	int rq, wq, rc;
	unsigned long long sk, cb;

	if (!filter_af_get(f, AF_NETLINK) || !(f->states & (1 << SS_CLOSE)))
		return 0;

	if (!getenv("PROC_NET_NETLINK") && !getenv("PROC_ROOT") &&
		netlink_show_netlink(f) == 0)
		return 0;

	if ((fp = net_netlink_open()) == NULL)
		return -1;
	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		sscanf(buf, "%llx %d %d %x %d %d %llx %d",
		       &sk,
		       &prot, &pid, &groups, &rq, &wq, &cb, &rc);

		netlink_show_one(f, prot, pid, groups, 0, 0, 0, rq, wq, sk, cb);
	}

	fclose(fp);
	return 0;
}

struct sock_diag_msg {
	__u8 sdiag_family;
};

static int generic_show_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg)
{
	struct sock_diag_msg *r = NLMSG_DATA(nlh);
	struct inet_diag_arg inet_arg = { .f = arg, .protocol = IPPROTO_MAX };

	switch (r->sdiag_family) {
	case AF_INET:
	case AF_INET6:
		return show_one_inet_sock(addr, nlh, &inet_arg);
	case AF_UNIX:
		return unix_show_sock(addr, nlh, arg);
	case AF_PACKET:
		return packet_show_sock(addr, nlh, arg);
	case AF_NETLINK:
		return netlink_show_sock(addr, nlh, arg);
	default:
		return -1;
	}
}

static int handle_follow_request(struct filter *f)
{
	int ret = -1;
	int groups = 0;
	struct rtnl_handle rth;

	if (f->families & (1 << AF_INET) && f->dbs & (1 << TCP_DB))
		groups |= 1 << (SKNLGRP_INET_TCP_DESTROY - 1);
	if (f->families & (1 << AF_INET) && f->dbs & (1 << UDP_DB))
		groups |= 1 << (SKNLGRP_INET_UDP_DESTROY - 1);
	if (f->families & (1 << AF_INET6) && f->dbs & (1 << TCP_DB))
		groups |= 1 << (SKNLGRP_INET6_TCP_DESTROY - 1);
	if (f->families & (1 << AF_INET6) && f->dbs & (1 << UDP_DB))
		groups |= 1 << (SKNLGRP_INET6_UDP_DESTROY - 1);

	if (groups == 0)
		return -1;

	if (rtnl_open_byproto(&rth, groups, NETLINK_SOCK_DIAG))
		return -1;

	rth.dump = 0;
	rth.local.nl_pid = 0;

	if (rtnl_dump_filter(&rth, generic_show_sock, f))
		goto Exit;

	ret = 0;
Exit:
	rtnl_close(&rth);
	return ret;
}

int c_main(int argc, char *argv[])
{
	FILE *filter_fp = NULL;
	int state_filter = 0;

//      -adtuwxiem
	show_options = 1;
	show_details++;
	show_mem = 1;
	show_tcpinfo = 1;
	filter_db_set(&current_filter, DCCP_DB);
	filter_db_set(&current_filter, TCP_DB);
	filter_db_set(&current_filter, UDP_DB);
	filter_db_set(&current_filter, RAW_DB);
	filter_af_set(&current_filter, AF_UNIX);
	state_filter = SS_ALL;

	argc -= optind;
	argv += optind;

	filter_states_set(&current_filter, state_filter);
	filter_merge_defaults(&current_filter);

	if (current_filter.dbs == 0) {
		fprintf(stderr, "ss: no socket tables to show with such filter.\n");
		exit(0);
	}
	if (current_filter.families == 0) {
		fprintf(stderr, "ss: no families to show with such filter.\n");
		exit(0);
	}
	if (current_filter.states == 0) {
		fprintf(stderr, "ss: no socket states to show with such filter.\n");
		exit(0);
	}

	if (ssfilter_parse(&current_filter.f, argc, argv, filter_fp)) {
          fprintf(stderr, "No options!\n");
          exit(1);
        }

	netid_width = 0;
	if (current_filter.dbs&(current_filter.dbs-1))
		netid_width = 5;

	state_width = 0;
	if (current_filter.states&(current_filter.states-1))
		state_width = 10;

	screen_width = 80;
	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				screen_width = w.ws_col;
		}
	}

	addrp_width = screen_width;
	addrp_width -= netid_width+1;
	addrp_width -= state_width+1;
	addrp_width -= 14;

	if (addrp_width&1) {
		if (netid_width)
			netid_width++;
		else if (state_width)
			state_width++;
	}

	addrp_width /= 2;
	addrp_width--;

	serv_width = resolve_services ? 7 : 5;

	if (addrp_width < 15+serv_width+1)
		addrp_width = 15+serv_width+1;

	addr_width = addrp_width - serv_width - 1;

	if (show_header) {
		if (netid_width)
			printf("%-*s ", netid_width, "Netid");
		if (state_width)
			printf("%-*s ", state_width, "State");
		printf("%-6s %-6s ", "Recv-Q", "Send-Q");
	}

	/* Make enough space for the local/remote port field */
	addr_width -= 13;
	serv_width += 13;

	if (show_header) {
		printf("%*s:%-*s %*s:%-*s\n",
		       addr_width, "Local Address", serv_width, "Port",
		       addr_width, "Peer Address", serv_width, "Port");
	}

	fflush(stdout);

	if (follow_events)
		exit(handle_follow_request(&current_filter));

	if (current_filter.dbs & (1<<NETLINK_DB))
		netlink_show(&current_filter);
	if (current_filter.dbs & PACKET_DBM)
		packet_show(&current_filter);
	if (current_filter.dbs & UNIX_DBM)
		unix_show(&current_filter);
	if (current_filter.dbs & (1<<RAW_DB))
		raw_show(&current_filter);
	if (current_filter.dbs & (1<<UDP_DB))
		udp_show(&current_filter);
	if (current_filter.dbs & (1<<TCP_DB))
		tcp_show(&current_filter, IPPROTO_TCP);
	if (current_filter.dbs & (1<<DCCP_DB))
		tcp_show(&current_filter, IPPROTO_DCCP);

	return 0;
}
