// TODO(gfr) separate out printing code from collection code.

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
static int show_header = 1;

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


static FILE *ephemeral_ports_open(void)
{
	return generic_proc_open("PROC_IP_LOCAL_PORT_RANGE", "sys/net/ipv4/ip_local_port_range");
}

enum entry_types {
	USERS,
	PROC_CTX,
	PROC_SOCK_CTX
};

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

static int ssfilter_bytecompile(struct ssfilter *f, char **bytecode) {
  fprintf(stderr, "Call to unimplemented ssfilter_bytecompile!\n");
  exit(1);
  return 0;
}

/*******************************************************************
 * Code for ssfilter (yacc).
 ******************************************************************/
void *parse_devcond(char *name)
{
  fprintf(stderr, "Call to unimplemented parse_devcond.\n");
  exit(1);
  return NULL;
}

void *parse_hostcond(char *addr, bool is_port) {
  fprintf(stderr, "Call to unimplemented parse_hostcond.\n");
  exit(1);
  return NULL;
}

void *parse_markmask(const char *markmask)
{
  fprintf(stderr, "Call to unimplemented parse_markmask.\n");
  exit(1);
  return NULL;
}

/*******************************************************************/

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

void stash_data(char *loc, char* rem, char* data, int family);

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

    // show_options
		s.has_ts_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_TIMESTAMPS);
		s.has_sack_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_SACK);
		s.has_ecn_opt	   = TCPI_HAS_OPT(info, TCPI_OPT_ECN);
		s.has_ecnseen_opt  = TCPI_HAS_OPT(info, TCPI_OPT_ECN_SEEN);
		s.has_fastopen_opt = TCPI_HAS_OPT(info, TCPI_OPT_SYN_DATA);

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

// Use this as template to extract the info we need from nlh, to stash
// away for future printing.
// TODO also look at netlink APIs for more information.
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

  // XXX
	memcpy(s->local.data, r->id.idiag_src, s->local.bytelen);
	memcpy(s->remote.data, r->id.idiag_dst, s->local.bytelen);
}

// This is called indirectly by rtnl_dump_filter to do the printing.
// INTERCEPT - modify this to stash the data!!
static int inet_show_sock(struct nlmsghdr *nlh,
			  struct sockstat *s,
			  int protocol)
{
  // STASH THE DATA HERE.  (about half the output data)
  if (STASH_DATA) {
    static int count = 0;
    count++;
    if (count % 10 == 0)
      fprintf(stderr, "inet_show_sock suppressed.  Data size = %ld\n",
              sizeof(struct nlmsghdr) + sizeof(struct sockstat) + sizeof(int) + nlh->nlmsg_len);
    return 0;
  }
  // GFR
	struct rtattr *tb[INET_DIAG_MAX+1];
	struct inet_diag_msg *r = NLMSG_DATA(nlh);

	parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
		     nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	if (tb[INET_DIAG_PROTOCOL])
		protocol = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);

	inet_stats_print(s, protocol);  // OUTPUT

  // show_options
	struct tcpstat t = {};

	t.timer = r->idiag_timer;
	t.timeout = r->idiag_expires;
	t.retrans = r->idiag_retrans;
	tcp_timer_print(&t);

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

	printf("\n\t");  // OUTPUT
	tcp_show_info(nlh, r, tb);

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
  // show_mem
	req.r.idiag_ext |= (1<<(INET_DIAG_MEMINFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_SKMEMINFO-1));

  // show_tcpinfo
	req.r.idiag_ext |= (1<<(INET_DIAG_INFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_CONG-1));

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
  // show_mem
	req.r.idiag_ext |= (1<<(INET_DIAG_MEMINFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_SKMEMINFO-1));

  // show_tcpinfo
	req.r.idiag_ext |= (1<<(INET_DIAG_INFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_VEGASINFO-1));
	req.r.idiag_ext |= (1<<(INET_DIAG_CONG-1));

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

// Instead of show_one_inet_sock (or ...) stash the data.
static int stash_indirect(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg) {
    static int count = 0;
    count++;
    if (count % 100 == 0)
    fprintf(stderr, "stash_indirect unimplemented\n");
  // Need to compute the key, and stash the appropriate amount of data.
  // TODO XXX
  stash_data("foo", "bar", "data", 0);
  return 0;
}

// INTERCEPT
// stash the data instead of printing.
// NOTE: addr not used, but it is part of interface!
static int show_one_inet_sock(const struct sockaddr_nl *addr,
		struct nlmsghdr *h, void *arg)
{
	int err;
	struct inet_diag_arg *diag_arg = arg;
	struct inet_diag_msg *r = NLMSG_DATA(h);
	struct sockstat s = {};

	if (!(diag_arg->f->families & (1 << r->idiag_family))) {
    fprintf(stderr, "%4d Filtered.\n", __LINE__);
		return 0;
  }

	parse_diag_msg(h, &s);

  // Deleted f->f related code.

  // This does some data collection (in kill_inet_sock)!
	if (diag_arg->f->kill && kill_inet_sock(h, arg) != 0) {
   fprintf(stderr, "%4d Filtered.\n", __LINE__);
		if (errno == EOPNOTSUPP || errno == ENOENT) {
			/* Socket can't be closed, or is already closed. */
			return 0;
		} else {
			perror("SOCK_DESTROY answers");
			return -1;
		}
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
    fprintf(stderr, "%4d Filtered.\n", __LINE__);
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
	if ((err = rtnl_dump_filter(&rth, stash_indirect /*show_one_inet_sock*/, &arg))) {
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

static int tcp_show(struct filter *f, int socktype)
{
	if (!filter_af_get(f, AF_INET) && !filter_af_get(f, AF_INET6)) {
    fprintf(stderr, "%4d Filtered.\n", __LINE__);
		return 0;
  }

	dg_proto = TCP_PROTO;

	if (inet_show_netlink(f, NULL, socktype) == 0) {
		return 0;
  }

  fprintf(stderr, "%4d Turns out we need this backup code after all!\n", __LINE__);
  exit(1);
}

static int udp_show(struct filter *f)
{
  if (SUPPRESS) {
    fprintf(stderr, "udp_show suppressed\n");
    return 0;
  } else {
    fprintf(stderr, "udp_show\n");
  }

	if (!filter_af_get(f, AF_INET) && !filter_af_get(f, AF_INET6)) {
    fprintf(stderr, "%4d Filtered.\n", __LINE__);
		return 0;
  }

	dg_proto = UDP_PROTO;

	if (inet_show_netlink(f, NULL, IPPROTO_UDP) == 0) {
		return 0;
  }

  fprintf(stderr, "%4d Turns out we need this backup code after all!\n", __LINE__);
  exit(1);
}

int unix_state_map[] = { SS_CLOSE, SS_SYN_SENT,
			 SS_ESTABLISHED, SS_CLOSING };

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
		if (!(f->states & (1 << s->state))) {
      fprintf(stderr, "%4d Skipped.\n", __LINE__);
			continue;
    }
		if (unix_type_skip(s, f)) {
      fprintf(stderr, "%4d Skipped.\n", __LINE__);
			continue;
    }

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

    // Deleted f->f related code.

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

	if (unix_type_skip(&stat, f)) {
    fprintf(stderr, "%4d Skipped.\n", __LINE__);
		return 0;
  }

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

  // Deleted f->f related code.

  // STASH DATA HERE.  (200 bytes)
	unix_stats_print(&stat, f);

  // show_mem
	printf("\t");
	print_skmeminfo(tb, UNIX_DIAG_MEMINFO);
  // show_details
	if (tb[UNIX_DIAG_SHUTDOWN]) {
		unsigned char mask;

		mask = *(__u8 *)RTA_DATA(tb[UNIX_DIAG_SHUTDOWN]);
		printf(" %c-%c", mask & 1 ? '-' : '<', mask & 2 ? '-' : '>');
	}
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
  // show_mem
	req.r.udiag_show |= UDIAG_SHOW_MEMINFO;

  // INTERCEPT ALL OF THE line printers.
  fprintf(stderr, "Calling handle_netlink_request. %d\n", __LINE__);
	return handle_netlink_request(f, &req.nlh, sizeof(req), stash_indirect /*unix_show_sock*/);
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

	if (!filter_af_get(f, AF_UNIX))
		return 0;

	if (unix_show_netlink(f) == 0)
		return 0;
  fprintf(stderr, "%4d Turns out we need this backup code after all!\n", __LINE__);
  exit(1);
}

struct sock_diag_msg {
	__u8 sdiag_family;
};

int c_main(int argc, char *argv[])
{
	FILE *filter_fp = NULL;
	int state_filter = 0;

//      -adtuwxiem
	show_options = 1;
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

	if (current_filter.dbs & (1<<NETLINK_DB)) {
    fprintf(stderr, "Unimplemented NETLINK_DB code.\n");
    exit(1);
  }
	if (current_filter.dbs & UNIX_DBM)
		unix_show(&current_filter);
	if (current_filter.dbs & (1<<UDP_DB))
		udp_show(&current_filter);
	if (current_filter.dbs & (1<<TCP_DB))
		tcp_show(&current_filter, IPPROTO_TCP);
	if (current_filter.dbs & (1<<DCCP_DB))
		tcp_show(&current_filter, IPPROTO_DCCP);

	return 0;
}
