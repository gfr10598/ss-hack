
#include "structs.h"

int netid_width;
int state_width;
int addrp_width;
int addr_width;
int serv_width;
int screen_width;

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

#if 0
static int netid_width;
static int state_width;
static int addr_width;
static int serv_width;

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
				peer = const_cast<char*>((p->name) ? : "*");
			}
		}

    // Deleted f->f related code.

		sock_state_print(s, unix_netid_name(s->type));

                sprintf(port_name, "%d", s->lport);
		sock_addr_print(s->name ?: "*", " ", port_name, NULL);
                sprintf(port_name, "%d", s->lport);
		sock_addr_print(peer, " ", port_name, NULL);

		printf("\n");
	}
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

// INTERCEPT
// instead of printing stuff here, stash it away and only print when the socket
// disappears.
static int unix_show_sock(const struct sockaddr_nl *addr, struct nlmsghdr *nlh,
		void *arg)
{
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
#endif

#if 0
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
#endif
#if 0
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
#endif

