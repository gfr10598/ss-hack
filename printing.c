/* Code derived from iproute2 ss.c
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
*/

// This code will be used for two purposes:
//  1. template for parsing tcp_info related data.
//  2. verifying that the binary data stashed by sidestream matches
//     the data saved by ss.c ???

#include <errno.h>
#include <netdb.h>  // setservent

#include "rt_names.h"

#include "poll_tcpinfo.h"

struct dctcpstat {
  unsigned int  ce_state;
  unsigned int  alpha;
  unsigned int  ab_ecn;
  unsigned int  ab_tot;
  bool    enabled;
};

struct tcpstat {
  struct sockstat     ss;
  int       timer;
  int       timeout;
  int       probes;
  char        cong_alg[16];
  double        rto, ato, rtt, rttvar;
  int       qack, ssthresh, backoff;
  double        send_bps;
  int       snd_wscale;
  int       rcv_wscale;
  int       mss;
  unsigned int      cwnd;
  unsigned int      lastsnd;
  unsigned int      lastrcv;
  unsigned int      lastack;
  double        pacing_rate;
  double        pacing_rate_max;
  unsigned long long  bytes_acked;
  unsigned long long  bytes_received;
  unsigned int      segs_out;
  unsigned int      segs_in;
  unsigned int      data_segs_out;
  unsigned int      data_segs_in;
  unsigned int      unacked;
  unsigned int      retrans;
  unsigned int      retrans_total;
  unsigned int      lost;
  unsigned int      sacked;
  unsigned int      fackets;
  unsigned int      reordering;
  unsigned int      not_sent;
  double        rcv_rtt;
  double        min_rtt;
  int       rcv_space;
  bool        has_ts_opt;
  bool        has_sack_opt;
  bool        has_ecn_opt;
  bool        has_ecnseen_opt;
  bool        has_fastopen_opt;
  bool        has_wscale_opt;
  struct dctcpstat    *dctcp;
  struct tcp_bbr_info *bbr_info;
};

int resolve_services = 1;

int netid_width;
int state_width;
int addrp_width;
int addr_width;
int serv_width;
int screen_width;

static const char *RAW_PROTO = "raw";
static const char *dg_proto;


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
  [SS_LISTEN] = "LISTEN",
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

// TODO - extract code from this to monitor minimum RTT.
static void tcp_show_info(const struct nlmsghdr *nlh, struct inet_diag_msg *r,
    struct rtattr *tb[])
{
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
    s.has_ts_opt     = TCPI_HAS_OPT(info, TCPI_OPT_TIMESTAMPS);
    s.has_sack_opt     = TCPI_HAS_OPT(info, TCPI_OPT_SACK);
    s.has_ecn_opt    = TCPI_HAS_OPT(info, TCPI_OPT_ECN);
    s.has_ecnseen_opt  = TCPI_HAS_OPT(info, TCPI_OPT_ECN_SEEN);
    s.has_fastopen_opt = TCPI_HAS_OPT(info, TCPI_OPT_SYN_DATA);

    if (tb[INET_DIAG_CONG])
      strncpy(s.cong_alg,
        rta_getattr_str(tb[INET_DIAG_CONG]),
        sizeof(s.cong_alg) - 1);

    if (TCPI_HAS_OPT(info, TCPI_OPT_WSCALE)) {
      s.has_wscale_opt  = true;
      s.snd_wscale    = info->tcpi_snd_wscale;
      s.rcv_wscale    = info->tcpi_rcv_wscale;
    }

    if (info->tcpi_rto && info->tcpi_rto != 3000000)
      s.rto = (double)info->tcpi_rto / 1000;

    s.backoff  = info->tcpi_backoff;
    s.rtt    = (double)info->tcpi_rtt / 1000;
    s.rttvar   = (double)info->tcpi_rttvar / 1000;
    s.ato    = (double)info->tcpi_ato / 1000;
    s.mss    = info->tcpi_snd_mss;
    s.rcv_space  = info->tcpi_rcv_space;
    s.rcv_rtt  = (double)info->tcpi_rcv_rtt / 1000;
    s.lastsnd  = info->tcpi_last_data_sent;
    s.lastrcv  = info->tcpi_last_data_recv;
    s.lastack  = info->tcpi_last_ack_recv;
    s.unacked  = info->tcpi_unacked;
    s.retrans  = info->tcpi_retrans;
    s.retrans_total  = info->tcpi_total_retrans;
    s.lost     = info->tcpi_lost;
    s.sacked   = info->tcpi_sacked;
    s.reordering   = info->tcpi_reordering;
    s.rcv_space  = info->tcpi_rcv_space;
    s.cwnd     = info->tcpi_snd_cwnd;

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

      dctcp->enabled  = !!dinfo->dctcp_enabled;
      dctcp->ce_state = dinfo->dctcp_ce_state;
      dctcp->alpha  = dinfo->dctcp_alpha;
      dctcp->ab_ecn = dinfo->dctcp_ab_ecn;
      dctcp->ab_tot = dinfo->dctcp_ab_tot;
      s.dctcp   = dctcp;
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
    tcp_stats_print(&s);
    free(s.dctcp);
    free(s.bbr_info);
  }
}

void parse_diag_msg(const struct nlmsghdr *nlh, struct sockstat *s)
{
  struct inet_diag_msg *r = NLMSG_DATA(nlh);

  s->state  = r->idiag_state;
  s->local.family = s->remote.family = r->idiag_family;
  s->lport  = ntohs(r->id.idiag_sport);
  s->rport  = ntohs(r->id.idiag_dport);
  s->wq   = r->idiag_wqueue;
  s->rq   = r->idiag_rqueue;
  s->ino    = r->idiag_inode;
  s->uid    = r->idiag_uid;
  s->iface  = r->id.idiag_if;
//  s->sk   = cookie_sk_get(&r->id.idiag_cookie[0]);

  if (s->local.family == AF_INET)
    s->local.bytelen = s->remote.bytelen = 4;
  else
    s->local.bytelen = s->remote.bytelen = 16;

  memcpy(s->local.data, r->id.idiag_src, s->local.bytelen);
  memcpy(s->remote.data, r->id.idiag_dst, s->local.bytelen);
}

int inet_show_sock(const struct nlmsghdr *nlh,
        struct sockstat *s,
        int protocol)
{
  struct rtattr *tb[INET_DIAG_MAX+1];
  struct inet_diag_msg *r = NLMSG_DATA(nlh);

  parse_rtattr(tb, INET_DIAG_MAX, (struct rtattr *)(r+1),
         nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

  if (tb[INET_DIAG_PROTOCOL])
    protocol = *(__u8 *)RTA_DATA(tb[INET_DIAG_PROTOCOL]);

  inet_stats_print(s, protocol);

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

  printf("\n\t");
  tcp_show_info(nlh, r, tb);

  printf("\n");
  return 0;
}

struct inet_diag_arg {
  struct filter *f;
  int protocol;
  struct rtnl_handle *rth;
};

