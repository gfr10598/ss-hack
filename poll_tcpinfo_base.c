// TODO(gfr) separate out printing code from collection code.

/*
 * Derived from iproute2 ss.c
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version
 *    2 of the License, or (at your option) any later version.
 *
 * Authors: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "utils.h"
#include "rt_names.h"
#include "libnetlink.h"

#include "structs.h"

int poll(void);
void stash_data_internal(int family, int protocol,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh);

int resolve_hosts;
static int resolve_services = 1;

static int netid_width;
static int state_width;
static int addrp_width;
static int serv_width;
static int screen_width;

static const char *TCP_PROTO = "tcp";
static const char *UDP_PROTO = "udp";
//static const char *RAW_PROTO = "raw";
static const char *dg_proto;

#define MAGIC_SEQ 123456

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
static struct filter current_filter;

static void filter_db_set(struct filter *f, int db)
{
  f->states   |= default_dbs[db].states;
  f->dbs      |= 1 << db;
  do_default   = 0;
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

struct scache {
  struct scache *next;
  int port;
  char *name;
  const char *proto;
};

struct scache *rlist;

struct inet_diag_arg {
  struct filter *f;
  int protocol;
  struct rtnl_handle *rth;
};

// External
void stash_data_internal(int family, int protocol,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh);

static int stash_inet(const struct sockaddr_nl *addr,
    struct nlmsghdr *nlh, void *arg) {
  struct inet_diag_arg *diag_arg = arg;
  // Need to compute the key, and stash the appropriate amount of data.
  // We will need the inet_diag_sockid, and maybe the family and state?
  struct inet_diag_msg *r = NLMSG_DATA(nlh);
  stash_data_internal(r->idiag_family, diag_arg->protocol, r->id, nlh);
  return 0;
}

static int tcpdiag_send(int fd, int protocol, struct filter *ff)
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
    .r.idiag_states = ff->states,
  };
  struct msghdr msg;
  struct iovec iov[3];
  int iovlen = 1;

  if (protocol == IPPROTO_UDP)
    return -1;

  if (protocol == IPPROTO_TCP)
    req.nlh.nlmsg_type = TCPDIAG_GETSOCK;
  else {
    req.nlh.nlmsg_type = DCCPDIAG_GETSOCK;
                fprintf(stderr, "Protocol = %d\n", protocol);
        }
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
  struct msghdr msg;
  struct iovec iov[3];
  int iovlen = 1;

  if (family == PF_UNSPEC) {
          fprintf(stderr, "!!!!!!!!!!Unspecified family.\n");
    return tcpdiag_send(fd, protocol, f);
        }

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

static int inet_show_netlink(struct filter *f, FILE *dump_fp, int protocol)
{
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

again:
  if ((err = sockdiag_send(family, rth.fd, protocol, f)))
    goto Exit;

        // This formerly passed show_one_inet_sock
  if ((err = rtnl_dump_filter(&rth, stash_inet, &arg))) {
    if (family != PF_UNSPEC) {
      family = PF_UNSPEC;
      goto again;
    }
    goto Exit;
  }
  if (family == PF_INET) {
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

struct sock_diag_msg {
  __u8 sdiag_family;
};

int poll(void)
{
  int state_filter = 0;

//      -tieom
  filter_db_set(&current_filter, TCP_DB);
//  filter_db_set(&current_filter, UDP_DB);
//  filter_db_set(&current_filter, DCCP_DB);
  state_filter = 1 << SS_ESTABLISHED;

  filter_states_set(&current_filter, state_filter);
  filter_merge_defaults(&current_filter);

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

  serv_width = resolve_services ? 7 : 5;

  serv_width += 13;

  if (current_filter.dbs & (1<<UDP_DB)) udp_show(&current_filter);
  if (current_filter.dbs & (1<<TCP_DB)) tcp_show(&current_filter, IPPROTO_TCP);
  if (current_filter.dbs & (1<<DCCP_DB))
    tcp_show(&current_filter, IPPROTO_DCCP);
  return 0;
}
