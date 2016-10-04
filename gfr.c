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

#include "structs.h"

#define SUPPRESS 0
#define STASH_DATA 0

int resolve_hosts;
static int resolve_services = 1;
int preferred_family = AF_UNSPEC;

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

#if 0
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
#endif
struct scache {
	struct scache *next;
	int port;
	char *name;
	const char *proto;
};

struct scache *rlist;

#if 0
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
#endif
#if 0
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
#endif

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

void stash_data(char *loc, char* rem, char* data, int family);

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
  // We need this to determine the number of bytes in the addresses.
	s->local.family	= s->remote.family = r->idiag_family;
	s->lport	= ntohs(r->id.idiag_sport);
	s->rport	= ntohs(r->id.idiag_dport);
	s->wq		= r->idiag_wqueue;
	s->rq		= r->idiag_rqueue;
	s->ino		= r->idiag_inode;
	s->uid		= r->idiag_uid;
	s->iface	= r->id.idiag_if;
//	s->sk		= cookie_sk_get(&r->id.idiag_cookie[0]);

  // Probably don't need this
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

// External
void stash_data_internal(int family,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh);

// Instead of show_one_inet_sock (or ...) stash the data.
// Don't use arg???
static int stash_indirect(const struct sockaddr_nl *addr,
		struct nlmsghdr *nlh, void *arg) {
  // Need to compute the key, and stash the appropriate amount of data.
  // We will need the inet_diag_sockid, and maybe the family and state?
  struct inet_diag_msg *r = NLMSG_DATA(nlh);
  stash_data_internal(r->idiag_family, r->id, nlh);
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
	if (ff->f) {
    // TODO - never executed.
		bclen = ssfilter_bytecompile(ff->f, &bc);
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

#if 0
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
#endif
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
  // TODO - how do we figure out how to interpret this later, without the
  // implicit info in the call to show_one_inet_sock?
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


static int handle_netlink_request(struct filter *f, struct nlmsghdr *req,
		size_t size, rtnl_filter_t show_one_sock)
{
  fprintf(stderr, "handle_netlink_request.\n");  // We see this once.
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
  // TODO - how do we figure out how to interpret this later, without the
  // implicit info in the call to unix_show_sock?
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

	serv_width = resolve_services ? 7 : 5;

	/* Make enough space for the local/remote port field */
	serv_width += 13;

	if (current_filter.dbs & (1<<NETLINK_DB)) {
    fprintf(stderr, "Unimplemented NETLINK_DB code.\n");
    exit(1);
  }
	if (current_filter.dbs & UNIX_DBM) unix_show(&current_filter);
	if (current_filter.dbs & (1<<UDP_DB)) udp_show(&current_filter);
	if (current_filter.dbs & (1<<TCP_DB)) tcp_show(&current_filter, IPPROTO_TCP);
	if (current_filter.dbs & (1<<DCCP_DB))
		tcp_show(&current_filter, IPPROTO_DCCP);

  finish_round();

	if (current_filter.dbs & UNIX_DBM) unix_show(&current_filter);
	if (current_filter.dbs & (1<<UDP_DB)) udp_show(&current_filter);
	if (current_filter.dbs & (1<<TCP_DB)) tcp_show(&current_filter, IPPROTO_TCP);
	if (current_filter.dbs & (1<<DCCP_DB))
		tcp_show(&current_filter, IPPROTO_DCCP);

	return 0;
}
