
#if 0
static int netid_width;
static int state_width;
static int addr_width;
static int serv_width;

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

