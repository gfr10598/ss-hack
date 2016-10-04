#ifndef MISC_STRUCTS_H
#define MISC_STRUCTS_H

#include "utils.h"

#include "libnetlink.h"

#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>

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
	SS_SYN_RECV,   // Excluded from SS_CONN
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,  // Excluded from SS_CONN
	SS_CLOSE,      // Excluded from SS_CONN
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,     // Excluded from SS_CONN
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

#if 0
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
#endif
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


#endif  // MISC_STRUCTS_H
