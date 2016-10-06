/* Code derived from iproute2 ss.c.  Forked from net-next Sept 2016.
 *
 * Contains common structs and functions required across SideStream modules.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
*/

#ifndef MISC_POLL_TCPINFO_H_
#define MISC_POLL_TCPINFO_H_

#include "utils.h"

#include "libnetlink.h"

#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>

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

struct filter {
  int dbs;
  int states;
  int families;
  struct ssfilter *f;
  bool kill;
};

struct sockstat {
  struct sockstat    *next;
  unsigned int      type;
  uint16_t      prot;
  inet_prefix     local;
  inet_prefix     remote;
  int       lport;
  int       rport;
  int       state;
  int       rq, wq;
  unsigned int ino;
  unsigned int uid;
  int       refcnt;
  unsigned int      iface;
  unsigned long long  sk;
  char *name;
  char *peer_name;
  __u32       mark;
};

#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif

// Poll all tcp socket connections in established state.
EXTERN_C
int poll(void);

// TODO(gfr) Move this to another .h file.
EXTERN_C
void stash_data_internal(int family, int protocol,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh);

// Print status data for a socket.
EXTERN_C
int inet_show_sock(const struct nlmsghdr *nlh, struct sockstat *s,
                   int protocol);
// Create sockstat structure from a raw message.
EXTERN_C
void parse_diag_msg(const struct nlmsghdr *nlh, struct sockstat *s);

#endif  // MISC_POLL_TCPINFO_H_
