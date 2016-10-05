// TODO:
//   Sometimes we see Removing N, Reported: 0.  No data associated with an
//   entry?
//   When decoding, we often see !!!Deficit, which come from parse_rtattr.

// #include "gfr.h"

#include <cstdio>
#include <stdint.h>
#include <stdlib.h>
#include <functional>
#include <string>
#include <unistd.h>
#include <unordered_map>
//#include <hash_bytes.h>

#include "structs.h"

extern "C" int c_main(int argc, char* argv[]);
extern "C"
int inet_show_sock(const struct nlmsghdr *nlh, struct sockstat *s, int protocol);
extern "C"
void parse_diag_msg(const struct nlmsghdr *nlh, struct sockstat *s);

struct Connection {
  bool operator==(const Connection& other) const {
    return (family == other.family) && (local_addr == other.local_addr) && (remote_addr == other.remote_addr);
  }
  std::string local_addr;
  std::string remote_addr;
  int family;
};

inline void hash_combine(std::size_t& seed) { }

template <typename T, typename... Rest>
inline void hash_combine(std::size_t& seed, const T& v, Rest... rest) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
    hash_combine(seed, rest...);
}

namespace std {
template<>
struct hash<Connection> {
  typedef Connection argument_type;
  typedef size_t result_type;
  result_type operator()(const Connection& c) const {
    size_t seed = c.family;
    hash_combine(seed, c.local_addr, c.remote_addr);
    return seed;
  }
};
}  // namespace std

struct Record {
  int round;
  int protocol;
  std::string msg;
};

class ConnectionTracker {
 public:
  using ConnectionMap = std::unordered_map<size_t, Record>;
  // Locate appropriate connection entry, swap its data, and update
  // its round.
  void StashData(size_t key, int protocol, std::string data) {
    if (data.size() == 0) {
      fprintf(stderr, "Zero size data.\n");
    }
    const auto& it = connections_.find(key);
    if (it == connections_.end()) {
      new_items_++;
      // TODO - optimize this.
      auto& entry = connections_[key];
      entry.round = round_;
      entry.protocol = protocol;  // Should we compare against previous?
      entry.msg.swap(data);
    } else {
      updates_++;
      if (it->second.round == round_) {
        fprintf(stderr, "!!!!Double update. %d\n", it->second.round);
      }
      it->second.round = round_;
      it->second.protocol = protocol;  // Should we compare against previous?
      it->second.msg.swap(data);
    }
  }

  // Where do we get the protocol??
  void OutputItem(const Record& record) {
	struct sockstat s = {};
        const auto* h = reinterpret_cast<const struct nlmsghdr*>(record.msg.c_str());
	parse_diag_msg(h, &s);
  // Protocol is IPPROTO_DCCP or IPPROTO_TCP
	/*err =*/ inet_show_sock(h, &s, record.protocol);
  }

  // Iterate through the map, find any items that are from previous
  // round, and take action on them.
  void FinishRound() {
    // size_after_last_round_ is the number of items in the cache before updates.
    // updates_ is the number of items updated in the cache.
    // new_items is the number of new items added to the cache.
    fprintf(stderr, "Added: %4d, Updated: %4d, Removing %4ld\n",
            new_items_, updates_, size_after_last_round_ - updates_);
#if 0
    if (size_after_last_round_ == updates_) {
      if (size() != new_items_ + updates_) {
        fprintf(stderr, "!!!CHECK: %lu != %d + %d\n", size(), updates_, new_items_);
      }
      size_after_last_round_ = size();
      updates_ = 0;
      new_items_ = 0;
      ++round_;  // Don't care about wrapping.
      return;
    }
#endif
    long ignored = 0;
    long erased = 0;
    int expired_count = 0;
    for (auto it = connections_.begin(); it != connections_.end();) {
      if (it->second.round != round_) {
        OutputItem(it->second);
        erased += it->second.msg.size();
        it = connections_.erase(it);
        ++expired_count;
      } else {
        ignored += it->second.msg.size();
        ++it;
      }
    }
    ++round_;  // Don't care about wrapping.
    fprintf(stderr, "map has %lu entries.  Retained: %ld,  Reported: %ld\n", size(), ignored, erased);

    // TODO Expect that size() = new_items_ + updates_.
    if (size() != new_items_ + updates_) {
      fprintf(stderr, "%4d !!!CHECK: %lu != %d + %d\n", __LINE__, size(), updates_, new_items_);
    }
    if (size_after_last_round_ != expired_count + updates_) {
      fprintf(stderr, "%4d !!!CHECK: %lu != %d + %d\n", __LINE__, size_after_last_round_, expired_count, updates_);
    }
    size_after_last_round_ = size();
    updates_ = 0;
    new_items_ = 0;
  }

  size_t size() const {
    return connections_.size();
  }

 private:
  // TODO(gfr) Consider having separate map for each family.
  ConnectionMap connections_;
  int round_ = 1;  // First round is round 0.
  size_t size_after_last_round_ = 0; // Items count after last FinishRound.
  unsigned updates_ = 0;  // Items updated since last FinishRound.
  unsigned new_items_ = 0;  // New items added since last FinishRound.
};

static ConnectionTracker g_tracker;

extern "C"
void finish_round() {
  g_tracker.FinishRound();
  sleep(1);
}

extern "C"
void stash_data_internal(int family, int protocol,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh) {
  size_t key = id.idiag_sport;
  hash_combine(key, id.idiag_dport);
  // We don't need to track sockets where the remote endpoint is localhost.
  bool endpoints_are_same = true;
  // TODO - are there other possible lengths we need to worry about?
  int words = (family == AF_INET) ? 1 : 4;
  for (int word = 0; word < words; ++word) {
    endpoints_are_same &= (id.idiag_src[word] == id.idiag_dst[word]);
    hash_combine(key, id.idiag_dport, id.idiag_src[word], id.idiag_dst[word]);
  }
  if (endpoints_are_same) return;
  std::string data(reinterpret_cast<const char*>(nlh), nlh->nlmsg_len);
  g_tracker.StashData(key, protocol, std::move(data));
}

int main(int argc, char* argv[]) {
  int r = c_main(argc, argv);
  return r;
}
