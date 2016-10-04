// #include "gfr.h"

#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <functional>
//#include <hash_bytes.h>

extern "C" void foobar();
extern "C" int c_main(int argc, char* argv[]);

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

class ConnectionTracker {
  using ConnectionMap = std::unordered_map<size_t, std::pair<int, std::string>>;
 public:
  // Locate appropriate connection entry, swap its data, and update
  // its round.
  void StashData(size_t key, char* data) {
    auto entry = connections_[key];
    entry.first = round_;
    entry.second = data;
  }

  void OutputItem(const ConnectionMap::value_type& value) {
//    std::printf("%s", value.first.local_addr.c_str());
  }

  // Iterate through the map, find any items that are from previous
  // round, and take action on them.
  void FinishRound() {
    for (auto it = connections_.begin(); it != connections_.end(); ++it) {
      if (it->second.first != round_) {
        OutputItem(*it);
        connections_.erase(it);
      }
    }
    ++round_;  // Don't care about wrapping.
  }

  size_t size() const {
    return connections_.size();
  }

 private:
  // TODO(gfr) Consider having separate map for each family.
  ConnectionMap connections_;
  int round_ = 0;
};

static ConnectionTracker g_tracker;


void foobar() {
  std::fprintf(stderr, "Hello world.\n");
}

#include "structs.h"

extern "C"
void stash_data_internal(int family,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh);

void stash_data_internal(int family,
                         const struct inet_diag_sockid id,
                         const struct nlmsghdr *nlh) {
  // TODO - are there other possible lengths we need to worry about?
  size_t key = id.idiag_sport;
  hash_combine(key, id.idiag_dport);
	int words = (family == AF_INET) ? 1 : 4;
  for (int word = 0; word < words; ++word) {
    hash_combine(key, id.idiag_dport, id.idiag_src[word], id.idiag_dst[word]);
  }
  // TODO data
  g_tracker.StashData(key, "data");
}

int main(int argc, char* argv[]) {
  //g_tracker.StashData("l", "r", 0, "foobar");
  int r = c_main(argc, argv);
  fprintf(stderr, "map has %lu entries.\n", g_tracker.size());
  return r;
}
