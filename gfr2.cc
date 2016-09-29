// #include "gfr.h"

#include <stdint.h>
#include <stdlib.h>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <functional>

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
  using ConnectionMap = std::unordered_map<Connection, std::pair<int, std::string>>;
 public:
  // Locate appropriate connection entry, swap its data, and update
  // its round.
  void StashData(char* local, char* remote, int family, char* data) {
    Connection c{local, remote, family};
    auto entry = connections_[c];
    entry.first = round_;
    entry.second = data;
  }

  void OutputItem(const ConnectionMap::value_type& value) {
    std::printf("%s", value.first.local_addr.c_str());
  }

#if 0
  // Iterate through the map, find any items that are from previous
  // round, and take action on them.
  void FinishRound() {
    for (auto& it = connections_.begin(); it != connections_.end(); ++it) {
      if (it->first.round != round_) {
        OutputItem(*it);
        connections_.erase(it);
      }
    }
    ++round_;  // Don't care about wrapping.
  }
#endif
 private:
  // TODO(gfr) Consider having separate map for each family.
  ConnectionMap connections_;
  int round_ = 0;
};

extern "C"
int stash_data(char *loc, char* rem, char* data, int family) {

}

void foobar() {
  std::fprintf(stderr, "Hello world.");
}


int main(int argc, char* argv[]) {
  return c_main(argc, argv);
}
