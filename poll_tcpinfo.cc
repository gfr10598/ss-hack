// NOTES:
//   The polling loop takes about 3 msec on my workstation.  This seems to be
//   somewhat independent of the number of connections reported.
//
#include <ctime>
#include <cstdio>
#include <fstream>
#include <functional>
#include <string>
#include <unordered_map>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "poll_tcpinfo.h"

#define VERBOSE 0

inline void hash_combine(std::size_t& seed) { }

template <typename T, typename... Rest>
inline void hash_combine(std::size_t& seed, const T& v, Rest... rest) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
    hash_combine(seed, rest...);
}

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
      // TODO(gfr) In addition to stashing the data, this should also parse
      // and compute various stats, e.g. min rtt.
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
    // TODO(gfr) By default, this should output raw data to a file.  As an
    // option, it should parse and write to stdout.
    parse_diag_msg(h, &s);
    inet_show_sock(h, &s, record.protocol);
  }

  // Iterate through the map, find any items that are from previous
  // round, and take action on them.
  void FinishRound() {
    if (VERBOSE) {
      fprintf(stderr, "Added: %4d, Updated: %4d, Removing %4ld\n",
              new_items_, updates_, size_after_last_round_ - updates_);
    }
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
    if (VERBOSE) {
      fprintf(stderr, "map has %lu entries.  Retained: %ld,  Reported: %ld\n",
              size(), ignored, erased);
    }

    // TODO Expect that size() = new_items_ + updates_.
    if (size() != new_items_ + updates_) {
      fprintf(stderr, "%4d !!!CHECK: %lu != %d + %d\n", __LINE__,
              size(), updates_, new_items_);
    }
    if (size_after_last_round_ != expired_count + updates_) {
      fprintf(stderr, "%4d !!!CHECK: %lu != %d + %d\n", __LINE__,
              size_after_last_round_, expired_count, updates_);
    }
    size_after_last_round_ = size();
    updates_ = 0;
    new_items_ = 0;
  }

  size_t size() const {
    return connections_.size();
  }

 private:
  ConnectionMap connections_;
  int round_ = 1;
  size_t size_after_last_round_ = 0; // Item count after last FinishRound.
  unsigned updates_ = 0;  // Items updated since last FinishRound.
  unsigned new_items_ = 0;  // New items added since last FinishRound.
};

static ConnectionTracker g_tracker;

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

// We anticipate new log records at on the order of < 1/second, or <3600/hr.
// Break the log into roughly hoursly files, with the file name indicating the
// GMT hour that its data falls into.
// 1. Keep track of the hour that was used to create the current filename.
// 2. Check on each write to the file to see if the hour has turned over.  If
//    it has, then close that file and open a new one.
class TCPInfoLog {
 public:
  // Ensures that the correct file is open.
  // TODO(gfr) Return status on error.
  void Open() {
    // Compare current time to file open time.
    if (0) {
      // Generate the file name.
      //
      // Open the file.
    }
  }

  // TODO(gfr) Return status on error.
  void WriteRecord(const std::string& record) {
//    fputs(record)
  }

 private:
  std::string path;  // The path prefix for the log files.
  struct tm log_start_time;  // Time at which the current log file was opened.
  std::string log_file_name;  // Name of the current log file.
  std::fstream log;
};

int main(int argc, char* argv[]) {
  for (int i = 0; i < 30; ++i) {
    int r = poll();
    if (r != 0) return r;

    g_tracker.FinishRound();
    sleep(1);
  }
  return 0;
}
