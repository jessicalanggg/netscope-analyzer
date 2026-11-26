#pragma once
#include "netscope/parser.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace netscope {
struct Endpoint {
 std::string ip; uint16_t port=0;
 bool operator<(const Endpoint& o) const {return ip==o.ip ? port<o.port : ip<o.ip;}
 bool operator==(const Endpoint&) const = default;
};
struct ConversationKey {
 Endpoint a,b; std::string protocol;
 bool operator<(const ConversationKey& o) const {
  if(protocol!=o.protocol) return protocol<o.protocol;
  if(a<o.a) return true;
  if(o.a<a) return false;
  return b<o.b;
 }
};
struct ConversationStats {
 uint64_t packets_a_to_b=0, packets_b_to_a=0, bytes_a_to_b=0, bytes_b_to_a=0;
 uint64_t first_us=0,last_us=0;
 bool syn=false,syn_ack=false,ack_after_syn=false,fin_a=false,fin_b=false,rst=false;
 uint64_t syn_count=0,fin_count=0,rst_count=0;
 uint64_t packets() const {return packets_a_to_b+packets_b_to_a;}
 uint64_t bytes() const {return bytes_a_to_b+bytes_b_to_a;}
 uint64_t duration_us() const {return last_us>=first_us?last_us-first_us:0;}
 double throughput_bps() const {return duration_us()?8.0*bytes()*1000000.0/duration_us():0;}
 std::string tcp_state() const;
};
struct ConversationRecord {ConversationKey key; ConversationStats stats;};
class ConversationTracker {
public:
 void observe(const Packet& packet,uint64_t timestamp_us);
 size_t count() const {return conversations_.size();}
 std::vector<ConversationRecord> top_conversations(size_t limit=100) const;
private:
 std::map<ConversationKey,ConversationStats> conversations_;
};
}
