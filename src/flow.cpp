#include "netscope/flow.hpp"
#include <algorithm>
#include <functional>
#include <tuple>
namespace netscope {
size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
 size_t seed=0;
 auto combine=[&seed](size_t h){seed ^= h + size_t{0x9e3779b9} + (seed<<6) + (seed>>2);};
 combine(std::hash<std::string>{}(key.source_ip));
 combine(std::hash<std::string>{}(key.destination_ip));
 combine(std::hash<std::string>{}(key.protocol));
 combine(std::hash<uint16_t>{}(key.source_port));
 combine(std::hash<uint16_t>{}(key.destination_port));
 return seed;
}
void FlowTracker::observe(const Packet& packet) {
 // Non-initial IPv4 fragments have no transport header to identify a 5-tuple.
 if(packet.protocol=="IPv4-fragment") return;
 FlowKey key{packet.source_ip,packet.destination_ip,packet.protocol,
             packet.source_port,packet.destination_port};
 auto& stats=flows_[key];
 ++stats.packets;
 stats.bytes+=packet.frame_length;
}
std::vector<FlowRecord> FlowTracker::top_flows(size_t limit) const {
 std::vector<FlowRecord> records;
 records.reserve(flows_.size());
 for(const auto& [key,stats]:flows_) records.push_back({key,stats});
 std::sort(records.begin(),records.end(),[](const FlowRecord& a,const FlowRecord& b){
  if(a.stats.bytes!=b.stats.bytes) return a.stats.bytes>b.stats.bytes;
  if(a.stats.packets!=b.stats.packets) return a.stats.packets>b.stats.packets;
  return std::tie(a.key.source_ip,a.key.destination_ip,a.key.protocol,a.key.source_port,a.key.destination_port)
       < std::tie(b.key.source_ip,b.key.destination_ip,b.key.protocol,b.key.source_port,b.key.destination_port);
 });
 if(records.size()>limit) records.resize(limit);
 return records;
}
}
