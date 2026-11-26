#pragma once
#include "netscope/parser.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
namespace netscope {
struct FlowKey {
 std::string source_ip, destination_ip, protocol;
 uint16_t source_port=0, destination_port=0;
 bool operator==(const FlowKey&) const = default;
};
struct FlowKeyHash { size_t operator()(const FlowKey& key) const noexcept; };
struct FlowStats { uint64_t packets=0, bytes=0; };
struct FlowRecord { FlowKey key; FlowStats stats; };
class FlowTracker {
public:
 void observe(const Packet& packet);
 size_t flow_count() const noexcept { return flows_.size(); }
 std::vector<FlowRecord> top_flows(size_t limit=10) const;
 const std::unordered_map<FlowKey,FlowStats,FlowKeyHash>& flows() const noexcept { return flows_; }
private:
 std::unordered_map<FlowKey,FlowStats,FlowKeyHash> flows_;
};
}
