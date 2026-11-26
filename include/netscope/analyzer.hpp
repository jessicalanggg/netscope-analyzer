#pragma once
#include "netscope/conversation.hpp"
#include "netscope/flow.hpp"
#include "netscope/parser.hpp"
#include "netscope/reassembly.hpp"
#include <cstdint>
#include <iosfwd>
#include <span>
#include <string>
#include <unordered_map>
namespace netscope {
// One-pass analysis pipeline shared by offline (`analyze`) and live (`capture`)
// modes: decode, protocol/talker/port counts, flows, conversations, TCP reassembly.
class Analyzer {
public:
 explicit Analyzer(bool reassemble=true, TcpReassembler::DataCallback on_data={});
 void observe(uint32_t linktype, std::span<const uint8_t> frame, uint64_t timestamp_us);
 void finish();
 void print_summary(std::ostream& out) const;
 uint64_t frames() const noexcept {return frames_;}
 uint64_t decoded() const noexcept {return decoded_;}
 uint64_t bytes() const noexcept {return bytes_;}
 const FlowTracker& flows() const noexcept {return flows_;}
 const ConversationTracker& conversations() const noexcept {return conversations_;}
 const TcpReassembler& reassembler() const noexcept {return reassembler_;}
private:
 bool reassemble_;
 uint64_t frames_=0, decoded_=0, bytes_=0, ipv4_=0, ipv6_=0, vlan_=0;
 std::unordered_map<std::string,uint64_t> protocols_, talkers_;
 std::unordered_map<uint16_t,uint64_t> ports_;
 FlowTracker flows_;
 ConversationTracker conversations_;
 TcpReassembler reassembler_;
};
}
