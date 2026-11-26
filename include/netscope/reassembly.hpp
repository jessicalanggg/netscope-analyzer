#pragma once
#include "netscope/parser.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>
namespace netscope {
// Bidirectional TCP stream reassembly. Streams are numbered in order of first
// appearance (matching Wireshark's tcp.stream); a fresh SYN on a stream that
// already closed or reset starts a new stream (port reuse). Direction 0 is the
// endpoint that sent the first packet of the stream.
struct TcpDirectionStats {
 uint64_t segments=0, payload_bytes=0, delivered_bytes=0;
 uint64_t retransmitted_bytes=0, out_of_order_segments=0, missing_bytes=0;
 bool syn=false, fin=false, rst=false;
};
struct TcpStreamInfo {
 uint64_t id=0;
 std::string address[2]; uint16_t port[2]={0,0};
 uint64_t first_us=0, last_us=0;
 TcpDirectionStats dir[2];
};
class TcpReassembler {
public:
 using DataCallback=std::function<void(uint64_t stream,int direction,std::span<const uint8_t> data)>;
 explicit TcpReassembler(DataCallback on_data={}, size_t max_buffered_per_direction=8u*1024*1024);
 // `frame` must be the bytes the Packet was decoded from.
 void observe(const Packet& packet, std::span<const uint8_t> frame, uint64_t timestamp_us);
 // Flushes buffered out-of-order data, accounting unfilled gaps as missing bytes.
 void finish();
 const std::vector<TcpStreamInfo>& streams() const noexcept {return info_;}
 uint64_t buffered_bytes() const noexcept {return buffered_;}
private:
 struct Direction {
  bool has_isn=false; uint32_t isn=0; uint64_t next=0;
  bool fin_known=false; uint64_t fin_at=0; bool closed=false;
  std::map<uint64_t,std::vector<uint8_t>> pending; size_t pending_bytes=0;
 };
 struct Stream {uint64_t id; Direction d[2]; bool closed_or_reset=false;};
 struct Key {
  std::string a; uint16_t pa; std::string b; uint16_t pb;
  bool operator<(const Key& o) const;
 };
 void deliver(Stream& s,int dir,std::span<const uint8_t> data);
 void drain(Stream& s,int dir);
 void segment(Stream& s,int dir,const Packet& p,std::span<const uint8_t> payload);
 void flush_direction(Stream& s,int dir);
 DataCallback on_data_;
 size_t max_buffered_;
 uint64_t buffered_=0;
 std::map<Key,Stream> streams_;
 std::vector<TcpStreamInfo> info_;
};
}
