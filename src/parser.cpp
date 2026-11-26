#include "netscope/parser.hpp"
#include <sstream>
namespace netscope {
namespace {
uint32_t be32(std::span<const uint8_t> b, size_t i) { return (uint32_t(b[i])<<24)|(uint32_t(b[i+1])<<16)|(uint32_t(b[i+2])<<8)|b[i+3]; }
uint16_t be16(std::span<const uint8_t> b, size_t i) { return static_cast<uint16_t>((b[i]<<8)|b[i+1]); }
std::string ip(std::span<const uint8_t> b, size_t i) {
 return std::to_string(b[i])+"."+std::to_string(b[i+1])+"."+std::to_string(b[i+2])+"."+std::to_string(b[i+3]);
}
}
std::optional<Packet> decode_ethernet(std::span<const uint8_t> b) {
 if(b.size()<14 || be16(b,12)!=0x0800) return std::nullopt;
 size_t o=14;
 if(b.size()<o+20 || (b[o]>>4)!=4) return std::nullopt;
 size_t ihl=(b[o]&0x0f)*4;
 if(ihl<20 || b.size()<o+ihl) return std::nullopt;
 uint16_t total=be16(b,o+2);
 if(total<ihl || b.size()-o<total) return std::nullopt;
 Packet p; p.frame_length=b.size();p.ipv4_ttl=b[o+8];p.ipv4_header_length=static_cast<uint8_t>(ihl); p.source_ip=ip(b,o+12); p.destination_ip=ip(b,o+16);
 uint16_t fragment=be16(b,o+6);
 size_t t=o+ihl, available=o+total-t;
 if((fragment&0x1fff)!=0) {p.protocol="IPv4-fragment";return p;}
 switch(b[o+9]) {
 case 6:
  if(available<20 || (b[t+12]>>4)<5 || static_cast<size_t>((b[t+12]>>4)*4)>available) return std::nullopt;
  p.protocol="TCP";p.source_port=be16(b,t);p.destination_port=be16(b,t+2);p.tcp_flags=b[t+13];p.tcp_sequence=be32(b,t+4);p.tcp_acknowledgment=be32(b,t+8);p.tcp_header_length=static_cast<uint8_t>((b[t+12]>>4)*4);p.tcp_window=be16(b,t+14);break;
 case 17:
  if(available<8 || be16(b,t+4)<8 || be16(b,t+4)>available) return std::nullopt;
  p.protocol="UDP";p.source_port=be16(b,t);p.destination_port=be16(b,t+2);break;
 case 1:
  if(available<4) return std::nullopt;
  p.protocol="ICMP";p.icmp_type=b[t];p.icmp_code=b[t+1];break;
 default:p.protocol="Other";break;
 }
 return p;
}
}
