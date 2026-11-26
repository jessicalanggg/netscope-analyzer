#pragma once
// Test helpers that hand-build link/network/transport headers.
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace testpkt {
using Bytes=std::vector<uint8_t>;
inline void put16(Bytes& b,uint16_t v) {b.push_back(uint8_t(v>>8));b.push_back(uint8_t(v));}
inline void put32(Bytes& b,uint32_t v) {put16(b,uint16_t(v>>16));put16(b,uint16_t(v));}
inline void set16(Bytes& b,size_t at,uint16_t v) {b[at]=uint8_t(v>>8);b[at+1]=uint8_t(v);}
inline Bytes ethernet(uint16_t ethertype,const std::vector<uint16_t>& vlan_tags={}) {
 Bytes b={0,1,2,3,4,5, 6,7,8,9,10,11};
 for(uint16_t tag:vlan_tags) {put16(b,0x8100);put16(b,tag);}
 put16(b,ethertype);
 return b;
}
inline Bytes tcp(uint16_t sport,uint16_t dport,uint32_t seq,uint32_t ack,uint8_t flags,const std::string& payload={}) {
 Bytes b;put16(b,sport);put16(b,dport);put32(b,seq);put32(b,ack);
 b.push_back(0x50);b.push_back(flags);put16(b,65535);put16(b,0);put16(b,0);
 b.insert(b.end(),payload.begin(),payload.end());
 return b;
}
inline Bytes udp(uint16_t sport,uint16_t dport,const std::string& payload={}) {
 Bytes b;put16(b,sport);put16(b,dport);put16(b,uint16_t(8+payload.size()));put16(b,0);
 b.insert(b.end(),payload.begin(),payload.end());
 return b;
}
inline Bytes ipv4(std::array<uint8_t,4> src,std::array<uint8_t,4> dst,uint8_t proto,const Bytes& l4,uint16_t frag=0) {
 Bytes b={0x45,0};put16(b,uint16_t(20+l4.size()));put16(b,1);put16(b,frag);b.push_back(64);b.push_back(proto);put16(b,0);
 b.insert(b.end(),src.begin(),src.end());b.insert(b.end(),dst.begin(),dst.end());
 b.insert(b.end(),l4.begin(),l4.end());
 return b;
}
// `ext` is a pre-built extension-header chain whose first header type is `first_next`;
// the last extension header's next-header byte must already name `proto`.
inline Bytes ipv6(const std::array<uint8_t,16>& src,const std::array<uint8_t,16>& dst,uint8_t first_next,const Bytes& ext,const Bytes& l4) {
 Bytes b={0x60,0,0,0};put16(b,uint16_t(ext.size()+l4.size()));b.push_back(first_next);b.push_back(55);
 b.insert(b.end(),src.begin(),src.end());b.insert(b.end(),dst.begin(),dst.end());
 b.insert(b.end(),ext.begin(),ext.end());b.insert(b.end(),l4.begin(),l4.end());
 return b;
}
inline Bytes cat(Bytes a,const Bytes& b) {a.insert(a.end(),b.begin(),b.end());return a;}
inline std::array<uint8_t,16> v6(std::initializer_list<uint16_t> words) {
 std::array<uint8_t,16> a{};size_t i=0;
 for(uint16_t w:words) {a[i++]=uint8_t(w>>8);a[i++]=uint8_t(w);}
 return a;
}
}
