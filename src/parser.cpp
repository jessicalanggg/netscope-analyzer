#include "netscope/parser.hpp"
#include <algorithm>
#include <cstdio>
namespace netscope {
namespace {
uint32_t be32(std::span<const uint8_t> b, size_t i) { return (uint32_t(b[i])<<24)|(uint32_t(b[i+1])<<16)|(uint32_t(b[i+2])<<8)|b[i+3]; }
uint16_t be16(std::span<const uint8_t> b, size_t i) { return static_cast<uint16_t>((b[i]<<8)|b[i+1]); }
std::string ipv4(std::span<const uint8_t> b, size_t i) {
 char buf[16];
 std::snprintf(buf,sizeof buf,"%u.%u.%u.%u",b[i],b[i+1],b[i+2],b[i+3]);
 return buf;
}

// Decodes TCP/UDP/ICMP/ICMPv6 starting at offset t with `available` bytes of
// L4 data (as declared by the IP header). Returns false on a malformed header.
bool decode_transport(std::span<const uint8_t> b, Packet& p, uint8_t proto, size_t t, size_t available) {
 switch(proto) {
 case 6: {
  if(available<20) return false;
  const size_t hl=static_cast<size_t>(b[t+12]>>4)*4;
  if(hl<20 || hl>available) return false;
  p.protocol="TCP";p.source_port=be16(b,t);p.destination_port=be16(b,t+2);p.tcp_flags=b[t+13];
  p.tcp_sequence=be32(b,t+4);p.tcp_acknowledgment=be32(b,t+8);p.tcp_header_length=static_cast<uint8_t>(hl);p.tcp_window=be16(b,t+14);
  p.payload_offset=t+hl;p.payload_length=available-hl;
  return true;
 }
 case 17: {
  if(available<8) return false;
  const uint16_t len=be16(b,t+4);
  if(len<8 || len>available) return false;
  p.protocol="UDP";p.source_port=be16(b,t);p.destination_port=be16(b,t+2);
  p.payload_offset=t+8;p.payload_length=len-8u;
  return true;
 }
 case 1:
 case 58:
  if(available<4) return false;
  p.protocol=proto==1?"ICMP":"ICMPv6";p.icmp_type=b[t];p.icmp_code=b[t+1];
  p.payload_offset=t+4;p.payload_length=available-4;
  return true;
 default:
  p.protocol="Other";
  p.payload_offset=t;p.payload_length=available;
  return true;
 }
}

std::optional<Packet> decode_ipv4(std::span<const uint8_t> b, size_t o) {
 if(b.size()<o+20 || (b[o]>>4)!=4) return std::nullopt;
 const size_t ihl=(b[o]&0x0f)*4;
 if(ihl<20 || b.size()<o+ihl) return std::nullopt;
 const uint16_t total=be16(b,o+2);
 if(total<ihl || b.size()-o<total) return std::nullopt;
 Packet p;p.frame_length=b.size();p.ip_version=4;p.ipv4_ttl=b[o+8];p.ipv4_header_length=static_cast<uint8_t>(ihl);
 p.source_ip=ipv4(b,o+12);p.destination_ip=ipv4(b,o+16);
 const uint16_t fragment=be16(b,o+6);
 const size_t t=o+ihl, available=o+total-t;
 if((fragment&0x1fff)!=0) {p.protocol="IPv4-fragment";return p;}
 if(!decode_transport(b,p,b[o+9],t,available)) return std::nullopt;
 return p;
}

std::optional<Packet> decode_ipv6(std::span<const uint8_t> b, size_t o) {
 if(b.size()<o+40 || (b[o]>>4)!=6) return std::nullopt;
 const uint16_t payload=be16(b,o+4);
 if(b.size()-o-40<payload) return std::nullopt; // jumbograms (payload==0 w/ HBH option) unsupported
 Packet p;p.frame_length=b.size();p.ip_version=6;p.ipv4_ttl=b[o+7];
 p.source_ip=format_ipv6(b.data()+o+8);p.destination_ip=format_ipv6(b.data()+o+24);
 const size_t end=o+40+payload;
 uint8_t next=b[o+6];
 size_t t=o+40;
 // Walk extension headers. Bounded: each iteration advances by >=8 bytes.
 for(;;) {
  if(next==0 || next==43 || next==60) {       // hop-by-hop, routing, destination options
   if(end-t<8) return std::nullopt;
   const size_t len=(static_cast<size_t>(b[t+1])+1)*8;
   if(len>end-t) return std::nullopt;
   next=b[t];t+=len;
  } else if(next==44) {                       // fragment
   if(end-t<8) return std::nullopt;
   const uint16_t off=be16(b,t+2)>>3;
   next=b[t];t+=8;
   if(off!=0) {p.protocol="IPv6-fragment";p.ipv4_header_length=static_cast<uint8_t>(std::min<size_t>(t-o,255));return p;}
  } else if(next==51) {                       // authentication header: length in 4-byte units
   if(end-t<8) return std::nullopt;
   const size_t len=(static_cast<size_t>(b[t+1])+2)*4;
   if(len>end-t) return std::nullopt;
   next=b[t];t+=len;
  } else break;
 }
 p.ipv4_header_length=static_cast<uint8_t>(std::min<size_t>(t-o,255));
 if(next==59) {p.protocol="Other";return p;}  // no next header
 if(!decode_transport(b,p,next,t,end-t)) return std::nullopt;
 return p;
}

std::optional<Packet> decode_ip_by_version(std::span<const uint8_t> b, size_t o) {
 if(b.size()<=o) return std::nullopt;
 switch(b[o]>>4) {
 case 4:return decode_ipv4(b,o);
 case 6:return decode_ipv6(b,o);
 default:return std::nullopt;
 }
}

std::optional<Packet> decode_ethertype(std::span<const uint8_t> b, uint16_t type, size_t o, uint8_t depth, uint16_t vlan) {
 std::optional<Packet> p;
 if(type==0x0800) p=decode_ipv4(b,o);
 else if(type==0x86DD) p=decode_ipv6(b,o);
 else return std::nullopt;
 if(p) {p->vlan_depth=depth;p->vlan_id=vlan;}
 return p;
}
}

std::string format_ipv6(const uint8_t* a) {
 uint16_t w[8];
 for(int i=0;i<8;++i) w[i]=static_cast<uint16_t>((a[2*i]<<8)|a[2*i+1]);
 // RFC 5952: compress the longest run (>=2) of zero words, leftmost on ties.
 int best=-1,bestLen=0;
 for(int i=0;i<8;) {
  if(w[i]!=0) {++i;continue;}
  int j=i;while(j<8&&w[j]==0) ++j;
  if(j-i>bestLen && j-i>=2) {best=i;bestLen=j-i;}
  i=j;
 }
 std::string out;char buf[8];
 // IPv4-mapped ::ffff:a.b.c.d
 if(best==0 && bestLen==5 && w[5]==0xffff) {
  std::snprintf(buf,sizeof buf,"%u.",a[12]);out="::ffff:";out+=buf;
  std::snprintf(buf,sizeof buf,"%u.",a[13]);out+=buf;
  std::snprintf(buf,sizeof buf,"%u.",a[14]);out+=buf;
  std::snprintf(buf,sizeof buf,"%u",a[15]);out+=buf;
  return out;
 }
 for(int i=0;i<8;) {
  if(i==best) {out+="::";i+=bestLen;continue;}
  if(!out.empty() && out.back()!=':') out+=':';
  std::snprintf(buf,sizeof buf,"%x",w[i]);out+=buf;++i;
 }
 return out;
}

std::optional<Packet> decode_ethernet(std::span<const uint8_t> b) {
 if(b.size()<14) return std::nullopt;
 uint16_t type=be16(b,12);
 size_t o=14;uint8_t depth=0;uint16_t vlan=0;
 // 802.1Q (0x8100), 802.1ad (0x88A8) and legacy QinQ (0x9100) tags; cap stacking depth.
 while((type==0x8100 || type==0x88A8 || type==0x9100) && depth<4) {
  if(b.size()<o+4) return std::nullopt;
  if(depth==0) vlan=be16(b,o)&0x0fff;
  type=be16(b,o+2);o+=4;++depth;
 }
 return decode_ethertype(b,type,o,depth,vlan);
}

std::optional<Packet> decode_frame(uint32_t linktype, std::span<const uint8_t> b) {
 switch(linktype) {
 case LINKTYPE_ETHERNET:return decode_ethernet(b);
 case LINKTYPE_RAW:return decode_ip_by_version(b,0);
 case LINKTYPE_IPV4:return decode_ipv4(b,0);
 case LINKTYPE_IPV6:return decode_ipv6(b,0);
 case LINKTYPE_NULL:
 case LINKTYPE_LOOP:
  // Address family is host-order (NULL) or network-order (LOOP); the IP
  // version nibble is authoritative either way, and AF values differ per OS.
  return decode_ip_by_version(b,4);
 case LINKTYPE_LINUX_SLL:
  if(b.size()<16) return std::nullopt;
  return decode_ethertype(b,be16(b,14),16,0,0);
 default:return std::nullopt;
 }
}
}
