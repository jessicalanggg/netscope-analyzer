#include "netscope/parser.hpp"
#include "packet_builder.hpp"
#include <cassert>
#include <iostream>
using namespace testpkt;
using netscope::decode_ethernet;
using netscope::decode_frame;
int main() {
 // RFC 5952 formatting.
 assert(netscope::format_ipv6(v6({0,0,0,0,0,0,0,1}).data())=="::1");
 assert(netscope::format_ipv6(v6({0,0,0,0,0,0,0,0}).data())=="::");
 assert(netscope::format_ipv6(v6({0x2001,0xdb8,0,0,0,0,0,1}).data())=="2001:db8::1");
 assert(netscope::format_ipv6(v6({0xfe80,0,0,0,0,0,0,0}).data())=="fe80::");
 assert(netscope::format_ipv6(v6({0x2001,0xdb8,0,1,1,1,1,1}).data())=="2001:db8:0:1:1:1:1:1");
 assert(netscope::format_ipv6(v6({0x2001,0,0,1,0,0,0,1}).data())=="2001:0:0:1::1");
 assert(netscope::format_ipv6(v6({0,0,0,0,0,0xffff,0x0102,0x0304}).data())=="::ffff:1.2.3.4");

 const auto a=v6({0x2001,0xdb8,0,0,0,0,0,0x10}), b=v6({0x2001,0xdb8,0,0,0,0,0,0x20});
 // IPv6 + UDP
 auto f=cat(ethernet(0x86DD),ipv6(a,b,17,{},udp(5353,53,"query")));
 auto p=decode_ethernet(f);
 assert(p && p->ip_version==6 && p->protocol=="UDP" && p->source_ip=="2001:db8::10" && p->destination_ip=="2001:db8::20");
 assert(p->source_port==5353 && p->destination_port==53 && p->payload_length==5 && p->ipv4_ttl==55);
 for(size_t n=0;n<f.size();++n) assert(!decode_ethernet(std::span(f.data(),n)));

 // IPv6 + hop-by-hop (8 bytes) + destination options (16 bytes) + TCP
 Bytes ext={60,0, 1,4,0,0,0,0,   6,1, 1,12,0,0,0,0,0,0,0,0,0,0,0,0};
 f=cat(ethernet(0x86DD),ipv6(a,b,0,ext,tcp(40000,443,1000,0,0x02)));
 p=decode_ethernet(f);
 assert(p && p->protocol=="TCP" && p->destination_port==443 && p->tcp_flags==0x02 && p->ipv4_header_length==40+24);
 for(size_t n=0;n<f.size();++n) assert(!decode_ethernet(std::span(f.data(),n)));
 // Extension header claiming more length than present is rejected.
 auto bad=f;bad[14+40+1]=200;assert(!decode_ethernet(bad));

 // Non-first IPv6 fragment carries no transport header.
 Bytes frag={17,0,0,0x08,0,0,0,1}; // offset 1 (8 bytes)
 f=cat(ethernet(0x86DD),ipv6(a,b,44,frag,Bytes(16,0xaa)));
 p=decode_ethernet(f);
 assert(p && p->protocol=="IPv6-fragment");
 // First fragment (offset 0) is decoded normally.
 Bytes first={17,0,0,0x01,0,0,0,1};
 f=cat(ethernet(0x86DD),ipv6(a,b,44,first,udp(1,2,"x")));
 p=decode_ethernet(f);
 assert(p && p->protocol=="UDP" && p->destination_port==2);

 // ICMPv6
 Bytes icmp6={128,0,0,0,0,1,0,1};
 f=cat(ethernet(0x86DD),ipv6(a,b,58,{},icmp6));
 p=decode_ethernet(f);
 assert(p && p->protocol=="ICMPv6" && p->icmp_type==128);

 // 802.1Q VLAN and QinQ, IPv4 and IPv6 inside.
 f=cat(ethernet(0x0800,{0x2064}),ipv4({10,0,0,1},{10,0,0,2},6,tcp(1234,80,1,0,0x02)));
 p=decode_ethernet(f);
 assert(p && p->vlan_depth==1 && p->vlan_id==100 && p->protocol=="TCP" && p->destination_port==80);
 for(size_t n=0;n<f.size();++n) assert(!decode_ethernet(std::span(f.data(),n)));
 f=cat(ethernet(0x86DD,{0x000a,0x0014}),ipv6(a,b,17,{},udp(1,2)));
 p=decode_ethernet(f);
 assert(p && p->vlan_depth==2 && p->vlan_id==10 && p->ip_version==6);

 // Ethernet padding must not be counted as payload.
 f=cat(ethernet(0x0800),ipv4({10,0,0,1},{10,0,0,2},6,tcp(1,2,1,0,0x18,"hi")));
 f.resize(60,0);
 p=decode_ethernet(f);
 assert(p && p->payload_length==2 && p->frame_length==60);

 // Other link types.
 auto raw4=ipv4({192,168,0,1},{192,168,0,2},17,udp(1,2,"x"));
 p=decode_frame(netscope::LINKTYPE_RAW,raw4);assert(p && p->ip_version==4 && p->protocol=="UDP");
 auto raw6=ipv6(a,b,17,{},udp(1,2,"x"));
 p=decode_frame(netscope::LINKTYPE_RAW,raw6);assert(p && p->ip_version==6);
 p=decode_frame(netscope::LINKTYPE_IPV6,raw6);assert(p && p->ip_version==6);
 auto loop=cat(Bytes{2,0,0,0},raw4);   // BSD loopback AF_INET, host order
 p=decode_frame(netscope::LINKTYPE_NULL,loop);assert(p && p->source_ip=="192.168.0.1");
 Bytes sll(14,0);put16(sll,0x86DD);
 p=decode_frame(netscope::LINKTYPE_LINUX_SLL,cat(sll,raw6));assert(p && p->ip_version==6);
 assert(!decode_frame(9999,raw4));
 std::cout<<"IPv6 / VLAN / link-type tests passed\n";
}
