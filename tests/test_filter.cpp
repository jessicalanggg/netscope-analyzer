#include "netscope/filter.hpp"
#include <cassert>
#include <iostream>
int main() {
 netscope::Packet p; p.source_ip="192.168.1.10";p.destination_ip="8.8.8.8";
 p.protocol="UDP";p.source_port=12345;p.destination_port=53;
 auto match=[&](const char* expr){auto f=netscope::parse_filter(expr);assert(f.kind!=netscope::PacketFilter::Kind::Invalid);return f.matches(&p,1,42);};
 assert(match("udp"));assert(!match("tcp"));
 assert(match("ip.src == 192.168.1.10"));assert(!match("ip.dst == 192.168.1.10"));
 assert(match("udp.port == 53"));assert(match("port == 12345"));
 assert(!match("tcp.port == 53"));assert(match("frame.number == 1"));
 assert(!match("frame.number == 2"));assert(match("8.8.8.8"));
 assert(match("UDP"));assert(match("42"));
 assert(netscope::parse_filter("tcp.port == abc").kind==netscope::PacketFilter::Kind::Invalid);
 assert(netscope::parse_filter("ip.foo == 2").kind==netscope::PacketFilter::Kind::Invalid);
 assert(netscope::parse_filter("udp.port == 65536").kind==netscope::PacketFilter::Kind::Invalid);
 assert(netscope::parse_filter(" ").matches(nullptr,1,1));
 std::cout<<"Filter tests passed\n";
}
