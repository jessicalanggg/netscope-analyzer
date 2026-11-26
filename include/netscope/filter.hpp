#pragma once
#include "netscope/parser.hpp"
#include <cstddef>
#include <string>
#include <string_view>
namespace netscope {
// Valid expressions: tcp, udp, icmp, ip.src == X, ip.dst == X,
// tcp.port == N, udp.port == N, port == N, frame.number == N.
// Plain text performs a case-insensitive search across displayed packet fields.
struct PacketFilter {
 enum class Kind { All, Text, Protocol, SourceIP, DestinationIP, Port, TcpPort, UdpPort, Number, Invalid };
 Kind kind=Kind::All;
 std::string value;
 unsigned number=0;
 std::string error;
 bool matches(const Packet* packet, size_t frameNumber, size_t frameLength) const;
};
PacketFilter parse_filter(std::string_view expression);
}
