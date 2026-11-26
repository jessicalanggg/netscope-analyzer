#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace netscope {
struct Packet {
 std::string source_ip, destination_ip, protocol;
 uint16_t source_port=0, destination_port=0;
 uint8_t tcp_flags=0, icmp_type=0, icmp_code=0;
 uint8_t ipv4_ttl=0, ipv4_header_length=0, tcp_header_length=0;
 uint32_t tcp_sequence=0, tcp_acknowledgment=0;
 uint16_t tcp_window=0;
 size_t frame_length=0;
};
std::optional<Packet> decode_ethernet(std::span<const uint8_t> bytes);
}
