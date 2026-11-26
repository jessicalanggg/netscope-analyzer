#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace netscope {
// Link-layer types (pcap LINKTYPE_* values) understood by decode_frame.
enum : uint32_t {
 LINKTYPE_NULL=0,        // BSD loopback: 4-byte host-order address family
 LINKTYPE_ETHERNET=1,
 LINKTYPE_RAW=101,       // raw IPv4/IPv6, version taken from the first nibble
 LINKTYPE_LOOP=108,      // OpenBSD loopback: 4-byte network-order address family
 LINKTYPE_LINUX_SLL=113, // Linux "any" cooked capture
 LINKTYPE_IPV4=228,
 LINKTYPE_IPV6=229,
};
struct Packet {
 std::string source_ip, destination_ip, protocol;
 uint16_t source_port=0, destination_port=0;
 uint8_t tcp_flags=0, icmp_type=0, icmp_code=0;
 uint8_t ip_version=0;          // 4 or 6
 uint8_t ipv4_ttl=0;            // IPv4 TTL or IPv6 hop limit
 uint8_t ipv4_header_length=0;  // IPv4 header, or IPv6 base + extension headers
 uint8_t tcp_header_length=0;
 uint8_t vlan_depth=0;          // number of 802.1Q/802.1ad tags
 uint16_t vlan_id=0;            // outermost VLAN ID when vlan_depth>0
 uint32_t tcp_sequence=0, tcp_acknowledgment=0;
 uint16_t tcp_window=0;
 size_t frame_length=0;
 // Transport payload location inside the frame. Bounded by the IP length field,
 // so Ethernet padding is never counted as payload.
 size_t payload_offset=0, payload_length=0;
};
std::optional<Packet> decode_ethernet(std::span<const uint8_t> bytes);
std::optional<Packet> decode_frame(uint32_t linktype, std::span<const uint8_t> bytes);
std::string format_ipv6(const uint8_t* address16);
}
