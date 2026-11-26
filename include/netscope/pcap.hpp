#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
namespace netscope {
struct PcapRecord { std::vector<uint8_t> bytes; uint64_t timestamp_us=0; uint32_t original_length=0; };
using RecordCallback=std::function<void(const PcapRecord&)>;
void read_pcap_records(const std::string& path, const RecordCallback& callback);
using PacketCallback=std::function<void(const std::vector<uint8_t>&)>;
void read_pcap(const std::string& path, const PacketCallback& callback);
}
