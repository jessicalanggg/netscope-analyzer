#pragma once
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
namespace netscope {
struct PcapRecord {
 std::vector<uint8_t> bytes;
 uint64_t timestamp_us=0;
 uint32_t original_length=0;
 uint32_t linktype=1;
};
// Location of one packet's bytes inside the capture file.
struct RecordInfo {
 uint64_t data_offset=0, timestamp_us=0;
 uint32_t captured_length=0, original_length=0, linktype=1;
};
// Streaming reader for classic libpcap (µs/ns, either byte order) and pcapng
// (multiple sections, multiple interfaces, EPB/SPB/legacy PB, if_tsresol/if_tsoffset).
class CaptureReader {
public:
 enum class Format { Pcap, PcapNg };
 explicit CaptureReader(const std::string& path);
 ~CaptureReader();
 CaptureReader(const CaptureReader&)=delete;
 CaptureReader& operator=(const CaptureReader&)=delete;
 // Returns false at a clean end of file. When `bytes` is null the packet data
 // is skipped with a seek; otherwise it is read into *bytes (resized).
 bool next(RecordInfo& info, std::vector<uint8_t>* bytes);
 Format format() const noexcept;
 uint64_t file_size() const noexcept;
private:
 struct Impl;
 std::unique_ptr<Impl> impl_;
};
using RecordCallback=std::function<void(const PcapRecord&)>;
void read_pcap_records(const std::string& path, const RecordCallback& callback);
using PacketCallback=std::function<void(const std::vector<uint8_t>&)>;
void read_pcap(const std::string& path, const PacketCallback& callback);

// Minimal classic-pcap (microsecond) writer, used by live capture and tests.
class PcapWriter {
public:
 PcapWriter(const std::string& path, uint32_t linktype, uint32_t snaplen=262144);
 void write(uint64_t timestamp_us, const uint8_t* data, uint32_t captured_length, uint32_t original_length);
 void flush();
private:
 std::ofstream out_;
};
}
