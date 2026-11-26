#include "netscope/pcap.hpp"
#include <array>
#include <limits>
#include <fstream>
#include <stdexcept>
namespace netscope {
void read_pcap_records(const std::string& path, const RecordCallback& callback) {
 std::ifstream f(path,std::ios::binary);
 if(!f) throw std::runtime_error("Cannot open PCAP: "+path);
 std::array<uint8_t,24> h{};
 if(!f.read(reinterpret_cast<char*>(h.data()),h.size())) throw std::runtime_error("Truncated PCAP header");
 bool little;
 if(h[0]==0xd4 && h[1]==0xc3 && h[2]==0xb2 && h[3]==0xa1) little=true;
 else if(h[0]==0xa1 && h[1]==0xb2 && h[2]==0xc3 && h[3]==0xd4) little=false;
 else if(h[0]==0x4d && h[1]==0x3c && h[2]==0xb2 && h[3]==0xa1) little=true;
 else if(h[0]==0xa1 && h[1]==0xb2 && h[2]==0x3c && h[3]==0x4d) little=false;
 else throw std::runtime_error("Unsupported PCAP magic (pcapng is not supported)");
 auto u32=[little](const uint8_t* p)->uint32_t {
  if(little) return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
  return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];
 };
 if(u32(h.data()+20)!=1) throw std::runtime_error("Only Ethernet (DLT_EN10MB) captures are supported");
 const bool nanos=(h[0]==0x4d || h[2]==0x3c);
 constexpr uint32_t max_record=16*1024*1024;
 std::array<uint8_t,16> record{};
 while(true) {
  f.read(reinterpret_cast<char*>(record.data()),record.size());
  if(f.gcount()==0 && f.eof()) break;
  if(f.gcount()!=static_cast<std::streamsize>(record.size())) throw std::runtime_error("Truncated record header");
  uint32_t n=u32(record.data()+8), original=u32(record.data()+12);
  if(n>max_record || n>original) throw std::runtime_error("Invalid captured packet length");
  std::vector<uint8_t> bytes(n);
  if(!f.read(reinterpret_cast<char*>(bytes.data()),n)) throw std::runtime_error("Truncated packet data");
  const uint64_t sec=u32(record.data());
  const uint32_t fraction=u32(record.data()+4);
  if(fraction >= (nanos?1000000000u:1000000u)) throw std::runtime_error("Invalid PCAP timestamp fraction");
  callback(PcapRecord{std::move(bytes),sec*1000000ull+(nanos?fraction/1000u:fraction),original});
 }
}
void read_pcap(const std::string& path, const PacketCallback& callback) {
 read_pcap_records(path,[&](const PcapRecord& r){callback(r.bytes);});
}
}
