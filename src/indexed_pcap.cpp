#include "netscope/indexed_pcap.hpp"
#include <array>
#include <limits>
#include <stdexcept>
namespace netscope {
namespace {
uint32_t u32(const uint8_t* p,bool little) {
 if(little) return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
 return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]);
}
}
IndexedPcap::IndexedPcap(const std::string& path):path_(path) {
 std::ifstream f(path,std::ios::binary|std::ios::ate);
 if(!f) throw std::runtime_error("Cannot open PCAP: "+path);
 const auto end=f.tellg();
 if(end<24) throw std::runtime_error("Truncated PCAP header");
 const auto file_size=static_cast<uint64_t>(end);
 f.seekg(0);
 std::array<uint8_t,24> h{};
 if(!f.read(reinterpret_cast<char*>(h.data()),24)) throw std::runtime_error("Truncated PCAP header");
 bool little=false,nanos=false;
 if(h[0]==0xd4&&h[1]==0xc3&&h[2]==0xb2&&h[3]==0xa1) little=true;
 else if(h[0]==0xa1&&h[1]==0xb2&&h[2]==0xc3&&h[3]==0xd4) little=false;
 else if(h[0]==0x4d&&h[1]==0x3c&&h[2]==0xb2&&h[3]==0xa1) little=nanos=true;
 else if(h[0]==0xa1&&h[1]==0xb2&&h[2]==0x3c&&h[3]==0x4d) nanos=true;
 else throw std::runtime_error("Unsupported PCAP magic (pcapng is not supported)");
 if(u32(h.data()+20,little)!=1) throw std::runtime_error("Only Ethernet PCAP is supported");
 uint64_t pos=24;
 std::array<uint8_t,16> rec{};
 while(pos<file_size) {
  if(file_size-pos<16) throw std::runtime_error("Truncated record header");
  if(!f.read(reinterpret_cast<char*>(rec.data()),16)) throw std::runtime_error("Truncated record header");
  pos+=16;
  auto length=u32(rec.data()+8,little), original=u32(rec.data()+12,little);
  auto fraction=u32(rec.data()+4,little);
  if(length>16u*1024*1024 || length>original || length>file_size-pos) throw std::runtime_error("Invalid or truncated packet data");
  if(fraction >= (nanos?1000000000u:1000000u)) throw std::runtime_error("Invalid PCAP timestamp fraction");
  uint64_t timestamp=uint64_t(u32(rec.data(),little))*1000000ull+(nanos?fraction/1000u:fraction);
  entries_.push_back({pos,timestamp,length,original});
  pos+=length;
  f.seekg(static_cast<std::streamoff>(pos));
  if(!f) throw std::runtime_error("Invalid PCAP file offset");
 }
}
std::vector<uint8_t> IndexedPcap::read_packet(size_t index) const {
 if(index>=entries_.size()) throw std::out_of_range("Packet index out of range");
 const auto& e=entries_[index];
 std::ifstream f(path_,std::ios::binary);
 if(!f) throw std::runtime_error("Cannot reopen PCAP: "+path_);
 f.seekg(static_cast<std::streamoff>(e.data_offset));
 if(!f) throw std::runtime_error("Cannot seek to packet");
 std::vector<uint8_t> bytes(e.captured_length);
 if(e.captured_length && !f.read(reinterpret_cast<char*>(bytes.data()),e.captured_length)) throw std::runtime_error("PCAP changed or truncated after indexing");
 return bytes;
}
void PacketCache::clear() noexcept {lookup_.clear();lru_.clear();oversized_.clear();used_=0;}
const std::vector<uint8_t>& PacketCache::get(const IndexedPcap& pcap,size_t index) {
 auto found=lookup_.find(index);
 if(found!=lookup_.end()) {lru_.splice(lru_.begin(),lru_,found->second);return lru_.begin()->bytes;}
 auto bytes=pcap.read_packet(index);
 if(bytes.size()>budget_ || budget_==0) {oversized_=std::move(bytes);return oversized_;}
 while(used_+bytes.size()>budget_ && !lru_.empty()) {
  used_-=lru_.back().bytes.size();lookup_.erase(lru_.back().index);lru_.pop_back();
 }
 used_+=bytes.size();lru_.push_front({index,std::move(bytes)});lookup_[index]=lru_.begin();
 return lru_.begin()->bytes;
}
}
