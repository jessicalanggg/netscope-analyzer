#include "netscope/indexed_pcap.hpp"
#include <array>
#include <limits>
#include <stdexcept>
namespace netscope {
IndexedPcap::IndexedPcap(const std::string& path):path_(path) {
 CaptureReader reader(path);
 RecordInfo info;
 while(reader.next(info,nullptr))
  entries_.push_back({info.data_offset,info.timestamp_us,info.captured_length,info.original_length,info.linktype});
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
