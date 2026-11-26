#pragma once
#include "netscope/pcap.hpp"
#include <cstdint>
#include <fstream>
#include <functional>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>
namespace netscope {
struct PacketIndexEntry { uint64_t data_offset=0, timestamp_us=0; uint32_t captured_length=0, original_length=0; };
class IndexedPcap {
public:
 explicit IndexedPcap(const std::string& path);
 const std::vector<PacketIndexEntry>& entries() const noexcept {return entries_;}
 const std::string& path() const noexcept {return path_;}
 std::vector<uint8_t> read_packet(size_t index) const;
private:
 std::string path_;
 std::vector<PacketIndexEntry> entries_;
};
class PacketCache {
public:
 explicit PacketCache(size_t budget_bytes=64ull*1024*1024):budget_(budget_bytes){}
 const std::vector<uint8_t>& get(const IndexedPcap& pcap,size_t index);
 void clear() noexcept;
 size_t bytes_used() const noexcept {return used_;}
 size_t entries() const noexcept {return lookup_.size();}
 size_t budget() const noexcept {return budget_;}
private:
 struct Item {size_t index;std::vector<uint8_t> bytes;};
 size_t budget_,used_=0;
 std::list<Item> lru_;
 std::unordered_map<size_t,std::list<Item>::iterator> lookup_;
 std::vector<uint8_t> oversized_; // one selected oversized packet, never added to cache
};
}
