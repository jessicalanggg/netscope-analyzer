#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
namespace netscope {
// Single-producer / single-consumer lock-free ring of variable-length packet
// records stored contiguously in one preallocated arena. The capture thread
// pushes; the analysis thread drains. When the consumer falls behind, pushes
// fail (and are counted as drops) instead of blocking the capture thread.
class PacketRing {
public:
 struct Header {uint32_t record_bytes, captured_length, original_length, reserved; uint64_t timestamp_us;};
 static constexpr size_t kAlign=8;
 static constexpr uint32_t kWrapMarker=0xffffffffu;

 explicit PacketRing(size_t capacity_bytes) {
  if(capacity_bytes<4096 || (capacity_bytes&(capacity_bytes-1))) throw std::invalid_argument("Ring capacity must be a power of two >= 4096");
  capacity_=capacity_bytes;mask_=capacity_bytes-1;
  data_=std::make_unique<uint8_t[]>(capacity_bytes);
 }
 size_t capacity() const noexcept {return capacity_;}
 size_t used() const noexcept {return static_cast<size_t>(head_.load(std::memory_order_acquire)-tail_.load(std::memory_order_acquire));}

 // Producer side. Returns false (record dropped) if there is not enough room.
 bool try_push(uint64_t timestamp_us,const uint8_t* data,uint32_t captured,uint32_t original) {
  const size_t need=align(sizeof(Header)+captured);
  if(need>capacity_/2) return false;
  const uint64_t head=head_.load(std::memory_order_relaxed);
  const size_t pos=static_cast<size_t>(head&mask_);
  const size_t contiguous=capacity_-pos;
  const size_t total=need<=contiguous?need:contiguous+need;
  if(capacity_-(head-cached_tail_)<total) {
   cached_tail_=tail_.load(std::memory_order_acquire);
   if(capacity_-(head-cached_tail_)<total) return false;
  }
  uint64_t write=head;
  if(need>contiguous) {
   std::memcpy(data_.get()+pos,&kWrapMarker,sizeof kWrapMarker);
   write+=contiguous;
  }
  uint8_t* dst=data_.get()+(write&mask_);
  const Header h{static_cast<uint32_t>(need),captured,original,0,timestamp_us};
  std::memcpy(dst,&h,sizeof h);
  if(captured) std::memcpy(dst+sizeof h,data,captured);
  head_.store(write+need,std::memory_order_release);
  return true;
 }

 // Consumer side. Calls f(const Header&, std::span<const uint8_t>) for up to
 // `max_records` records; returns how many were consumed.
 template<class F> size_t drain(F&& f,size_t max_records=SIZE_MAX) {
  uint64_t tail=tail_.load(std::memory_order_relaxed);
  const uint64_t head=head_.load(std::memory_order_acquire);
  size_t n=0;
  while(tail<head && n<max_records) {
   const size_t pos=static_cast<size_t>(tail&mask_);
   uint32_t first;std::memcpy(&first,data_.get()+pos,sizeof first);
   if(first==kWrapMarker) {tail+=capacity_-pos;continue;}
   Header h;std::memcpy(&h,data_.get()+pos,sizeof h);
   f(h,std::span<const uint8_t>(data_.get()+pos+sizeof h,h.captured_length));
   tail+=h.record_bytes;++n;
   tail_.store(tail,std::memory_order_release);
  }
  tail_.store(tail,std::memory_order_release);
  return n;
 }
private:
 static size_t align(size_t n) {return (n+kAlign-1)&~(kAlign-1);}
 size_t capacity_=0,mask_=0;
 std::unique_ptr<uint8_t[]> data_;
 alignas(64) std::atomic<uint64_t> head_{0};
 alignas(64) uint64_t cached_tail_=0;          // producer-private
 alignas(64) std::atomic<uint64_t> tail_{0};
};
}
