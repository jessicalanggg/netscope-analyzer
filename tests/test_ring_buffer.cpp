#include "netscope/ring_buffer.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
using netscope::PacketRing;
int main() {
 {
  // Single-threaded: fill, reject when full, drain, wrap around many times.
  PacketRing ring(4096);
  std::vector<uint8_t> pkt(1000,7);
  int pushed=0;
  while(ring.try_push(pushed,pkt.data(),1000,1500)) ++pushed;
  assert(pushed==4);   // 4 * align(24+1000)=4096 bytes
  assert(!ring.try_push(0,pkt.data(),1000,1000));
  assert(!ring.try_push(0,pkt.data(),3000,3000)); // larger than half the ring: always rejected
  int seen=0;
  ring.drain([&](const PacketRing::Header& h,std::span<const uint8_t> d){
   assert(h.timestamp_us==uint64_t(seen) && h.captured_length==1000 && h.original_length==1500 && d.size()==1000 && d[999]==7);
   ++seen;
  });
  assert(seen==4 && ring.used()==0);
  uint64_t next_push=0,next_pop=0;
  for(int round=0;round<10000;++round) {
   const uint32_t len=uint32_t((round*37)%700);
   std::vector<uint8_t> v(len,uint8_t(round));
   if(ring.try_push(next_push,v.data(),len,len)) ++next_push;
   if(round%3==0) ring.drain([&](const PacketRing::Header& h,std::span<const uint8_t> d){
    assert(h.timestamp_us==next_pop++);
    for(uint8_t x:d) assert(x==d[0]);
   });
  }
  ring.drain([&](const PacketRing::Header& h,std::span<const uint8_t>){assert(h.timestamp_us==next_pop++);});
  assert(next_pop==next_push && next_push>9000);
 }
 {
  // Two threads: producer never blocks; every accepted record arrives intact and in order.
  PacketRing ring(1<<16);
  constexpr uint64_t N=500000;
  std::atomic<bool> done{false};
  uint64_t accepted=0;
  std::thread producer([&]{
   std::vector<uint8_t> buf(1600);
   for(uint64_t i=0;i<N;++i) {
    const uint32_t len=uint32_t(40+(i*7919)%1500);
    for(uint32_t k=0;k<len;k+=97) buf[k]=uint8_t(i+k);
    buf[len-1]=uint8_t(i);
    if(ring.try_push(i,buf.data(),len,len)) ++accepted;
   }
   done=true;
  });
  uint64_t received=0,last=0;bool first=true;
  auto check=[&](const PacketRing::Header& h,std::span<const uint8_t> d){
   assert(first || h.timestamp_us>last);
   first=false;last=h.timestamp_us;
   const uint64_t i=h.timestamp_us;
   assert(d.size()==40+(i*7919)%1500);
   for(uint32_t k=0;k+1<d.size();k+=97) assert(d[k]==uint8_t(i+k));
   assert(d.back()==uint8_t(i));
   ++received;
  };
  while(!done.load()) ring.drain(check);
  producer.join();
  ring.drain(check);
  assert(received==accepted && accepted>0);
  std::cout<<"Ring buffer: "<<accepted<<"/"<<N<<" records accepted under contention\n";
 }
 std::cout<<"Ring buffer tests passed\n";
}
