#include "netscope/reassembly.hpp"
#include "packet_builder.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <string>
using namespace testpkt;
namespace {
struct Harness {
 std::map<std::pair<uint64_t,int>,std::string> data;
 netscope::TcpReassembler r{[this](uint64_t s,int d,std::span<const uint8_t> bytes){data[{s,d}].append(bytes.begin(),bytes.end());}};
 uint64_t ts=0;
 void send(bool client,uint32_t seq,uint32_t ack,uint8_t flags,const std::string& payload={},uint16_t cport=50000) {
  auto l4=client?tcp(cport,80,seq,ack,flags,payload):tcp(80,cport,seq,ack,flags,payload);
  auto frame=cat(ethernet(0x0800),client?ipv4({10,0,0,1},{10,0,0,2},6,l4):ipv4({10,0,0,2},{10,0,0,1},6,l4));
  auto p=netscope::decode_ethernet(frame);
  assert(p);
  r.observe(*p,frame,++ts);
 }
};
constexpr uint8_t SYN=0x02,ACK=0x10,FIN=0x01,RST=0x04,PSH=0x08;
}
int main() {
 {
  // In-order handshake + data + teardown, with an ISN that wraps past 2^32.
  Harness h;const uint32_t c=0xfffffff0u, s=1000;
  h.send(true,c,0,SYN);
  h.send(false,s,c+1,SYN|ACK);
  h.send(true,c+1,s+1,ACK);
  h.send(true,c+1,s+1,PSH|ACK,"GET / HTTP/1.1\r\n");   // crosses the wrap
  h.send(true,c+17,s+1,PSH|ACK,"Host: x\r\n\r\n");
  h.send(false,s+1,c+28,PSH|ACK,"HTTP/1.1 200 OK\r\n");
  h.send(true,c+28,s+18,FIN|ACK);
  h.send(false,s+18,c+29,FIN|ACK);
  h.r.finish();
  assert((h.data[{0,0}]=="GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
  assert((h.data[{0,1}]=="HTTP/1.1 200 OK\r\n"));
  const auto& st=h.r.streams();
  assert(st.size()==1 && st[0].port[0]==50000 && st[0].dir[0].syn && st[0].dir[0].fin && st[0].dir[1].fin);
  assert(st[0].dir[0].retransmitted_bytes==0 && st[0].dir[0].missing_bytes==0);
 }
 {
  // Out-of-order, duplicate and overlapping segments.
  Harness h;
  h.send(true,0,0,SYN);h.send(false,0,1,SYN|ACK);
  h.send(true,6,1,ACK,"world");       // early
  h.send(true,11,1,ACK,"!!");         // early
  h.send(true,6,1,ACK,"world");       // duplicate of a buffered segment
  h.send(true,1,1,ACK,"hello");       // fills the hole -> "helloworld!!"
  h.send(true,1,1,ACK,"hello");       // full retransmission
  h.send(true,9,1,ACK,"ld!!more");    // overlap: only "more" is new
  h.r.finish();
  assert((h.data[{0,0}]=="helloworld!!more"));
  const auto& d=h.r.streams()[0].dir[0];
  assert(d.out_of_order_segments==3);
  assert(d.retransmitted_bytes==5+5+4);
  assert(d.missing_bytes==0 && d.delivered_bytes==16);
  assert(h.r.buffered_bytes()==0);
 }
 {
  // Gap that is never filled: flushed at finish() and accounted as missing.
  Harness h;
  h.send(true,0,0,SYN);
  h.send(true,1,0,ACK,"abc");
  h.send(true,10,0,ACK,"xyz");  // bytes 4..9 never arrive
  h.r.finish();
  assert((h.data[{0,0}]=="abcxyz"));
  assert(h.r.streams()[0].dir[0].missing_bytes==6);
 }
 {
  // Midstream pickup (no SYN seen) still reassembles.
  Harness h;
  h.send(true,5000,0,ACK,"mid");
  h.send(true,5003,0,ACK,"stream");
  h.r.finish();
  assert((h.data[{0,0}]=="midstream"));
 }
 {
  // Port reuse: a new SYN after RST starts stream 1; other ports get their own stream.
  Harness h;
  h.send(true,0,0,SYN);h.send(true,1,0,ACK,"one");h.send(false,0,0,RST);
  h.send(true,100,0,SYN);h.send(true,101,0,ACK,"two");
  h.send(true,0,0,SYN,{},50001);
  h.r.finish();
  assert(h.r.streams().size()==3);
  assert((h.data[{0,0}]=="one" && h.data[{1,0}]=="two"));
  assert(h.r.streams()[0].dir[1].rst && h.r.streams()[2].port[0]==50001);
 }
 {
  // Memory bound: with a tiny buffer the oldest hole is abandoned.
  std::string got;
  netscope::TcpReassembler r([&](uint64_t,int,std::span<const uint8_t> b){got.append(b.begin(),b.end());},8);
  uint64_t ts=0;
  auto send=[&](uint32_t seq,const std::string& pl,uint8_t fl){
   auto frame=cat(ethernet(0x0800),ipv4({1,1,1,1},{2,2,2,2},6,tcp(1,2,seq,0,fl,pl)));
   auto p=netscope::decode_ethernet(frame);r.observe(*p,frame,++ts);
  };
  send(0,"",SYN);
  send(11,"12345",ACK);  // hole at 1..10, 5 buffered
  send(16,"6789",ACK);   // 9 buffered > 8 -> give up on hole
  assert(got=="123456789" && r.streams()[0].dir[0].missing_bytes==10 && r.buffered_bytes()==0);
 }
 std::cout<<"TCP reassembly tests passed\n";
}
