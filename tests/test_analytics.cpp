#include "netscope/analytics.hpp"
#include "netscope/parser.hpp"
#include "netscope/pcap.hpp"
#include <cassert>
#include <iostream>
int main(int argc,char** argv) {
 netscope::TrafficTimeline timeline;
 timeline.observe(1700000000100000ull,42);
 timeline.observe(1700000000900000ull,60);
 timeline.observe(1700000001000000ull,100);
 auto b=timeline.buckets();
 assert(b.size()==2 && b[0].packets==2 && b[0].bytes==102 && b[1].bytes==100);
 assert(netscope::tcp_flag_names(0x18)=="PSH | ACK");
 assert(netscope::tcp_flag_names(0)=="None");
 assert(netscope::csv_escape("a,b")=="\"a,b\"");
 if(argc>1) {
  uint64_t count=0; netscope::TrafficTimeline capture;
  netscope::read_pcap_records(argv[1],[&](const netscope::PcapRecord& r){++count;capture.observe(r.timestamp_us,r.bytes.size());});
  assert(count==240 && capture.buckets().size()==3);
 }
 std::cout<<"Analytics tests passed\n";
}
