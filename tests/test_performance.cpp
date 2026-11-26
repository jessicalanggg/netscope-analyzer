#include "netscope/indexed_pcap.hpp"
#include "netscope/pcap.hpp"
#include <cassert>
#include <iostream>
int main(int argc,char** argv) {
 assert(argc==2);
 netscope::IndexedPcap idx(argv[1]);
 size_t i=0;
 netscope::read_pcap_records(argv[1],[&](const netscope::PcapRecord& record){
  assert(i<idx.entries().size());
  const auto& e=idx.entries()[i];
  assert(e.timestamp_us==record.timestamp_us);
  assert(e.captured_length==record.bytes.size());
  if(i%17==0) assert(idx.read_packet(i)==record.bytes);
  ++i;
 });
 assert(i==idx.entries().size());
 std::cout<<"Sequential scan and index agree on "<<i<<" packets\n";
}
