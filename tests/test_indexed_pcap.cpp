#include "netscope/indexed_pcap.hpp"
#include "netscope/pcap.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
int main(int argc,char** argv) {
 assert(argc==2);
 netscope::IndexedPcap index(argv[1]);
 assert(index.entries().size()==240);
 size_t i=0;
 netscope::read_pcap_records(argv[1],[&](const netscope::PcapRecord& record){
  assert(index.entries()[i].captured_length==record.bytes.size());
  assert(index.entries()[i].timestamp_us==record.timestamp_us);
  assert(index.read_packet(i)==record.bytes);
  ++i;
 });
 assert(i==240);
 netscope::PacketCache cache(120);
 auto first=cache.get(index,0);
 assert(first==index.read_packet(0));
 assert(cache.bytes_used()<=120);
 for(size_t n=0;n<40;++n) {cache.get(index,n);assert(cache.bytes_used()<=120);}
 cache.get(index,0);
 assert(cache.bytes_used()<=120);
 netscope::PacketCache zero(0);
 assert(zero.get(index,0)==index.read_packet(0));
 assert(zero.bytes_used()==0);
 bool caught=false;
 try {index.read_packet(240);}catch(const std::out_of_range&) {caught=true;}
 assert(caught);
 const auto bad=std::filesystem::temp_directory_path()/"netscope_v08_truncated.pcap";
 {std::ofstream f(bad,std::ios::binary);f<<"bad";}
 caught=false;
 try {netscope::IndexedPcap malformed(bad.string());}catch(const std::runtime_error&) {caught=true;}
 std::filesystem::remove(bad);
 assert(caught);
 std::cout<<"Indexed PCAP and cache tests passed\n";
}
