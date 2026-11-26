#include "netscope/indexed_pcap.hpp"
#include "netscope/parser.hpp"
#include "netscope/pcap.hpp"
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
using Bytes=std::vector<uint8_t>;
struct Ng {
 Bytes out; bool little=true;
 void u16(uint16_t v) {if(little){out.push_back(uint8_t(v));out.push_back(uint8_t(v>>8));}else{out.push_back(uint8_t(v>>8));out.push_back(uint8_t(v));}}
 void u32(uint32_t v) {if(little){u16(uint16_t(v));u16(uint16_t(v>>16));}else{u16(uint16_t(v>>16));u16(uint16_t(v));}}
 void block(uint32_t type,const Bytes& body) {
  Bytes padded=body;while(padded.size()%4) padded.push_back(0);
  const uint32_t len=uint32_t(12+padded.size());
  u32(type);u32(len);out.insert(out.end(),padded.begin(),padded.end());u32(len);
 }
 Bytes body() {Bytes b;std::swap(b,out);return b;}
 void shb() {Ng t;t.little=little;t.u32(0x1A2B3C4D);t.u16(1);t.u16(0);t.u32(0xffffffff);t.u32(0xffffffff);block(0x0A0D0D0A,t.out);}
 void idb(uint16_t linktype,int tsresol=-1,uint32_t snaplen=0) {
  Ng t;t.little=little;t.u16(linktype);t.u16(0);t.u32(snaplen);
  if(tsresol>=0) {t.u16(9);t.u16(1);t.out.push_back(uint8_t(tsresol));t.out.push_back(0);t.out.push_back(0);t.out.push_back(0);}
  t.u16(0);t.u16(0);
  block(1,t.out);
 }
 void epb(uint32_t iface,uint64_t ts,const Bytes& data,uint32_t orig=0) {
  Ng t;t.little=little;t.u32(iface);t.u32(uint32_t(ts>>32));t.u32(uint32_t(ts));t.u32(uint32_t(data.size()));t.u32(orig?orig:uint32_t(data.size()));
  t.out.insert(t.out.end(),data.begin(),data.end());
  while(t.out.size()%4) t.out.push_back(0);
  t.u16(1);t.u16(3);t.out.insert(t.out.end(),{'a','b','c',0});t.u16(0);t.u16(0); // opt_comment + end
  block(6,t.out);
 }
 void spb(const Bytes& data) {Ng t;t.little=little;t.u32(uint32_t(data.size()));t.out.insert(t.out.end(),data.begin(),data.end());block(3,t.out);}
};
std::filesystem::path write_temp(const std::string& name,const Bytes& b) {
 auto p=std::filesystem::temp_directory_path()/name;
 std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),std::streamsize(b.size()));
 return p;
}
bool throws(const std::filesystem::path& p) {
 try {netscope::read_pcap_records(p.string(),[](const netscope::PcapRecord&){});}catch(const std::runtime_error&) {return true;}
 return false;
}
}
int main(int argc,char** argv) {
 assert(argc==2);
 // 1. Re-encode showcase.pcap as pcapng (nanosecond resolution) and compare record-for-record.
 std::vector<netscope::PcapRecord> classic;
 netscope::read_pcap_records(argv[1],[&](const netscope::PcapRecord& r){classic.push_back(r);});
 assert(classic.size()==240);
 Ng ng;ng.shb();ng.idb(1,9);
 ng.block(4,Bytes(8,0)); // name resolution block: must be skipped
 for(const auto& r:classic) ng.epb(0,r.timestamp_us*1000,r.bytes,r.original_length);
 ng.block(5,Bytes(12,0)); // interface statistics block: skipped
 auto path=write_temp("netscope_test.pcapng",ng.out);
 size_t i=0;
 netscope::read_pcap_records(path.string(),[&](const netscope::PcapRecord& r){
  assert(i<classic.size());
  assert(r.bytes==classic[i].bytes && r.timestamp_us==classic[i].timestamp_us && r.original_length==classic[i].original_length && r.linktype==1);
  ++i;
 });
 assert(i==classic.size());
 {
  netscope::CaptureReader reader(path.string());
  assert(reader.format()==netscope::CaptureReader::Format::PcapNg);
 }
 // Indexed access over pcapng returns identical bytes.
 netscope::IndexedPcap index(path.string());
 assert(index.entries().size()==classic.size());
 for(size_t k=0;k<classic.size();k+=17) assert(index.read_packet(k)==classic[k].bytes && index.entries()[k].timestamp_us==classic[k].timestamp_us);

 // 2. Two sections: little-endian then big-endian; multiple interfaces and link types; SPB; binary tsresol.
 Ng mix;
 mix.shb();mix.idb(1);mix.idb(101,0x80|10);       // iface0 Ethernet µs, iface1 raw IP 2^-10 s
 const Bytes eth=classic[0].bytes;
 Bytes raw(eth.begin()+14,eth.end());
 mix.epb(0,1'700'000'000'000'000ull,eth);
 mix.epb(1,(uint64_t(5)<<10)|512,raw);            // 5.5 s
 Ng be;be.little=false;be.shb();be.idb(1,3,64);   // milliseconds, snaplen 64
 be.epb(0,1234,eth);
 be.spb(eth);
 mix.out.insert(mix.out.end(),be.out.begin(),be.out.end());
 path=write_temp("netscope_test_mixed.pcapng",mix.out);
 std::vector<netscope::PcapRecord> got;
 netscope::read_pcap_records(path.string(),[&](const netscope::PcapRecord& r){got.push_back(r);});
 assert(got.size()==4);
 assert(got[0].timestamp_us==1'700'000'000'000'000ull && got[0].linktype==1);
 assert(got[1].timestamp_us==5'500'000ull && got[1].linktype==101 && got[1].bytes==raw);
 assert(netscope::decode_frame(got[1].linktype,got[1].bytes));
 assert(got[2].timestamp_us==1'234'000ull && got[2].bytes==eth);
 assert(got[3].bytes.size()==std::min<size_t>(64,eth.size()) && got[3].original_length==eth.size());

 // 3. Malformed inputs are rejected, not misread.
 auto broken=ng.out;broken[broken.size()-1]^=0xff;                 // trailer length mismatch
 assert(throws(write_temp("netscope_bad1.pcapng",broken)));
 broken=ng.out;broken.resize(broken.size()-6);                     // truncated block
 assert(throws(write_temp("netscope_bad2.pcapng",broken)));
 Ng noif;noif.shb();noif.epb(0,0,eth);                              // packet before any interface
 assert(throws(write_temp("netscope_bad3.pcapng",noif.out)));
 broken=ng.out;broken[8]=0;broken[9]=0;broken[10]=0;broken[11]=0;   // bad byte-order magic
 assert(throws(write_temp("netscope_bad4.pcapng",broken)));
 for(const auto* n:{"netscope_test.pcapng","netscope_test_mixed.pcapng","netscope_bad1.pcapng","netscope_bad2.pcapng","netscope_bad3.pcapng","netscope_bad4.pcapng"})
  std::filesystem::remove(std::filesystem::temp_directory_path()/n);
 std::cout<<"pcapng tests passed\n";
}
