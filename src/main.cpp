#include "netscope/analyzer.hpp"
#include "netscope/indexed_pcap.hpp"
#include "netscope/live_capture.hpp"
#include "netscope/pcap.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
constexpr const char* kVersion="NetScope v1.1";
void usage() {
 std::cout<<kVersion<<"\n"
 "Usage:\n"
 "  netscope analyze <capture>                 summary: protocols, talkers, flows, conversations, TCP streams\n"
 "  netscope benchmark <capture> [repeats]     time the full analysis pipeline (median of repeats)\n"
 "  netscope benchmark-index <capture> [n]     time packet-offset index construction\n"
 "  netscope streams <capture>                 list reassembled TCP streams (TSV)\n"
 "  netscope follow <capture> <id[,id...]> [--raw]  print reassembled TCP streams (--raw: hex, same format as tshark)\n"
 "  netscope interfaces                        list live-capture interfaces\n"
 "  netscope capture <iface> [options]         live capture + analysis\n"
 "      -c N   stop after N packets     -d SEC  stop after SEC seconds     -f BPF  capture filter\n"
 "      -w F   also write packets to F  -p      promiscuous mode            -q      no per-second status\n"
 "      --ring MiB  user-space ring buffer size (default 64)\n"
 "Captures may be classic pcap or pcapng; Ethernet (incl. VLAN), raw IP, loopback and Linux SLL link types.\n";
}
std::string endpoint(const std::string& ip,uint16_t port) {
 return ip.find(':')!=std::string::npos?"["+ip+"]:"+std::to_string(port):ip+":"+std::to_string(port);
}
void run_file(netscope::Analyzer& analyzer,const std::string& path) {
 netscope::read_pcap_records(path,[&](const netscope::PcapRecord& r){analyzer.observe(r.linktype,r.bytes,r.timestamp_us);});
 analyzer.finish();
}
int analyze(const std::string& path) {
 netscope::Analyzer analyzer;
 run_file(analyzer,path);
 std::cout<<kVersion<<"\n";
 analyzer.print_summary(std::cout);
 return 0;
}
int benchmark(const std::string& path,int repeats) {
 std::vector<double> seconds;
 uint64_t frames=0,decoded=0,streams=0;
 for(int i=0;i<repeats;++i) {
  const auto start=std::chrono::steady_clock::now();
  netscope::Analyzer analyzer;
  run_file(analyzer,path);
  seconds.push_back(std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count());
  frames=analyzer.frames();decoded=analyzer.decoded();streams=analyzer.reassembler().streams().size();
 }
 std::sort(seconds.begin(),seconds.end());
 const double median=seconds[seconds.size()/2];
 const double mb=static_cast<double>(std::filesystem::file_size(path))/1e6;
 std::cout<<kVersion<<" benchmark (decode + flows + conversations + TCP reassembly)\nFrames: "<<frames<<"\nDecoded IP: "<<decoded
          <<"\nTCP streams: "<<streams<<"\nRuns: "<<repeats<<"\nMedian elapsed seconds: "<<std::fixed<<std::setprecision(6)<<median
          <<"\nFrames/sec: "<<std::setprecision(1)<<(median>0?frames/median:0)
          <<"\nMB/sec: "<<(median>0?mb/median:0)<<"\n";
 return 0;
}
int benchmark_index(const std::string& path,int repeats) {
 std::vector<double> measurements;
 size_t count=0,index_bytes=0;
 for(int run=0;run<repeats;++run) {
  const auto start=std::chrono::steady_clock::now();
  netscope::IndexedPcap index(path);
  const auto stop=std::chrono::steady_clock::now();
  count=index.entries().size();
  index_bytes=index.entries().capacity()*sizeof(netscope::PacketIndexEntry);
  measurements.push_back(std::chrono::duration<double>(stop-start).count());
 }
 std::sort(measurements.begin(),measurements.end());
 const double median=measurements[measurements.size()/2];
 std::cout<<kVersion<<" index benchmark\nFrames: "<<count<<"\nCapture bytes: "<<std::filesystem::file_size(path)
          <<"\nIndex capacity bytes (estimate): "<<index_bytes<<"\nRuns: "<<repeats
          <<"\nMedian index seconds: "<<std::fixed<<std::setprecision(6)<<median
          <<"\nMedian frames/sec: "<<std::setprecision(1)<<(median>0?count/median:0)<<"\n";
 return 0;
}
int streams(const std::string& path) {
 netscope::Analyzer analyzer;
 run_file(analyzer,path);
 std::cout<<"stream\tnode0\tnode1\tsegments\tbytes_0to1\tbytes_1to0\tretransmitted\tout_of_order\tmissing\n";
 for(const auto& s:analyzer.reassembler().streams()) {
  std::cout<<s.id<<'\t'<<endpoint(s.address[0],s.port[0])<<'\t'<<endpoint(s.address[1],s.port[1])<<'\t'
           <<s.dir[0].segments+s.dir[1].segments<<'\t'<<s.dir[0].delivered_bytes<<'\t'<<s.dir[1].delivered_bytes<<'\t'
           <<s.dir[0].retransmitted_bytes+s.dir[1].retransmitted_bytes<<'\t'
           <<s.dir[0].out_of_order_segments+s.dir[1].out_of_order_segments<<'\t'
           <<s.dir[0].missing_bytes+s.dir[1].missing_bytes<<'\n';
 }
 return 0;
}
// Follows one or more streams in a single pass. Output matches `tshark -q -z follow,tcp,raw,N`
// (one hex line per delivered chunk; node-1 lines are tab-prefixed) so results can be diffed.
int follow(const std::string& path,const std::vector<uint64_t>& ids,bool raw) {
 std::map<uint64_t,std::string> out;
 for(uint64_t id:ids) out[id];
 static const char* hex="0123456789abcdef";
 netscope::Analyzer analyzer(true,[&](uint64_t stream,int dir,std::span<const uint8_t> data){
  auto it=out.find(stream);
  if(it==out.end()) return;
  auto& o=it->second;
  if(raw) {
   if(dir==1) o+='\t';
   for(uint8_t b:data) {o+=hex[b>>4];o+=hex[b&15];}
   o+='\n';
  } else {
   o+=dir==0?">> ":"<< ";
   for(uint8_t b:data) o+=(b=='\n'||b=='\t'||(b>=32&&b<127))?static_cast<char>(b):'.';
   if(o.back()!='\n') o+='\n';
  }
 });
 run_file(analyzer,path);
 const auto& all=analyzer.reassembler().streams();
 for(uint64_t id:ids) {
  if(id>=all.size()) throw std::runtime_error("No TCP stream "+std::to_string(id)+" (capture has "+std::to_string(all.size())+")");
  const auto& s=all[id];
  std::cout<<"\n===================================================================\n"
           <<"Follow: tcp,"<<(raw?"raw":"ascii")<<"\nFilter: tcp.stream eq "<<id<<"\n"
           <<"Node 0: "<<endpoint(s.address[0],s.port[0])<<"\nNode 1: "<<endpoint(s.address[1],s.port[1])<<"\n"
           <<out[id]<<"===================================================================\n";
 }
 return 0;
}
std::vector<uint64_t> parse_ids(const std::string& list) {
 std::vector<uint64_t> ids;size_t start=0;
 while(start<=list.size()) {
  const size_t comma=list.find(',',start);
  ids.push_back(std::stoull(list.substr(start,comma-start)));
  if(comma==std::string::npos) break;
  start=comma+1;
 }
 return ids;
}
int capture(int argc,char** argv) {
 netscope::LiveOptions opt;
 opt.interface=argv[2];
 for(int i=3;i<argc;++i) {
  const std::string a=argv[i];
  auto value=[&]()->std::string {if(i+1>=argc) throw std::runtime_error("Missing value for "+a);return argv[++i];};
  if(a=="-c") opt.max_packets=std::stoull(value());
  else if(a=="-d") opt.duration_seconds=std::stod(value());
  else if(a=="-f") opt.bpf_filter=value();
  else if(a=="-w") opt.write_path=value();
  else if(a=="-p") opt.promiscuous=true;
  else if(a=="-q") opt.quiet=true;
  else if(a=="--ring") opt.ring_bytes=static_cast<size_t>(std::stoull(value()))*1024*1024;
  else throw std::runtime_error("Unknown capture option: "+a);
 }
 const auto stats=netscope::run_live_capture(opt,std::cout);
 return stats.ring_drops||stats.kernel_drops?3:0;
}
int repeats_arg(int argc,char** argv,int fallback) {
 if(argc<4) return fallback;
 const int n=std::stoi(argv[3]);
 if(n<1 || n>30) throw std::runtime_error("Repeats must be 1..30");
 return n;
}
}
int main(int argc,char** argv) {
 try {
  if(argc<2) {usage();return 1;}
  const std::string cmd=argv[1];
  if(cmd=="interfaces") {
   for(const auto& [name,desc]:netscope::list_interfaces()) std::cout<<name<<(desc.empty()?"":"\t"+desc)<<'\n';
   return 0;
  }
  if(argc<3) {usage();return 1;}
  if(cmd=="analyze") return analyze(argv[2]);
  if(cmd=="benchmark") return benchmark(argv[2],repeats_arg(argc,argv,1));
  if(cmd=="benchmark-index") return benchmark_index(argv[2],repeats_arg(argc,argv,3));
  if(cmd=="streams") return streams(argv[2]);
  if(cmd=="follow") {
   if(argc<4) {usage();return 1;}
   return follow(argv[2],parse_ids(argv[3]),argc>4 && std::strcmp(argv[4],"--raw")==0);
  }
  if(cmd=="capture") return capture(argc,argv);
  usage();return 1;
 } catch(const std::exception& e) {std::cerr<<"Error: "<<e.what()<<'\n';return 2;}
}
