#include "netscope/parser.hpp"
#include "netscope/pcap.hpp"
#include "netscope/flow.hpp"
#include "netscope/conversation.hpp"
#include "netscope/indexed_pcap.hpp"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <filesystem>
#include <stdexcept>
#include <vector>
int main(int argc,char** argv) {
 if(argc<3 || (std::string(argv[1])!="analyze" && std::string(argv[1])!="benchmark" && std::string(argv[1])!="benchmark-index")) {
  std::cout<<"Usage: netscope analyze <file.pcap> | netscope benchmark <file.pcap> | netscope benchmark-index <file.pcap> [repeats]\n";return 1;
 }
 if(std::string(argv[1])=="benchmark-index") {
  try {
   int repeats=3;
   if(argc>=4) {repeats=std::stoi(argv[3]);if(repeats<1 || repeats>30) throw std::runtime_error("Repeats must be 1..30");}
   std::vector<double> measurements;
   size_t count=0,index_bytes=0;
   for(int run=0;run<repeats;++run) {
    const auto start=std::chrono::steady_clock::now();
    netscope::IndexedPcap index(argv[2]);
    const auto stop=std::chrono::steady_clock::now();
    count=index.entries().size();
    index_bytes=index.entries().capacity()*sizeof(netscope::PacketIndexEntry);
    measurements.push_back(std::chrono::duration<double>(stop-start).count());
   }
   std::sort(measurements.begin(),measurements.end());
   const double median=measurements[measurements.size()/2];
   std::cout<<"NetScope v1.0 index benchmark\nFrames: "<<count
            <<"\nCapture bytes: "<<std::filesystem::file_size(argv[2])
            <<"\nIndex capacity bytes (estimate): "<<index_bytes
            <<"\nRuns: "<<repeats
            <<"\nMedian index seconds: "<<std::fixed<<std::setprecision(6)<<median
            <<"\nMedian frames/sec: "<<std::setprecision(1)<<(median>0?count/median:0)<<"\n";
   return 0;
  } catch(const std::exception& e) {std::cerr<<"Error: "<<e.what()<<'\n';return 2;}
 }
 const bool benchmark=std::string(argv[1])=="benchmark";
 const auto started=std::chrono::steady_clock::now();
 try {
  netscope::FlowTracker tracker;
  size_t frames=0,decoded=0; std::map<std::string,size_t> protocols,talkers,ports;
  netscope::read_pcap(argv[2],[&](const std::vector<uint8_t>& frame){
   ++frames;
   auto p=netscope::decode_ethernet(frame);
   if(!p) return;
   ++decoded;tracker.observe(*p);++protocols[p->protocol];++talkers[p->source_ip];
   if(p->protocol=="TCP" || p->protocol=="UDP") ++ports[std::to_string(p->destination_port)];
  });
  if(benchmark) {
   const double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
   std::cout<<"NetScope v1.0 benchmark\nFrames: "<<frames<<"\nDecoded IPv4: "<<decoded
            <<"\nElapsed seconds: "<<std::fixed<<std::setprecision(6)<<seconds
            <<"\nFrames/sec: "<<std::setprecision(1)<<(seconds>0 ? frames/seconds : 0)
            <<"\nFlows: "<<tracker.flow_count()<<"\n";
   return 0;
  }
  std::cout<<"NetScope v1.0\nFrames: "<<frames<<"\nDecoded IPv4: "<<decoded<<"\nProtocols:\n";
  for(const auto& [name,count]:protocols) std::cout<<"  "<<name<<": "<<count<<'\n';
  auto top=[](const auto& m){
   using Pair=std::pair<std::string,size_t>;
   std::vector<Pair> v(m.begin(),m.end());
   std::sort(v.begin(),v.end(),[](const auto& a,const auto& b){return a.second>b.second;});
   for(size_t i=0;i<std::min<size_t>(5,v.size());++i) std::cout<<"  "<<v[i].first<<": "<<v[i].second<<'\n';
  };
  std::cout<<"Top source IPs:\n";top(talkers);
  std::cout<<"Top destination ports:\n";top(ports);
  std::cout<<"Flows: "<<tracker.flow_count()<<"\nTop flows (by bytes):\n";
  for(const auto& flow:tracker.top_flows(5)) {
   const auto& k=flow.key;
   std::cout<<"  "<<k.source_ip<<":"<<k.source_port<<" -> "
            <<k.destination_ip<<":"<<k.destination_port<<" "<<k.protocol
            <<" packets="<<flow.stats.packets<<" bytes="<<flow.stats.bytes<<"\n";
  }
 } catch(const std::exception& e) {std::cerr<<"Error: "<<e.what()<<'\n';return 2;}
}
