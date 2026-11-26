#include "netscope/analyzer.hpp"
#include <algorithm>
#include <ostream>
#include <vector>
namespace netscope {
Analyzer::Analyzer(bool reassemble,TcpReassembler::DataCallback on_data)
 :reassemble_(reassemble),reassembler_(std::move(on_data)) {}

void Analyzer::observe(uint32_t linktype,std::span<const uint8_t> frame,uint64_t ts) {
 ++frames_;bytes_+=frame.size();
 auto p=decode_frame(linktype,frame);
 if(!p) return;
 ++decoded_;
 if(p->ip_version==4) ++ipv4_; else ++ipv6_;
 if(p->vlan_depth) ++vlan_;
 ++protocols_[p->protocol];++talkers_[p->source_ip];
 if(p->protocol=="TCP" || p->protocol=="UDP") ++ports_[p->destination_port];
 flows_.observe(*p);
 conversations_.observe(*p,ts);
 if(reassemble_) reassembler_.observe(*p,frame,ts);
}

void Analyzer::finish() {if(reassemble_) reassembler_.finish();}

void Analyzer::print_summary(std::ostream& out) const {
 out<<"Frames: "<<frames_<<"\nDecoded IP: "<<decoded_<<" (IPv4 "<<ipv4_<<", IPv6 "<<ipv6_<<", VLAN-tagged "<<vlan_<<")\nProtocols:\n";
 std::vector<std::pair<std::string,uint64_t>> protocols(protocols_.begin(),protocols_.end());
 std::sort(protocols.begin(),protocols.end());
 for(const auto& [name,count]:protocols) out<<"  "<<name<<": "<<count<<'\n';
 auto top=[&out](auto rows){
  std::sort(rows.begin(),rows.end(),[](const auto& a,const auto& b){return a.second!=b.second?a.second>b.second:a.first<b.first;});
  for(size_t i=0;i<std::min<size_t>(5,rows.size());++i) out<<"  "<<rows[i].first<<": "<<rows[i].second<<'\n';
 };
 out<<"Top source IPs:\n";top(std::vector<std::pair<std::string,uint64_t>>(talkers_.begin(),talkers_.end()));
 out<<"Top destination ports:\n";top(std::vector<std::pair<uint16_t,uint64_t>>(ports_.begin(),ports_.end()));
 out<<"Flows: "<<flows_.flow_count()<<"\nConversations: "<<conversations_.count()<<"\nTop flows (by bytes):\n";
 for(const auto& flow:flows_.top_flows(5)) {
  const auto& k=flow.key;
  const bool v6=k.source_ip.find(':')!=std::string::npos;
  auto ep=[v6](const std::string& ip,uint16_t port){return v6?"["+ip+"]:"+std::to_string(port):ip+":"+std::to_string(port);};
  out<<"  "<<ep(k.source_ip,k.source_port)<<" -> "<<ep(k.destination_ip,k.destination_port)<<" "<<k.protocol
     <<" packets="<<flow.stats.packets<<" bytes="<<flow.stats.bytes<<"\n";
 }
 if(reassemble_) {
  uint64_t delivered=0,retrans=0,ooo=0,missing=0;
  for(const auto& s:reassembler_.streams()) for(const auto& d:s.dir) {
   delivered+=d.delivered_bytes;retrans+=d.retransmitted_bytes;ooo+=d.out_of_order_segments;missing+=d.missing_bytes;
  }
  out<<"TCP streams: "<<reassembler_.streams().size()<<"\n  Reassembled payload bytes: "<<delivered
     <<"\n  Retransmitted bytes: "<<retrans<<"\n  Out-of-order segments: "<<ooo<<"\n  Missing bytes (gaps): "<<missing<<"\n";
 }
}
}
