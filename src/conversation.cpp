#include "netscope/conversation.hpp"
#include <algorithm>
namespace netscope {
std::string ConversationStats::tcp_state() const {
 if(rst) return "Reset";
 if(fin_a&&fin_b) return "Closing/Closed";
 if(fin_a||fin_b) return "Half-closed";
 if(syn && syn_ack && ack_after_syn) return "Established (observed)";
 if(syn_ack) return "SYN-ACK seen";
 if(syn) return "SYN seen";
 return "Unknown / midstream";
}
void ConversationTracker::observe(const Packet& p,uint64_t timestamp_us) {
 if(p.protocol!="TCP" && p.protocol!="UDP") return;
 Endpoint src{p.source_ip,p.source_port}, dst{p.destination_ip,p.destination_port};
 if(src.ip.empty() || dst.ip.empty()) return;
 const bool forward=!(dst<src);
 ConversationKey key{forward?src:dst,forward?dst:src,p.protocol};
 auto [it,inserted]=conversations_.try_emplace(std::move(key));
 auto& s=it->second;
 if(inserted) s.first_us=timestamp_us;
 s.first_us=std::min(s.first_us,timestamp_us);
 s.last_us=std::max(s.last_us,timestamp_us);
 if(forward){++s.packets_a_to_b;s.bytes_a_to_b+=p.frame_length;}
 else {++s.packets_b_to_a;s.bytes_b_to_a+=p.frame_length;}
 if(p.protocol!="TCP") return;
 const bool syn=(p.tcp_flags&0x02)!=0, ack=(p.tcp_flags&0x10)!=0;
 if(syn){++s.syn_count;if(ack)s.syn_ack=true;else s.syn=true;}
 if(ack&&!syn&&s.syn&&s.syn_ack)s.ack_after_syn=true;
 if(p.tcp_flags&0x01){++s.fin_count;if(forward)s.fin_a=true;else s.fin_b=true;}
 if(p.tcp_flags&0x04){++s.rst_count;s.rst=true;}
}
std::vector<ConversationRecord> ConversationTracker::top_conversations(size_t limit) const {
 std::vector<ConversationRecord> rows; rows.reserve(conversations_.size());
 for(const auto& [k,v]:conversations_)rows.push_back({k,v});
 std::sort(rows.begin(),rows.end(),[](const auto& x,const auto& y){
  if(x.stats.bytes()!=y.stats.bytes())return x.stats.bytes()>y.stats.bytes();
  if(x.stats.packets()!=y.stats.packets())return x.stats.packets()>y.stats.packets();
  return x.key<y.key;
 });
 if(rows.size()>limit)rows.resize(limit);
 return rows;
}
}
