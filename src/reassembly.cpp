#include "netscope/reassembly.hpp"
#include <algorithm>
#include <tuple>
namespace netscope {
namespace {
// Maps a 32-bit offset from the ISN onto the 64-bit stream offset nearest to
// `reference`, so sequence-number wraparound is transparent.
uint64_t unwrap(uint32_t relative,uint64_t reference) {
 constexpr uint64_t kSpan=uint64_t{1}<<32;
 uint64_t candidate=(reference&~(kSpan-1))|relative;
 if(candidate>reference && candidate-reference>kSpan/2 && candidate>=kSpan) candidate-=kSpan;
 else if(candidate<reference && reference-candidate>kSpan/2) candidate+=kSpan;
 return candidate;
}
}
bool TcpReassembler::Key::operator<(const Key& o) const {return std::tie(a,pa,b,pb)<std::tie(o.a,o.pa,o.b,o.pb);}

TcpReassembler::TcpReassembler(DataCallback on_data,size_t max_buffered)
 :on_data_(std::move(on_data)),max_buffered_(max_buffered) {}

void TcpReassembler::deliver(Stream& s,int dir,std::span<const uint8_t> data) {
 if(data.empty()) return;
 info_[s.id].dir[dir].delivered_bytes+=data.size();
 if(on_data_) on_data_(s.id,dir,data);
}

void TcpReassembler::drain(Stream& s,int dir) {
 auto& d=s.d[dir];
 auto& st=info_[s.id].dir[dir];
 while(!d.pending.empty()) {
  auto it=d.pending.begin();
  if(it->first>d.next) break;
  const uint64_t start=it->first, end=start+it->second.size();
  if(end>d.next) {
   const size_t skip=static_cast<size_t>(d.next-start);
   st.retransmitted_bytes+=skip;
   deliver(s,dir,std::span<const uint8_t>(it->second).subspan(skip));
   d.next=end;
  } else st.retransmitted_bytes+=it->second.size();
  d.pending_bytes-=it->second.size();buffered_-=it->second.size();
  d.pending.erase(it);
 }
 if(d.fin_known && !d.closed && d.next>=d.fin_at) {d.closed=true;d.next=d.fin_at+1;}
}

void TcpReassembler::segment(Stream& s,int dir,const Packet& p,std::span<const uint8_t> payload) {
 auto& d=s.d[dir];
 auto& st=info_[s.id].dir[dir];
 const bool syn=p.tcp_flags&0x02, fin=p.tcp_flags&0x01, rst=p.tcp_flags&0x04;
 ++st.segments;st.payload_bytes+=payload.size();
 if(syn) st.syn=true;
 if(rst) {st.rst=true;s.closed_or_reset=true;}
 if(!d.has_isn) {
  d.has_isn=true;d.isn=p.tcp_sequence;
  d.next=syn?1:0; // SYN occupies one sequence number; midstream pickup starts at 0
 }
 uint64_t at=unwrap(p.tcp_sequence-d.isn,d.next);
 if(syn) at+=1;
 if(fin) {d.fin_known=true;d.fin_at=at+payload.size();st.fin=true;}
 if(!payload.empty()) {
  const uint64_t end=at+payload.size();
  if(end<=d.next) st.retransmitted_bytes+=payload.size();
  else if(at<=d.next) {
   const size_t skip=static_cast<size_t>(d.next-at);
   st.retransmitted_bytes+=skip;
   deliver(s,dir,payload.subspan(skip));
   d.next=end;
  } else {
   ++st.out_of_order_segments;
   auto [it,inserted]=d.pending.try_emplace(at);
   if(inserted || it->second.size()<payload.size()) {
    d.pending_bytes-=it->second.size();buffered_-=it->second.size();
    it->second.assign(payload.begin(),payload.end());
    d.pending_bytes+=payload.size();buffered_+=payload.size();
   } else st.retransmitted_bytes+=payload.size();
   // Bound memory: give up on the oldest hole rather than buffering forever.
   while(d.pending_bytes>max_buffered_ && !d.pending.empty()) {
    st.missing_bytes+=d.pending.begin()->first-d.next;
    d.next=d.pending.begin()->first;
    drain(s,dir);
   }
  }
 }
 drain(s,dir);
 if(d.closed && s.d[1-dir].closed) s.closed_or_reset=true;
}

void TcpReassembler::observe(const Packet& p,std::span<const uint8_t> frame,uint64_t ts) {
 if(p.protocol!="TCP") return;
 const bool src_first=std::tie(p.source_ip,p.source_port)<std::tie(p.destination_ip,p.destination_port);
 Key key=src_first?Key{p.source_ip,p.source_port,p.destination_ip,p.destination_port}
                  :Key{p.destination_ip,p.destination_port,p.source_ip,p.source_port};
 auto it=streams_.find(key);
 const bool pure_syn=(p.tcp_flags&0x12)==0x02;
 if(it!=streams_.end() && pure_syn && it->second.closed_or_reset) {
  flush_direction(it->second,0);flush_direction(it->second,1);
  streams_.erase(it);it=streams_.end();
 }
 if(it==streams_.end()) {
  Stream s{info_.size(),{},false};
  TcpStreamInfo info;info.id=s.id;
  info.address[0]=p.source_ip;info.port[0]=p.source_port;
  info.address[1]=p.destination_ip;info.port[1]=p.destination_port;
  info.first_us=ts;
  info_.push_back(std::move(info));
  it=streams_.emplace(std::move(key),std::move(s)).first;
 }
 auto& s=it->second;
 auto& info=info_[s.id];
 info.last_us=std::max(info.last_us,ts);
 const int dir=(p.source_ip==info.address[0] && p.source_port==info.port[0])?0:1;
 std::span<const uint8_t> payload;
 if(p.payload_length && p.payload_offset+p.payload_length<=frame.size())
  payload=frame.subspan(p.payload_offset,p.payload_length);
 segment(s,dir,p,payload);
}

void TcpReassembler::flush_direction(Stream& s,int dir) {
 auto& d=s.d[dir];
 while(!d.pending.empty()) {
  const uint64_t first=d.pending.begin()->first;
  if(first>d.next) {info_[s.id].dir[dir].missing_bytes+=first-d.next;d.next=first;}
  drain(s,dir);
 }
}

void TcpReassembler::finish() {
 for(auto& [_,s]:streams_) {flush_direction(s,0);flush_direction(s,1);}
}
}
