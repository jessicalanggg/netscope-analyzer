#include "netscope/filter.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <limits>
namespace netscope {
namespace {
std::string trim(std::string_view v) {
 const auto first=v.find_first_not_of(" \t\r\n");
 if(first==std::string_view::npos) return {};
 const auto last=v.find_last_not_of(" \t\r\n");
 return std::string(v.substr(first,last-first+1));
}
std::string lower(std::string s) {
 std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
 return s;
}
bool parseUnsigned(const std::string& value,unsigned& out) {
 if(value.empty()) return false;
 const auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),out);
 return ec==std::errc{} && end==value.data()+value.size();
}
}
PacketFilter parse_filter(std::string_view expression) {
 PacketFilter f;
 auto text=trim(expression);
 if(text.empty()) return f;
 const auto normalized=lower(text);
 if(normalized=="tcp" || normalized=="udp" || normalized=="icmp") {
  f.kind=PacketFilter::Kind::Protocol;f.value=normalized;return f;
 }
 const auto pos=normalized.find("==");
 if(pos==std::string::npos) {f.kind=PacketFilter::Kind::Text;f.value=normalized;return f;}
 const auto field=trim(normalized.substr(0,pos));
 f.value=trim(text.substr(pos+2));
 if(f.value.empty()) {f.kind=PacketFilter::Kind::Invalid;f.error="Missing comparison value";return f;}
 if(field=="ip.src") f.kind=PacketFilter::Kind::SourceIP;
 else if(field=="ip.dst") f.kind=PacketFilter::Kind::DestinationIP;
 else if(field=="port" || field=="tcp.port" || field=="udp.port" || field=="frame.number") {
  if(!parseUnsigned(f.value,f.number) || (f.number>65535 && field!="frame.number")) {
   f.kind=PacketFilter::Kind::Invalid;f.error="Expected a valid non-negative number";return f;
  }
  if(field=="port") f.kind=PacketFilter::Kind::Port;
  else if(field=="tcp.port") f.kind=PacketFilter::Kind::TcpPort;
  else if(field=="udp.port") f.kind=PacketFilter::Kind::UdpPort;
  else f.kind=PacketFilter::Kind::Number;
 } else {f.kind=PacketFilter::Kind::Invalid;f.error="Unsupported filter field: "+field;}
 return f;
}
bool PacketFilter::matches(const Packet* p,size_t frameNumber,size_t frameLength) const {
 switch(kind) {
 case Kind::All:return true;
 case Kind::Invalid:return false;
 case Kind::Number:return frameNumber==number;
 case Kind::SourceIP:return p && p->source_ip==value;
 case Kind::DestinationIP:return p && p->destination_ip==value;
 case Kind::Protocol:return p && lower(p->protocol)==value;
 case Kind::Port: return p && (p->protocol=="TCP"||p->protocol=="UDP") && (p->source_port==number||p->destination_port==number);
 case Kind::TcpPort:return p && p->protocol=="TCP" && (p->source_port==number||p->destination_port==number);
 case Kind::UdpPort:return p && p->protocol=="UDP" && (p->source_port==number||p->destination_port==number);
 case Kind::Text: {
  std::string haystack=std::to_string(frameNumber)+" "+std::to_string(frameLength);
  if(p) haystack+=" "+p->source_ip+" "+p->destination_ip+" "+p->protocol+" "+std::to_string(p->source_port)+" "+std::to_string(p->destination_port);
  return lower(haystack).find(value)!=std::string::npos;
 }
 }
 return false;
}
}
