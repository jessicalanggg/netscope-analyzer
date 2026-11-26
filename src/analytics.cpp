#include "netscope/analytics.hpp"
namespace netscope {
void TrafficTimeline::observe(uint64_t timestamp_us,uint64_t bytes) {
 auto& bucket=data_[timestamp_us/1000000];
 bucket.second=timestamp_us/1000000;
 ++bucket.packets;bucket.bytes+=bytes;
}
std::vector<TimeBucket> TrafficTimeline::buckets() const {
 std::vector<TimeBucket> out;out.reserve(data_.size());
 for(const auto& [_,b]:data_) out.push_back(b);
 return out;
}
std::string tcp_flag_names(uint8_t flags) {
 std::string result;
 for(const auto& [mask,name]:std::initializer_list<std::pair<uint8_t,const char*>>{{0x01,"FIN"},{0x02,"SYN"},{0x04,"RST"},{0x08,"PSH"},{0x10,"ACK"},{0x20,"URG"},{0x40,"ECE"},{0x80,"CWR"}}) {
  if(flags&mask) {if(!result.empty()) result+=" | ";result+=name;}
 }
 return result.empty()?"None":result;
}
std::string csv_escape(const std::string& value) {
 if(value.find_first_of(",\"\n\r")==std::string::npos) return value;
 std::string out="\"";
 for(char c:value) {if(c=='\"') out+="\"";out+=c;}
 return out+"\"";
}
}
