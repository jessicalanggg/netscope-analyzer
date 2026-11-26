#pragma once
#include "netscope/parser.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace netscope {
struct TimeBucket { uint64_t second=0, packets=0, bytes=0; };
class TrafficTimeline {
public:
 void observe(uint64_t timestamp_us, uint64_t bytes);
 std::vector<TimeBucket> buckets() const;
private:
 std::map<uint64_t,TimeBucket> data_;
};
std::string tcp_flag_names(uint8_t flags);
std::string csv_escape(const std::string& value);
}
