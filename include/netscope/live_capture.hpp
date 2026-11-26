#pragma once
#include <cstdint>
#include <iosfwd>
#include <string>
#include <utility>
#include <vector>
namespace netscope {
struct LiveOptions {
 std::string interface;
 std::string bpf_filter;
 std::string write_path;          // optional classic-pcap output
 int snaplen=262144;
 bool promiscuous=false;
 uint64_t max_packets=0;          // 0 = unlimited
 double duration_seconds=0;       // 0 = until Ctrl-C
 size_t ring_bytes=64u*1024*1024; // user-space ring between capture and analysis threads
 int kernel_buffer_mb=16;
 bool quiet=false;                // suppress per-second status lines
};
struct LiveStats {
 uint64_t captured=0, analyzed=0, ring_drops=0, kernel_received=0, kernel_drops=0, interface_drops=0;
 double seconds=0;
 size_t ring_high_water=0;
};
// Returns true if this build has libpcap live-capture support.
bool live_capture_available();
// (name, description) for each capture interface.
std::vector<std::pair<std::string,std::string>> list_interfaces();
// Captures until a stop condition (count, duration, or Ctrl-C), analyzing on a
// separate thread fed by a lock-free ring buffer. Prints status and a summary.
LiveStats run_live_capture(const LiveOptions& options, std::ostream& out);
}
