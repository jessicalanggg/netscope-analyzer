#include "netscope/live_capture.hpp"
#include "netscope/analyzer.hpp"
#include "netscope/pcap.hpp"
#include "netscope/ring_buffer.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <iomanip>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <thread>
#ifdef NETSCOPE_HAVE_PCAP
#include <pcap.h>
#endif
namespace netscope {
#ifndef NETSCOPE_HAVE_PCAP
bool live_capture_available() {return false;}
std::vector<std::pair<std::string,std::string>> list_interfaces() {
 throw std::runtime_error("This build has no live-capture support (libpcap/Npcap not found at configure time)");
}
LiveStats run_live_capture(const LiveOptions&,std::ostream&) {
 throw std::runtime_error("This build has no live-capture support (libpcap/Npcap not found at configure time)");
}
#else
namespace {
std::atomic<bool> g_interrupted{false};
extern "C" void on_sigint(int) {g_interrupted.store(true);}

struct CaptureContext {
 PacketRing* ring=nullptr;
 uint64_t max_packets=0;
 std::atomic<uint64_t> captured{0}, ring_drops{0};
};
void on_packet(u_char* user,const pcap_pkthdr* h,const u_char* bytes) {
 auto* c=reinterpret_cast<CaptureContext*>(user);
 const uint64_t n=c->captured.load(std::memory_order_relaxed);
 if(c->max_packets && n>=c->max_packets) return;
 c->captured.store(n+1,std::memory_order_relaxed);
 const uint64_t ts=uint64_t(h->ts.tv_sec)*1000000ull+uint64_t(h->ts.tv_usec);
 if(!c->ring->try_push(ts,bytes,h->caplen,h->len)) c->ring_drops.fetch_add(1,std::memory_order_relaxed);
}
struct PcapCloser {void operator()(pcap_t* p) const {if(p) pcap_close(p);}};
size_t round_pow2(size_t n) {size_t p=4096;while(p<n && p<(size_t{1}<<34)) p<<=1;return p;}
}

bool live_capture_available() {return true;}

std::vector<std::pair<std::string,std::string>> list_interfaces() {
 char err[PCAP_ERRBUF_SIZE]{};
 pcap_if_t* all=nullptr;
 if(pcap_findalldevs(&all,err)!=0) throw std::runtime_error(std::string("pcap_findalldevs: ")+err);
 std::vector<std::pair<std::string,std::string>> out;
 for(auto* d=all;d;d=d->next) out.emplace_back(d->name,d->description?d->description:"");
 pcap_freealldevs(all);
 return out;
}

LiveStats run_live_capture(const LiveOptions& opt,std::ostream& out) {
 char err[PCAP_ERRBUF_SIZE]{};
 std::unique_ptr<pcap_t,PcapCloser> handle(pcap_create(opt.interface.c_str(),err));
 if(!handle) throw std::runtime_error(std::string("pcap_create: ")+err);
 pcap_set_snaplen(handle.get(),opt.snaplen);
 pcap_set_promisc(handle.get(),opt.promiscuous?1:0);
 pcap_set_timeout(handle.get(),50);
 pcap_set_buffer_size(handle.get(),opt.kernel_buffer_mb*1024*1024);
 const int activated=pcap_activate(handle.get());
 if(activated<0) {
  std::string msg=pcap_geterr(handle.get());
  if(activated==PCAP_ERROR_PERM_DENIED) msg+=" (capture needs permission: on macOS install Wireshark's ChmodBPF, on Linux run as root or grant CAP_NET_RAW)";
  throw std::runtime_error("pcap_activate("+opt.interface+"): "+msg);
 }
 if(activated>0) out<<"Warning: "<<pcap_statustostr(activated)<<"\n";
 if(!opt.bpf_filter.empty()) {
  bpf_program program{};
  if(pcap_compile(handle.get(),&program,opt.bpf_filter.c_str(),1,PCAP_NETMASK_UNKNOWN)!=0)
   throw std::runtime_error(std::string("Invalid BPF filter: ")+pcap_geterr(handle.get()));
  const int set=pcap_setfilter(handle.get(),&program);
  pcap_freecode(&program);
  if(set!=0) throw std::runtime_error(std::string("pcap_setfilter: ")+pcap_geterr(handle.get()));
 }
 const uint32_t linktype=static_cast<uint32_t>(pcap_datalink(handle.get()));

 // Created before the capture thread starts so a failure cannot leak a running thread.
 std::unique_ptr<PcapWriter> writer;
 if(!opt.write_path.empty()) writer=std::make_unique<PcapWriter>(opt.write_path,linktype,static_cast<uint32_t>(opt.snaplen));
 PacketRing ring(round_pow2(opt.ring_bytes));
 CaptureContext ctx;ctx.ring=&ring;ctx.max_packets=opt.max_packets;
 std::atomic<bool> stop{false};
 std::atomic<uint64_t> kernel_recv{0},kernel_drop{0},if_drop{0};
 std::string capture_error;            // written by capture thread, read after join
 std::atomic<bool> capture_finished{false};

 std::thread capture([&]{
  auto last_stats=std::chrono::steady_clock::now();
  while(!stop.load(std::memory_order_relaxed)) {
   const int r=pcap_dispatch(handle.get(),-1,on_packet,reinterpret_cast<u_char*>(&ctx));
   if(r==PCAP_ERROR_BREAK) break;
   if(r<0) {capture_error=pcap_geterr(handle.get());break;}
   const auto now=std::chrono::steady_clock::now();
   if(now-last_stats>std::chrono::milliseconds(250)) {
    pcap_stat s{};
    if(pcap_stats(handle.get(),&s)==0) {kernel_recv=s.ps_recv;kernel_drop=s.ps_drop;if_drop=s.ps_ifdrop;}
    last_stats=now;
   }
   if(ctx.max_packets && ctx.captured.load(std::memory_order_relaxed)>=ctx.max_packets) break;
  }
  pcap_stat s{};
  if(pcap_stats(handle.get(),&s)==0) {kernel_recv=s.ps_recv;kernel_drop=s.ps_drop;if_drop=s.ps_ifdrop;}
  capture_finished.store(true,std::memory_order_release);
 });

 g_interrupted=false;
 auto previous=std::signal(SIGINT,on_sigint);
 Analyzer analyzer;
 LiveStats stats;
 const auto started=std::chrono::steady_clock::now();
 auto next_status=started+std::chrono::seconds(1);
 uint64_t last_frames=0,last_bytes=0;
 auto consume=[&]{
  return ring.drain([&](const PacketRing::Header& h,std::span<const uint8_t> data){
   analyzer.observe(linktype,data,h.timestamp_us);
   if(writer) writer->write(h.timestamp_us,data.data(),h.captured_length,h.original_length);
  },4096);
 };
 if(!opt.quiet) out<<"Capturing on "<<opt.interface<<" (linktype "<<linktype<<", ring "<<ring.capacity()/(1024*1024)<<" MiB)"
                   <<(opt.bpf_filter.empty()?"":" filter: "+opt.bpf_filter)<<" — Ctrl-C to stop\n";
 try {
 for(;;) {
  stats.ring_high_water=std::max(stats.ring_high_water,ring.used());
  const size_t n=consume();
  const auto now=std::chrono::steady_clock::now();
  const double elapsed=std::chrono::duration<double>(now-started).count();
  const bool capture_done=capture_finished.load(std::memory_order_acquire) && ring.used()==0;
  if(g_interrupted.load() || (opt.duration_seconds>0 && elapsed>=opt.duration_seconds) || capture_done) break;
  if(!opt.quiet && now>=next_status) {
   const uint64_t f=analyzer.frames(),b=analyzer.bytes();
   out<<"["<<std::fixed<<std::setprecision(1)<<std::setw(6)<<elapsed<<"s] "<<f<<" pkts  "
      <<(f-last_frames)<<" pps  "<<std::setprecision(2)<<(b-last_bytes)*8.0/1e6<<" Mbps  ring "
      <<std::setprecision(1)<<100.0*ring.used()/ring.capacity()<<"%  drops ring="<<ctx.ring_drops.load()
      <<" kernel="<<kernel_drop.load()<<"\n"<<std::flush;
   last_frames=f;last_bytes=b;next_status+=std::chrono::seconds(1);
  }
  if(n==0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
 }
 } catch(...) {
  stop=true;pcap_breakloop(handle.get());capture.join();std::signal(SIGINT,previous);throw;
 }
 stop=true;
 pcap_breakloop(handle.get());
 capture.join();
 while(consume()) {}
 std::signal(SIGINT,previous);
 if(writer) writer->flush();
 if(!capture_error.empty()) throw std::runtime_error("Capture failed: "+capture_error);
 analyzer.finish();
 stats.seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count();
 stats.captured=ctx.captured.load();stats.analyzed=analyzer.frames();stats.ring_drops=ctx.ring_drops.load();
 stats.kernel_received=kernel_recv.load();stats.kernel_drops=kernel_drop.load();stats.interface_drops=if_drop.load();
 out<<"\nNetScope live capture summary ("<<std::fixed<<std::setprecision(2)<<stats.seconds<<" s on "<<opt.interface<<")\n";
 analyzer.print_summary(out);
 out<<"Capture: captured="<<stats.captured<<" analyzed="<<stats.analyzed<<" ring_drops="<<stats.ring_drops
    <<" kernel_drops="<<stats.kernel_drops<<" interface_drops="<<stats.interface_drops
    <<" ring_high_water="<<stats.ring_high_water<<" bytes\n";
 if(writer) out<<"Wrote "<<opt.write_path<<"\n";
 return stats;
}
#endif
}
