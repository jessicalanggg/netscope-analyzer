#include "netscope/pcap.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <stdexcept>
namespace netscope {
namespace {
constexpr uint32_t kMaxPacket=16u*1024*1024;
constexpr uint32_t kMaxBlock=kMaxPacket+1024;   // packet + generous option space
constexpr uint32_t kShb=0x0A0D0D0A, kIdb=1, kPb=2, kSpb=3, kEpb=6;

uint16_t rd16(const uint8_t* p,bool little) {
 return little?static_cast<uint16_t>(p[0]|(p[1]<<8)):static_cast<uint16_t>((p[0]<<8)|p[1]);
}
uint32_t rd32(const uint8_t* p,bool little) {
 if(little) return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
 return (uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|uint32_t(p[3]);
}
uint64_t rd64(const uint8_t* p,bool little) {
 const uint64_t a=rd32(p,little),b=rd32(p+4,little);
 return little?(b<<32)|a:(a<<32)|b;
}

struct Interface {
 uint32_t linktype=1, snaplen=0;
 bool binary=false; uint8_t exponent=6; // resolution 10^-exponent or 2^-exponent
 int64_t offset_seconds=0;
 uint64_t to_us(uint64_t ts) const {
  uint64_t us;
  if(!binary) {
   if(exponent==6) us=ts;
   else if(exponent<6) {uint64_t m=1;for(int i=exponent;i<6;++i) m*=10;us=ts*m;}
   else if(exponent>25) us=0;
   else {uint64_t d=1;for(int i=6;i<exponent;++i) d*=10;us=ts/d;} // 10^19 still fits in uint64
  } else {
   const unsigned n=exponent;
   if(n>=64) us=0;
   else {
    const uint64_t secs=n==0?ts:(ts>>n);
    const uint64_t frac=n==0?0:(ts&((uint64_t{1}<<n)-1));
    us=secs*1000000ull+static_cast<uint64_t>(std::ldexp(static_cast<long double>(frac)*1000000.0L,-static_cast<int>(n)));
   }
  }
  return static_cast<uint64_t>(static_cast<int64_t>(us)+offset_seconds*1000000);
 }
};
}

struct CaptureReader::Impl {
 std::ifstream f;
 std::vector<char> iobuf;
 Format format=Format::Pcap;
 uint64_t size=0, pos=0;
 // classic
 bool little=true, nanos=false; uint32_t linktype=1;
 // pcapng
 std::vector<Interface> interfaces;
 std::vector<uint8_t> scratch;

 void read_exact(void* dst,size_t n,const char* what) {
  if(n>size-pos) throw std::runtime_error(what);
  if(!f.read(static_cast<char*>(dst),static_cast<std::streamsize>(n))) throw std::runtime_error(what);
  pos+=n;
 }
 // Moves forward to `to`. Short skips are read and discarded: seekg() drops the
 // stream buffer and costs a syscall, which dominated per-packet cost when it
 // was used to step over packet data, pcapng options and block trailers.
 void seek(uint64_t to) {
  if(to>size || to<pos) throw std::runtime_error("Invalid capture file offset");
  if(to==pos) return;
  constexpr uint64_t kReadThrough=256*1024;
  if(to-pos<=kReadThrough) {
   discard.resize(static_cast<size_t>(to-pos));
   read_exact(discard.data(),discard.size(),"Truncated capture");
   return;
  }
  f.seekg(static_cast<std::streamoff>(to));if(!f) throw std::runtime_error("Invalid capture file offset");pos=to;
 }
 std::vector<uint8_t> discard;
 void data(RecordInfo& info,std::vector<uint8_t>* bytes) {
  info.data_offset=pos;
  if(bytes) {bytes->resize(info.captured_length);if(info.captured_length) read_exact(bytes->data(),info.captured_length,"Truncated packet data");}
  else {if(info.captured_length>size-pos) throw std::runtime_error("Truncated packet data");seek(pos+info.captured_length);}
 }

 bool next_classic(RecordInfo& info,std::vector<uint8_t>* bytes) {
  if(pos==size) return false;
  std::array<uint8_t,16> r{};
  read_exact(r.data(),16,"Truncated record header");
  const uint32_t n=rd32(r.data()+8,little), original=rd32(r.data()+12,little), fraction=rd32(r.data()+4,little);
  if(n>kMaxPacket || n>original) throw std::runtime_error("Invalid captured packet length");
  if(fraction>=(nanos?1000000000u:1000000u)) throw std::runtime_error("Invalid PCAP timestamp fraction");
  info.timestamp_us=uint64_t(rd32(r.data(),little))*1000000ull+(nanos?fraction/1000u:fraction);
  info.captured_length=n;info.original_length=original;info.linktype=linktype;
  data(info,bytes);
  return true;
 }

 void parse_shb(uint64_t start) {
  // Block type (4) already consumed; read length + byte-order magic together.
  std::array<uint8_t,8> h{};
  read_exact(h.data(),8,"Truncated pcapng section header");
  if(rd32(h.data()+4,true)==0x1A2B3C4D) little=true;
  else if(rd32(h.data()+4,false)==0x1A2B3C4D) little=false;
  else throw std::runtime_error("Invalid pcapng byte-order magic");
  const uint32_t len=rd32(h.data(),little);
  if(len<28 || len%4 || len>size-start) throw std::runtime_error("Invalid pcapng section header length");
  interfaces.clear();
  check_trailer(start+len,len);
 }

 void parse_idb(uint64_t start,uint32_t len) {
  if(len<20 || len>1024*1024) throw std::runtime_error("Invalid pcapng interface block");
  scratch.resize(len-8);
  read_exact(scratch.data(),scratch.size(),"Truncated pcapng interface block");
  Interface itf;
  itf.linktype=rd16(scratch.data(),little);
  itf.snaplen=rd32(scratch.data()+4,little);
  size_t o=8;const size_t end=scratch.size()-4;
  while(o+4<=end) {
   const uint16_t code=rd16(scratch.data()+o,little), olen=rd16(scratch.data()+o+2,little);
   o+=4;
   if(code==0) break;
   if(olen>end-o) throw std::runtime_error("Invalid pcapng interface option");
   if(code==9 && olen>=1) {const uint8_t v=scratch[o];itf.binary=(v&0x80)!=0;itf.exponent=v&0x7f;}
   else if(code==14 && olen>=8) itf.offset_seconds=static_cast<int64_t>(rd64(scratch.data()+o,little));
   o+=(olen+3u)&~3u;
  }
  if(rd32(scratch.data()+scratch.size()-4,little)!=len) throw std::runtime_error("pcapng block length mismatch");
  interfaces.push_back(itf);
  (void)start;
 }

 bool next_ng(RecordInfo& info,std::vector<uint8_t>* bytes) {
  for(;;) {
   if(pos==size) return false;
   const uint64_t start=pos;
   std::array<uint8_t,4> t{};
   read_exact(t.data(),4,"Truncated pcapng block header");
   if(rd32(t.data(),true)==kShb) {parse_shb(start);continue;}
   const uint32_t type=rd32(t.data(),little);
   std::array<uint8_t,4> l{};
   read_exact(l.data(),4,"Truncated pcapng block header");
   const uint32_t len=rd32(l.data(),little);
   if(len<12 || len%4 || len>kMaxBlock || len>size-start) throw std::runtime_error("Invalid pcapng block length");
   const uint64_t end=start+len;
   if(type==kIdb) {parse_idb(start,len);continue;}
   if(type==kEpb || type==kPb) {
    if(len<32) throw std::runtime_error("Invalid pcapng packet block");
    std::array<uint8_t,20> h{};
    read_exact(h.data(),20,"Truncated pcapng packet block");
    const uint32_t iface=type==kEpb?rd32(h.data(),little):rd16(h.data(),little);
    if(iface>=interfaces.size()) throw std::runtime_error("pcapng packet references unknown interface");
    const auto& itf=interfaces[iface];
    const uint64_t ts=(uint64_t(rd32(h.data()+4,little))<<32)|rd32(h.data()+8,little);
    info.captured_length=rd32(h.data()+12,little);info.original_length=rd32(h.data()+16,little);
    if(info.captured_length>len-32 || info.captured_length>kMaxPacket) throw std::runtime_error("Invalid pcapng captured length");
    info.timestamp_us=itf.to_us(ts);info.linktype=itf.linktype;
    data(info,bytes);
    check_trailer(end,len);
    return true;
   }
   if(type==kSpb) {
    if(len<16 || interfaces.empty()) throw std::runtime_error("Invalid pcapng simple packet block");
    std::array<uint8_t,4> h{};
    read_exact(h.data(),4,"Truncated pcapng simple packet block");
    const auto& itf=interfaces[0];
    info.original_length=rd32(h.data(),little);
    uint32_t cap=std::min(info.original_length,len-16);
    if(itf.snaplen) cap=std::min(cap,itf.snaplen);
    info.captured_length=cap;info.timestamp_us=0;info.linktype=itf.linktype;
    data(info,bytes);
    check_trailer(end,len);
    return true;
   }
   check_trailer(end,len); // NRB, ISB, DSB, custom blocks: skipped after validation
  }
 }
 void check_trailer(uint64_t end,uint32_t len) {
  seek(end-4);
  std::array<uint8_t,4> t{};
  read_exact(t.data(),4,"Truncated pcapng block trailer");
  if(rd32(t.data(),little)!=len) throw std::runtime_error("pcapng block length mismatch");
 }
};

CaptureReader::CaptureReader(const std::string& path):impl_(std::make_unique<Impl>()) {
 auto& m=*impl_;
 m.iobuf.resize(1<<20);
 m.f.rdbuf()->pubsetbuf(m.iobuf.data(),static_cast<std::streamsize>(m.iobuf.size()));
 m.f.open(path,std::ios::binary|std::ios::ate);
 if(!m.f) throw std::runtime_error("Cannot open capture: "+path);
 m.size=static_cast<uint64_t>(m.f.tellg());
 m.f.seekg(0);
 if(m.size<4) throw std::runtime_error("Truncated capture header");
 std::array<uint8_t,24> h{};
 m.read_exact(h.data(),4,"Truncated capture header");
 if(rd32(h.data(),true)==kShb) {
  m.format=Format::PcapNg;
  m.parse_shb(0);
  return;
 }
 if(h[0]==0xd4&&h[1]==0xc3&&h[2]==0xb2&&h[3]==0xa1) m.little=true;
 else if(h[0]==0xa1&&h[1]==0xb2&&h[2]==0xc3&&h[3]==0xd4) m.little=false;
 else if(h[0]==0x4d&&h[1]==0x3c&&h[2]==0xb2&&h[3]==0xa1) m.little=m.nanos=true;
 else if(h[0]==0xa1&&h[1]==0xb2&&h[2]==0x3c&&h[3]==0x4d) {m.little=false;m.nanos=true;}
 else throw std::runtime_error("Unsupported capture format (expected pcap or pcapng)");
 m.read_exact(h.data()+4,20,"Truncated PCAP header");
 m.linktype=rd32(h.data()+20,m.little)&0x0fffffff; // upper bits carry FCS info
}
CaptureReader::~CaptureReader()=default;
bool CaptureReader::next(RecordInfo& info,std::vector<uint8_t>* bytes) {
 return impl_->format==Format::Pcap?impl_->next_classic(info,bytes):impl_->next_ng(info,bytes);
}
CaptureReader::Format CaptureReader::format() const noexcept {return impl_->format;}
uint64_t CaptureReader::file_size() const noexcept {return impl_->size;}

void read_pcap_records(const std::string& path, const RecordCallback& callback) {
 CaptureReader reader(path);
 PcapRecord record;RecordInfo info;
 while(reader.next(info,&record.bytes)) {
  record.timestamp_us=info.timestamp_us;record.original_length=info.original_length;record.linktype=info.linktype;
  callback(record);
 }
}
void read_pcap(const std::string& path, const PacketCallback& callback) {
 read_pcap_records(path,[&](const PcapRecord& r){callback(r.bytes);});
}

PcapWriter::PcapWriter(const std::string& path,uint32_t linktype,uint32_t snaplen):out_(path,std::ios::binary) {
 if(!out_) throw std::runtime_error("Cannot create capture: "+path);
 auto put32=[this](uint32_t v){const uint8_t b[4]={uint8_t(v),uint8_t(v>>8),uint8_t(v>>16),uint8_t(v>>24)};out_.write(reinterpret_cast<const char*>(b),4);};
 auto put16=[this](uint16_t v){const uint8_t b[2]={uint8_t(v),uint8_t(v>>8)};out_.write(reinterpret_cast<const char*>(b),2);};
 put32(0xa1b2c3d4);put16(2);put16(4);put32(0);put32(0);put32(snaplen);put32(linktype);
}
void PcapWriter::write(uint64_t ts,const uint8_t* data,uint32_t caplen,uint32_t origlen) {
 const uint32_t v[4]={uint32_t(ts/1000000),uint32_t(ts%1000000),caplen,origlen};
 for(uint32_t x:v) {const uint8_t b[4]={uint8_t(x),uint8_t(x>>8),uint8_t(x>>16),uint8_t(x>>24)};out_.write(reinterpret_cast<const char*>(b),4);}
 out_.write(reinterpret_cast<const char*>(data),caplen);
 if(!out_) throw std::runtime_error("Capture write failed");
}
void PcapWriter::flush() {out_.flush();}
}
