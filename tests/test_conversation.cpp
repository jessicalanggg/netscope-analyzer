#include "netscope/conversation.hpp"
#include <cassert>
#include <iostream>
using namespace netscope;
int main(){
 ConversationTracker t;
 Packet a; a.protocol="TCP";a.source_ip="10.0.0.1";a.destination_ip="10.0.0.2";a.source_port=50000;a.destination_port=443;a.frame_length=100;a.tcp_flags=0x02;
 t.observe(a,1000000);
 Packet b=a;b.source_ip=a.destination_ip;b.destination_ip=a.source_ip;b.source_port=443;b.destination_port=50000;b.frame_length=200;b.tcp_flags=0x12;
 t.observe(b,1100000);
 a.tcp_flags=0x10;t.observe(a,1200000);
 assert(t.count()==1);
 auto r=t.top_conversations();assert(r.size()==1);
 assert(r[0].stats.packets()==3&&r[0].stats.bytes()==400);
 assert(r[0].stats.packets_a_to_b==2&&r[0].stats.packets_b_to_a==1);
 assert(r[0].stats.duration_us()==200000);
 assert(r[0].stats.tcp_state()=="Established (observed)");
 assert(r[0].stats.throughput_bps()==16000);
 a.tcp_flags=0x01;t.observe(a,1300000);
 assert(t.top_conversations()[0].stats.tcp_state()=="Half-closed");
 b.tcp_flags=0x11;t.observe(b,1400000);
 assert(t.top_conversations()[0].stats.tcp_state()=="Closing/Closed");
 b.tcp_flags=0x04;t.observe(b,1500000);
 assert(t.top_conversations()[0].stats.tcp_state()=="Reset");
 Packet udp=a;udp.protocol="UDP";udp.tcp_flags=0;
 t.observe(udp,2000000);assert(t.count()==2);
 Packet ignored=a;ignored.protocol="ICMP";t.observe(ignored,2000000);assert(t.count()==2);
 auto before=t.count();t.observe(udp,1900000);assert(t.count()==before);
 std::cout<<"Conversation tests passed\n";
}
