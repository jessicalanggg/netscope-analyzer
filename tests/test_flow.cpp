#include "netscope/flow.hpp"
#include <cassert>
#include <iostream>
using namespace netscope;
int main(){
 FlowTracker tracker;
 Packet a; a.source_ip="192.168.1.10"; a.destination_ip="10.0.0.20";
 a.protocol="TCP"; a.source_port=51000; a.destination_port=443; a.frame_length=100;
 tracker.observe(a); tracker.observe(a);
 assert(tracker.flow_count()==1);
 auto rows=tracker.top_flows();
 assert(rows.size()==1 && rows[0].stats.packets==2 && rows[0].stats.bytes==200);
 Packet b=a; b.source_port=51001; b.frame_length=70;
 tracker.observe(b);
 assert(tracker.flow_count()==2);
 rows=tracker.top_flows();
 assert(rows[0].key.source_port==51000 && rows[1].key.source_port==51001);
 assert(tracker.top_flows(1).size()==1);
 Packet reverse=a; reverse.source_ip=a.destination_ip; reverse.destination_ip=a.source_ip;
 reverse.source_port=443; reverse.destination_port=51000;
 tracker.observe(reverse);
 assert(tracker.flow_count()==3);
 Packet fragment=a; fragment.protocol="IPv4-fragment";
 tracker.observe(fragment);
 assert(tracker.flow_count()==3);
 std::cout<<"Flow tests passed\n";
}
