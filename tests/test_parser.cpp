#include "netscope/parser.hpp"
#include "netscope/pcap.hpp"
#include <cassert>
#include <iostream>
#include <vector>
int main(int argc,char** argv) {
 (void)argc;(void)argv;
 std::vector<uint8_t> packet(14+20+8,0);
 packet[12]=0x08;packet[13]=0x00;
 packet[14]=0x45;packet[16]=0;packet[17]=28;packet[23]=17;
 packet[26]=192;packet[27]=168;packet[28]=1;packet[29]=10;
 packet[30]=8;packet[31]=8;packet[32]=8;packet[33]=8;
 packet[34]=0x30;packet[35]=0x39;packet[36]=0;packet[37]=53;
 packet[38]=0;packet[39]=8;
 auto p=netscope::decode_ethernet(packet);
 assert(p && p->protocol=="UDP" && p->source_ip=="192.168.1.10" && p->destination_ip=="8.8.8.8");
 assert(p->source_port==12345 && p->destination_port==53);
 for(size_t n=0;n<packet.size();++n) assert(!netscope::decode_ethernet(std::span(packet.data(),n)));
 packet[12]=0x86;assert(!netscope::decode_ethernet(packet));
 std::cout<<"Parser tests passed\n";
}
