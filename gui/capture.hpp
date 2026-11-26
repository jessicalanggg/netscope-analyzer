#pragma once
#include "netscope/parser.hpp"
#include <cstdint>
#include <vector>
struct CapturedPacket {
 uint32_t captured_length=0;
 uint64_t timestamp_us=0;
 bool decoded=false;
 netscope::Packet packet;
};
