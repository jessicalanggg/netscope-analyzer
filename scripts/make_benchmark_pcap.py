#!/usr/bin/env python3
"""Generate a deterministic classic Ethernet PCAP without holding packets in RAM.
Synthetic traffic only. Do not treat its throughput as representative of real captures.
"""
import argparse
import ipaddress
import struct
from pathlib import Path


def make_packet(i: int, payload_size: int) -> bytes:
    # Ethernet + IPv4 + UDP; no IP fragmentation; consistent header lengths.
    src_ip = ipaddress.IPv4Address(0x0A000001 + (i % 128)).packed
    dst_ip = ipaddress.IPv4Address(0xC0000201 + ((i // 128) % 64)).packed
    udp_length = 8 + payload_size
    ip_length = 20 + udp_length
    eth = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_length, i % 65536, 0, 64, 17, 0, src_ip, dst_ip)
    udp = struct.pack("!HHHH", 40000 + (i % 1024), 53, udp_length, 0)
    return eth + ipv4 + udp + bytes([i % 256]) * payload_size


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--payload", type=int, default=32)
    parser.add_argument("--output", type=Path, default=Path("benchmark_100k.pcap"))
    args = parser.parse_args()
    if not 1 <= args.packets <= 10000000 or not 0 <= args.payload <= 1400:
        parser.error("packets must be 1..10,000,000; payload must be 0..1400")
    with args.output.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(args.packets):
            pkt = make_packet(i, args.payload)
            f.write(struct.pack("<IIII", 1700000000 + i // 1000, (i % 1000) * 1000, len(pkt), len(pkt)))
            f.write(pkt)
    print(f"Generated {args.packets:,} packets: {args.output} ({args.output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
