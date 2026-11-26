"""Generate deterministic synthetic Ethernet/IPv4 TCP/UDP/ICMP frames for GUI demos.
This is synthetic traffic, not a recording of real users or networks.
"""
from pathlib import Path
import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    value = sum(words)
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def frame(src, dst, proto, sport=0, dport=0, payload=b'', serial=1):
    eth = bytes.fromhex('00112233445566778899aabb0800')
    if proto == 6:
        transport = struct.pack('!HHIIHHHH', sport, dport, serial, 0, (5 << 12) | 0x18, 4096, 0, 0) + payload
    elif proto == 17:
        transport = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        body = struct.pack('!BBHHH', 8 if serial % 2 else 0, 0, 0, serial & 0xffff, 1) + payload
        transport = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    source = ipaddress.IPv4Address(src).packed
    dest = ipaddress.IPv4Address(dst).packed
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), serial & 0xffff, 0, 64, proto, 0, source, dest)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return eth + ip + transport


frames = []
for i in range(240):
    if i % 6 in (0, 1, 2):
        frames.append(frame('192.168.10.10', '10.20.0.5', 6, 51000 + i % 4, 443, b'TLS demo data ' + bytes([i % 256]) * (i % 45), i + 1))
    elif i % 6 in (3, 4):
        frames.append(frame('192.168.10.20', '8.8.8.8', 17, 52000 + i % 3, 53, b'DNS demo ' + bytes([i % 256]) * (i % 20), i + 1))
    else:
        frames.append(frame('192.168.10.30', '10.20.0.1', 1, payload=b'ping' + bytes([i % 256]) * 8, serial=i + 1))

out = Path(__file__).resolve().parent.parent / 'showcase.pcap'
with out.open('wb') as f:
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, packet in enumerate(frames):
        f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000, len(packet), len(packet)))
        f.write(packet)
print(f'Created {out} with {len(frames)} synthetic frames')
