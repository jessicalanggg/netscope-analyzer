"""Generate synthetic Ethernet/IPv4/UDP packets; no capture permissions required."""
import struct
from pathlib import Path

def packet(src, dst, sport, dport):
    eth = bytes.fromhex('00112233445566778899aabb0800')
    ip = struct.pack('!BBHHHBBH4s4s', 0x45,0,28,1,0,64,17,0,bytes(src),bytes(dst))
    udp = struct.pack('!HHHH',sport,dport,8,0)
    return eth+ip+udp

out=Path(__file__).resolve().parent.parent/'demo.pcap'
frames=[packet((192,168,1,10),(8,8,8,8),12345,53),packet((192,168,1,10),(1,1,1,1),12346,53),packet((10,0,0,2),(192,168,1,10),50000,443)]
with out.open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i,p in enumerate(frames):
        f.write(struct.pack('<IIII',i,0,len(p),len(p)))
        f.write(p)
print(f'Created {out} ({len(frames)} synthetic packets)')
