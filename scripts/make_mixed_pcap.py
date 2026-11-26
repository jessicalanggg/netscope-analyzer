#!/usr/bin/env python3
"""Generate a deterministic, realistic-shaped synthetic capture for benchmarking.

Traffic mix (by session): TCP request/response sessions with full handshakes and
teardowns, some reordered and retransmitted segments; DNS-like UDP; ICMP echo.
About a quarter of sessions are IPv6 and ~15% carry an 802.1Q VLAN tag.
Synthetic data only: no real hosts or payloads.
"""
import argparse
import random
import struct
from pathlib import Path

ETH_SRC, ETH_DST = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def eth(ethertype, vlan):
    tag = struct.pack("!HH", 0x8100, vlan) if vlan else b""
    return ETH_DST + ETH_SRC + tag + struct.pack("!H", ethertype)


def ipv4(src, dst, proto, l4):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0, src, dst) + l4


def ipv6(src, dst, proto, l4):
    return struct.pack("!IHBB16s16s", 0x60000000, len(l4), proto, 64, src, dst) + l4


def tcp(sp, dp, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 0x50, flags, 65535, 0, 0) + payload


def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


class Session:
    def __init__(self, rng, i):
        self.v6 = rng.random() < 0.25
        self.vlan = rng.choice([10, 20, 30]) if rng.random() < 0.15 else 0
        if self.v6:
            self.c = bytes.fromhex("20010db8000000000000000000") + struct.pack("!H", i % 4096)[0:2] + bytes([i % 251])
            self.s = bytes.fromhex("20010db8ffff000000000000000000") + bytes([1 + i % 7])
        else:
            self.c = bytes([10, (i >> 16) & 255, (i >> 8) & 255, i & 255 or 1])
            self.s = bytes([192, 0, 2, 1 + i % 20])
        self.cp = 1024 + (i * 7) % 60000

    def frame(self, from_client, proto, l4):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        ip = ipv6(src, dst, proto, l4) if self.v6 else ipv4(src, dst, proto, l4)
        return eth(0x86DD if self.v6 else 0x0800, self.vlan) + ip


def tcp_session(rng, s):
    cs, ss = rng.getrandbits(32), rng.getrandbits(32)
    port = rng.choice([80, 443, 8080, 5432, 6379])
    c = lambda flags, seq, ack, pl=b"": s.frame(True, 6, tcp(s.cp, port, seq, ack, flags, pl))
    v = lambda flags, seq, ack, pl=b"": s.frame(False, 6, tcp(port, s.cp, seq, ack, flags, pl))
    out = [c(0x02, cs, 0), v(0x12, ss, cs + 1), c(0x10, cs + 1, ss + 1)]
    cseq, sseq = cs + 1, ss + 1
    for _ in range(rng.randint(1, 4)):                       # request/response rounds
        req = bytes(rng.getrandbits(8) for _ in range(rng.randint(40, 600)))
        out.append(c(0x18, cseq, sseq, req)); cseq += len(req)
        segs = []
        for _ in range(rng.randint(1, 12)):
            pl = bytes([rng.getrandbits(8)]) * rng.randint(200, 1400)
            segs.append(v(0x18, sseq, cseq, pl)); sseq += len(pl)
        if len(segs) > 2 and rng.random() < 0.05:            # reorder two segments
            k = rng.randrange(len(segs) - 1); segs[k], segs[k + 1] = segs[k + 1], segs[k]
        if segs and rng.random() < 0.03:                     # retransmit one
            segs.append(segs[rng.randrange(len(segs))])
        out += segs
        out.append(c(0x10, cseq, sseq))
    out += [c(0x11, cseq, sseq), v(0x11, sseq, cseq + 1), c(0x10, cseq + 1, sseq + 1)]
    return out


def udp_session(rng, s):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes(rng.getrandbits(8) for _ in range(rng.randint(12, 40)))
    return [s.frame(True, 17, udp(s.cp, 53, q)), s.frame(False, 17, udp(53, s.cp, q + bytes(rng.randint(16, 200))))]


def icmp_session(rng, s):
    if s.v6:
        return [s.frame(True, 58, struct.pack("!BBHHH", 128, 0, 0, 1, 1) + bytes(32)),
                s.frame(False, 58, struct.pack("!BBHHH", 129, 0, 0, 1, 1) + bytes(32))]
    return [s.frame(True, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + bytes(32)),
            s.frame(False, 1, struct.pack("!BBHHH", 0, 0, 0, 1, 1) + bytes(32))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if not 1 <= args.packets <= 20_000_000:
        ap.error("packets must be 1..20,000,000")
    rng = random.Random(args.seed)
    written, i, ts = 0, 0, 1_700_000_000_000_000
    active = []  # interleave sessions so streams overlap in time, like real traffic
    with args.output.open("wb", buffering=1 << 20) as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        while written < args.packets:
            while len(active) < 64:
                s = Session(rng, i); i += 1
                r = rng.random()
                pkts = tcp_session(rng, s) if r < 0.70 else udp_session(rng, s) if r < 0.95 else icmp_session(rng, s)
                active.append(iter(pkts))
            k = rng.randrange(len(active))
            pkt = next(active[k], None)
            if pkt is None:
                active.pop(k); continue
            ts += rng.randint(1, 200)
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(pkt), len(pkt)))
            f.write(pkt)
            written += 1
    print(f"Generated {written:,} packets from {i:,} sessions: {args.output} ({args.output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
