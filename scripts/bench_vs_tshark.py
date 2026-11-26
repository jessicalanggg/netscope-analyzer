#!/usr/bin/env python3
"""Benchmark NetScope against Wireshark's tshark and cross-check correctness.

For each capture:
  * Speed: wall time and peak RSS (median of N runs, after one warm-up run) for
      netscope analyze <cap>
      tshark -n -q -r <cap> -z conv,tcp -z conv,udp -z io,phs
    Both make one pass producing protocol hierarchy + TCP/UDP conversation tables;
    NetScope additionally reassembles every TCP stream.
  * Correctness vs tshark:
      - total frames
      - TCP and UDP conversation counts
      - byte-identical reassembled payload, per direction, for a sample of streams
        (netscope follow <ids> --raw  vs  tshark -z follow,tcp,raw,<id> ...)

Usage: python3 scripts/bench_vs_tshark.py --netscope build/netscope cap1.pcap [cap2.pcapng ...]
"""
import argparse
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time


def run_measured(cmd):
    """Run cmd, return (seconds, peak_rss_mb, stdout)."""
    start = time.perf_counter()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    elapsed = time.perf_counter() - start
    if p.returncode != 0:
        sys.exit(f"command failed ({p.returncode}): {' '.join(cmd)}\n{err.decode(errors='replace')}")
    return elapsed, out.decode(errors="replace")


def peak_rss_mb(cmd):
    """Peak RSS of a single run, via wait4()."""
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _, _, ru = os.wait4(p.pid, 0)
    p.returncode = 0
    scale = 1 if platform.system() == "Darwin" else 1024  # bytes on macOS, KiB on Linux
    return ru.ru_maxrss * scale / 1e6


def bench(cmd, runs):
    run_measured(cmd)  # warm page cache
    times = [run_measured(cmd)[0] for _ in range(runs)]
    return statistics.median(times), peak_rss_mb(cmd)


def parse_follow(text):
    """{stream: (node0_hex, node1_hex)} from `follow,tcp,raw` style output."""
    streams, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"Filter: tcp\.stream eq (\d+)", line)
        if m:
            cur = int(m.group(1)); streams[cur] = ["", ""]; continue
        if cur is None or not line or line.startswith(("=", "Follow:", "Node ")):
            continue
        if re.fullmatch(r"\t?[0-9a-f]+", line):
            streams[cur][1 if line.startswith("\t") else 0] += line.strip()
    return {k: tuple(v) for k, v in streams.items()}


def conv_rows(text, section):
    block = re.search(rf"{section} Conversations.*?\n(.*?)(?:\n=+)", text, re.S)
    return len(re.findall(r"<->", block.group(1))) if block else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--netscope", required=True)
    ap.add_argument("--tshark", default=shutil.which("tshark") or "tshark")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--sample", type=int, default=40, help="TCP streams to verify byte-for-byte")
    ap.add_argument("captures", nargs="+")
    a = ap.parse_args()

    ver = subprocess.run([a.tshark, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    print(f"# NetScope vs {ver}\n")
    print(f"Host: {platform.platform()}, {platform.machine()}, {os.cpu_count()} logical CPUs; median of {a.runs} runs after warm-up.\n")
    print("| Capture | Frames | Size | NetScope | tshark | Speedup | NetScope RSS | tshark RSS |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    checks = []
    for cap in a.captures:
        size_mb = os.path.getsize(cap) / 1e6
        ns_cmd = [a.netscope, "analyze", cap]
        ts_cmd = [a.tshark, "-n", "-q", "-r", cap, "-z", "conv,tcp", "-z", "conv,udp", "-z", "io,phs"]
        ns_t, ns_rss = bench(ns_cmd, a.runs)
        ts_t, ts_rss = bench(ts_cmd, a.runs)
        _, ns_out = run_measured(ns_cmd)
        _, ts_out = run_measured(ts_cmd)
        frames = int(re.search(r"Frames: (\d+)", ns_out).group(1))
        print(f"| {os.path.basename(cap)} | {frames:,} | {size_mb:,.1f} MB | {ns_t:.2f} s | {ts_t:.2f} s | "
              f"**{ts_t / ns_t:.1f}x** | {ns_rss:,.0f} MB | {ts_rss:,.0f} MB |")

        # --- correctness ---
        ts_frames = int(re.search(r"^frame\s+frames:(\d+)", ts_out, re.M).group(1))
        _, streams_tsv = run_measured([a.netscope, "streams", cap])
        ns_streams = len(streams_tsv.strip().splitlines()) - 1
        ns_conv = int(re.search(r"Conversations: (\d+)", ns_out).group(1))
        ts_tcp, ts_udp = conv_rows(ts_out, "TCP"), conv_rows(ts_out, "UDP")
        # Half the sample: streams with retransmitted or out-of-order segments (the hard cases);
        # the rest evenly spaced across the capture.
        rows = [r.split("\t") for r in streams_tsv.strip().splitlines()[1:]]
        hard = [int(r[0]) for r in rows if int(r[6]) or int(r[7])]
        ids = set(hard[: a.sample // 2])
        even = a.sample - len(ids)
        ids |= {round(i * (ns_streams - 1) / max(1, even - 1)) for i in range(even)} if ns_streams else set()
        ids = sorted(ids)
        hard_in_sample = len(set(hard) & set(ids))
        same = 0
        if ids:
            _, ns_f = run_measured([a.netscope, "follow", cap, ",".join(map(str, ids)), "--raw"])
            ts_args = [a.tshark, "-n", "-q", "-r", cap]
            for i in ids:
                ts_args += ["-z", f"follow,tcp,raw,{i}"]
            _, ts_f = run_measured(ts_args)
            ns_map, ts_map = parse_follow(ns_f), parse_follow(ts_f)
            same = sum(1 for i in ids if ns_map.get(i) == ts_map.get(i))
            sampled_bytes = sum(len(x) // 2 + len(y) // 2 for i, (x, y) in ns_map.items())
        else:
            sampled_bytes = 0
        checks.append((os.path.basename(cap), frames, ts_frames, ns_streams, ts_tcp, ns_conv, ts_tcp + ts_udp,
                       same, len(ids), sampled_bytes, hard_in_sample))

    print("\n## Correctness vs tshark\n")
    print("| Capture | Frames (NS / tshark) | TCP streams (NS / tshark) | TCP+UDP conversations (NS / tshark) | Sampled streams byte-identical | of which reordered/retransmitted |")
    print("|---|---|---|---|---|---:|")
    ok = True
    for name, f, tf, s, ts, c, tc, same, n, b, hard in checks:
        ok &= f == tf and s == ts and c == tc and same == n
        print(f"| {name} | {f:,} / {tf:,} | {s:,} / {ts:,} | {c:,} / {tc:,} | {same}/{n} ({b:,} bytes) | {hard} |")
    print("\nAll checks match." if ok else "\nMISMATCH detected.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
