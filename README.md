# NetScope

**A fast packet analyzer in C++20, with a Qt 6 desktop GUI and a CLI.** It reads pcap and
pcapng files or captures live traffic. It decodes Ethernet/VLAN, IPv4 and IPv6, and TCP, UDP and
ICMP, then builds flows and conversations and reassembles every TCP stream. Its results are checked
against Wireshark in CI.

## NetScope vs Wireshark (tshark 4.6.10)

The comparison is one pass over the same file for both tools. NetScope runs `analyze`, which includes full
TCP reassembly. tshark runs `-n -q -z conv,tcp -z conv,udp -z io,phs`. Timings are the median of 3 warm
runs on an Apple Silicon Mac (10 cores), using synthetic mixed traffic.

| Capture | Frames | Size | NetScope | tshark | Speedup | Peak RSS (NetScope / tshark) |
|---|---:|---:|---:|---:|---:|---:|
| mixed_1m.pcap | 1,000,000 | 569 MB | 2.92 s | 30.08 s | **10.3×** | 65 MB / 578 MB |
| mixed_1m.pcapng | 1,000,000 | 587 MB | 2.14 s | 26.32 s | **12.3×** | 68 MB / 612 MB |
| mixed_100k.pcap | 100,000 | 57 MB | 0.28 s | 3.41 s | **12.1×** | 8 MB / 215 MB |
| mixed_100k.pcapng | 100,000 | 59 MB | 0.25 s | 3.95 s | **15.7×** | 9 MB / 215 MB |

**Correctness against tshark**: on every capture above, both tools report the same frame count, the
same TCP stream count (35,603 on the 1M capture) and the same TCP+UDP conversation count. For 60
sampled streams per capture, the reassembled payload is **byte-identical** in both directions. More
than half of the sampled streams contain reordered or retransmitted segments. The
`wireshark-parity` CI job repeats this check on every push.

> These numbers compare a purpose-built L2–L4 analyzer with Wireshark's full dissection engine, which
> decodes thousands of protocols. NetScope is faster because it does less work per packet, not because
> it replaces Wireshark. Reproduce the comparison with `scripts/bench_vs_tshark.py` (see below).


## Features

- **Formats**: classic pcap (µs/ns, either byte order) and **pcapng**. pcapng files may have several
  sections and interfaces, EPB/SPB blocks, and per-interface timestamp resolution.
- **Link types**: Ethernet with **802.1Q/802.1ad VLAN** (QinQ), raw IP, BSD loopback, Linux cooked capture.
- **Protocols**: IPv4 (fragments), **IPv6** (extension headers, fragments, RFC 5952 addresses),
  TCP, UDP, ICMP, ICMPv6.
- **TCP stream reassembly**: handles sequence-number wraparound, out-of-order segments, retransmissions
  and overlaps. Buffering is capped per stream, and abandoned gaps are counted. Stream numbering
  matches Wireshark's `tcp.stream`.
- **Live capture**: libpcap feeds a capture thread, which passes packets through a **lock-free SPSC
  ring buffer** to the analysis thread. Per-second rates are printed, and ring drops and kernel drops
  are counted separately. BPF filters, packet-count and duration limits, and `-w` to save the capture.
- **Analytics**: directional 5-tuple flows, bidirectional conversations, observed TCP state, a traffic
  timeline, and CSV export (GUI).
- **Large files**: a packet-offset index loads raw bytes on demand, with a capped LRU cache, and
  loading runs in the background (GUI).

## Usage

```text
netscope analyze  <capture>                  protocols, talkers, flows, conversations, TCP stream stats
netscope streams  <capture>                  every reassembled TCP stream (TSV)
netscope follow   <capture> <id[,id]> [--raw] stream contents; --raw output matches tshark follow,tcp,raw
netscope benchmark <capture> [runs]          time the full pipeline
netscope interfaces                          list capture interfaces
netscope capture  <iface> [-c N] [-d SEC] [-f BPF] [-w out.pcap] [-p] [-q] [--ring MiB]
```

```text
$ netscope capture lo0 -f "port 47123 or port 47124" -d 4 -w live.pcap
Capturing on lo0 (linktype 0, ring 64 MiB) filter: port 47123 or port 47124 — Ctrl-C to stop
[   2.0s] 86 pkts  86 pps  1.64 Mbps  ring 0.0%  drops ring=0 kernel=0
...
Decoded IP: 86 (IPv4 36, IPv6 50, VLAN-tagged 0)
TCP streams: 1
  Reassembled payload bytes: 200010
Capture: captured=86 analyzed=86 ring_drops=0 kernel_drops=0 interface_drops=0
```

Live capture needs permission. On macOS, install Wireshark's ChmodBPF (it adds you to `access_bpf`).
On Linux, run as root or give the binary `cap_net_raw,cap_net_admin`.

## Architecture

```text
 pcap / pcapng file ──> CaptureReader ──┬──> Analyzer ──> decode_frame (Eth/VLAN/SLL/loopback/raw → IPv4/IPv6 → TCP/UDP/ICMP)
                                        │                 ├─> FlowTracker, ConversationTracker, timeline
 live interface ──> libpcap ──> capture │                 └─> TcpReassembler ──> follow / streams / stats
                    thread ──> PacketRing (lock-free SPSC) ┘
                                        └──> IndexedPcap ──> LRU raw-byte cache ──> Qt GUI (table, details, hex, dashboard)
```

Design notes: [docs/V11_PROTOCOLS_REASSEMBLY_LIVE.md](docs/V11_PROTOCOLS_REASSEMBLY_LIVE.md) and the earlier `docs/V0*` files.

## Build

**macOS** (Apple Silicon or Intel). libpcap comes with the SDK:

```bash
brew install cmake ninja qt
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$(brew --prefix qt)"
cmake --build build && ctest --test-dir build --output-on-failure
open build/netscope-gui.app
```

**Linux** (CLI):

```bash
sudo apt-get install -y cmake libpcap-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNETSCOPE_BUILD_GUI=OFF
cmake --build build && ctest --test-dir build --output-on-failure
```

**Windows**: build with MSYS2 UCRT64 and Qt 6. Live capture needs the Npcap SDK on `CMAKE_PREFIX_PATH`;
without it the build is offline-only.

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64 -DNETSCOPE_PACKAGE_WINDOWS=ON
cmake --build build; ctest --test-dir build --output-on-failure
cmake --build build --target package-windows   # portable ZIP with Qt and its dependent DLLs
```

## Reproducing the Wireshark comparison

```bash
python3 scripts/make_mixed_pcap.py --packets 1000000 --output mixed_1m.pcap
editcap -F pcapng mixed_1m.pcap mixed_1m.pcapng
python3 scripts/bench_vs_tshark.py --netscope build/netscope mixed_1m.pcap mixed_1m.pcapng
```

The generator writes deterministic synthetic traffic: interleaved TCP sessions with handshakes,
teardowns, and some reordered and retransmitted segments, plus DNS-like UDP and ICMP. About 25% is
IPv6 and about 15% is VLAN-tagged. No real hosts or payloads are included.

## Testing

There are 11 CTest suites. They run in Release builds with assertions enabled, on Linux, Windows,
macOS arm64 and macOS x86-64. A separate CI job checks the results against tshark, and Linux CI runs
a live loopback capture.

## Limitations

- tshark dissects thousands of protocols; NetScope decodes L2–L4 only. It has no application-layer
  dissectors, IP defragmentation, checksum validation or IDS.
- TCP state is *observed* from flags; NetScope does not run a full protocol state machine.
- Benchmarks use synthetic traffic on a single machine. Real capture mixes behave differently.
- The parser rejects malformed input with bounds checks and is tested on every truncated prefix, but
  it has not been fuzzed. Treat captures from untrusted sources with care.

## License

MIT, see `LICENSE`. Qt and MSYS2 libraries keep their own licenses.
