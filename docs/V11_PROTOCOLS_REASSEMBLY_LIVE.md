# NetScope v1.1: pcapng, IPv6/VLAN, TCP reassembly, live capture, Wireshark parity

## Capture formats (`src/pcap.cpp`)
`CaptureReader` is the single parser behind streaming reads (`read_pcap_records`) and the
packet-offset index (`IndexedPcap`), so the CLI, the GUI and random access all accept the same files.

- **Classic pcap**: µs and ns magic, either byte order, any link type (the upper FCS bits are masked).
- **pcapng**: multiple sections (each SHB resets byte order and interfaces), multiple interfaces
  with different link types, Enhanced, Simple and legacy Packet Blocks, `if_tsresol` (decimal and
  binary) and `if_tsoffset`. Unknown blocks (NRB, ISB, DSB, custom) are skipped after their
  trailing length is checked.
- **Validation**: every block's leading and trailing lengths must match and stay inside the file.
  Captured length can't exceed the block or 16 MiB, and a packet that names an undeclared interface
  is rejected. Malformed files raise an error and are never read past their actual contents.
- **I/O**: one 1 MiB stream buffer, and the packet buffer is reused between records, so there is no
  allocation per packet.

## Decoding (`src/parser.cpp`)
`decode_frame(linktype, bytes)` supports Ethernet, raw IP (101/228/229), BSD/OpenBSD loopback (0/108)
and Linux cooked capture (113). On top of those:

- **VLAN**: 802.1Q, 802.1ad and 0x9100 tags, stacked up to four deep. The outer VLAN ID is recorded.
- **IPv6**: the extension-header walk handles hop-by-hop, routing, destination options, fragment and
  AH headers. Each step advances at least 8 bytes and is checked against the payload length. Non-first
  fragments are labelled `IPv6-fragment`. Addresses are printed in RFC 5952 form (`2001:db8::1`, `::ffff:1.2.3.4`).
- **Transport payload bounds** come from the IP length fields, so Ethernet padding never counts as
  TCP payload.

## TCP stream reassembly (`src/reassembly.cpp`)
- Streams are numbered in order of first appearance, the same way Wireshark assigns `tcp.stream`.
  A fresh SYN on a stream that already closed or reset starts a new stream (port reuse).
- Each direction tracks its ISN and a 64-bit "next expected" offset. 32-bit sequence numbers are
  unwrapped relative to that offset, so wraparound past 2^32 is handled transparently.
- In-order data is delivered right away. Segments that arrive early are buffered in an ordered map
  and drained once the hole fills. Duplicate and overlapping bytes are trimmed and counted as
  retransmissions.
- **Memory is bounded**: once a direction buffers more than `max_buffered_per_direction` (8 MiB by
  default), the oldest hole is abandoned and counted as `missing_bytes`. `finish()` flushes any
  remaining holes the same way.
- Stats for each stream and direction: segments, payload bytes, delivered bytes, retransmitted bytes,
  out-of-order segments, missing bytes, and SYN/FIN/RST flags.

## Live capture (`src/live_capture.cpp`, `include/netscope/ring_buffer.hpp`)
```
libpcap (kernel BPF buffer) ──> capture thread ──> PacketRing (lock-free SPSC) ──> analysis thread
                                 pcap_dispatch,       one preallocated arena,        decode, flows,
                                 copy + timestamp     variable-length records         reassembly, -w writer
```
- **`PacketRing`** is a single-producer/single-consumer ring of variable-length records in one
  power-of-two arena. Head and tail are monotonic 64-bit counters on separate cache lines; the
  producer keeps a private cached copy of the tail. A wrap marker is used when a record doesn't fit
  at the end of the arena.
- **The capture thread never blocks.** When the ring is full the packet is dropped and counted
  (`ring_drops`), and that count is reported separately from kernel drops (`pcap_stats`) and
  interface drops.
- Capture stops on a packet count (`-c`), a duration (`-d`) or Ctrl-C. A failure during analysis
  stops and joins the capture thread before the error is reported.
- The feature is built only when CMake finds libpcap (macOS SDK, Linux `libpcap-dev`, or the Windows
  Npcap SDK). Otherwise `capture` reports that live capture isn't available in this build.

## Wireshark parity and benchmark (`scripts/bench_vs_tshark.py`)
The script runs both tools on the same captures and checks:
1. Total frame count.
2. TCP stream count and TCP+UDP conversation count against `tshark -z conv,tcp -z conv,udp`.
3. Byte-identical reassembled payload, per direction, for a sample of streams, using
   `netscope follow ... --raw` and `tshark -z follow,tcp,raw,N`. At least half of the sample is drawn
   from streams that contain reordered or retransmitted segments.

It exits non-zero on any mismatch. The `wireshark-parity` CI job runs it on every push, on both
pcap and pcapng.

**What the speed numbers mean.** NetScope decodes a fixed set of layers (L2–L4) and reassembles TCP.
tshark runs full protocol dissection for every packet. NetScope is faster because it does
*less work*: it is a purpose-built analyzer for this one job. It does not replace Wireshark's
dissectors.

## Tests added
`ipv6_vlan_tests`, `pcapng_tests`, `reassembly_tests` and `ring_buffer_tests` cover RFC 5952
formatting, extension headers, fragments, QinQ, every-prefix truncation and Ethernet padding. They
also round-trip all 240 showcase packets through pcapng, mix byte orders and timestamp resolutions,
reject malformed blocks, reassemble across the ISN wrap with OOO, duplicate and overlap cases, handle
port reuse and the memory bound, and run a two-thread stress test of 500k ring records.

Earlier test suites used `assert()` while CI built in Release, where `NDEBUG` disables `assert()`, so
those tests checked nothing. Test targets now compile with `-UNDEBUG` (`/UNDEBUG` on MSVC).
