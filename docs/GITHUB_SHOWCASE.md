# GitHub showcase guide

## Suggested repository description
NetScope — cross-platform C++20/Qt 6 PCAP analyzer with indexed packet access, LRU caching, flow analytics, and a desktop packet explorer.

## Suggested repository topics
cpp, cpp20, qt6, networking, pcap, packet-analysis, cmake, desktop-app, systems-programming

## Demo (2–3 minutes)
1. Open `showcase.pcap` in the GUI; show the packet table, filters, decoded fields and hex view.
2. Navigate to directional flows and bidirectional conversations; discuss inferred TCP states.
3. Explain the classic PCAP reader, offset index and bounded raw-byte cache.
4. Run `ctest --test-dir build --output-on-failure` and show the CLI benchmark command.
5. State the limitations: classic PCAP only, Ethernet II/IPv4, no live capture, no stream reassembly.

## Portfolio bullet (adapt to personal contribution)
Built a C++20/Qt 6 offline PCAP analysis application featuring Ethernet/IPv4/TCP/UDP/ICMP parsing, bidirectional flow aggregation, indexed packet access, and LRU caching; implemented CMake/CTest automation and reproducible Windows dependency packaging.

## Screenshot checklist
- Packet table and decoded packet details
- Conversation analytics
- Protocol dashboard
- Theme comparison

Only add real screenshots taken from a running build; do not publish fabricated UI captures. Document benchmark hardware and dataset before using throughput claims.
