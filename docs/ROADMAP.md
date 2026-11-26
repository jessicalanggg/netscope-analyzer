# NetScope Eight-Week Roadmap

| Week | Milestone | Acceptance criteria |
|---|---|---|
| 1 | CMake, Git, byte reading | Clean Windows/Linux build and test |
| 2 | Ethernet/IPv4 | Valid and truncated frame tests |
| 3 | TCP/UDP/ICMP | Protocol decoding and malformed length tests |
| 4 | PCAP ingestion | Multiple records and invalid-file tests |
| 5 | Flow tracking | Five-tuple counters and deterministic tests |
| 6 | Filters and exports | CLI filters, JSON/CSV schema tests |
| 7 | CI and profiling | Windows/Linux CI, sanitizer job, reproducible benchmark |
| 8 | Live capture (stretch), demo | Permission-aware capture, README, video and tagged release |

## Stretch goals
IPv6, 802.1Q VLAN, pcapng, flow expiry, TCP stream analysis, optional GUI.

## Demo script
1. Show repository architecture and CMake.
2. Run CTest.
3. Generate synthetic `demo.pcap`.
4. Run `netscope analyze demo.pcap` and explain packet/port counts.
5. Show malformed/truncated packet tests.
6. Open CI history and explain OS matrix.
7. Discuss limitations and security/privacy considerations.
