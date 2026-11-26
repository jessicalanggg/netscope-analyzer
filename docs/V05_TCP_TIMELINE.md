# NetScope v0.5 — TCP inspection and traffic analytics

## New functionality
- TCP sequence/acknowledgment numbers, TCP header length, window and decoded flags; IPv4 TTL/header length.
- PCAP microsecond/nanosecond timestamps normalized to microseconds; one-second packet/byte aggregation.
- Dashboard timeline, sortable flow columns, CSV exports for all loaded packets and flows.
- Four core CTest suites, including PCAP timeline verification.

## Notes and limitations
- Classic Ethernet PCAP only; PCAPNG is not supported.
- Offline captures are fully loaded in memory; large files need a streaming model in a later release.
- Timeline uses UTC second buckets and displays raw captured frame lengths.
- TCP decoding is header-level; no stream reassembly or TLS decryption.
- CSV exports all loaded packets (not only the currently filtered packet table).
- GUI is Qt 6 Widgets and requires Windows/MSYS2 UCRT64 validation.
