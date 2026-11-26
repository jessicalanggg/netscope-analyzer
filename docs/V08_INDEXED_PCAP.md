# NetScope v0.8 — Indexed PCAP and bounded raw packet cache

- The index stores one offset, timestamp, and length pair per packet. It supports classic Ethernet PCAP, not pcapng.
- The GUI background loader decodes packets sequentially and retains **metadata only**; raw packet bytes are read on selection.
- The LRU cache defaults to 64 MiB of raw bytes. A single packet larger than the budget is returned without caching.
- The GUI still retains per-packet decoded metadata, flow state, and timeline. Memory therefore grows with packet and flow count; this is **not** constant-memory capture analysis.
- The index constructor scans record headers and validates lengths. The GUI currently reads each packet separately during its background decode pass; performance can be improved by streaming sequentially.
- If the capture file changes after indexing, selected raw bytes may be stale or fail to load; do not modify the PCAP while it is open.
- The existing CLI benchmark is unchanged and does **not** measure the new GUI index/cache path.
- GUI compilation requires Qt6 Widgets and Windows verification.
