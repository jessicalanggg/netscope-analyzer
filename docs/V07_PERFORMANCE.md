# NetScope v0.7 — Performance baseline and GUI safety limit

## New command

`netscope benchmark showcase.pcap` processes the capture using the streaming PCAP reader, without retaining raw packets in a GUI table. It reports elapsed wall-clock time, frames/second, IPv4 count, and directional flows. Run multiple times and use larger captures for representative measurements. Timings include file I/O and decoding, and vary by hardware and cache.

## GUI safety limit

The GUI stops loading after 100,000 packets and displays a safety-limit message in the status bar. This is a **packet-count cap, not a memory bound**: PCAP records may be up to 16 MiB each and the GUI still stores raw bytes and decoded metadata in memory. The CLI benchmark does not impose the GUI cap. The cap prevents accidental runaway GUI allocations on ordinary captures but does not guarantee low memory usage.

## Scope and limitations

The GUI remains an in-memory viewer. The background worker still reads into a temporary vector before swapping it into the UI; progress remains indeterminate. The next architecture milestone is a file-offset index and on-demand packet reads, with a bounded cache and explicit cancellation.

## Windows build

Use the MSYS2 UCRT64 toolchain and Qt 6.12 as in v0.6. Run `ctest --test-dir build --output-on-failure` and `netscope benchmark showcase.pcap`.
