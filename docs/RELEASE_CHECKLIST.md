# NetScope v1.0 — Release gates

## Core
- [ ] Configure Release build and run all CTest suites on Windows.
- [ ] Confirm 240 showcase packets and correct packet/flow/conversation details.
- [ ] Confirm 100,000-packet synthetic PCAP loads without UI crash.
- [ ] Capture before/after GUI memory using the *same process ID*.
- [ ] Record analysis/index benchmark results, CPU, OS, build type, capture size.

## Portable Windows distribution
- [ ] Run `cmake --build build --target package-windows` from a clean build.
- [ ] Confirm the target completes without unresolved dependency errors.
- [ ] Confirm ZIP includes `netscope-gui.exe`, `netscope.exe`, `platforms/qwindows.dll`, `showcase.pcap` and `manifest.json`.
- [ ] Extract ZIP to a new directory and test with MSYS2 removed from PATH.
- [ ] Repeat on a second Windows PC or clean Windows VM with no MSYS2/Qt installed.
- [ ] Confirm theme changes, file open, packet hex inspection and CSV export.
- [ ] Review third-party redistribution notices and licenses before publishing.

## Publication
- [ ] Add real screenshots and a short screen recording (do not fabricate UI shots).
- [ ] Publish reproducible build/test commands and measured benchmarks.
- [ ] Link CI results; describe unsupported PCAP formats and security limitations.
- [ ] Tag `v1.0.0` only after the Windows portable test passes.
