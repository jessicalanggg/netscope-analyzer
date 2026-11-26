# NetScope v0.9 — Large-capture performance baseline

## Changes
- Added `benchmark-index` CLI command: repeats index construction and reports median time, packet count, and approximate allocated index-entry capacity.
- Replaced per-packet file reopen during GUI background load with one sequential packet scan after index creation. Raw bytes remain on disk except for selected packets in the LRU cache.
- Added deterministic streaming synthetic-PCAP generator and sequential-vs-index consistency regression test.

## Generate and benchmark (Windows PowerShell)
```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
python scripts/make_benchmark_pcap.py --packets 100000 --output benchmark_100k.pcap
.\build\netscope.exe benchmark benchmark_100k.pcap
.\build\netscope.exe benchmark-index benchmark_100k.pcap 5
```
For a larger test: `python scripts/make_benchmark_pcap.py --packets 1000000 --output benchmark_1m.pcap`.

## Observe memory usage (Windows PowerShell)
Launch GUI and open the generated capture, then from another PowerShell window:
```powershell
Get-Process netscope-gui | Select-Object ProcessName, @{N='WorkingSetMiB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, @{N='PrivateMiB';E={[math]::Round($_.PrivateMemorySize64/1MB,1)}}
```
Record idle, post-load, and post-inspection readings. These are process measurements, **not** just raw-packet cache size.

## Interpretation and limitations
- `benchmark` measures the streaming CLI parser/flow pipeline; `benchmark-index` measures index construction alone. Do not compare them as if they perform the same work.
- Index-capacity bytes are `vector.capacity() * sizeof(PacketIndexEntry)`, not total process memory.
- Synthetic traffic is not a representative real-world protocol mix. Repeat tests, use Release builds, and compare median times on the same hardware.
- GUI retains decoded packet metadata and flow aggregates; memory is not fully bounded. The GUI has not been verified on Windows for this release.
- Classic Ethernet PCAP only; pcapng is not supported.
