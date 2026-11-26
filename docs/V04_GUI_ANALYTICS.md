# NetScope v0.4 — GUI analytics and packet filters

## What's new

- Resizable packet/detail/hex panes with more balanced initial sizes.
- First visible packet selected automatically; selection retained when possible after filtering.
- Packet row coloring: TCP blue, UDP green, ICMP amber.
- A filter engine in the **core library**, independent of Qt, with dedicated unit tests.
- Dashboard with protocol distribution and top source IPs shown as progress bars.
- `showcase.pcap`: 240 deterministic synthetic TCP, UDP, and ICMP frames for demonstrating GUI features.

## Filter syntax

| Example | Meaning |
|---|---|
| `tcp` | TCP only |
| `udp` | UDP only |
| `icmp` | ICMP only |
| `ip.src == 192.168.10.10` | Exact source IP |
| `ip.dst == 8.8.8.8` | Exact destination IP |
| `tcp.port == 443` | TCP with either port 443 |
| `udp.port == 53` | UDP with either port 53 |
| `port == 443` | TCP or UDP with either port 443 |
| `frame.number == 1` | Frame number 1 |
| `192.168.10` | Case-insensitive substring search of packet display fields |

Unsupported expressions show an error message rather than silently matching packets. `==` is supported; complex Boolean expressions (`and`, `or`, parentheses) are **not** supported in v0.4.

## Windows build (PowerShell)

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64 -DNETSCOPE_BUILD_GUI=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\netscope-gui.exe
```

Open `showcase.pcap` via **File > Open PCAP** or Ctrl+O. Try filtering for `tcp`, `udp.port == 53`, and `icmp`. Open the Flows and Dashboard tabs.

## Validation

Linux GCC: CLI builds, and all three CTest suites pass. `showcase.pcap` decodes 240/240 IPv4 packets (120 TCP, 80 UDP, 40 ICMP). Windows Qt GUI compilation and runtime require verification on the user's Windows/MSYS2 machine.

## Current limitations

- Only classic Ethernet PCAP supported; PCAPNG and live capture are not yet implemented.
- Packet table currently populates all rows in memory; a model/view implementation would scale better for very large captures.
- GUI layout and filters have not yet been covered by automated Qt UI tests.
- Dashboard uses progress bars, not interactive time-series charts.
