# NetScope v0.2 — Flow Tracking

A **directional five-tuple** comprises source IP, destination IP, protocol, source port and destination port. Reverse-direction traffic is counted as a different flow. ICMP and unknown protocols use zero ports because the parser does not expose transport ports for them. Non-initial IPv4 fragments are excluded from five-tuple tracking.

`FlowTracker::observe` aggregates frame lengths (captured Ethernet frame bytes) and packet counts in an `std::unordered_map<FlowKey, FlowStats, FlowKeyHash>`. This is average O(1) insertion/lookup, while `top_flows` sorts all flow records in O(F log F) time for F flows.

## Windows PowerShell

Use your existing `netscope-dev.ps1` to ensure the UCRT64 DLL directory is first in PATH. If you copied this update over an existing project, reconfigure and build:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
.\build\netscope.exe analyze demo.pcap
```

The bundled `demo.pcap` contains three different UDP five-tuples, so the expected flow count is 3. The flow unit test also checks aggregation, distinct ports, reverse direction and exclusion of non-initial fragments.

## Limitations

This milestone does not yet provide timestamps, TCP session reconstruction, IPv6, VLAN decoding, live capture or Qt GUI. It assumes valid decoded `Packet` objects. PCAP parsing currently supports classic Ethernet PCAP only, not pcapng. Future improvements should add fragmentation handling and more robust parser tests.
