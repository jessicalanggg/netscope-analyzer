# NetScope v0.3 — Qt 6 Widgets desktop GUI

## What's included

- `netscope-gui.exe` is a separate desktop executable; `netscope.exe` CLI remains unchanged.
- File > Open PCAP (`Ctrl+O`) loads classic Ethernet PCAP captures through the existing core reader.
- Packets tab: table, case-insensitive text filter, protocol fields and hexadecimal/ASCII view.
- Flows tab: directional 5-tuple flow statistics, sorted by byte count.
- Dashboard tab: packet counts, protocol breakdown, and top source IP addresses.
- Invalid PCAPs display an error and do not overwrite the previously loaded capture.

## Windows build (MSYS2 UCRT64)

In a **fresh Windows PowerShell terminal**, from the extracted `netscope-starter` directory:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64 -DNETSCOPE_BUILD_GUI=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\netscope.exe analyze demo.pcap
.\build\netscope-gui.exe
```

If you are reusing an older `build` directory from another compiler or folder, use a new build directory, e.g. `-B build-v03` and adjust subsequent commands.

Check CMake configure output for `Qt6 Widgets found: building netscope-gui`. If CMake reports `Qt6 Widgets not found`, check your `CMAKE_PREFIX_PATH` and Qt UCRT64 installation. CMake intentionally builds CLI-only when Qt isn't found.

The MSYS2 UCRT64 runtime DLLs must remain discoverable. The PATH command above is per-terminal; it doesn't modify system PATH.

## Current limitations

- Classic `.pcap` with Ethernet link type only; **pcapng is not supported**.
- Offline analysis only; no live capture.
- All captured packets and bytes are stored in RAM for inspection. Use small captures for v0.3.
- Packet details show decoded fields from the existing parser, not all Ethernet/IP header fields.
- Fragmented traffic follows the v0.2 parser behavior; non-initial fragments aren't assigned to a transport 5-tuple.
- GUI compilation is not verified in the package's Linux build environment (Qt6 Widgets is unavailable there); validate the GUI build on your Windows UCRT64 installation.

## Next steps

Add a model/view-based virtualized packet table for large PCAPs, full protocol-field trees, flow-to-packet navigation, filters, and automated Qt GUI tests.
