# NetScope v0.11 — Desktop polish and portable packaging

## Changes
- View > Appearance > Light/Dark theme, persisted via QSettings.
- Saved window size; improved table/header styling, toolbar spacing, and contrast.
- Help > About dialog; same capture analysis and exports as v0.10.
- Optional CMake `package-windows` target uses Qt `windeployqt`.

## Windows 11 PowerShell 5.1 (MSYS2 UCRT64)
```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64 -DNETSCOPE_BUILD_GUI=ON -DNETSCOPE_PACKAGE_WINDOWS=ON
cmake --build build
ctest --test-dir build --output-on-failure
cmake --build build --target package-windows
.\build\NetScope-portable\netscope-gui.exe
```

**Deployment caveat:** `windeployqt --compiler-runtime` may not bundle every MinGW UCRT64 dependency. Test the portable folder in a clean Windows environment without `C:\msys64\ucrt64\bin` in PATH. If a runtime DLL is missing, inspect dependencies and copy only the legally redistributable DLLs needed by the exact build. The deployment target is a starting point, not a verified installer.

## Smoke test
1. Open `showcase.pcap`, check 240 frames and the Conversations tab.
2. Toggle View > Appearance > Dark theme, restart and check persistence.
3. Export packet, flow, and conversation CSVs.
4. Open `benchmark_100k.pcap` and check 100,000 frames, then select a packet and inspect its bytes.
5. Run all seven test suites.

## Limitations
Offline classic PCAP only; not PCAPNG or live capture. TCP state is inferred from observed flags. Large captures still retain metadata proportional to packet count. Windows Qt build and deployment require local validation.
