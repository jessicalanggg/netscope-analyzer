# NetScope v1.0

**Offline network packet analyzer built in C++20 and Qt 6.** An educational systems/networking project demonstrating PCAP parsing, flow aggregation, indexed packet access, bounded raw-byte caching, and desktop UI engineering.

## Features

- Ethernet II / IPv4 / TCP / UDP / ICMP decoding from classic PCAP captures
- Packet explorer with protocol details, hex inspection and packet filtering
- Directional 5-tuple flows and bidirectional conversations
- TCP flag observations and inferred connection state (incomplete captures may be midstream)
- Protocol dashboard, time-series summaries, sortable tables and CSV exports
- Indexed PCAP access, on-demand raw-byte retrieval, LRU cache, background loading
- Light/dark appearance preferences, CTest regression suites and CLI benchmarks
- Portable Windows packaging target with recursive MinGW/UCRT DLL dependency collection

## Build — Windows 11, MSYS2 UCRT64, Qt 6

From the `netscope-starter` directory in PowerShell 5.1:

```powershell
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
cmake -S . -B build -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_PREFIX_PATH=C:/msys64/ucrt64 `
  -DNETSCOPE_BUILD_GUI=ON `
  -DNETSCOPE_PACKAGE_WINDOWS=ON
cmake --build build
ctest --test-dir build --output-on-failure
.\build\netscope-gui.exe
cmake --build build --target package-windows
```

The packaging target **deletes and recreates** `build/NetScope-portable` before deployment, then runs `windeployqt`, recursively collects MSYS2 UCRT64 DLL imports, generates a SHA-256 manifest, and creates `build/NetScope-v1.0-Windows-Portable.zip`. The target requires PowerShell, `objdump.exe`, and `windeployqt.exe` from the matching UCRT64 toolchain. If any non-system import cannot be resolved, packaging fails instead of silently shipping an incomplete distribution.

**Clean-machine test:** extract the portable ZIP on a compatible Windows PC with no Qt/MSYS2 installed; launch `netscope-gui.exe` and open `showcase.pcap`. A successful build on the development PC is not sufficient proof of portability. See `docs/RELEASE_CHECKLIST.md`.

## Build — macOS (Apple Silicon or Intel)

Install Apple's Command Line Tools, Homebrew, CMake, Ninja, and Qt 6. This builds the **native macOS** GUI and CLI; the Windows portable ZIP does not run on macOS.

```bash
xcode-select --install                 # skip if already installed
brew install cmake ninja qt

git clone https://github.com/YOUR-USERNAME/NetScope.git
cd NetScope
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$(brew --prefix qt)" \
  -DNETSCOPE_BUILD_GUI=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/netscope analyze showcase.pcap
open ./build/netscope-gui.app
```

Replace `YOUR-USERNAME` with the repository owner's actual GitHub username. The Qt GUI target is created as a macOS `.app` bundle by CMake's `WIN32` executable option; `open` launches it. Homebrew automatically uses the native architecture and prefix (`/opt/homebrew` for typical Apple Silicon installations, `/usr/local` for typical Intel installations). The build requires a Qt 6 version supported by the installed macOS and compiler.

**Mac support status:** source/build instructions and CI are included, but a native MacBook GUI launch and packaged `.dmg` have **not** been independently verified. `NETSCOPE_PACKAGE_WINDOWS` is Windows-only. If Qt is not found, CMake currently builds the CLI only; confirm `netscope-gui.app` exists before claiming GUI success.

## Build — Linux CLI

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNETSCOPE_BUILD_GUI=OFF
cmake --build build
ctest --test-dir build --output-on-failure
./build/netscope analyze showcase.pcap
./build/netscope benchmark showcase.pcap
```

## Benchmarking

```powershell
python scripts/make_benchmark_pcap.py --packets 100000 --output benchmark_100k.pcap
.\build\netscope.exe benchmark benchmark_100k.pcap
.\build\netscope.exe benchmark-index benchmark_100k.pcap 5
```

Measured on one Windows development machine for a synthetic 100,000-frame (~9 MB) capture: CLI analysis ~2.01 million frames/sec, indexing median ~458,000 frames/sec over five runs. These are **different workloads** and not representative of arbitrary real-world PCAPs. Benchmark hardware/configuration and multiple runs should accompany public performance claims.

## Architecture

```text
Classic PCAP file
      | 
      +--> Sequential PCAP reader --> Protocol decoder --> Flow/conversation analytics
      |
      +--> Packet offset index --> On-demand raw bytes --> Bounded LRU packet cache
                                                      |
Qt Widgets GUI <--> Packet table model / filters / dashboard / details / hex view
CLI          <--> Analysis and index benchmark commands
```

## Limitations and safety

Classic PCAP only (not pcapng); Ethernet II/IPv4 only; no IPv6, VLAN, TCP stream reassembly, checksum validation, live capture, or intrusion detection. TCP states are **observations**, not a complete protocol state machine. The raw-byte cache is bounded, but packet metadata, index and flow statistics grow with capture size. The parser is not fully fuzz-hardened; do not assume malicious PCAPs are safe. Analyze only authorized captures.

## GitHub release and demonstration

The repository keeps exactly **one README file**, this root `README.md`. Technical design notes are under `docs/`. Build outputs and portable archives are not committed to Git. Publish Windows ZIPs as GitHub **Release assets** after clean-machine testing; macOS users should build from source until native macOS distribution is validated.

To publish from a local clone or extracted source folder:

```bash
git init
git add .
git commit -m "Release NetScope v1.0"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/NetScope.git
git push -u origin main
```

Create the empty GitHub repository first and replace the placeholder URL. If this is an existing Git repository, do **not** run `git init` or overwrite its history; review `git status`, commit, and push on the existing branch instead.

## Portfolio demonstration

1. Load `showcase.pcap` and demonstrate protocol decoding and hexadecimal details.
2. Apply packet filters; explore directional flows and bidirectional conversations.
3. Explain indexed access, LRU cache trade-offs, and memory complexity.
4. Show benchmark and CTest outputs; explain measurement limitations.
5. Demonstrate the portable ZIP on a clean Windows machine.

## Project layout

`src/` analysis engine and CLI; `include/netscope/` public headers; `gui/` Qt desktop app; `tests/` regression suites; `scripts/` deterministic PCAP generators; `packaging/` Windows deployment; `docs/` architecture and release checklist; `.github/workflows/` CI.

## License

See `LICENSE`. Third-party Qt and MSYS2 libraries retain their own licenses; check redistribution requirements when publishing binaries.
