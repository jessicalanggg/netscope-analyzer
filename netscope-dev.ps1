$ErrorActionPreference = "Stop"

$ucrt = "C:\msys64\ucrt64\bin"

if (-not (Test-Path "$ucrt\g++.exe")) {
    throw "MSYS2 UCRT64 compiler not found"
}

# Ensure the correct C++ runtime libraries
# take priority in this process.
$env:Path = "$ucrt;$env:Path"

Set-Location $PSScriptRoot

Write-Host "NetScope development environment ready"

# Configure the build if necessary.
if (-not (Test-Path "build\CMakeCache.txt")) {
    cmake -S . -B build -G Ninja `
        -DCMAKE_BUILD_TYPE=Debug
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

# Compile
cmake --build build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Run tests
ctest --test-dir build --output-on-failure
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Run NetScope
& ".\build\netscope.exe" analyze demo.pcap
exit $LASTEXITCODE