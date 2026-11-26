# NetScope v1.0 portable packaging. Windows PowerShell 5.1 compatible.
# Run via CMake target package-windows or directly with explicit paths.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$GuiExe,
    [Parameter(Mandatory=$true)][string]$CliExe,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [Parameter(Mandatory=$true)][string]$ToolchainBin,
    [Parameter(Mandatory=$true)][string]$Windeployqt,
    [string]$SampleCapture,
    [string]$ReadmeFile,
    [switch]$CreateZip
)
$ErrorActionPreference = 'Stop'
function Require-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required file not found: $Path" }
}
foreach ($file in @($GuiExe, $CliExe, $Windeployqt)) { Require-File $file }
$objdump = Join-Path $ToolchainBin 'objdump.exe'
Require-File $objdump
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$parent = Split-Path -Parent $OutputDir
if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
# Always start clean: stale DLLs must not make a broken package appear valid.
if (Test-Path $OutputDir) { Remove-Item -LiteralPath $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDir | Out-Null
Copy-Item -LiteralPath $GuiExe -Destination $OutputDir
Copy-Item -LiteralPath $CliExe -Destination $OutputDir
if ($SampleCapture) { Require-File $SampleCapture; Copy-Item -LiteralPath $SampleCapture -Destination $OutputDir }
if ($ReadmeFile) { Require-File $ReadmeFile; Copy-Item -LiteralPath $ReadmeFile -Destination (Join-Path $OutputDir 'README.md') }

# windeployqt provides Qt libraries and plugins. We collect the MinGW/UCRT
# dependency closure afterward, including dependencies imported by plugins.
Write-Host 'Running windeployqt...'
& $Windeployqt --release --compiler-runtime (Join-Path $OutputDir 'netscope-gui.exe')
if ($LASTEXITCODE -ne 0) { throw "windeployqt failed: exit code $LASTEXITCODE" }

$copied = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$round = 0
$unresolved = @()
do {
    $round++
    $newCopies = 0
    $unresolved = @()
    $files = @(Get-ChildItem -LiteralPath $OutputDir -Recurse -File | Where-Object { $_.Extension -in @('.exe', '.dll') })
    Write-Host "Dependency closure round $round ($($files.Count) binaries)"
    foreach ($file in $files) {
        $raw = & $objdump -p $file.FullName 2>$null
        if ($LASTEXITCODE -ne 0) { throw "objdump failed on $($file.FullName)" }
        foreach ($line in $raw) {
            if ($line -notmatch 'DLL Name:\s*(\S+)') { continue }
            $dll = $Matches[1]
            # Windows API-set contracts are virtual DLL names, not redistributable files.
            if ($dll -match '^(api-ms-|ext-ms-)') { continue }
            $local = Join-Path $file.DirectoryName $dll
            $root = Join-Path $OutputDir $dll
            $system = Join-Path $env:WINDIR "System32\$dll"
            if ((Test-Path $local) -or (Test-Path $root) -or (Test-Path $system)) { continue }
            $source = Join-Path $ToolchainBin $dll
            if (Test-Path $source -PathType Leaf) {
                Copy-Item -LiteralPath $source -Destination $root
                [void]$copied.Add($dll)
                $newCopies++
                Write-Host "  + $dll"
            } else {
                $unresolved += "$($file.Name) -> $dll"
            }
        }
    }
    if ($round -ge 30 -and $newCopies -gt 0) { throw 'Dependency closure exceeded 30 rounds' }
} while ($newCopies -gt 0)

if ($unresolved.Count -gt 0) {
    $details = ($unresolved | Sort-Object -Unique) -join "`n"
    throw "Unresolved non-API-set DLL imports:`n$details"
}
Write-Host "Dependency closure complete. Copied $($copied.Count) additional DLLs."

# Validate that essential Qt platform plugin was deployed.
Require-File (Join-Path $OutputDir 'platforms\qwindows.dll')
Require-File (Join-Path $OutputDir 'netscope-gui.exe')
Require-File (Join-Path $OutputDir 'netscope.exe')

# Manifest allows inspection of exact binaries and checksums.
$manifest = Get-ChildItem -LiteralPath $OutputDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($OutputDir.Length).TrimStart('\')
    [PSCustomObject]@{ path=$relative; bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $OutputDir 'manifest.json') -Encoding UTF8
if ($CreateZip) {
    $zip = Join-Path $parent 'NetScope-v1.0-Windows-Portable.zip'
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $OutputDir '*') -DestinationPath $zip -CompressionLevel Optimal
    Write-Host "Created $zip"
}
Write-Host "Portable distribution ready for clean-machine validation: $OutputDir"
