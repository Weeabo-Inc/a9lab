# build-king.ps1 - reproducibly build the King checkm8 exploit on Windows.
#
# King (github.com/pgarba/King) is a C/C++ port of axi0mX's checkm8 (ipwndfu).
# Upstream ipwndfu CANNOT exploit A9 and is Python 2 only, so King is the
# Windows-native route. Verified working as of 2026-10-03.
#
# Requirements (all handled or checked below):
#   * Visual Studio Build Tools with MSVC + nmake
#   * CMake >= 3.10
#   * libusb 1.0.x Windows binaries (official release .7z)
#
# Usage:
#   .\build-king.ps1
#
# Output: <REPO_ROOT>\a9lab\king\build\king.exe

[CmdletBinding()]
param(
    [string]$Root     = '<REPO_ROOT>\a9lab',
    [string]$KingRepo = 'https://github.com/pgarba/King.git',
    [string]$LibusbUrl = 'https://github.com/libusb/libusb/releases/download/v1.0.30/libusb-1.0.30.7z',
    # libusb arch flavour to link against
    [string]$LibusbFlavour = 'VS2022\MS64'
)

$ErrorActionPreference = 'Stop'
$KingDir  = Join-Path $Root 'king'
$LibusbDir = Join-Path $Root 'libusb'
$SevenZ   = 'C:\Program Files (x86)\Lua\5.1\7z.exe'

function Info($m) { Write-Host "  $m" }
function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

# --- locate MSVC -----------------------------------------------------------
Step "Locating Visual Studio Build Tools"
$vcvars = Get-ChildItem 'C:\Program Files (x86)\Microsoft Visual Studio' -Recurse `
    -Filter 'vcvars64.bat' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $vcvars) { throw "vcvars64.bat not found - install VS Build Tools with the C++ workload." }
Info "vcvars64: $vcvars"

# --- clone King ------------------------------------------------------------
Step "Fetching King"
if (Test-Path (Join-Path $KingDir '.git')) {
    Info "already cloned at $KingDir"
} else {
    & git clone --depth 1 $KingRepo $KingDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    Info "cloned"
}

# --- libusb ----------------------------------------------------------------
Step "Preparing libusb"
$Lu10 = Join-Path $LibusbDir 'libusb10'
if (-not (Test-Path (Join-Path $Lu10 'include\libusb-1.0\libusb.h'))) {
    if (-not (Test-Path (Join-Path $LibusbDir 'include\libusb.h'))) {
        New-Item -ItemType Directory -Force -Path $LibusbDir | Out-Null
        $archive = Join-Path $LibusbDir 'libusb.7z'
        Info "downloading $LibusbUrl"
        Invoke-WebRequest -Uri $LibusbUrl -OutFile $archive -UseBasicParsing
        if (-not (Test-Path $SevenZ)) { throw "7z not found at $SevenZ" }
        # The archive contains some 0-byte ARM64 entries that 7z reports as errors;
        # that is expected and harmless - we only need the x64 MSVC flavour.
        & $SevenZ x $archive "-o$LibusbDir" -y | Out-Null
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $Lu10 'include') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $Lu10 'lib') | Out-Null
    Copy-Item (Join-Path $LibusbDir 'include\libusb.h') (Join-Path $Lu10 'include\') -Force
    Copy-Item (Join-Path $LibusbDir "$LibusbFlavour\dll\libusb-1.0.lib") (Join-Path $Lu10 'lib\') -Force
}

# IMPORTANT: King's dfu.h does `#include <libusb-1.0/libusb.h>`, so the header
# must ALSO exist under an include/libusb-1.0/ subdirectory. Without this the
# build fails with C1083 'Cannot open include file: libusb-1.0/libusb.h'.
New-Item -ItemType Directory -Force -Path (Join-Path $Lu10 'include\libusb-1.0') | Out-Null
Copy-Item (Join-Path $Lu10 'include\libusb.h') (Join-Path $Lu10 'include\libusb-1.0\libusb.h') -Force
Info "libusb prepared at $Lu10"

# --- configure + build via a .bat so vcvars applies ------------------------
Step "Configuring and building"
$buildDir = Join-Path $KingDir 'build'
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
$luFwd = $Lu10 -replace '\\', '/'

$bat = @"
@echo off
call "$vcvars" >nul 2>&1
cd /d "$KingDir"
if not exist build mkdir build
cd build
cmake .. -G "NMake Makefiles" -DLIBUSB10_PATH=$luFwd -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1
nmake
if errorlevel 1 exit /b 1
echo BUILD_OK
"@
$batPath = Join-Path $Root 'build-king.bat'
Set-Content -Path $batPath -Value $bat -Encoding ascii

$out = & cmd.exe /c $batPath 2>&1
$out | Select-Object -Last 12 | ForEach-Object { Info $_ }
if ($out -notmatch 'BUILD_OK') { throw "build failed - see output above" }

# --- ship the runtime DLL next to the exe ---------------------------------
Step "Placing runtime DLL"
$dll = Join-Path $LibusbDir "$LibusbFlavour\dll\libusb-1.0.dll"
Copy-Item $dll (Join-Path $buildDir 'libusb-1.0.dll') -Force
Info "libusb-1.0.dll copied"

Step "Result"
$exe = Join-Path $buildDir 'king.exe'
if (Test-Path $exe) {
    $k = [math]::Round((Get-Item $exe).Length / 1KB)
    Write-Host "  king.exe built: $exe ($k KB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  NEXT: bind libusbK (NOT WinUSB) to the DFU device via Zadig," -ForegroundColor Yellow
    Write-Host "        then put the phone in DFU and run:  king.exe checkm8" -ForegroundColor Yellow
} else {
    throw "king.exe not produced"
}
