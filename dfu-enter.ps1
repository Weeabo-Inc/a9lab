# dfu-enter.ps1 - guided DFU mode entry for A9 research, with live confirmation.
#
# Why a script: DFU entry is timing-critical AND gives no visual feedback - the
# screen stays black whether you succeeded or failed. Doing it by eye means
# guessing. This counts the intervals out loud and tells you the moment the
# device actually enumerates in DFU.
#
# This is READ-ONLY. It never writes to, restores, or flashes the device.
#
# Usage:
#   .\dfu-enter.ps1              # guided countdown, then wait & confirm
#   .\dfu-enter.ps1 -WatchOnly   # just watch for DFU (skip the countdown)

[CmdletBinding()]
param(
    [switch]$WatchOnly,
    [int]$WatchSeconds = 90
)

$ErrorActionPreference = 'Continue'
$APPLE_VID = 'VID_05AC'

# Apple PIDs observed in various modes.
#
# CORRECTIONS from primary-source review (libirecovery / checkm8 source):
#   * 0x1222 is WTF mode (SecureROM debug), NOT DFU.
#   * 0x1227 is used by BOTH SecureROM DFU and iBSS/LLB DFU. The PID alone
#     CANNOT distinguish them - only SRTG does (read via `irecovery -q`).
#     checkm8 refuses to run against iBSS DFU, so SRTG MUST be checked before
#     any exploit attempt. This is the single most important gate.
#   * 0xF014 is "Port DFU".
#   * PIDs are reused across SoC families, so PID = mode indicator only.
$KNOWN = @{
    '1227' = @{ mode = 'DFU';      note = 'DFU - SecureROM OR iBSS; MUST confirm via SRTG' }
    '1222' = @{ mode = 'WTF';      note = 'WTF mode (SecureROM debug) - not DFU' }
    'F014' = @{ mode = 'DFU';      note = 'Port DFU' }
    '1280' = @{ mode = 'Recovery'; note = 'iBSS/iBEC recovery' }
    '1281' = @{ mode = 'Recovery'; note = 'iBSS/iBEC recovery' }
    '1282' = @{ mode = 'Recovery'; note = 'iBSS/iBEC recovery' }
    '1283' = @{ mode = 'Recovery'; note = 'iBSS/iBEC recovery' }
    '12A8' = @{ mode = 'Normal';   note = 'iOS running' }
    '12A0' = @{ mode = 'Normal';   note = 'iOS running (older)' }
    '12AB' = @{ mode = 'Normal';   note = 'iOS running' }
    '024F' = @{ mode = 'Peripheral'; note = 'Apple HID (keyboard/mouse) - NOT a phone' }
    '0250' = @{ mode = 'Peripheral'; note = 'Apple HID - NOT a phone' }
}

function Get-AppleDevices {
    try {
        Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceId -match $APPLE_VID }
    } catch { @() }
}

function Get-ProdIdFromInstanceId {
    param([string]$InstanceId)
    if ($InstanceId -match 'PID_([0-9A-Fa-f]{4})') { return $Matches[1].ToUpper() }
    return $null
}

function Show-CurrentState {
    $devs = Get-AppleDevices
    if (-not $devs) {
        Write-Host "  (no Apple USB device present)" -ForegroundColor DarkGray
        return $null
    }
    $seen = @{}
    foreach ($d in $devs) {
        $prodId = Get-ProdIdFromInstanceId $d.InstanceId
        if (-not $prodId -or $seen.ContainsKey($prodId)) { continue }
        $seen[$prodId] = $true
        $info = $KNOWN[$prodId]
        $mode = if ($info) { $info.mode } else { 'Unknown' }
        $note = if ($info) { $info.note } else { 'unrecognised PID' }
        $colour = switch ($mode) {
            'DFU'        { 'Green' }
            'Recovery'   { 'Yellow' }
            'Normal'     { 'Cyan' }
            'WTF'        { 'Magenta' }
            'Peripheral' { 'DarkGray' }
            default      { 'Red' }
        }
        Write-Host ("  PID {0}  {1,-11} {2}" -f $prodId, $mode, $note) -ForegroundColor $colour
    }
    return $seen
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " A9 DFU ENTRY ASSISTANT  (read-only, nothing is written)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $WatchOnly) {
    Write-Host "BEFORE YOU START" -ForegroundColor Yellow
    Write-Host "  * Plug the iPhone into this PC with a DATA cable (not charge-only)."
    Write-Host "  * Phone must be OFF (or it will be forced off by the sequence)."
    Write-Host "  * You need: the Side/Power button and the Volume DOWN button."
    Write-Host ""
    Write-Host "THE SEQUENCE (A9 / iPhone SE 1st gen, iPhone 6s, 6s Plus):" -ForegroundColor Green
    Write-Host "  1. Hold POWER + VOLUME DOWN together"
    Write-Host "  2. Keep holding for 8 seconds, then RELEASE POWER (keep Vol Down held)"
    Write-Host "  3. Keep holding VOLUME DOWN for a further 10 seconds"
    Write-Host "  4. Release. Screen stays BLACK in DFU - that is correct."
    Write-Host ""
    Write-Host "NOTE: if the Apple logo appears at any point, you missed it - start again." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Ready? Press ENTER to start the countdown." -ForegroundColor White
    [void](Read-Host)

    Write-Host ""
    Write-Host ">>> STEP 1+2: HOLD POWER + VOLUME DOWN NOW" -ForegroundColor Green
    for ($i = 8; $i -ge 1; $i--) {
        Write-Host ("    releasing POWER in {0}..." -f $i) -NoNewline
        Write-Host "`r" -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host "    >>> RELEASE POWER NOW - KEEP HOLDING VOLUME DOWN        " -ForegroundColor Yellow
    for ($i = 10; $i -ge 1; $i--) {
        Write-Host ("    release VOLUME DOWN in {0}...   " -f $i)
        Start-Sleep -Seconds 1
    }
    Write-Host "    >>> RELEASE VOLUME DOWN NOW                             " -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Watching for device enumeration (up to $WatchSeconds s)..." -ForegroundColor Cyan
Write-Host ""

$deadline = (Get-Date).AddSeconds($WatchSeconds)
$lastState = ''
$dfuFound = $false

while ((Get-Date) -lt $deadline) {
    $snapshot = @()
    foreach ($d in Get-AppleDevices) {
        $p = Get-ProdIdFromInstanceId $d.InstanceId
        if ($p) { $snapshot += $p }
    }
    $snapshot = ($snapshot | Sort-Object -Unique) -join ','

    if ($snapshot -ne $lastState) {
        Write-Host ("[{0}] change detected:" -f (Get-Date -Format 'HH:mm:ss')) -ForegroundColor White
        Show-CurrentState | Out-Null
        $lastState = $snapshot

        foreach ($p in ($snapshot -split ',')) {
            if ($KNOWN[$p] -and $KNOWN[$p].mode -eq 'DFU') { $dfuFound = $true }
        }
        if ($dfuFound) { break }
    }
    Start-Sleep -Milliseconds 500
}

Write-Host ""
if ($dfuFound) {
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " *** DFU MODE CONFIRMED ***" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " The device is in SecureROM DFU. Next steps:"
    Write-Host "   1. Record the exact PID seen above (measure, do not assume)."
    Write-Host "   2. Query it:  <REPO_ROOT>\libimobile\irecovery.exe -q"
    Write-Host "   3. Log the result: python <REPO_ROOT>\a9lab\research-log.py add ..."
    Write-Host ""
    Write-Host " If irecovery cannot open the device, WinUSB is not bound to the DFU" -ForegroundColor Yellow
    Write-Host " node yet - that is the expected Zadig step, not a failure." -ForegroundColor Yellow
} else {
    Write-Host "No DFU device appeared within $WatchSeconds s." -ForegroundColor Yellow
    Write-Host "Last observed state:"
    Show-CurrentState | Out-Null
    Write-Host ""
    Write-Host "Common causes:" -ForegroundColor Yellow
    Write-Host "  * Charge-only cable (no data lines) - try another cable."
    Write-Host "  * Timing missed - the Apple logo appearing means start over."
    Write-Host "  * Button combination differs - some units need a longer hold."
    Write-Host "  * Battery too flat to run SecureROM - charge longer and retry."
}
Write-Host ""
