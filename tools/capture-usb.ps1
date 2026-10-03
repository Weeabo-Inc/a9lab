<#
capture-usb.ps1 - one elevated run: start USBPcap, optionally run a command
under capture, stop, and PROVE the result is a real capture.

WHY A SCRIPT
------------
USBPcapCMD cannot open \\.\USBPcapN without Administrator. Unelevated it exits
with code 0 and writes a zero-byte pcap: no error, no output, nothing to see.
That is the single worst failure mode here, because you then analyse the empty
file and conclude the device was silent.

It also cannot be driven interactively from a non-interactive shell. Run it
without -d/-o and it goes into its own console prompt and reads the real
console, not stdin, so piping "q" at it does nothing and you are left with an
orphan window. Always pass -d and -o. This script exists so that is automatic.

USAGE
-----
  # who is on this hub? (descriptors only, nothing running)
  capture-usb.ps1 -Hub 1 -Seconds 4 -InjectDescriptors

  # run something under capture
  capture-usb.ps1 -Hub 1 -Run 'C:\path\to\king.exe checkm8' -RunWorkDir 'C:\path\to'

The script asserts the pcap is non-empty before reporting success.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][int]$Hub,
    [string]$Out,
    [int]$Seconds = 0,
    [string]$Run,
    [string]$RunWorkDir,
    [switch]$InjectDescriptors,
    [int[]]$Devices,
    [string]$Log
)

$ErrorActionPreference = 'Continue'

$cmd     = 'C:\Program Files\USBPcap\USBPcapCMD.exe'
$capture = "<REPO_ROOT>\a9lab\captures"
$device  = "\\.\USBPcap$Hub"

if (-not $Out) { $Out = Join-Path $capture ("hub{0}-{1}.pcap" -f $Hub, (Get-Date -Format 'HHmmss')) }
if (-not $Log) { $Log = Join-Path $capture 'capture.log' }
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
New-Item -ItemType Directory -Force -Path $capture | Out-Null
$errFile = Join-Path $capture 'usbpcap.err'
$outFile = Join-Path $capture 'usbpcap.out'

function Say($m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    Add-Content -Path $Log -Value $line
}

Set-Content -Path $Log -Value ("=== capture run {0} ===" -f (Get-Date -Format 'u'))

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
$isAdmin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Say ("elevated : {0}" -f $isAdmin)
Say ("hub      : {0}" -f $device)
Say ("output   : {0}" -f $Out)
if (-not $isAdmin) {
    Say "FATAL: not elevated. USBPcapCMD cannot open $device."
    Say "       Unelevated it exits 0 and writes a ZERO-BYTE pcap, which looks like 'no traffic'."
    exit 2
}
if (-not (Test-Path $cmd)) { Say "FATAL: $cmd not found"; exit 2 }

Remove-Item $Out -Force -ErrorAction SilentlyContinue
Remove-Item $errFile -Force -ErrorAction SilentlyContinue
Remove-Item $outFile -Force -ErrorAction SilentlyContinue

# --- build the argument list -------------------------------------------------
$argv = @('-d', $device, '-o', $Out, '-A')
if ($InjectDescriptors) { $argv += '--inject-descriptors' }
if ($Devices -and $Devices.Count -gt 0) {
    $argv += '--devices'
    $argv += ($Devices -join ',')
}
Say ("argv     : USBPcapCMD.exe {0}" -f ($argv -join ' '))

# --- start capture -----------------------------------------------------------
$cap = Start-Process -FilePath $cmd -ArgumentList $argv -PassThru `
    -RedirectStandardError $errFile -RedirectStandardOutput $outFile -WindowStyle Hidden

Start-Sleep -Seconds 2
if ($cap.HasExited) {
    Say ("FATAL: capture exited immediately with code {0}" -f $cap.ExitCode)
    if (Test-Path $errFile) {
        Get-Content $errFile -ErrorAction SilentlyContinue | ForEach-Object { Say ("  err: " + $_) }
    }
    if (Test-Path $outFile) {
        Get-Content $outFile -ErrorAction SilentlyContinue | ForEach-Object { Say ("  out: " + $_) }
    }
    Say "HINT: 'Couldn't open device - 2' means the USBPcap filter is not attached to this hub."
    exit 3
}
Say ("capture running, pid {0}" -f $cap.Id)

# --- optionally run something under capture ----------------------------------
$ran = $false
if ($Run) {
    Say ("running under capture: {0}" -f $Run)
    $prev = Get-Location
    if ($RunWorkDir) { Set-Location $RunWorkDir }
    try {
        $cmdOut = & ([scriptblock]::Create($Run)) 2>&1 | Out-String
    } catch {
        $cmdOut = "EXCEPTION: $_"
    } finally {
        Set-Location $prev
    }
    $ran = $true
    Add-Content -Path $Log -Value $cmdOut
    $cmdOut -split "`r?`n" | Where-Object { $_.Trim() } |
        ForEach-Object { Say ("  run: " + $_.Trim()) }
}

# --- wait out the requested duration -----------------------------------------
if ($Seconds -gt 0) {
    Say ("capturing for {0}s" -f $Seconds)
    Start-Sleep -Seconds $Seconds
} elseif (-not $ran) {
    Say "capturing 3s (default)"
    Start-Sleep -Seconds 3
} else {
    Start-Sleep -Seconds 2
}

# --- stop --------------------------------------------------------------------
Say "stopping capture"
Stop-Process -Id $cap.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# --- ASSERT the capture is real ----------------------------------------------
if (-not (Test-Path $Out)) { Say "FATAL: no pcap was produced"; exit 4 }
$len = (Get-Item $Out).Length
Say ("pcap size: {0:N0} bytes" -f $len)
if ($len -eq 0) {
    Say "FATAL: pcap is EMPTY. Do NOT read this as 'the device was silent'."
    Say "       An empty pcap from an elevated run means the filter recorded nothing."
    if (Test-Path $errFile) {
        Get-Content $errFile -ErrorAction SilentlyContinue | ForEach-Object { Say ("  err: " + $_) }
    }
    exit 5
}

$b = [System.IO.File]::ReadAllBytes($Out)
Say ("magic: {0:x2}{1:x2}{2:x2}{3:x2}" -f $b[0], $b[1], $b[2], $b[3])
Say "CAPTURE OK"
Say ("PCAP={0}" -f $Out)
exit 0
