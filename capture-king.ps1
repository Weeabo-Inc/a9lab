# capture-king.ps1 - capture USB traffic while King runs checkm8, then stop.
#
# WHY THIS IS A SCRIPT AND NOT A ONE-LINER
#
# USBPcapCMD needs Administrator to open \\.\USBPcapN. Without elevation it
# exits silently: no stderr, no stdout, exit code 0, zero-byte pcap. A capture
# that fails silently is worse than no capture, because you analyse the empty
# file and conclude the device sent nothing.
#
# So this does the whole sequence in one elevated run:
#   start capture -> run king -> stop capture -> report
# and it ASSERTS the pcap is non-empty before claiming success.

$ErrorActionPreference = 'Continue'

$cmd  = "C:\Program Files\USBPcap\USBPcapCMD.exe"
$king = "<REPO_ROOT>\a9lab\king\build\king.exe"
$out  = "<REPO_ROOT>\a9lab\captures\king-checkm8.pcap"
$log  = "<REPO_ROOT>\a9lab\captures\capture.log"

New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
Remove-Item $out -Force -ErrorAction SilentlyContinue

function Say($m) {
    Write-Host $m
    Add-Content -Path $log -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m)
}

Set-Content -Path $log -Value ("=== capture run {0} ===" -f (Get-Date -Format 'u'))

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
$isAdmin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
Say ("elevated: {0}" -f $isAdmin)

if (-not $isAdmin) {
    Say "FATAL: not elevated. USBPcapCMD cannot open \\.\USBPcapN without Administrator."
    Say "       (it exits silently with code 0 and writes a zero-byte pcap)"
    exit 2
}

# --- start capture ---
Say "starting capture on \\.\USBPcap1 (all devices, inject descriptors)"
$cap = Start-Process -FilePath $cmd `
    -ArgumentList @("-d", "\\.\USBPcap1", "-o", $out, "-A", "--inject-descriptors") `
    -PassThru -RedirectStandardError "<REPO_ROOT>\a9lab\captures\usbpcap.err" `
    -RedirectStandardOutput "<REPO_ROOT>\a9lab\captures\usbpcap.out" `
    -WindowStyle Hidden

Start-Sleep -Seconds 2
if ($cap.HasExited) {
    Say ("FATAL: capture exited immediately, code {0}" -f $cap.ExitCode)
    Get-Content "<REPO_ROOT>\a9lab\captures\usbpcap.err" -ErrorAction SilentlyContinue |
        ForEach-Object { Say ("  err: " + $_) }
    exit 3
}
Say ("capture running, pid {0}" -f $cap.Id)

# --- run the exploit under capture ---
Say "running king checkm8 under capture"
$kout = & $king checkm8 2>&1 | Out-String
Add-Content -Path $log -Value $kout
$kout -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 5 | ForEach-Object { Say ("  king: " + $_.Trim()) }

# --- stop capture ---
Start-Sleep -Seconds 2
Say "stopping capture"
if (-not $cap.HasExited) { Stop-Process -Id $cap.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# --- ASSERT the capture is real, do not just claim it ---
if (-not (Test-Path $out)) {
    Say "FATAL: no pcap was produced"
    exit 4
}
$len = (Get-Item $out).Length
Say ("pcap size: {0:N0} bytes" -f $len)
if ($len -eq 0) {
    Say "FATAL: pcap is EMPTY. The capture did not record anything - do not read this as 'no traffic'."
    exit 5
}

# pcap global header magic
$b = [System.IO.File]::ReadAllBytes($out)
Say ("magic: {0:x2}{1:x2}{2:x2}{3:x2}  (a1b2c3d4 = little-endian pcap)" -f $b[0],$b[1],$b[2],$b[3])
Say "CAPTURE OK"
exit 0
