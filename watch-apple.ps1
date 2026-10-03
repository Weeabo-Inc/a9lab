$ErrorActionPreference='Continue'
$last = ""
Write-Output "watching for Apple devices... (PID 1227=DFU, 1281=Recovery, 12A8=normal A9/A10, 12AB=A11)"
while ($true) {
  $d = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_05AC' }
  $cur = ($d | ForEach-Object { if ($_.InstanceId -match 'PID_([0-9A-Fa-f]{4})') { $matches[1].ToUpper() } } | Sort-Object -Unique) -join ","
  if ($cur -ne $last) {
    $ts = Get-Date -Format "HH:mm:ss"
    if ([string]::IsNullOrWhiteSpace($cur)) { Write-Output "[$ts] bus empty" }
    else {
      Write-Output "[$ts] APPLE DEVICE: PID(s) = $cur"
      foreach ($x in $d) {
        $pid4 = if ($x.InstanceId -match 'PID_([0-9A-Fa-f]{4})') { $matches[1].ToUpper() } else { "?" }
        $mode = switch ($pid4) { "1227" {"DFU"} "1281" {"RECOVERY"} "12A8" {"NORMAL (A9/A10)"} "12AB" {"NORMAL (A11)"} "024F" {"** AULA DONGLE - not a phone **"} default {"unknown"} }
        Write-Output ("          {0}  {1}  {2}" -f $pid4, $mode, $x.FriendlyName)
      }
    }
    $last = $cur
  }
  Start-Sleep -Seconds 2
}
