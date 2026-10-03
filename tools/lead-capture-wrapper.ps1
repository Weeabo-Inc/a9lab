# Lead capture wrapper — runs the USBPcap capture ELEVATED (UAC) around a
# SETUP-only a9pwn run, so the pcap and the JSONL trace describe the same
# attempts and transport-engineer can correlate them.
#
# Why these exact arguments:
#  - `--pad-timeout-ms 5` restores gaster's own value. The default 40 catches a
#    ~21-37 ms DEVICE WATCHDOG STALL, which is not the corruption signal
#    (MEASURED: pad STALLed on attempt 1 at 23,308 us). With 5 ms the pads NAK
#    and we get 200 real attempts for the capture to look at.
#  - No --stop-after-setup-stall: we want the full 200 attempts in the pcap,
#    not a run that halts on the first (watchdog) STALL.
#  - --stage reset first: it parks the machine in MANIFEST_WAIT_RESET, SETUP's
#    precondition in the reference flow (gaster.c:1229-1250).
$ErrorActionPreference = 'Stop'

$exe = 'E:\Reverseing\Arlo\a9pwn\target\release\a9pwn.exe'
$run = "$exe run --stage reset; " +
       "$exe run --stage setup --setup-budget 200 --pad-timeout-ms 5 " +
       "--trace E:\Reverseing\Arlo\a9pwn-traces\wire-setup.jsonl"

& 'E:\Reverseing\Arlo\a9lab\tools\capture-usb.ps1' `
  -Hub 1 `
  -Out 'E:\Reverseing\Arlo\a9lab\captures\wire-setup.pcap' `
  -Log 'E:\Reverseing\Arlo\a9lab\captures\wire-setup.log' `
  -Run $run `
  -RunWorkDir 'E:\Reverseing\Arlo\a9pwn' `
  -InjectDescriptors

"wrapper exit=$LASTEXITCODE"
