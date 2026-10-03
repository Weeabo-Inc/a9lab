# ipwndfu on a Windows host for A9 (iPhone SE 1st gen) — feasibility report

Subject: `github.com/axi0mX/ipwndfu`, studied at commit `0e28932ec6a2a570b10fd77e50bda4216418cd98` (current `master`), read file-by-file.
Host basis: Windows 10/11 x64, `<REPO_ROOT>\libimobile\` (libimobiledevice 1.2.1 win-x64, includes `libusb-1.0.dll` 1.0.24), Python 3.14.7, usbipd-win 5.3.0.

Label key: **VERIFIED** = read directly from source or observed on this host. **INFERRED** = follows from verified facts but not executed. **SECONDHAND** = third-party/forum claim. **SPECULATIVE** = explicitly a guess. No device-unique identifiers appear in this report (`<ECID>` placeholders).

---

## 1. Actual dependencies (from repo source)

### 1.1 Non-stdlib imports

**VERIFIED.**

* `usb` — **pyusb, but not from site-packages**: a private vendored copy is committed in-tree at `usb/` (`usb/__init__.py`, `usb/core.py`, `usb/backend/libusb1.py`, …). `dfu.py:2` carries the stale comment `import usb # pyusb: use 'pip install pyusb' to install this module`, but the in-tree package shadows any installed one. The vendored copy is a 1.0.0-beta-era pyusb (`usb/legacy.py` exists; `usb/__init__.py:39` "Since version 1.0, main PyUSB implementation lives in the 'usb.core'"). Upstream README credits "walac for pyusb".
* `libusbfinder` — in-tree helper (`libusbfinder/__init__.py`) whose only job is to find a **macOS** libusb dylib.
* Everything else imported by the tool is stdlib: `binascii, datetime, getopt, hashlib, struct, sys, time, array, ctypes, subprocess`, plus Python-2-only `cStringIO`, plus local modules (`dfu, nor, utilities, alloc8, checkm8, image3_24Kpwn, limera1n, SHAtter, steaks4uce, usbexec, dfuexec, device_platform`).

### 1.2 The code is Python 2 and will not parse under the host's Python 3.14.7

**VERIFIED.** This is the first and hardest dependency, and it is independent of USB:

* `print` **statements** throughout, e.g. `ipwndfu:11  print 'USAGE: ipwndfu [options]'`, `dfu.py:22  print 'ERROR: No Apple device in DFU Mode 0x1227 detected after %0.2f second timeout. Exiting.' % timeout`, `checkm8.py:468  print 'Found:', device.serial_number`.
* `usbexec.py:118  elif isinstance(args[i], basestring) and i == len(args) - 1:` (`basestring` removed in Py3).
* `checkm8.py:84  return '47000058E0001FD6'.decode('hex') + struct.pack('<Q', dest)` and `libusbfinder/__init__.py:16  dylib_patches=[(0x8fd1, 'E985000000'.decode('hex'))]` (`str.decode('hex')` removed in Py3).
* `dfu.py:58  data += ret.tostring()` / `usbexec.py:106,108  ....tostring()` (`array.tostring` removed in Py3.9+).
* `libusbfinder/__init__.py:1  import hashlib, os, platform, cStringIO, tarfile`; `ipwndfu:91  raw_input("Press ENTER to continue.")`.

Files are also shebanged `#!/usr/bin/python` (`ipwndfu:1`). **A native run on Python 3.14.7 dies at parse time, before any USB call.**

### 1.3 How it touches USB

**VERIFIED.** It is a pure EP0 control-transfer client; it never claims an interface, never sets a configuration, never detaches a kernel driver (no `claim_interface`, `set_configuration`, or `detach_kernel_driver` anywhere in the application code).

Device discovery — `dfu.py:9-16`:

```python
backend = usb.backend.libusb1.get_backend(find_library=lambda x:libusbfinder.libusb1_path())
...
for device in usb.core.find(find_all=True, idVendor=0x5AC, idProduct=0x1227, backend=backend):
    if match is not None and match not in device.serial_number:
        continue
    return device
```

(Recovery-mode sibling: `recovery.py:14  usb.core.find(idVendor=0x5AC, idProduct=0x1281, backend=backend)`.)

Raw control transfers, `dfu.py`:

```python
32: assert device.ctrl_transfer(0x21, 4, 0, 0, 0, 1000) == 0          # DFU clrstatus/abort
48: assert device.ctrl_transfer(0x21, 1, 0, 0, data[index:index+amount], 5000) == amount   # DFU DNLOAD
56: ret = device.ctrl_transfer(0xA1, 2, 0, 0, part, 5000)            # DFU UPLOAD
37: device.reset()                                                   # dfu.usb_reset()
```

The exploit itself reaches **into libusb through pyusb's private globals** — `checkm8.py:10-45`: `usb.backend.libusb1._lib.libusb_alloc_transfer(0)`, `transfer.dev_handle = device._ctx.handle.handle`, `transfer.buffer = request.buffer_info()[0]`, `libusb_submit_transfer(...)` then `libusb_cancel_transfer(...)`. It also asserts the backend identity: `checkm8.py:28  if usb.backend.libusb1._lib is not device._ctx.backend.lib: print 'ERROR: This exploit requires libusb1 backend...'`. The stall primitive is a *submitted-then-cancelled* async control transfer with a 10 µs budget (`checkm8.py:118  stall(): ... 'A' * 0xC0, 0.00001`).

Device-side identification is by USB serial-number **string descriptor** (`device.serial_number`), matched against `CPID:`/`CPRV:`/`SRTG:` fields (`checkm8.py:455-460`, `dfu.py:17`). A9 appears as `CPID:8010` (t8010) or `CPID:8011` (t8011); `ipwndfu:72-78` routes both to `checkm8.exploit()`, and `checkm8.py` supplies full arm64 payload/config tables for both.

### 1.4 Linux-only facilities

**VERIFIED: there are none in the exploit path.** A full-repo grep found **no** `/dev/`, `/sys/`, `udev`, `os.getuid()`, `seteuid`/`setuid`, `chmod`, `termios`, `fcntl`, `ioctl`, and **no** `subprocess` call to `dfu-util`, `system_profiler`, `ioreg`, or any shell script.

The platform-specific code that does exist is:

* **macOS-only library finding** — `libusbfinder/__init__.py:67  version = platform.mac_ver()[0]` with the explicit fallback `if version == '': # We're not running on a Mac.  return None`. It also ships prebuilt macOS libusb "bottles" (`libusbfinder/bottles/libusb-1.0.22.mojave.bottle.tar.gz`, …) and byte-patches `libusb-1.0.0.dylib`.
* **External binaries via `subprocess`** — `utilities.py:17  subprocess.Popen(['openssl', 'enc', '-aes-%s-cbc' ...])` and `utilities.py:30  subprocess.Popen(['xxd', '-o', str(address)], ...)`. Neither is on the A9 checkm8 path: the sole caller of the openssl helper is `image3.py:60  return utilities.aes_decrypt(...)` (the iPhone 3GS image3 path), while on a checkm8-pwned device every AES operation runs **on the device** (`dfuexec.py:168 aes_hex()` → `self.aes()` → `execute()`; `usbexec.py:31-32`). `xxd` is reached only through `--hexdump` (`ipwndfu:185,191`); `--dump-rom` (the primary A9 goal) needs neither binary.
* **macOS-only toolchain** — `Makefile:38,42,46,50  xcrun -sdk iphoneos clang ...`. This only rebuilds the ARM shellcode in `src/`; the compiled `bin/*.bin` blobs are committed, so `make` is **not** needed to run ipwndfu (README: "You will not need to use `make` or compile anything to use ipwndfu.").

So the *only* real platform coupling is "libusb discoverable + libusb1 backend", which the vendored pyusb itself implements for Windows (`usb/backend/libusb1.py:279  if sys.platform == 'win32': win_cls = WinDLL`; `usb/libloader.py:87` `'.dll'` workaround; `usb/backend/libusb1.py:285` candidates `('usb-1.0', 'libusb-1.0', 'usb')`).

---

## 2. Platform support claimed upstream

**VERIFIED.** README.md says, in full:

> ## Dependencies
> This tool should be compatible with Mac and Linux. It won't work in a virtual machine.
> * libusb, `If you are using Linux: install libusb using your package manager.`

* No Windows claim, no Windows code path, no Windows note anywhere in the README or `JAILBREAK-GUIDE.md`.
* **No packaging or CI metadata at all**: the repo tree contains no `setup.py`, no `pyproject.toml`, no `setup.cfg`, no `.github/`, no `tox.ini`, no classifier list. The only build file is the macOS-only `Makefile` for ARM assembly.
* The only `win32`/`cygwin` handling in the whole repo lives inside the *vendored pyusb*, not in ipwndfu.
* **The maintained Python-3 fork does not add Windows either**: PyPI `ipwndfu` 2.0.0b5 (`requires_python >=3.8,<4.0`, `py3-none-any` wheel, description "This fork is maintained by the hack-different team") repeats verbatim "This tool should be compatible with Mac and Linux. It won't work in a virtual machine." with no OS classifiers.

---

## 3. The Windows driver requirement

### 3.1 What the DFU node must be bound to

**VERIFIED (libusb source).** libusb on Windows can only open a device whose node is bound to a libusb-compatible driver — WinUSB, libusbK, or libusb0 (Zadig is the usual way to swap the driver). For ipwndfu specifically, **prefer libusbK over WinUSB**, because the exploit needs `device.reset()` (`dfu.usb_reset`, `dfu.py:37`) and libusb 1.0.24 says WinUSB cannot do it (`libusb/os/windows_winusb.c`):

```
3083 /* ... from the "How to Use WinUSB to Communicate with a USB Device" Microsoft white paper ...
3086  * "WinUSB does not support host-initiated reset port and cycle port operations" and
3088  * ... the best we can do is cycle the pipes (and even then, the control pipe can not be reset using WinUSB)
3092 static int winusbx_reset_device(...)
3101 	// Reset any available pipe (except control)
3124 	// libusbK & libusb0 have the ability to issue an actual device reset
3125 	if ((sub_api != SUB_API_WINUSB) && (WinUSBX[sub_api].ResetDevice != NULL)) {
3128 			WinUSBX[sub_api].ResetDevice(winusb_handle);
```

I.e. with **WinUSB bound, `libusb_reset_device()` is a no-op pipe cycle for EP0** — and checkm8's staged sequence calls `usb_reset` twice (`checkm8.py:485, 506`). This is the most concrete Windows-specific hazard I found. **INFERRED consequence:** even with a driver bound, the exploit's reset-driven re-enumeration stages are at risk of silently doing nothing. **SPECULATIVE:** it is not proven that the exploit *cannot* complete without a real port reset; nobody has published a Windows attempt to check against.

Additional Windows hazard — **libusb's fixed-length device instance buffer**: `libusb/os/windows_winusb.c:1380  char dev_id[MAX_PATH_LENGTH];` (still present in current `master` at line 1990). **SECONDHAND:** the King README states Windows requires "`libusb` with fixed `MAX_PATH_LENGTH` ([see this PR](https://github.com/libusb/libusb/pull/699))"; that PR is **closed, not merged** (GitHub API: `state=closed`, `merged_at=null`). Since `libusb-1.0.dll` on this host is **1.0.24**, a long device-interface path could make `libusb_open()` fail — unverifiable without the device attached.

### 3.2 The exact USB IDs to bind

**VERIFIED** (`dfu.py:16`, `dfu.py:22`, and `include/libirecovery.h:40-47`):

| Mode | VID | PID | Source |
|---|---|---|---|
| **DFU (SecureROM DFU — what A9 checkm8 needs)** | **0x05AC** | **0x1227** | `dfu.py:16`; `IRECV_K_DFU_MODE = 0x1227` |
| WTF / iBSS-DFU | 0x05AC | 0x1222 | `IRECV_K_WTF_MODE` |
| Recovery 1–4 | 0x05AC | 0x1280 / 0x1281 / 0x1282 / 0x1283 | `IRECV_K_RECOVERY_MODE_1..4`; `recovery.py:14` uses 0x1281 |
| Port DFU | 0x05AC | 0xF014 | `IRECV_K_PORT_DFU_MODE` |
| Debug USB (KIS) | 0x05AC | 0x1881 | `KIS_PRODUCT_ID` |

Apple's vendor ID is fixed: `APPLE_VENDOR_ID 0x05AC` (`src/libirecovery.c:145`). **INFERRED (well-supported):** after a successful exploit the device **stays at 0x05AC:0x1227** and merely gains `PWND:[checkm8]` inside its serial string — because `dfu.acquire_device()` still matches on `idProduct=0x1227` and only then tests `'PWND:[checkm8]' in device.serial_number` (`checkm8.py:505-513`). So one driver binding at `0x1227` covers the whole flow. No `<ECID>`-specific binding is needed (ECID appears only in the serial string, which `dfu.py:17` can filter on).

### 3.3 Host state I could observe (read-only)

* `<REPO_ROOT>\libimobile\libusb-1.0.dll` = **libusb 1.0.24.11584** — a WinUSB-capable libusb already exists on the host.
* `C:\Windows\System32\drivers\winusb.sys` present (in-box). `usbaapl64.sys` **absent**, so Apple's USB driver is not claiming the DFU node; a Zadig-style binding would not have to fight iTunes.
* `pnputil /enum-drivers` returned no `winusb`/`libusbk`/`libusb0`/`usbaapl` third-party entries (may be elevation-limited — see §6). No `zadig` binary found under the workspace or `Downloads`.
* usbipd-win **5.3.0** confirmed at `C:\Program Files\usbipd-win\usbipd.exe`.
* `wsl -l -v` at the time of writing: `docker-desktop` **Stopped**, `Ubuntu-24.04` **Stopped**, `podman-main` **Stopped** (the task brief said podman-main was running; I observed it stopped).

### 3.4 Secondhand reports of ipwndfu on Windows

**Plainly: I found no first-hand or credible second-hand report of upstream `ipwndfu` running on Windows. No evidence found.** The upstream repo has no Windows issue/commit/CI to point at, and the maintained Python-3 fork still documents Mac+Linux only.

What *does* exist (**SECONDHAND**, third-party project READMEs, not verified by me):

* [`pgarba/King`](https://github.com/pgarba/King) — "Port of @axi0mX's checkm8 exploit ([ipwndfu](https://github.com/axi0mX/ipwndfu)) to C/C++". Its README claims **"Works on: Windows (see notes below), Linux, MacOS"**, with Windows requirements being "**libusbK** driver (can be installed with [zadig](https://zadig.akeo.ie/))" and libusb "with fixed MAX_PATH_LENGTH", and it shows Windows console transcripts (`C:\src\King\build>Release\king.exe dump-rom`). Its device list includes `iPhone SE` and `iPhone 7` (`king` C source handles `cpid == 0x8010 || cpid == 0x8011 || cpid == 0x8015 ...`). I could not find CI or tests in that repo, so treat the Windows claim as unverified.
* [`0x7ff/gaster`](https://github.com/0x7ff/gaster) — independent checkm8 reimplementation with `#ifdef WIN32  Sleep(ms)` (`gaster.c:179`) and `libusb_reset_device()` (`gaster.c:199`); it is libusb-based and contains A9-specific payloads (`payload_A9.S/.bin`). Its `Makefile` targets `macos`, `libusb`, `ios` — the `libusb` target is `$(CC) ... -DHAVE_LIBUSB ... -lusb-1.0`, i.e. plausibly buildable with MinGW, but there is no Windows target and no README.
* Third-party Python-3 repackages exist on PyPI (`ipwndfu` 2.0.0b5, "hack-different team") but still claim Mac/Linux only.

---

## 4. Viable paths, ranked

### Rank 1 — (d) Move the phone to a cheap real Linux host (bare-metal live USB on this PC, or a Raspberry Pi)

* Effort: **low–medium**. Risk: **low**. This is the only option that matches documented upstream support (README: Mac and Linux).
* Needs: a Linux environment with real xHCI/libusb access, `python2` (or a py3 port), `libusb-1.0`, and — for A9 on GitHub's `master` — the committed `bin/*.bin` blobs are already present, so **no ARM toolchain is needed**.
* Critical constraint from the README: **"It won't work in a virtual machine."** A VM (VMware/VirtualBox/Hyper-V/WSL2) is therefore *not* a substitute, because a real USB port reset and EP0 abort timing are required. A live-USB boot on the physical host, or a Pi with a real USB controller, is.
* Extra practicalities, **INFERRED**: use a USB-A **2.0** port/hub if the exploit proves flaky (`checkm8` is timing sensitive; the README itself says to retry `-p` because "it is not reliable"); on Linux you generally need `sudo` for libusb detach/reset; a Pi Zero/3/4 works but a Pi's USB stack has its own quirks — a live USB on this same PC is the cheaper first try.

### Rank 2 — (e-adjacent / native C port) Build `pgarba/King` on Windows with libusbK

* Effort: **medium–high**. Risk: **medium–high**. This is the only *Windows-native* checkm8 path I found with an explicit Windows claim.
* What would have to be true: CMake + MSVC (or MinGW) toolchain; `libusbK` bound to `0x1227` via Zadig (not WinUSB — see §3.1, libusbK *can* do a real `ResetDevice`); a libusb build with the long-device-path issue addressed (`libusb/os/windows_winusb.c:1380`); and the vendor's Windows claim actually holding for A9.
* Caveat: it is a third-party port at an unknown revision of the exploit; correct A9 (`t8010`/`t8011`) payload constants must be present in it. Verify before trusting.

### Rank 3 — (a) Native Windows: upstream ipwndfu + pyusb + WinUSB/libusbK + Zadig

* Effort: **high**. Risk: **high** (probably the wrong tool, even if it boots). Ranked below the C port because three independent blockers must all be cleared before a single USB byte moves:
  1. **Python 2.** Host has only 3.14.7; the source cannot be parsed (proof in §1.2). You would need Python 2.7 (EOL, not installable per this task's rules), or a port of ~1500 lines incl. `basestring`, `.decode('hex')`, `.tostring()`, `print`, `raw_input`, and py2 `array`/`struct` semantics. Note the vendored pyusb must be ported too if it is to keep `usb.core.find(find_all=True, ..., backend=backend)` working as the app expects.
  2. **libusbfinder returns `None` off macOS** (`libusbfinder/__init__.py:67-71`), so `dfu.py:9` hands pyusb a `find_library` that always returns `None`. **INFERRED, technically interesting:** this is survivable — `usb/backend/libusb1.py:939 get_backend()` returns `None` on that failure, and then `usb/core.py:1252-1261` sees `backend is None` and auto-retries `libusb1.get_backend()` *with* the default `find_library`, which on Windows applies the `.dll` workaround (`usb/libloader.py:87-93`) and looks for `libusb-1.0.dll` on `PATH`. So dropping `libusb-1.0.dll` (the 1.0.24 one already in `libimobile\`) on `PATH` may satisfy this dependency without patching. But the exploit path then relies on pyusb **private internals** (`usb.backend.libusb1._lib`, `device._ctx.handle.handle`, `device._ctx.backend.lib`) — those exist in the vendored copy and are not Windows-conditional, so this part is plausible.
  3. **Driver + reset semantics.** Zadig must bind libusbK (or WinUSB) to `0x05AC:0x1227`; with WinUSB, `device.reset()` is effectively a no-op for EP0 (§3.1). The exploit's two reset stages would then silently degrade, and the stall primitive needs a 10 µs submit→cancel round trip through the Windows USB stack, which is not a documented-supported precision path. **SPECULATIVE:** that the Windows stack can hit the cancel timing at all; libusb's async+cancel path is real on Windows, but the 10 µs budget in `checkm8.py:118` is a macOS/Linux-tuned constant.
* Honest verdict: **not a viable path as-is.** The realistic native variant of (a) is Rank 2 (a C reimplementation that was written with Windows in mind).

### Rank 4 — (c) usbipd-win → Linux environment

* Effort: **medium**. Risk: **medium–high**, and it is currently **blocked by the environment, not by usbipd**.
* What usbipd can do (**VERIFIED** from its README): `usbipd bind --busid=<BUSID>` then either `usbipd attach --wsl --busid=<BUSID>` (WSL 2) or `usbip attach --remote=<HOST> --busid=<BUSID>` from a separate Linux machine. It explicitly supports WSL 2 and warns that the **WSL 2 kernel must support the device** ("Update WSL 2 with `wsl --update` to get the latest kernel, which supports most USB devices"; "See the wiki on how to add drivers for USB devices that are not supported by the default WSL 2 kernel").
* The catches here, in order of severity:
  1. **There is no working Linux target.** Ubuntu-24.04 fails to start ("Failed to start the systemd user session"), and I observed `podman-main` **Stopped**. usbipd needs a *running* WSL 2 distro (or a second physical box, which collapses into Rank 1).
  2. The chosen distro's kernel needs the **usbip client + vhci_hcd** modules; a stripped podman-machine kernel may not have them.
  3. **USBIP is a network-transported USB stack** — device enumeration, control transfers and especially resets are mediated by the `usbip` client/server pair. checkm8 is a timing- and reset-sensitive exploit; **SPECULATIVE but likely:** the added latency/jitter and the virtual host controller's reset semantics will hurt reliability, and `libusb_reset_device()` over USBIP is not the same operation as a real port reset.
  4. While attached, the device is claimed by usbipd's stub driver — it disappears from the Windows side (`usbipd unbind` restores it).
* Verdict: worth a *test* only if a WSL2 kernel with usbip modules can be produced; it is a research detour, not a shortcut. (Ironically, an earlier stage of this path — Intel Macs running Linux in a VM — is exactly what the README warns against.)

### Rank 5 — (b) podman container

* Effort: **high**. Risk: **high**. Assessed honestly: **not recommended.**
* `podman-main` is a WSL 2 VM. A container inside it can only see a USB device that the *WSL VM* already sees. So this is strictly worse than Rank 4: you must first solve USBIP-into-WSL (Rank 4's problems), then add container plumbing (`--device /dev/bus/usb/00X/00Y`, `--privileged`, cgroup device rules, hot-plug handling when the device re-enumerates mid-exploit — which checkm8 *does*), and then live with the fact that USB hot-plug/re-enumeration is the single most fragile part of container device passthrough. The README's own "won't work in a virtual machine" applies to the VM underneath. There is no upside over booting Linux directly.

### Rank 6 — (e) `irecovery -k` as a native Windows payload path

**VERIFIED: `-k` is limera1n-only and does NOT cover checkm8 on A9. It is not an alternative.**

Evidence, in order:

1. Local binary, `<REPO_ROOT>\libimobile\irecovery.exe -h` (observed, version reported as `irecovery 1.0.0`):
   `-k, --payload FILE	send limera1n usb exploit payload from FILE`
2. Export table of the local `irecovery.dll` contains `irecv_trigger_limera1n_exploit` (and `irecv_send_file`, `irecv_send_command`, `irecv_send_buffer`) — no checkm8 symbol of any kind.
3. Upstream `tools/irecovery.c`: `476: printf("  -k, --payload FILE\tsend limera1n usb exploit payload from FILE\n");`, `498: { "payload", required_argument, NULL, 'k' },`, `576-579: case 'k': action = kSendExploit;` → `669-684: case kSendExploit: ... irecv_send_file(client, argument, 0); ... error = irecv_trigger_limera1n_exploit(client);`
4. Upstream `src/libirecovery.c:4112 irecv_trigger_limera1n_exploit()` really is limera1n and only limera1n: on macOS (`#ifdef HAVE_IOKIT`) it submits a `bmRequestType 0x21 / bRequest 2 / wLength 0` request on a **second thread** and then `USBDeviceAbortPipeZero()` after 5 ms (lines 4125-4145). On **every non-Apple platform**, including Windows, the fallback is a single synchronous request with no abort:
   ```c
   4156: #else
   4157: 	irecv_usb_control_transfer(client, 0x21, 2, 0, 0, NULL, 0, USB_TIMEOUT);
   4158: #endif
   ```
   A plain `DFU_DNLOAD(0)` is not an exploit trigger. limera1n targets **S5L8920/S5L8922** only (ipwndfu routes `CPID:8920`/`CPID:8922` to `limera1n.exploit()`); A9 is `0x8010`/`0x8011`, which ipwndfu routes to `checkm8.exploit()`.
5. The only shell-level exploit entry point in upstream `irecovery.c` is the script command `81: /limera1n [FILE]	run limera1n exploit and send optional payload from FILE`.

**Conclusion:** `irecovery -k` can send a file and, on macOS only, run limera1n. It has **no checkm8 implementation and no A9 payload path**. checkm8 must be driven by a host-side exploit that speaks raw EP0 control transfers with submit/cancel timing (ipwndfu, gaster, King, checkra1n). What `irecovery` *is* good for on this host is everything **after** pwned DFU: `-q` for identification, `-c` to run commands in pwned DFU on the device side, and (on the chosen Linux host) `-f` to send an iBSS/iBoot. It is a perfectly good **post-exploit** tool and a useless exploit tool.

---

## 5. Bottom line

**The single most likely path to actually running checkm8 against this A9: stop trying to make the Windows host do it — boot a bare-metal Linux live USB on this same PC (Rank 1), move the iPhone SE there, and run a libusb checkm8 tool (upstream `ipwndfu` or `gaster`) with libusb-1.0 and real xHCI access.** That is the only path with no unproven platform assumptions; the phone stays plugged into the same physical machine, only the OS changes. The best *native Windows* possibility is compiling `pgarba/King` against libusb with the **libusbK** driver bound to `0x05AC:0x1227` (Zadig), because libusb only performs a real `ResetDevice` on libusbK/libusb0, not on WinUSB.

**What the first failure would probably be** (in order, for the native attempt):

1. If you try upstream `ipwndfu` directly on this host: **a Python 2 `SyntaxError` on `ipwndfu:11`, before any USB code executes.** Nothing about Zadig, WSL or libusb matters until that is solved (by using Python 2.7 on Linux, or by porting the code).
2. If you port it to Python 3 first: **`No Apple device in DFU Mode 0x1227 detected after 5.00 second timeout`** (`dfu.py:22`) — the device is either not visible to libusb because no WinUSB/libusbK driver is bound to the `0x1227` node, or `libusb-1.0.dll` was not on `PATH` for pyusb's fallback backend probe (`usb/core.py:1252-1261`). Fixing this is the "easy" part.
3. Then the silent one: the exploit's `device.reset()` stages (`checkm8.py:485,506`) degrade to a WinUSB pipe cycle and the device never re-enumerates with `PWND:[checkm8]`, so `checkm8.py:511` prints `ERROR: Exploit failed. Device did not enter pwned DFU Mode.` with no error from any layer below it.

---

## 6. What I could not verify

* **Whether any libusb driver is currently bound to an Apple USB node.** No A9 was attached during this research, and `pnputil /enum-drivers` produced no matching entries (it may require elevation, so this is inconclusive rather than a negative). The concrete check to run once the phone is in DFU: `usbipd list` and Device Manager's driver for `USB\VID_05AC&PID_1227`.
* **Whether `pgarba/King` actually works on Windows for A9.** Its Windows claim is a third-party README; I found no CI, tests, or independent confirmation, and I did not build it (no installs permitted).
* **Whether the vendored pyusb (1.0.0-beta era) plus `checkm8.py`'s private-internals poking (`usb.backend.libusb1._lib`, `device._ctx.handle.handle`) works against libusb 1.0.24 on Windows.** The code paths exist and are not `#ifdef`-ed out on Windows, but I could not execute them.
* **Whether the `MAX_PATH_LENGTH` issue (`libusb/os/windows_winusb.c:1380`, PR #699 closed/unmerged) affects *this* device.** Depends on the device instance path length, unknown without the phone.
* **Whether WinUSB's inability to do a real reset actually breaks checkm8**, versus merely costing reliability. Not proven either way by any source I found; nobody appears to have published a Windows A9 attempt.
* **The parent's statement that `podman-main` is running** — I observed it `Stopped` (and `docker-desktop`, `Ubuntu-24.04` stopped) at the time of writing, so I could not test `usbipd attach --wsl` against it, nor whether that distro's kernel carries `vhci_hcd`/`usbip`.
* **The current `irecovery.dll`'s exact upstream revision.** The tool prints `irecovery 1.0.0` and its `-h` matches current upstream text; the DLL carries no version resource, and the bundle's `-k` behaviour was reasoned from upstream `master` source plus the local export table, not from the bundled DLL's own binary logic.
* **Whether the PyPI `ipwndfu` 2.0.0b5 (Python 3.8+) fork works on Windows.** Its own description still says Mac and Linux; I did not download or inspect its code.

---

## Sources

Primary (all fetched during this task):

* ipwndfu repo tree and files at commit `0e28932ec6a2a570b10fd77e50bda4216418cd98` — <https://github.com/axi0mX/ipwndfu> (README.md, ipwndfu, dfu.py, usbexec.py, checkm8.py, dfuexec.py, utilities.py, libusbfinder/__init__.py, usb/core.py, usb/backend/libusb1.py, usb/libloader.py, Makefile)
* libirecovery `master` — <https://github.com/libimobiledevice/libirecovery> (`src/libirecovery.c:145,4112-4160`, `tools/irecovery.c:81,476,498,576,669-684`, `include/libirecovery.h:40-47`)
* libusb v1.0.24 and `master` — <https://github.com/libusb/libusb> (`libusb/os/windows_winusb.c:1380` and the `winusbx_reset_device` block at 3083-3132)
* Local host inspection (read-only): `libimobile\irecovery.exe -h`, `irecovery.dll` export strings, `libusb-1.0.dll` file version, `usbipd --version`, `wsl -l -v`, `pnputil /enum-drivers`, `C:\Windows\System32\drivers\`
* usbipd-win README — <https://github.com/dorssel/usbipd-win>
* PyPI metadata for `ipwndfu` 2.0.0b5 — <https://pypi.org/project/ipwndfu/>

Secondary/secondhand (labelled as such above, not independently verified):

* `pgarba/King` README (Windows + libusbK claim) — <https://github.com/pgarba/King>
* `0x7ff/gaster` source/Makefile (WIN32 sleep, libusb reset, A9 payloads) — <https://github.com/0x7ff/gaster>
* libusb PR #699 (closed, unmerged) — <https://github.com/libusb/libusb/pull/699>
