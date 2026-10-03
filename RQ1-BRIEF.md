# RQ1 Brief — Apple A9 (iPhone SE 1st gen / 6s / 6s Plus): SecureROM, DFU Surface, and Hard Limits

**Purpose:** make the next DFU session *targeted* instead of exploratory.
**Target:** iPhone SE (1st generation, `iPhone8,4`) / iPhone 6s (`iPhone8,1`) / 6s Plus (`iPhone8,2`) — Apple A9, SoC `s8000` (Samsung) / `s8003` (TSMC).
**Device-unique identifiers:** none appear in this document. `<ECID>`, `<UDID>`, `<SRNM>` are placeholders.

**Confidence tags used throughout:**
- **[V]** = VERIFIED — read directly in a primary source (repo source, Apple document, published technical write-up).
- **[I]** = INFERRED — follows from verified facts but not stated verbatim.
- **[S]** = SPECULATIVE — plausible, not established; treat as a hypothesis to test.

---

## 0. Corrections to prior assumptions (read this first)

Three claims in the existing `PLAN.md` are **wrong** and would misdirect the lab. They are corrected here.

| Prior claim | Reality | Basis |
|---|---|---|
| Layer 3 protection on A9 is "KTRR, PPL — hardware page protection armed by iBoot" | **A9 has neither KTRR nor PPL.** KTRR is A10+. A9's kernel-integrity mechanism is **KPP/WatchTower**, a *software* monitor in TrustZone (EL3), which is bypassable and has been bypassed publicly. | **[V]** Siguza, [KTRR](https://blog.siguza.net/KTRR/) — "the mechanism used in Apple's **A10 chips and later**"; "Older chips attempt to do this via a monitor program loaded in EL3, which is inherently flawed and bypassable". xerub, [Tick (FPU) Tock (IRQ)](https://xerub.github.io/ios/kpp/2017/04/13/tick-tock.html). |
| "Booting a foreign OS (Linux) on A9: **not achievable** … requires defeating KTRR" | KTRR is absent on A9, so that specific blocker does not exist. Separately, **mainline Linux now carries device trees for the A9** — `s8000`/`s8003`, covering iPhone 6s / 6s Plus / SE 1st gen / iPad 5. | **[V]** [PATCH v6 RESEND 15/20] *arm64: dts: apple: Add A9 devices* ([LKML](https://lkml.iu.edu/hypermail/linux/kernel/2410.2/10132.html)); present in `arch/arm64/boot/dts/apple/Makefile` ([torvalds/linux](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/boot/dts/apple/Makefile)). |
| checkm8 CVE = "CVE-2019-8566 family" | checkm8 is **CVE-2019-8900**. | **[V]** [The Apple Wiki — checkm8](https://theapplewiki.com/wiki/Checkm8_Exploit); [CERT/CC VU#941987](https://www.kb.cert.org/vuls/id/941987/). |
| `a9id.py` labels A9 bootrom "`s5l8960x`-era" | `s5l8960x` is **A7** (iPhone 5s), not A9. A9 is `s8000`/`s8003`. | **[V]** libirecovery device table (below); Linux `s8000.dtsi` header: *"Apple S8000 "A9" (Samsung) SoC … Other names: H8P, "Maui""*. |

The **headline correction**: the reachable surface on A9 is *wider* than previously assumed, not narrower. The blockers are the **boot chain (layer 2)** and the **Secure Enclave (layer 4)** — not KTRR.

---

## 1. SecureROM / BootROM overview (A9)

### 1.1 What it is and why it is immutable
**[V]** SecureROM (Apple's "BootROM") is the first code the application processor executes after power-on reset. It is **mask ROM** — the logic is fixed in silicon at fabrication. No software update, restore, or firmware image can alter it, because there is nothing to write to: the code is not stored in rewritable memory. This is why a SecureROM bug is permanent for the life of the silicon.

Position in the boot chain:
`SecureROM (mask ROM)` → validates and loads `LLB` → `iBoot` → `iBSS`/`iBEC` → `kernelcache` → `launchd`.

SecureROM's jobs: minimal hardware init, enable the secure boot path, and expose **USB DFU** as the recovery entry point when no valid next stage is present.

**[V]** SecureROM is where checkm8 executes. As of iOS 9, all arm64 devices have kernel patch protection "wherein something likely other than the kernel checks every so often for kernel integrity" ([kpwn/iOSRE KPP notes](https://raw.githubusercontent.com/kpwn/iOSRE/master/wiki/Kernel-Patch-Protection-(KPP).md)) — that is *downstream* of SecureROM and is a different problem (§4.1).

### 1.2 The checkm8 vulnerability class — precise mechanism
**[V]** checkm8 is a **use-after-free (UAF) in SecureROM's USB DFU stack**, triggered by an **incomplete data phase on a `DFU_DNLOAD` control transfer**. Disclosed by axi0mX on 27 Sep 2019 (CVE-2019-8900). Primary technical description: [The Apple Wiki — checkm8](https://theapplewiki.com/wiki/Checkm8_Exploit) and the deepest public reverse-engineering is [Alfie CG, *A comprehensive write-up of the checkm8 BootROM exploit*](https://alfiecg.uk/2023/07/21/A-comprehensive-write-up-of-the-checkm8-BootROM-exploit).

The mechanism, step by step:

1. `usb_dfu_init()` allocates a **global I/O buffer** — `memalign(0x800, 0x40)`, i.e. **0x800 bytes**, 0x40-aligned — and `bzero()`s it. Global state includes a pointer to this buffer (`ep0DataPhaseBuffer`) and a length (`ep0DataPhaseLength`). **[V]**
2. On a host→device control request with `bRequest = 1` (**`DFU_DNLOAD`**), `handle_interface_request()` checks `wLength <= sizeof(io_buffer)` and, if it passes, sets `*out_buffer = io_buffer` and returns `wLength`. The data phase is now armed, pointing at the global buffer. **[V]**
3. The host **never completes the data phase**. `handle_ep0_data_phase()` only clears the global state in its `done:` path (`ep0DataPhaseReceived = 0; ep0DataPhaseLength = 0; ep0DataPhaseBuffer = NULL; …`). A partial transfer returns early **without clearing**. **[V]**
4. The host sends **`DFU_ABORT` (`bRequest = 6`)** or **`DFU_CLR_STATUS` (`bRequest = 4`)**, or issues a USB reset → `dfuDone = true` → `getDFUImage()` calls `usb_quiesce()` → `usb_free()` → `usb_dfu_exit()` → **`free(io_buffer)`**. **[V]**
5. DFU re-enters. The globals are **not re-initialised**, so a dangling pointer to the freed 0x800-byte buffer survives. **[V]**

That is the UAF. Exploitation then requires a second problem to be solved: on re-entry the allocator would normally place the new I/O buffer exactly on top of the freed one, making the dangling pointer useless. checkm8 solves this with **heap feng shui**:

- **[V]** A **memory leak**: `standard_device_request_cb()` queues an extra zero-length packet iff `io_length > 0 && (io_length % 0x40) == 0 && setup_request.wLength > io_length`. If the pipe is stalled and the stack is then shut down, those queued zero-length packets are never sent and never freed — they leak. Leaking two allocations exactly `0x800` apart creates a hole the allocator prefers for the next `0x800` allocation.
- **[V]** The overwrite targets a **`usb_device_io_request`** structure:
  ```
  struct usb_device_io_request {
      u_int32_t endpoint; volatile u_int8_t *io_buffer; int status;
      u_int32_t io_length; u_int32_t return_count;
      void (*callback)(struct usb_device_io_request *);   /* offset 0x20 */
      struct usb_device_io_request *next;
  };
  ```
  Overwriting **`callback`** and **`next`** lets the exploit (a) stop the corrupted object from being freed (invalid heap metadata would panic) via a BootROM "nop gadget" `ldp x29,x30,[sp,#0x10]; ldp x20,x19,[sp],#0x20; ret`, and (b) redirect the callback chain into attacker shellcode when a USB reset flushes the pending request list. **[V]**

**A9-specific note — this matters directly for RQ1.**
**[V]** The wiki states: *"This leak is not needed on A8, A8X and A9 devices — where a **DFU abort bug** is abused to achieve **direct code execution** without the need of ROP or JOP."* A9 therefore takes a distinct, simpler exploitation path than A10/A11 (which need the leak + ROP chain, cf. `checkm8.py`'s `t8010_*`/`t8011_*`/`t8015_*` callback chains). Any A9 work should follow the A9 path, not port the A10/A11 payloads.

### 1.3 Why it is unpatchable
**[V]** Because SecureROM is mask ROM (§1.1), Apple cannot patch checkm8 on any already-manufactured A5–A11 device. Apple's only remedy was to fix it in **later silicon**: the fix landed in SecureROM `3865.0.0.4.7`, and **[V]** per the wiki the UAF itself is still present on A12/A12X/A13 *but is not exploitable without the memory leak*, which was patched in A12. This distinction matters: the UAF and the leak are **two separate bugs**, and it is the leak fix that kills exploitable checkm8 on A12+.

### 1.4 A9 chip IDs (CPID) and board IDs (BDID)
**[V]** Source: libirecovery's compiled-in device table, [`src/libirecovery.c`](https://raw.githubusercontent.com/libimobiledevice/libirecovery/master/src/libirecovery.c).

| Product type | Hardware model | BDID | **CPID** | Display name |
|---|---|---|---|---|
| `iPhone8,1` | `n71ap` | 0x04 | **0x8000** | iPhone 6s (Samsung) |
| `iPhone8,1` | `n71map` | 0x04 | **0x8003** | iPhone 6s (TSMC) |
| `iPhone8,2` | `n66ap` | 0x06 | **0x8000** | iPhone 6s Plus (Samsung) |
| `iPhone8,2` | `n66map` | 0x06 | **0x8003** | iPhone 6s Plus (TSMC) |
| `iPhone8,4` | `n69ap` | 0x02 | **0x8003** | iPhone SE 1st gen (TSMC) |
| `iPhone8,4` | `n69uap` | 0x02 | **0x8000** | iPhone SE 1st gen (Samsung) |

**[V]** A9 exists in two fab variants on different process nodes: **S8000 "Maui" (Samsung, 14 nm)** and **S8003 "Malta" (TSMC, 16 nm)** — Linux `s8000.dtsi` comment. They are functionally equivalent as far as Linux is concerned, but they carry distinct part numbers/CPIDs. **Practical consequence: the same iPhone model name can present either CPID. Do not assume "iPhone SE = 0x8003".** Read it.

**[V]** **How CPID/BDID are read:** they are emitted by SecureROM/iBoot into the **USB serial-number string descriptor**, in the `iBoot string` format, and parsed by the host. libirecovery's `irecv_load_device_info_from_iboot_string()` does plain substring scans for `CPID:`, `CPRV:`, `CPFM:`, `SCEP:`, `BDID:`, `ECID:`, `IBFL:`, `SRNM:[<SRNM>]`, `IMEI:[<IMEI>]`, `SRTG:[<version>]`. There is **no authentication, encryption, or signature check anywhere in this path** — it is read straight off the descriptor. That is itself a core RQ1 fact.

**[I]** The `SRTG:[…]` field carries the boot-stage version string (e.g. `iBoot-…`). checkm8's own implementation relies on it: `exploit_config()` matches `'SRTG:[%s]' % config.version` and, if only the CPID matches, errors with *"CPID is compatible, but serial number string does not match. Make sure device is in SecureROM DFU Mode and not LLB/iBSS DFU Mode."* **[V]** (`checkm8.py`). This is the device-side signal that distinguishes SecureROM DFU from iBSS DFU — critical for RQ1 (§2.4).

---

## 2. The DFU USB interface

### 2.1 USB identity
**[V]** **VID = `0x05AC` (Apple)**. Relevant PIDs, from libirecovery's `enum irecv_mode` in [`include/libirecovery.h`](https://raw.githubusercontent.com/libimobiledevice/libirecovery/master/include/libirecovery.h):

| PID | Mode | `irecv_mode` |
|---|---|---|
| **`0x1227`** | **DFU** | `IRECV_K_DFU_MODE` |
| `0x1222` | WTF mode | `IRECV_K_WTF_MODE` |
| `0x1280`–`0x1283` | Recovery (iBSS/iBEC) | `IRECV_K_RECOVERY_MODE_1..4` |
| `0xF014` | Port DFU | `IRECV_K_PORT_DFU_MODE` |
| `0x1881` | KIS | `KIS_PRODUCT_ID` |

**[V]** `ipwndfu/dfu.py` acquires the device with exactly `idVendor=0x5AC, idProduct=0x1227`.

**What the PID does NOT tell you [V]:** Apple reuses the same PIDs across SoC families. `0x1227` alone does **not** identify the chip, the board, or even the model — and it does not distinguish SecureROM DFU from iBSS DFU. The PID is only a *mode* indicator. Chip identity comes from `CPID`/`BDID` in the serial string. This is exactly the trap `a9id.py` warns about in its own comment — the comment is right; the surrounding `s5l8960x` label is not.

### 2.2 Control requests SecureROM's DFU handles
**[V]** The DFU class request set is visible in `ipwndfu/dfu.py` and `checkm8.py`. `ipwndfu` calls `ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout)`.

| bmRequestType | bRequest | DFU meaning | wValue | wIndex | wLength | Direction |
|---|---|---|---|---|---|---|
| `0x21` | `1` | `DFU_DNLOAD` | 0 | 0 | payload len (≤ `0x800`) | OUT (host→dev) |
| `0xA1` | `2` | `DFU_UPLOAD` | 0 | 0 | bytes wanted | IN (dev→host) |
| `0xA1` | `3` | `DFU_GETSTATUS` | 0 | 0 | 6 | IN |
| `0x21` | `4` | `DFU_CLRSTATUS` | 0 | 0 | 0 | OUT |
| `0xA1` | `5` | `DFU_GETSTATE` | 0 | 0 | 1 | IN |
| `0x21` | `6` | `DFU_ABORT` | 0 | 0 | 0 | OUT |
| `0x80` | `6` | `GET_DESCRIPTOR` | `0x304` (BOS) / `0x100` | `0x40A` / 0 | `0xC0`/`0xC1`/`0x40`/`0x41` | IN |
| `0x02` | `3` | `SET_FEATURE` (stall) | 0 | `0x80` | 0 | OUT |
| `0x00` | `0` | **invalid/non-standard setup** | 0 | 0 | data len | OUT |

Notes, all **[V]** from `ipwndfu/dfu.py` + `checkm8.py`:
- `MAX_PACKET_SIZE = 0x800`; `send_data` chunks payloads into `0x800`-byte `DFU_DNLOAD` transfers.
- `reset_counters`: `ctrl_transfer(0x21, 4, 0, 0, 0, 1000)` — `DFU_CLRSTATUS`.
- `usb_req_stall`: `ctrl_transfer(0x2, 3, 0x0, 0x80, 0x0, 10)` — `SET_FEATURE` to endpoint `0x80` (stall EP0 IN).
- `usb_req_leak` / `usb_req_no_leak`: `GET_DESCRIPTOR` (`0x80, 6, wValue=0x304, wIndex=0x40A`) with `wLength` `0x40`/`0x41`; the `stall`/`leak`/`no_leak` variants use `0xC0`/`0xC1`.
- The line `libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, config.overwrite, 100)` sends `bmRequestType = 0x00` — **not a valid USB request type** — which is how the overwrite is delivered. Expect this to look like a protocol violation to any conformant stack. It is deliberate.
- `request_image_validation()`: `DFU_DNLOAD` (len 0) then three `DFU_GETSTATUS` reads of 6 bytes, then USB reset.

### 2.3 Which requests are PRE-AUTHENTICATION (the core of RQ1)
**[V]** On A9, SecureROM DFU **does not perform any signature verification before accepting the DFU class requests above.** The evidence is direct: checkm8 executes entirely pre-authentication. It triggers the UAF with `DFU_DNLOAD` + `DFU_ABORT`/`DFU_CLRSTATUS` and delivers its overwrite and payload through `DFU_DNLOAD` — with no image, no signature, and no APTicket involved. If a signature gate preceded those handlers, the exploit could not work as documented.

**[I]** Therefore the **pre-authentication request set is the whole DFU surface** enumerated in §2.2, plus the descriptor reads. Concretely, the security-relevant primitive is: *an unauthenticated host can drive `DFU_DNLOAD`'s length/state machine freely, and can force DFU exit and re-entry at will.*

**[S]** Whether SecureROM validates anything at all about the DFU transfer contents *before* the UAF is not something I could confirm from a primary source. The `image4_validate_property_callback()` patch in the checkm8 payload suggests validation happens on the *image*, later, not on the DFU transport. Worth an explicit read-only probe (§5.5).

### 2.4 Reading CPID / BDID / ECID / nonce over DFU
**Method [V]:** open the `0x05AC:0x1227` device, then read the **string descriptor at index `iSerialNumber`** from the USB device descriptor. Parse the `iBoot string`. libirecovery does this in `irecv_load_device_info_from_iboot_string()`; `ipwndfu` does the equivalent by inspecting `device.serial_number`.

Fields available, and their sensitivity:

| Field | Example form | Sensitivity |
|---|---|---|
| `CPID` | `CPID:8000` | **Not unique** — safe to publish (chip variant). |
| `BDID` | `BDID:02` | **Not unique** — safe to publish (board variant). |
| `CPRV`, `CPFM`, `SCEP`, `IBFL` | `CPRV:11` etc. | Not unique — security/feature flags. |
| `SRTG` | `SRTG:[iBoot-…]` | Not unique — boot-stage version. |
| **`ECID`** | `ECID:<ECID>` | **DEVICE-UNIQUE — DO NOT PUBLISH.** |
| **`SRNM`** | `SRNM:[<SRNM>]` | **DEVICE-UNIQUE — DO NOT PUBLISH.** |
| `IMEI` | `IMEI:[<IMEI>]` | **DEVICE-UNIQUE — DO NOT PUBLISH.** |
| **`NONC` / `SNON`** | (binary, parsed from string) | **Per-boot/per-device nonce — DO NOT PUBLISH.** |

**[V]** Nonces: libirecovery calls `irecv_copy_nonce_with_tag(client, "NONC", …)` for the **AP nonce** and `irecv_copy_nonce_with_tag(client, "SNON", …)` for the **SEP nonce** (`irecv_open_with_ecid`). The tags are `NONC` and `SNON`.

**[I]** It is not confirmed that **SecureROM** DFU (as opposed to iBSS/Recovery) emits `SNON`. The parse function tolerates absence. Treat "which nonces are visible in SecureROM DFU" as an open, testable question — it is a good RQ1 observation (§5.6).

**[V]** The `descriptor read is not gated.** No authentication precedes it.

---

## 3. Tooling map

| Tool | Repo / URL | What it is | State today | Platforms |
|---|---|---|---|---|
| **`ipwndfu`** | [github.com/axi0mX/ipwndfu](https://github.com/axi0mX/ipwndfu) | axi0mX's DFU exploitation toolkit; the reference implementation of checkm8 | **[V]** Upstream is **Python 2** (`print` statements, `'…'.decode('hex')`), README still says `pip install pyusb` and `brew cask install`. Effectively unmaintained. | **[V]** "Mac and Linux. It won't work in a virtual machine." Requires **libusb1** backend — it hard-exits if another backend is in use. |
| **`libirecovery`** | [github.com/libimobiledevice/libirecovery](https://github.com/libimobiledevice/libirecovery) | C library + `irecovery` CLI to talk to iBoot/iBSS/SecureROM over USB | **[V]** Actively maintained (copyright through 2023; device table includes iPhone 17-gen entries). | **[V]** Repo tagline: *"Library and utility to talk to iBoot/iBSS via USB on **Mac OS X, Windows, and Linux**"*. Windows path uses `setupapi`/`CreateFileA`. **Windows-native — no WSL required.** |
| **PongoOS** | [github.com/checkra1n/PongoOS](https://github.com/checkra1n/PongoOS) | *"A pre-boot execution environment for Apple boards built on top of checkra1n."* The payload stage between SecureROM and iBoot. | **[V]** Public, MIT-licensed; builds on macOS and Linux (`clang` + `ld64` + `cctools-strip`). | macOS, Linux |
| **`checkra1n`** | checkra.in (payloads; PongoOS is the open part) | checkm8-based jailbreak | **[V]** Largely superseded by palera1n. | macOS, Linux |
| **`palera1n`** | [github.com/palera1n/palera1n](https://github.com/palera1n/palera1n) | checkm8-based jailbreak, wraps checkra1n + PongoOS + KPF | **[V]** Active. Takes `-i/--override-checkra1n`, `-k/--override-pongo`, `-K/--override-kpf`, `-p/--pongo-shell`. | **[V]** Requires **"Linux or macOS computer"**. |

### 3.1 ipwndfu — and its critical A9 limitation
**[V] The upstream `ipwndfu` does not support A9 at all.** Its SoC table (`all_exploit_configs()` in `checkm8.py`) contains:

- current: `s5l8947x`, `s5l8950x`, `s5l8955x`, `s5l8960x` (A7), `t8002`, `t8004` (A8), `t8010` (A10), `t8011` (A10X), `t8015` (A11)
- "future SoC support" (never implemented): `s5l8940x`, `s5l8942x`, `s5l8945x`, `s5l8747x`, `t7000`, `t7001`, `s7002`, **`s8000`**, **`s8003`**, `t8012`

So `s8000`/`s8003` — **our A9 chips — are listed as unimplemented "future" support.** Running upstream `ipwndfu -p` against an iPhone SE would hit `exploit_config()`'s fallthrough: *"ERROR: This is not a compatible device. Exiting."*

**Consequence for the lab:** A9 checkm8 requires either a maintained fork or a different implementation. Candidates: **`gaster`** ([github.com/0x7FF/gaster](https://github.com/0x7FF/gaster)) and **Alfie CG's `Achilles`** ([github.com/alfiecg24/Achilles](https://github.com/alfiecg24/Achilles)) — both cited by the Alfie CG write-up as working implementations, and both the basis for the A9 path. Anything relying on upstream ipwndfu must be re-scoped.

Other **[V]** ipwndfu limitations:
- **VM-hostile**: README states it won't work in a virtual machine (raw USB access).
- **Unreliable**: README says of `./ipwndfu -p`: *"Repeat the process if it fails, it is not reliable."* Expect multiple attempts.
- **Apple Silicon USB-C**: **[V]** The Apple Wiki records a USB-stack issue on Apple Silicon Macs where checkm8 fails over USB-C for some devices; checkra1n and gaster work around it, ipwndfu and Fugu do not.
- **Ephemeral**: checkm8 does not persist. Every reboot requires re-exploitation — hence "semi-tethered".

### 3.2 libirecovery — practical use for RQ1
**[V]** Relevant surface: `irecv_open_with_ecid()`, `irecv_get_device_info()` (returns `struct irecv_device_info` with `cpid`, `cprv`, `cpfm`, `scep`, `bdid`, `ecid`, `ibfl`, `srnm`, `imei`, `srtg`, `ap_nonce`, `sep_nonce`, `pid`), `irecv_usb_control_transfer()` (raw `bmRequestType/bRequest/wValue/wIndex/data/wLength` — enough to send the whole §2.2 table by hand), `irecv_reset_counters()`, `irecv_finish_transfer()`, `irecv_trigger_limera1n_exploit()`.

**[I]** `irecv_usb_control_transfer()` plus `irecv_get_device_info()` is sufficient to run most of the §5 read-only probes without ipwndfu at all — which is important, since ipwndfu can't drive A9. **This is the recommended primary tool for RQ1.**

**[V]** The existing lab already has this: `<REPO_ROOT>\libimobile\irecovery.exe` is Windows-native and exposes `-q/--query` (device info — read-only), `-m/--mode`.

### 3.3 checkra1n / palera1n — what they do and do NOT do
**[V]** Both use checkm8 to gain SecureROM code execution, boot **PongoOS** as a pre-boot environment, and use checkra1n's **kernel patchfinder (KPF)** Pongo module to patch the *running kernel in memory*. PongoOS's README also notes the KPF bundle *"currently includes the SEP exploit"*.

**[V]** palera1n device support for our target: **iPhone 6s, iPhone 6s Plus, iPhone SE (2016)** are explicitly listed, on **iOS 15.0+**.

**Explicitly, what they do NOT do [V]:**
- They **jailbreak an existing, already-signed, already-installed iOS**. They do not replace the OS, reinstall it, or install a foreign OS.
- They do **not** make anything persistent. The kernel is patched in memory at each boot via PongoOS; power off and you are back to stock. This is why they are called **semi-tethered**.
- They do **not** defeat Apple's boot chain permanently — Apple's stock boot chain still runs and still validates every image each boot.
- palera1n's own README confirms the jailbreak is removable (`--force-revert`, "Remove jailbreak") and warns about passcode interaction on **A11 only** [V] — note this is an A11 constraint, **not** an A9 one.

---

## 4. Known hard limits (blunt)

### 4.1 KTRR and PPL do not apply to A9 — but the *class* of limit does
**[V]** **KTRR is A10 and later.** Siguza's write-up opens: *"This post tries to detail the mechanism used in Apple's **A10 chips and later**."* It rests on two A10 hardware primitives absent from A9: **RoRgn** (MMIO `RORGNBASEADDR`/`RORGNENDADDR`/`RORGNLOCK` in the AMCC; locks DRAM against writes) and the **KTRR registers** (`ARM64_REG_KTRR_LOWER_EL1` = `S3_4_c15_c2_3`, `_UPPER_EL1` = `S3_4_c15_c2_4`, `_LOCK_EL1` = `S3_4_c15_c2_2`; write-once, enforce the executable range at EL1 with MMU on). **[V]** Neither exists on A9.

**[V]** **A9's actual mechanism is KPP ("WatchTower")**: iBoot carves a Mach-O monitor out of the kernelcache, loads it at `0x4100000000`, and runs it **in EL3** (TrustZone). It hashes `__TEXT` and `__DATA.__const` on a periodic heartbeat driven by FPU traps and IRQs, compares against saved digests, validates page tables and system registers (`SCTLR_EL1`, `TCR_EL1`, `TTBR1_EL1`, `VBAR_EL1`), and panics the kernel via an SError on mismatch. **[V]** xerub's *Tick (FPU) Tock (IRQ)* documents this in full, including the bypass: *"steal away the CPACR_EL1 access to a separate trampoline: 1. undo patches 2. hit CPACR_EL1, hypervisor runs and restores execution right after our CPACR_EL1 3. redo patches 4. profit"* — *"This bypass was demo-ed by @qwertyoruiop in yalu102."*

**[I]** So on A9, kernel-text modification is *not* hardware-blocked; it is *policed asynchronously by a bypassable EL3 monitor*. That is a materially weaker position than A10+.

**But the general limit still holds, and this is the honest framing:** boot-time code execution **before** a protection is armed does not equal a **persistent bypass**, for two reasons.
1. **Arming is downstream of you.** checkm8 runs in SecureROM, before iBoot loads the kernel and before KPP hashes anything. Running earlier does not grant control over what runs later.
2. **Non-persistence.** Any patch made at boot time lives in RAM. It is re-derived (or re-exploited) on the next boot. There is no writable, verified persistent surface that checkm8 can reach — SecureROM is ROM, and the boot chain re-verifies every image on every boot. **[V]** palera1n's semi-tethered model is the empirical proof.

**[V]** On **PPL specifically: I could not verify from a primary source whether PPL exists on A9, and I believe it does not.** **[S]** The weight of evidence points to PPL arriving with the A11/APRR generation. Since A9 lacks KTRR, PPL (which protects the page tables KTRR relies on) would have nothing to protect on A9. **Do not plan A9 work around PPL.** Treat "does A9 have PPL?" as an open documentation question, not a design assumption.

### 4.2 The Secure Enclave — out of scope, and specifically why
**[V]** The SEP is a **separate ARM processor** with its own boot ROM, its own signed firmware, and its own OS (**SepOS**, an L4-family microkernel). It is not a mode of the application processor. Apple's [iOS/Platform Security Guide](https://support.apple.com/guide/security/welcome/web) describes it as holding the **UID** (device-unique AES key) and **GID** (shared class key), performing key wrapping, passcode verification, and secure boot authorization.

**[V]** Apple's security guide and the Common Criteria Security Targets state plainly that **the UID is not accessible by any software**, and that **UID and GID are not available via JTAG or other debug interfaces**. Keys derived from the UID never leave the SEP.

**[I]** What this means concretely for the A9 lab:
- checkm8 gives you code execution on the **application processor**. It does not give you execution on the SEP. The SEP has its own boot chain and its own mask ROM; A9's SecureROM bug is not A9's SEP bug.
- The AP↔SE relationship is a **mailbox/service protocol**, not shared memory you can simply read.
- Therefore: **no host-side technique recovers UID-derived secrets.** This is architectural, not a tooling gap.

**[V]** What *is* public: the **SEP firmware itself has been dumped and is being reverse-engineered** (the *blackbox* research line, presented publicly — see *Attack Secure Boot of SEP*, [windknown/presentations](https://raw.githubusercontent.com/windknown/presentations/master/Attack_Secure_Boot_of_SEP.pdf)). That is static analysis of SEP firmware, **not** code execution on a live A9 SEP.
**[I]** There is **no public full SEP compromise for A9.** Note that SEPROM exploits exist for other generations (`blackbird`, `hardbird` — [The Apple Wiki SEPROM](https://theapplewiki.com/wiki/SEPROM)); do **not** assume these apply to A9 without evidence.
**[V]** checkra1n's PongoOS README mentions its KPF bundle *"currently includes the SEP exploit"* — this is a real, if narrowly scoped, SEP interaction worth reading before claiming SEP is untouched, but it is not a general SEP break.

### 4.3 Baseband — why there is no open driver
**[V]** The baseband is a **separate processor** running its own RTOS and its own signed firmware, communicating with the AP over a serial/PCIe-ish link. There is no public programming reference for any Apple iPhone baseband, and the firmware is signed.
**[I]** No open baseband driver exists for any iPhone generation. Host-side SecureROM code execution does not produce one, because the baseband is not on the other side of that bug.
**[S]** A9 devices are widely understood to use **Qualcomm** basebands (iPhone 6s/6s Plus/SE 1st gen), with Intel appearing in the iPhone 7 generation. **I could not verify the exact A9 baseband part number from a primary source** — see §6. Reconstructing it requires a physical teardown or a firmware-level study, which is outside RQ1.

### 4.4 Has a foreign OS ever booted on A9? — the honest, nuanced answer
This is where the prior `PLAN.md` is most misleading, in both directions. The accurate position:

- **[V] Mainline Linux now has A9 device trees.** Nick Chan's series *Initial device trees for A7–A11 based Apple devices* includes *"arch/arm64/boot/dts/apple: Add A9 devices"* covering **iPhone 6s, 6s Plus, iPhone SE (2016), iPad 5** across both `s8000` and `s8003`. These are in `arch/arm64/boot/dts/apple/Makefile` upstream today.
- **[V] The DT is deliberately loader-supplied and minimal.** Its `chosen`/`memory` nodes are `/* To be filled by loader */`, CPUs are `enable-method = "spin-table"` with `cpu-release-addr = /* To be filled in by loader */`, and the SoC provides only **UART** (`apple,s5l-uart`), **AIC** interrupt controller, **pinctrl** (AP + AOP), and **watchdog**. There is a framebuffer stub marked `status = "disabled"`.
- **[V]** The DT header notes: *"Note that A9 doesn't actually have a hypervisor (EL2 is not implemented)."*
- **[V]** The transport to boot it is real and public: **PongoOS** is a pre-boot execution environment, and palera1n exposes `-p/--pongo-shell` and `-k/--override-pongo`.
- **[V]** `ipwndfu`'s README lists as its purpose "dumping SecureROM, decrypting keybags for iOS firmware, and demoting device for JTAG" — not booting foreign OSes.

**Bottom line [I]:** A9 Linux support **exists in mainline, in a bring-up-only state**, and the checkm8/PongoOS toolchain is a plausible loader path. But **[V]** the upstream DT implements essentially no user-facing hardware, and **I could not find a primary-source record of a publicly demonstrated general-purpose Linux userland (display/storage/network) running on an A9 iPhone.** The correct statement for the brief is:

> A9 Linux device trees are upstream and bootable-in-principle via a checkm8-based loader, but the port is bring-up-only (UART/AIC/pinctrl/watchdog). **A publicly demonstrated general-purpose foreign OS on A9: not established.** This is a *distinct* claim from "not achievable" (the prior PLAN.md) and from "achieved".

Anyone asserting "Linux boots on A9" or "Linux cannot boot on A9" should be asked for the specific commit *and* a boot log; neither is in hand here.

---

## 5. RQ1 experiment proposals — read-only observations

**Ground rules.** Read-only means: **no `DFU_DNLOAD` with an image, no `DFU_UPLOAD` of flash, no restore, no `-k/--payload` send, no demote, no NOR access.** Everything below is descriptor reads, zero-length or status-class requests, and observation. Use `libirecovery` (`irecovery.exe -q`, or `irecv_usb_control_transfer`) rather than ipwndfu, which cannot drive A9.

**Redaction rule:** scrub `ECID`, `SRNM`, `IMEI`, and nonce bytes from every artifact **before** it leaves the machine. Log `CPID`/`BDID`/`SRTG` freely.

| # | Observation | What to send / read | Interesting result | Null result means |
|---|---|---|---|---|
| **5.1** | **USB identity + composition** | Read device descriptor (VID/PID/`bDeviceClass`/`bNumConfigurations`), configuration descriptor, interface descriptor. | VID `0x05AC`, PID `0x1227`, and a **DFU-class, EP0-control-only** interface. Confirms the §2.1 model. | PID present but **no DFU class** → the control surface is not where §2 assumes; re-derive the request map before anything else. **[S]** possibly a different USB mode than assumed. |
| **5.2** | **SoC identity (the RQ1 gate)** | Read the `iSerialNumber` string descriptor; parse `CPID:`, `BDID:`, `CPRV:`, `CPFM:`, `SCEP:`, `IBFL:`, `SRTG:`. | `CPID` ∈ {`0x8000`,`0x8003`} and `BDID` ∈ {`0x02`,`0x04`,`0x06}` per §1.4 → confirms A9 and pins the fab variant. **Also record whether `SRTG` is present** (SecureROM evidence). | **`CPID` not `8000`/`8003`** → the unit is not the SoC we think it is; every downstream assumption is void. **`SRTG` absent/malformed** → the §1.4 SecureROM-vs-iBSS discriminator is unavailable, and any future exploit-config matching must be done another way. |
| **5.3** | **Pre-auth request surface enumeration** | Send only benign class reads: `DFU_GETSTATE` (`0xA1,5`, wLength 1), `DFU_GETSTATUS` (`0xA1,3`, wLength 6). Never `DFU_DNLOAD`. | Successful reads with plausible state (`dfuIDLE` = 2) and a well-formed status struct prove the DFU **state machine is live and unauthenticated**. | **STALL or no response** → the request set in §2.2 is wrong for this revision, or the device is not in the mode we believe. Both are high-value corrections. |
| **5.4** | **Descriptor-read semantics (the heap-primitive baseline)** | Issue `GET_DESCRIPTOR` with the checkm8 setup exactly: `bmRequestType=0x80, bRequest=6, wValue=0x304, wIndex=0x40A`, `wLength=0xC1` (and variants `0xC0`, `0x41`, `0x40`). Observe STALL vs. returned length. | The documented behaviour is a **partial read / STALL** (the `stall`/`leak`/`no_leak` distinction). Reproducing it *read-only* establishes which `wLength` values the device accepts before we ever touch the state machine. | **No STALL and no partial read** → the A9 heap-grooming primitive does not behave as documented, which would invalidate the A8/A9 "no-leak-needed" path in §1.2. **This is the single highest-value early experiment.** |
| **5.5** | **Does SecureROM validate anything pre-UAF?** | Send a `DFU_DNLOAD` with **wLength = 0** (zero-length, no data phase started), then `DFU_GETSTATUS`. Do **not** send a real image. | Outcome distinguishes "accepts anything" from "sanity-checks length/state". Either answer bounds what §2.3 can claim. | **A STALL on zero-length DNLOAD** → there *is* a pre-parse validation we did not know about; §2.3's "whole surface is pre-auth" needs qualification. |
| **5.6** | **Nonce visibility** | After each of 5.1–5.5, re-read the serial string and check for `NONC` (AP nonce) and `SNON` (SEP nonce). Then USB-reset and re-read. | Whether `NONC`/`SNON` appear **at all in SecureROM DFU**, and whether they **change across a reset**. If both are present and change, there is live nonce material in the pre-auth path. | **Neither tag present** → SecureROM DFU exposes no nonce, resolving the §2.4 open question negatively. That is a publishable negative result and it removes a whole class of assumed attack surface. |
| **5.7** | **Abort / re-entry behaviour (no UAF)** | Record the full descriptor set. Send **only** `DFU_ABORT` (`0x21,6`, wLength 0) — with **no preceding incomplete `DFU_DNLOAD`**, so the UAF precondition is *not* met. Then wait, re-enumerate, record again. | Confirms clean DFU exit → SecureROM re-entry, and whether the USB identity/descriptors are byte-identical on re-entry. Required baseline for §5.6. | **Device does not re-enumerate** → DFU exit/re-entry is not the reliable primitive §1.2 assumes, which would undermine the UAF trigger sequence itself. |
| **5.8** | **Reproducibility / determinism** | Repeat 5.1–5.7 across N cold boots (power-cycle each time), same host, same cable, same port. Log host controller/USB topology. | Byte-identical `CPID`/`BDID`/`SRTG` and stable descriptor lengths across boots; documents any variation attributable to the host, not the device. | **Non-determinism** → heap/state assumptions carried into a later exploit session are unsound; capture the variation before attempting anything stateful. |

**[I]** Sequencing note: 5.1 → 5.2 → 5.3 → 5.7 → 5.6 → 5.4 → 5.5 → 5.8. Get identity and a clean baseline **before** 5.4, which is the only probe that exercises the documented heap primitive. Stop immediately and log if the device leaves DFU unexpectedly.

**[S]** Risk note: 5.4 and 5.5 deliberately send the exact setup packets the exploit uses. Neither should start a data phase or free the I/O buffer, but they are the closest probes to the vulnerability. Run them on a **sacrificial unit**, and not on a device holding data you care about.

---

## 6. Sourcing

### PRIMARY (read directly; the factual basis of this brief)
1. **`ipwndfu` source** — [github.com/axi0mX/ipwndfu](https://github.com/axi0mX/ipwndfu). Specifically [`dfu.py`](https://raw.githubusercontent.com/axi0mX/ipwndfu/master/dfu.py) (PIDs, control requests, `MAX_PACKET_SIZE`, `reset_counters`, `request_image_validation`) and [`checkm8.py`](https://raw.githubusercontent.com/axi0mX/ipwndfu/master/checkm8.py) (`DeviceConfig`, `all_exploit_configs()` SoC table, stall/leak/no_leak, `exploit_config()` SRTG/CPID matching, `usb_device_io_request` overwrite offsets). — **PRIMARY**
2. **`libirecovery` source** — [github.com/libimobiledevice/libirecovery](https://github.com/libimobiledevice/libirecovery). [`src/libirecovery.c`](https://raw.githubusercontent.com/libimobiledevice/libirecovery/master/src/libirecovery.c) (A9 CPID/BDID device table, `irecv_load_device_info_from_iboot_string()`, `NONC`/`SNON` parsing, Windows/`setupapi` path) and [`include/libirecovery.h`](https://raw.githubusercontent.com/libimobiledevice/libirecovery/master/include/libirecovery.h) (`enum irecv_mode` PIDs, `struct irecv_device_info`). — **PRIMARY**
3. **Siguza, *KTRR*** — [blog.siguza.net/KTRR](https://blog.siguza.net/KTRR/). KTRR is A10+; RoRgn/KTRR register definitions and lockdown sequence; A9-and-earlier EL3 monitor framing. — **PRIMARY**
4. **xerub, *Tick (FPU) Tock (IRQ)*** — [xerub.github.io/ios/kpp/2017/04/13/tick-tock.html](https://xerub.github.io/ios/kpp/2017/04/13/tick-tock.html). A9 KPP/WatchTower internals in EL3, hash ranges, and the documented bypass. — **PRIMARY**
5. **Alfie CG, *A comprehensive write-up of the checkm8 BootROM exploit*** — [alfiecg.uk](https://alfiecg.uk/2023/07/21/A-comprehensive-write-up-of-the-checkm8-BootROM-exploit). Deepest public RE of the UAF, `usb_dfu_init()`/`handle_interface_request()`/`handle_ep0_data_phase()` pseudocode, `usb_device_io_request` layout, leak condition, payload analysis. — **PRIMARY (independent technical analysis; pseudocode, not Apple source)**
6. **`palera1n` README** — [github.com/palera1n/palera1n](https://github.com/palera1n/palera1n). A8–A11/T2, iOS 15.0+, device list including iPhone 6s/6s Plus/SE; Linux-or-macOS requirement; `--force-revert`; A11-only passcode caveat. — **PRIMARY**
7. **PongoOS README** — [github.com/checkra1n/PongoOS](https://github.com/checkra1n/PongoOS). "Pre-boot execution environment"; KPF + SEP exploit note. — **PRIMARY**
8. **Linux kernel, Apple device trees** — [`arch/arm64/boot/dts/apple/Makefile`](https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/boot/dts/apple/Makefile) (`s8000`/`s8003` entries) and **[PATCH v6 RESEND 15/20] *arm64: dts: apple: Add A9 devices*** ([LKML](https://lkml.iu.edu/hypermail/linux/kernel/2410.2/10132.html)) — A9 DT contents, `s8000`="Maui"/`s8003`="Malta", "A9 doesn't actually have a hypervisor (EL2 is not implemented)", loader-filled nodes. — **PRIMARY**
9. **Apple, Platform Security Guide** — [support.apple.com/guide/security](https://support.apple.com/guide/security/welcome/web), and the [iOS Security white paper (HT211006)](https://support.apple.com/library/APPLE/APPLECARE_ALLGEOS/HT211006/st-vid10937-st.pdf): UID/GID, "not accessible by any software", not available via JTAG/debug interfaces. — **PRIMARY**
10. **CERT/CC VU#941987** — [kb.cert.org/vuls/id/941987](https://www.kb.cert.org/vuls/id/941987/), and [CVE-2019-8900](https://www.cve.org/CVERecord?id=CVE-2019-8900): advisory/CVE for checkm8. — **PRIMARY (advisory record)**

### SECONDHAND (used for corroboration; label as such)
11. **The Apple Wiki — *checkm8 Exploit*** — [theapplewiki.com/wiki/Checkm8_Exploit](https://theapplewiki.com/wiki/Checkm8_Exploit). Community wiki; the UAF/leak description, A9 "DFU abort bug → direct code execution without ROP/JOP", CVE, fixed-in/reported-in versions, Apple Silicon USB-C issue. Widely repeated and consistent with (5), but **not** a vendor or author publication. — **SECONDHAND**
12. **The Apple Wiki — *SEPROM*** — [theapplewiki.com/wiki/SEPROM](https://theapplewiki.com/wiki/SEPROM) (`blackbird`, `hardbird`). — **SECONDHAND**
13. **kpwn/iOSRE KPP notes** — [raw.githubusercontent.com/kpwn/iOSRE/master/wiki/Kernel-Patch-Protection-(KPP).md](https://raw.githubusercontent.com/kpwn/iOSRE/master/wiki/Kernel-Patch-Protection-(KPP).md). Community wiki; "as of iOS9, all arm64 devices have KPP", checked ranges, Pangu9 data-only avoidance. — **SECONDHAND**
14. **tin-z, *iOS Exploit Starterpack* — KTRR & CTRR** — [tin-z.github.io](https://tin-z.github.io/ios-exploit-starterpack/en/ktrr-ctrr/): "KTRR (A10 – iPhone 7+)", register names, CTRR (A15+). Corroborates (3); used only as secondary confirmation. — **SECONDHAND**
15. **`ipwndfu` pypi mirror / assorted forks** (GeoSn0w `ipwndfu-fixed`, `epeth0mus/checkra1n-mod` DeepWiki, onejailbreak, XDA/forum posts). Encountered during search; **not** used as a factual basis for any claim here. — **SECONDHAND, not relied upon**

### What I could not verify
1. **PPL on A9.** I could not find a primary source stating whether the Page Protection Layer exists on A9. I **believe it does not** (PPL is tied to the KTRR/APRR era, A10/A11+), and **[V]** an Apple security-guide table surfaced in search is keyed on A10/A11/A12–A14/A15–A17/M1–M3 chips — i.e. it has **no A9 column**. I could not retrieve that Apple page's HTML or text directly (the guide served a content type the fetch tool could not decode), so I am **not** claiming it as verified. Treat A9-PPL as **open**.
2. **The A9 baseband part number.** No primary source obtained. The Qualcomm-for-A9 / Intel-for-A7-era split is my **[S]** understanding, not verified here.
3. **Whether SecureROM DFU emits `SNON`** (SEP nonce), as opposed to `NONC` only. libirecovery tries both but tolerates absence. Open — and testable via §5.6.
4. **Exact SecureROM version string for A9.** I could not confirm the precise `SRTG` value our unit will report. Read it (§5.2); do not hardcode it.
5. **Any concrete public demonstration of a general-purpose foreign OS on A9.** I found upstream **device trees** and a plausible loader (**PongoOS**), but **no** primary-source boot log, video, or project write-up of a working userland. Absence of evidence here is genuinely absence of evidence — I searched and did not find it.
6. **`gaster` / `Achilles` A9 support in detail.** Both are cited by [5] as checkm8 implementations and are the likely A9-capable route, but I did not fetch and read their source, so I make **no** claim about their A9 configs. **Recommended next verification step.**
7. **`usbliter8`** (a newer SecureROM bug, A12/A13-ish) surfaced in search. I did not verify it and it is **not** relevant to A9. Noted only so it is not confused with checkm8.
8. **Apple Silicon / USB-host effects on A9 exploitation.** The USB-C issue in [11] is reported for Apple Silicon Macs; our host is Windows on a different platform. Host-side behaviour of `libusb`/WinUSB against DFU on Windows for checkm8 is **not** verified here and will need empirical checks (WinUSB binding to the `0x1227` device node — already flagged in `PLAN.md`).

---

## 7. Bottom line for the next session

**What is settled [V]:** checkm8 = **CVE-2019-8900**, a UAF in SecureROM's USB DFU stack driven by an **incomplete `DFU_DNLOAD` data phase** followed by **`DFU_ABORT`/`DFU_CLRSTATUS`**; unpatchable because SecureROM is mask ROM. A9 = **`s8000`/`s8003`, CPID `0x8000`/`0x8003`**, read unauthenticated from the USB serial string. DFU PID = **`0x1227`** and it tells you the *mode* only. A9 gets **direct code execution via a DFU abort bug — no ROP/JOP, no memory leak needed**. A9 has **no KTRR and (almost certainly) no PPL**; its kernel-integrity guard is the **bypassable EL3 KPP**. The SEP and baseband are **separate processors** and stay out of scope.

**What changed vs. the prior plan:** the A9 story is **not** "blocked by KTRR". Layers 1–3 are more reachable than `PLAN.md` assumed, and the real walls are **layer 2 persistence** and **layer 4 (SEP)**. Linux DT support for A9 is **upstream**, but a general-purpose foreign OS on A9 is **not established**.

**Do next, in order:**
1. **Fix `PLAN.md`** — KTRR/PPL do not apply to A9; the correct CVE is **CVE-2019-8900**; `a9id.py`'s "`s5l8960x`-era" label should be `s8000`/`s8003`. *(Not changed here: this brief was the only authorized write.)*
2. **Verify `gaster` and `Achilles` A9 support** — upstream `ipwndfu` **cannot** do A9, so this determines whether the toolchain exists at all.
3. **Run §5.1–5.3** the moment the device is in DFU — identity before anything else.
4. **Then §5.4**, the one probe that tests the documented heap primitive read-only.
