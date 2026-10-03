# A9 Security Research — Plan & Findings

**Target:** iPhone SE (1st generation) — Apple A9, `s5l8960`/`s8000`-era SecureROM
**Why this device:** `checkm8` (2019) affects A5–A11 bootroms. Because it lives in **mask ROM**, it is **unpatchable by any software update** — Apple cannot fix it, ever. The SE 1st gen is therefore a permanently-exploitable research platform.

**Status:** environment built, awaiting device on USB.

---

## 1. The five layers (and what is actually reachable)

This framing matters because "bypass Apple's security" is really five independent problems, and conflating them is how projects die.

| # | Layer | Protections | Reachable on A9? |
|---|---|---|---|
| 1 | **SecureROM** (bootrom) | Immutable mask ROM | ✅ **Fully — `checkm8` (CVE-2019-8900) gives code exec** |
| 2 | **Boot chain** | Image4 signature verification, every boot | ⚠️ Bypass at runtime; re-verified next boot |
| 3 | **Kernel / memory** | **KPP / "WatchTower"** — a *software* monitor in TrustZone EL3, loaded by iBoot, hashing `__TEXT`/`__DATA.__const` on an FPU-trap/IRQ heartbeat | ⚠️ **More reachable than assumed** — bypass demonstrated publicly (yalu102) |
| 4 | **Secure Enclave** | Separate ARM core, own OS (SEPOS), own boot chain | ❌ No public exploit |
| 5 | **Baseband** | Signed modem firmware, separate CPU | ❌ No open driver |

> ### ⚠️ CORRECTION (2026-10-03) — layer 3 does NOT use KTRR
>
> An earlier version of this table claimed A9's layer 3 was "**KTRR, PPL** — hardware
> page protection armed by iBoot". **That was wrong and would have sent a future
> session chasing a blocker that does not exist on this silicon.**
>
> **KTRR is A10 and later.** Siguza's *KTRR* writeup states it is the mechanism used
> in Apple's **A10 chips and later**, and it depends on A10-only primitives (AMCC RoRgn
> MMIO, plus the per-core `KTRR_LOWER`/`KTRR_UPPER`/`KTRR_LOCK_EL1` registers).
>
> **A9's actual guard is KPP / WatchTower** — a **software** monitor that iBoot loads
> at `0x4100000000` and runs in **TrustZone EL3**. It watches a heartbeat and hashes
> kernel text; it is not a hardware lock. Its bypass is documented (xerub, *Tick (FPU)
> Tock (IRQ)*) and was demonstrated publicly in **yalu102**.
>
> **Consequence: A9 layer 3 is *easier* than this plan originally claimed, not harder.**
>
> **Open, not settled:** whether A9 has **PPL**. Evidence points to PPL being
> A11/APRR-era, but this could not be verified from a primary source. **Do not design
> around A9-PPL either way.**

**The honest ceiling:** layers 1–3 are the reachable research surface. Layers 4–5 are architecturally out of scope for a host-side project — not "undiscovered", but defended by a separate processor we do not control. **The real walls are layer 2 (persistence) and layer 4 (SEP) — not KTRR.**

---

## 2. Research questions worth answering

These are ordered by tractability, not by how impressive they sound.

### RQ1 — Bootrom surface (high tractability)
- What does the A9 SecureROM actually expose over USB in DFU?
- Which USB control requests are handled pre-authentication, and what do they leak?
- Confirm CPID / BDID / ECID reading, and verify our device's SoC identity.
- **Deliverable:** a documented DFU request map for our specific unit.

### RQ2 — What iBoot actually validates (medium)
- Which components does the boot chain verify before handing off to the kernel?
- Where are the verification gates, and what is the *minimum* that must pass?
- How does APTicket / nonce enforcement interact on A9?
- **Deliverable:** an annotated boot-chain map, sourced from published research and verified where possible against our device.

### RQ3 — SEPOS boundary (low, but valuable to document)
- What is observable about the Secure Enclave from the application processor?
- Which SEP services are reachable over the AP↔SE mailboxes in a jailbroken context?
- **Deliverable:** a boundary map — what's visible, what isn't, and *why* it isn't. Negative results are publishable here.

### RQ4 — Tooling gaps (high value, low glamour)
- What is genuinely missing in the checkm8 / palera1n toolchain?
- Reproducibility: can a third party rebuild our environment and get the same result?
- **Deliverable:** reproducible tooling, which is the part most projects skip and most reviewers want.

---

## 3. Environment

| Component | Purpose | Location |
|---|---|---|
| `a9id.py` | Device/mode identification, SoC mapping | [a9id.py](a9id.py) |
| `research-log.py` | Timestamped findings log | [research-log.py](research-log.py) |
| `iwhale.ps1` | Live iPhone battery/health/presence | [iwhale.ps1](../iphone/iwhale.ps1) |
| libimobiledevice 1.2.1 | Host↔device comms (normal mode) | `<REPO_ROOT>\libimobile` |
| **libirecovery (`irecovery.exe`)** | **DFU / Recovery mode comms — RQ1** | `<REPO_ROOT>\libimobile\irecovery.exe` |
| Apple Mobile Device Support 19.4 | usbmuxd transport | installed, service running |

### `irecovery` is Windows-native — but it CANNOT run checkm8

Verified by running `irecovery.exe -h` on this host (2026-10-03):

```
-q, --query     query device info        <- RQ1 reconnaissance (read-only)
-m, --mode      print current device mode
-k, --payload   send LIMERA1N usb exploit payload from FILE
-c, --command   run CMD on device
-s, --shell     interactive shell
-f, --file      send file to device
-n, --normal    reboot device into normal mode
```

> ### ⚠️ CORRECTION (2026-10-03) — `-k` is limera1n, NOT checkm8
>
> An earlier version of this section implied `irecovery -k` gave us a checkm8 payload
> path on Windows. **That was an unfounded inference from the `-k` help text, and it
> is wrong.** Confirmed two independent ways:
>
> 1. **Binary symbols** — `irecovery.dll` exports `irecv_trigger_limera1n_exploit`,
>    and **`irecv_trigger_checkm8_exploit` is absent entirely.**
> 2. **Source** — upstream `tools/irecovery.c` routes `-k` to
>    `irecv_trigger_limera1n_exploit()`, implemented **limera1n-only** in
>    `src/libirecovery.c`; on non-Apple platforms it degenerates to a single
>    synchronous `0x21/2` transfer with none of the macOS abort-thread trick.
>
> **limera1n targets S5L8920/8922 (A4-era). A9 needs checkm8.** So `irecovery` is
> useful **only AFTER pwn** (`-q`, `-c`, `-f`, `-s`) — it is *not* the exploit path.
>
> **This is the third unverified assumption caught in this project.** Recorded in full
> because the pattern matters: *a plausible-looking flag is not a capability.*

**This removes the assumed WSL/Linux dependency for reconnaissance.** DFU interaction
and all read-only RQ1 probes happen natively on Windows. The **exploit** needs a
different tool — see below.

### The Windows exploit path, and the silent trap

| Option | Status |
|---|---|
| **`ipwndfu` (upstream)** | ❌ **Cannot exploit A9.** Its SoC table lists `s8000`/`s8003` only under a never-implemented "future support" comment. Also **Python 2 only** (parse-time failure under Python 3.14), hard-requires the libusb1 backend, README says it won't work in a VM. |
| **`gaster`** (`0x7FF/gaster`) | ✅ **Ships `payload_A9.S` / `payload_A9.bin`** — an explicit A9 payload path. Has `#ifdef WIN32`. Verified by direct repo listing. |
| **`King`** (`pgarba/King`) | ⚠️ C port of checkm8 claiming **Windows** support (libusbK + Zadig), lists iPhone SE. 140★, pushed 2024-06. **SECONDHAND — not built or run by us.** |
| **`irecovery -k`** | ❌ limera1n only (see correction above). |

> ### 🔴 THE SILENT FAILURE TRAP — bind **libusbK**, NOT WinUSB
>
> `checkm8` calls `device.reset()` **twice**. libusb 1.0.24's own source states that
> Windows/WinUSB **cannot perform a host-initiated reset** — *"the best we can do is
> cycle the pipes (and even then, the control pipe can not be reset using WinUSB)"*.
> Only **libusbK / libusb0** actually call `ResetDevice`.
>
> **Consequence of getting this wrong:** the reset stages become **silent no-ops**.
> You get *"Exploit failed. Device did not enter pwned DFU Mode"* with **no underlying
> error**. You would then debug the wrong layer for hours.
>
> **Bind libusbK via Zadig for the DFU node (VID 0x05AC / PID 0x1227) — never WinUSB.**
>
> Note the irony: for the **Samsung** we had to *remove* WinUSB so `usbser.sys` could
> bind. Here we must *add* a libusb driver — and specifically **not** WinUSB.

### USB IDs

| PID | Meaning |
|---|---|
| **0x1227** | **DFU — the binding target.** *Pwned* DFU stays on 0x1227; success is confirmed by `PWND:[checkm8]` in the serial string. |
| 0x1222 | WTF mode (SecureROM debug) |
| 0x1280–0x1283 | Recovery (iBSS/iBEC) |
| 0xF014 | Port DFU |
| 0x1881 | KIS |

**Bind target: `0x05AC:0x1227`.**

**WSL status (not blocking):** `Ubuntu-24.04` fails with `Failed to start the
systemd user session`; `wsl --shutdown` does not clear it. **All distros — including
`podman-main` — auto-stop when idle**, so distro state is a *moving target*: check at
the time of use. Since `irecovery` covers recon natively and `gaster`/`King` cover the
exploit natively, WSL is not on the critical path.

---

## 4. Method

1. **Observe before touching.** Record device state, IDs, and modes first. Changes without a baseline are unfalsifiable.
2. **One variable at a time.** If we change two things and it works, we've learned nothing.
3. **Log negative results.** "X did not respond" is a finding.
4. **Verify against published work.** Primary sources: the `checkm8` writeup (`axi0mX`), `ipwndfu` / `libirecovery` / `gaster` source, Siguza's *KTRR*, xerub's *Tick (FPU) Tock (IRQ)*, Corellium research, mainline Linux Apple DTS. Community claims (XDA, Apple Wiki) are marked **secondhand** and used only for corroboration.
   **`checkm8` is CVE-2019-8900 (CERT/CC VU#941987)** — an earlier draft cited "CVE-2019-8566 family", which was wrong.
5. **Distinguish measured from inferred.** Every entry says which.
6. **Never publish device-unique identifiers.** ECID, UDID, and serial numbers stay out of any write-up.

---

## 5. Findings log

| # | Timestamp | RQ | Finding | Confidence |
|---|---|---|---|---|
| F001 | 2026-10-03T04:09:58Z | RQ0 | Research environment built and host toolchain verified | measured |
| F002 | 2026-10-03T04:14:01Z | RQ1 | libirecovery is Windows-native; WSL is NOT required for DFU work | measured |
| F003 | 2026-10-03T04:14:01Z | RQ1 | WSL Ubuntu-24.04 unusable; podman-main unaffected | measured |
| F004 | 2026-10-03T04:15:09Z | RQ0 | Target device hardware confirmed intact: screen and buttons reliable | secondhand |
| F005 | 2026-10-03T04:18:19Z | RQ1 | Four PLAN.md errors corrected: KTRR is A10+, A9 uses KPP/WatchTower | secondhand |
| F006 | 2026-10-03T04:18:19Z | RQ1 | ipwndfu CANNOT exploit A9; gaster HAS a dedicated A9 payload | secondhand |
| F007 | 2026-10-03T04:18:19Z | RQ1 | SRTG is the SecureROM-vs-iBSS gate; PID 0x1227 is shared by both | secondhand |
| F008 | 2026-10-03T04:18:19Z | RQ0 | iPhone SE battery reported in perfect state; swelling risk cleared | secondhand |
| F009 | 2026-10-03T04:19:31Z | RQ1 | SILENT TRAP: bind libusbK not WinUSB for DFU, or checkm8 fails with no error | secondhand |
| F010 | 2026-10-03T04:19:31Z | RQ1 | irecovery -k is limera1n-ONLY; verified via DLL exports (my earlier inference was wrong) | measured |
| F011 | 2026-10-03T04:19:31Z | RQ1 | Windows exploit path: gaster has payload_A9; King (pgarba) claims Windows+libusbK | secondhand |
| F012 | 2026-10-03T04:32:17Z | RQ1 | King BUILT for Windows: king.exe produced from source, A9 path confirmed in code | measured |
| F013 | 2026-10-03T04:32:18Z | RQ1 | A9 DFU CPID is 8000/8003 - confirmed by King dispatch; 8010 is T8010/A10 | measured |

---

## 6. Known limitations (recorded so we don't re-litigate them)

> ### ⚠️ CORRECTION (2026-10-03) — the Linux entry below was wrong
>
> This section previously read: *"Booting a foreign OS (Linux) on A9: **not achievable**.
> Not a tooling gap — requires defeating KTRR..."* **Both halves were wrong:**
> KTRR is not present on A9 (see layer 3), and mainline Linux **does** now carry A9
> device trees.
>
> **Corrected position — A9 Linux is upstream and bootable-in-principle, but not
> demonstrated as general-purpose:**
>
> - Mainline Linux contains **A9 device trees** for `s8000` ("Maui", Samsung 14nm) and
>   `s8003` ("Malta", TSMC 16nm) — covering iPhone 6s / 6s Plus / **iPhone SE 2016** /
>   iPad 5. They are in `arch/arm64/boot/dts/apple/Makefile` upstream today.
> - **But the DT is bring-up-only:** memory/`chosen` nodes are `/* To be filled by
>   loader */`, CPUs are spin-table with loader-filled release addresses, and the SoC
>   implements only **UART + AIC + pinctrl + watchdog** (the framebuffer stub is
>   `status="disabled"`).
> - **PongoOS is a real pre-boot execution environment**, so a checkm8-based loader is
>   not fantasy.
> - **What is NOT established:** a publicly demonstrated *general-purpose* foreign OS
>   running on A9. That is distinct from both "impossible" and "achieved".
>
> **The genuine walls are layer 2 (every-boot signature re-verification) and layer 4
> (SEP), not KTRR.** Recorded so this isn't re-litigated as either solved or forbidden.
- **Breaking image verification persistently: not achievable.** Layer 2 re-verifies every boot; checkm8 wins each boot but cannot make a change stick at layer 2.
- **Modem: out of scope.** No open baseband driver exists for any iPhone generation.

These are recorded as *architectural*, not as *we failed*.
