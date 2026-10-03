<div align="center">
	<img width=140 src="assets/cover.svg" />
	<h2>a9lab</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Python-3776AB.svg?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-research-purple.svg?style=flat-square)]()

### Researching a chip Apple cannot patch.

Security research tooling for Apple A9 devices: iPhone SE (1st gen), iPhone 6s, 6s Plus.

The A9 is one of the best research platforms in existence, for one specific reason. It is vulnerable to `checkm8` (**CVE-2019-8900**), a use-after-free in SecureROM. SecureROM is mask ROM, so **Apple cannot patch it. This device will still be exploitable in 2040.**

This repository is the lab around that: device identification, guided DFU entry, a findings log that forces you to record how confident you actually are, and the research documents.

---

### Why a findings log is a tool

The interesting part of this repository is not the scripts. It is [`research-log.py`](research-log.py), which exists because of a failure mode that bit us repeatedly.

Every finding must be tagged:

| Tag | Meaning |
|---|---|
| `measured` | I ran something and observed this |
| `inferred` | it follows from something measured |
| `secondhand` | someone else said it |
| `failed` | it did not work. **Recorded, not deleted.** |

Mixed silently, an inference becomes a known fact three paragraphs later. In one session we logged **four separate false statements** that had already been written into a plan as fact, including a claim that A9 uses KTRR. It does not. KTRR is A10 and later.

The log also **refuses to write device-unique identifiers**. ECID, UDID, IMEI and serial numbers are scanned for and rejected, so a research artifact can be published without leaking the identity of the device it came from.

```console
$ python research-log.py add --rq RQ1 --title "libirecovery is Windows-native" \
    --detail "irecovery.exe -h confirms full DFU capability..." \
    --confidence measured --repro "irecovery.exe -h"
logged F002 (measured): libirecovery is Windows-native; WSL is NOT required for DFU work
```

---

### The tools

| File | What it does |
|---|---|
| [`a9id.py`](a9id.py) | Identifies an attached Apple device and reports which research mode it is in: DFU, Recovery, normal, or HID peripheral. Maps CPID and BDID to a concrete model and fab. |
| [`dfu-enter.ps1`](dfu-enter.ps1) | **Guided DFU entry with live confirmation.** Counts the intervals out loud and tells you the moment the device enumerates. |
| [`research-log.py`](research-log.py) | Confidence-tagged, append-only findings log with an identifier guard |
| [`build-king.ps1`](build-king.ps1) | Reproducibly builds the [King](https://github.com/pgarba/King) checkm8 port on Windows |

#### Why `dfu-enter.ps1` is a script and not a paragraph of instructions

DFU entry on A9 is **Power plus Volume Down for 8 seconds, release Power, hold Volume Down for a further 10 seconds**, and the screen stays **black whether you succeeded or failed**. There is no feedback. Doing that by eye is guesswork.

```
>>> STEP 1+2: HOLD POWER + VOLUME DOWN NOW
    releasing POWER in 8...
    releasing POWER in 7...
    >>> RELEASE POWER NOW - KEEP HOLDING VOLUME DOWN
    release VOLUME DOWN in 10...
```

It counts at you. Out loud. Like a very impatient coxswain who has watched too many people fumble this exact thing and has stopped being nice about it.

#### Why `a9id.py` refuses to guess

It ships a CPID and BDID table, because the same iPhone model can present **either** chip depending on which fab built it:

```
n69ap  -> CPID 0x8003  (s8003 "Malta", TSMC 16nm)
n69uap -> CPID 0x8000  (s8000 "Maui",  Samsung 14nm)
```

**A mismatched exploit payload brick-loops the device.** So `a9id.py` reads CPID and BDID off the device rather than inferring them from the model number, and says so when it cannot.

---

### The five layers, and which ones are reachable

| Layer | Protection | Reachable on A9? |
|---|---|---|
| 1. SecureROM | mask ROM | **fully. checkm8 gives code exec.** |
| 2. Boot chain | Image4 signatures, verified **every boot** | bypassed at runtime, re-verified next boot |
| 3. Kernel | **KPP / "WatchTower"**, a *software* monitor in TrustZone EL3 | bypass demonstrated publicly in yalu102 |
| 4. Secure Enclave | separate ARM core, own OS (SEPOS) | no public exploit |
| 5. Baseband | signed modem firmware, separate CPU | no open driver |

**The real walls are layer 2 and layer 4, not KTRR.** That correction matters, because several published summaries say "you would have to defeat KTRR" about A9, and that is simply wrong. KTRR is A10 and later.

---

### The one trap worth knowing before you start

`checkm8` calls `device.reset()` **twice**. On Windows, **WinUSB cannot perform a host-initiated reset.** libusb's own source says so:

> "the best we can do is cycle the pipes (and even then, the control pipe can not be reset using WinUSB)"

Only **libusbK** and **libusb0** actually call `ResetDevice`.

**Get this wrong and the failure is silent.** You will see `"Exploit failed. Device did not enter pwned DFU Mode"` with **no underlying error**, and you will debug the wrong layer for hours.

**Bind libusbK through Zadig to the DFU node (`05AC:1227`). Never WinUSB.**

---

### Documents

| Document | Contents |
|---|---|
| [`RQ1-BRIEF.md`](RQ1-BRIEF.md) | Bootrom and DFU research brief: what SecureROM exposes pre-authentication, the DFU request map, iBoot's verification gates, tooling map, and 8 proposed read-only experiments. Primary sourced. |
| [`IPWNDFU-FEASIBILITY.md`](IPWNDFU-FEASIBILITY.md) | Why upstream `ipwndfu` **cannot** exploit A9, and what the alternatives are. |
| [`PLAN.md`](PLAN.md) | Research questions, method, findings table, and known limitations |

---

### How do I use it?

```console
$ python a9id.py                 # what is attached, and in which mode?
$ python a9id.py --json          # machine-readable
$ powershell -File dfu-enter.ps1 # guided DFU entry
$ python research-log.py list    # what we know so far
```

Requirements: Python 3.10+, PowerShell 5.1+. Optional: [libimobiledevice win-x64](https://github.com/libimobiledevice-win32/imobiledevice-net) for talking to a booted device.

---

### What it can and can't do

**Can do:**
- Identify an attached Apple device and its current mode
- Map CPID and BDID to a model and fabrication plant
- Guide DFU entry with live confirmation instead of guesswork
- Maintain a confidence-tagged findings log with an identifier guard
- Build the Windows checkm8 port reproducibly
- Document what is and is not reachable, with sources

**Can't do, and this is recorded as architectural rather than as a failure:**
- **Boot a foreign OS.** Requires defeating layer 2 and layer 4. Not a tooling gap.
- **Persist a verification bypass.** Layer 2 re-verifies every boot. `checkm8` wins each boot. It cannot make a change stick at layer 2.
- **Touch the modem.** No open baseband driver exists for any iPhone generation.
- **Reach the Secure Enclave.** A separate processor with its own boot chain and no public exploit.

---

### Project layout

```
a9lab/
├── assets/
│   └── cover.svg
├── a9id.py                device and mode identification
├── dfu-enter.ps1          guided DFU entry
├── research-log.py        findings log with identifier guard
├── build-king.ps1         reproducible checkm8 build
├── PLAN.md                research questions and findings
├── RQ1-BRIEF.md           bootrom and DFU brief
└── IPWNDFU-FEASIBILITY.md tooling feasibility
```

---

### Legal and ethical

This is **security research on hardware you own**. `checkm8` has been public since 2019 and is the subject of published academic and industry research. Nothing here circumvents DRM, decrypts anything, or accesses data protected by the Secure Enclave. The CERT/CC advisory for this vulnerability notes that without the device passcode or biometrics, an attacker **cannot** gain access to SEP-protected information.

The identifier guard exists so that published findings do not leak the identity of the researcher's own device.

---

### Credits

- [axi0mX](https://github.com/axi0mX/ipwndfu) for `checkm8`
- [pgarba](https://github.com/pgarba/King) for the C port of the exploit
- [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) for the host tooling
- [Twemoji](https://github.com/twitter/twemoji) for the cover art, CC BY 4.0

---

<div align="center">
	<br/>
	<i>mask ROM cannot be patched. that is the entire point.</i>
	<br/>
	<sub>for devices you own. record your confidence, and keep the negative results.</sub>
</div>
