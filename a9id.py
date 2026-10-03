#!/usr/bin/env python3
"""
a9id - identify an attached Apple device and report which research modes it is in.

Security research tooling for the A9 (iPhone SE 1st gen, iPhone 6s/6s Plus).
Read-only: it never writes to, restores, or modifies a device.

What it does:
  * Enumerates Apple USB devices (VID 0x05AC) via Windows PnP.
  * Detects DFU / Recovery / Normal mode from the USB product ID, because those
    are the only reliable mode indicators before any Apple service is up.
  * Reads libimobiledevice info when the device is booted and trusted.
  * Maps the device to its SoC generation, which determines exploitability.

Why the PID table matters for research:
  DFU and Recovery PIDs are stable per-platform and are the *only* signal
  available when the device is not running iOS. Being able to say "this is an
  A9 in DFU" from the host is the entry condition for all bootrom research.

Usage:
    python a9id.py            # one-shot report
    python a9id.py --json     # machine-readable
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

LIBIMOBILE = Path(r"<REPO_ROOT>\libimobile")
IDEVICEINFO = LIBIMOBILE / "ideviceinfo.exe"
IDEVICE_ID = LIBIMOBILE / "idevice_id.exe"

# Apple vendor id
APPLE_VID = "VID_05AC"

# Product IDs that indicate boot stage. These are the host's only reliable
# signal when iOS is not running. (Apple reuses PIDs across SoC families.)
#
# DFU:      0x1227  - used by A9/A10/A11 era in DFU. SecureROM listens on this.
# Recovery: 0x1280..0x1283 - iBSS/iBEC stage, varies by SoC family.
# Normal:   0x12A8 (A9+) / 0x12A0 (older) / 0x12AB, plus composite PIDs.
#
# NOTE: DFU PID alone does NOT identify the SoC. The definitive SoC check is the
# `CPID` (chip id) and `BDID` (board id) read from the device while in DFU.
DFU_PIDS = {
    "1227": "DFU (SecureROM) - bootrom code execution surface",
    "1222": "DFU (older platform)",
    "1281": "Recovery (iBSS/iBEC)",
    "1282": "Recovery (iBSS/iBEC)",
    "1283": "Recovery (iBSS/iBEC)",
    "1280": "Recovery (iBSS/iBEC)",
}
NORMAL_PIDS = {
    "12A8": "Normal / iOS running",
    "12A0": "Normal / iOS running (older)",
    "12AB": "Normal / iOS running",
    "024F": "HID peripheral (keyboard/mouse/trackpad) - NOT a phone",
    "0250": "HID peripheral - NOT a phone",
}

# SoC generation -> is the bootrom exploit known/vulnerable?
# checkm8 (CVE-2019-8566 family) affects A5-A11 bootroms. Unpatchable: mask ROM.
SOC_TABLE = {
    "A9": {
        "devices": ["iPhone SE (1st gen)", "iPhone 6s", "iPhone 6s Plus"],
        # CORRECTION: s5l8960x is A7 (iPhone 5s) - NOT A9. A9 is s8000/s8003.
        #   s8000 = "Maui" (Samsung 14nm), s8003 = "Malta" (TSMC 16nm).
        # The SAME model can present EITHER CPID depending on which fab built it,
        # so CPID must be read from the device, never assumed from the model.
        "bootrom": "SecureROM (s8000/s8003) - CPID 0x8000 or 0x8003",
        "checkm8_vulnerable": True,
        "cve": "CVE-2019-8900",
        "notes": "Permanent, unpatchable bootrom hole. Best A-series research target. "
                 "Layer-3 guard is KPP/WatchTower (software, EL3) - NOT KTRR (A10+).",
    },
    "A10": {"devices": ["iPhone 7", "iPhone 7 Plus"], "checkm8_vulnerable": True},
    "A11": {"devices": ["iPhone 8", "iPhone 8 Plus", "iPhone X"], "checkm8_vulnerable": True},
    "A12": {"devices": ["iPhone XS/XR"], "checkm8_vulnerable": False,
            "notes": "Bootrom fixed. checkm8 does NOT apply."},
}


# A9 chip/board identity reference table (from libirecovery source).
#
# CRITICAL: the SAME model can present EITHER CPID depending on which fab built
# it - s8000 "Maui" is Samsung 14nm, s8003 "Malta" is TSMC 16nm. So CPID must be
# READ from the device in DFU, never inferred from the model number.
#
# This matters for the exploit: a mismatched payload/config brick-loops the
# device instead of working, so identity is verified BEFORE any exploit attempt.
A9_CPID_BDID = {
    ("0x8000", "0x04"): "iPhone 6s (n71ap) - s8000 Maui",
    ("0x8003", "0x04"): "iPhone 6s (n71map) - s8003 Malta",
    ("0x8000", "0x06"): "iPhone 6s Plus (n66ap) - s8000 Maui",
    ("0x8003", "0x06"): "iPhone 6s Plus (n66map) - s8003 Malta",
    ("0x8003", "0x02"): "iPhone SE 1st gen (n69ap) - s8003 Malta",
    ("0x8000", "0x02"): "iPhone SE 1st gen (n69uap) - s8000 Maui",
}


def describe_a9(cpid: str | None, bdid: str | None) -> str:
    """Map a CPID/BDID pair to a concrete model + fab."""
    if not cpid or not bdid:
        return "CPID/BDID not provided"
    key = (cpid.lower(), bdid.lower())
    return A9_CPID_BDID.get(key, f"unrecognised A9 pair CPID={cpid} BDID={bdid}")


def enum_apple_usb() -> list[dict]:
    """Enumerate Apple USB devices present on this Windows host."""
    ps = (
        "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.InstanceId -match '{APPLE_VID}' }} | "
        "Select-Object Status,Class,FriendlyName,InstanceId | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except Exception:
        return []
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def extract_pid(instance_id: str) -> str | None:
    """Pull the PID out of a Windows instance id, e.g. USB\\VID_05AC&PID_1227\\..."""
    iid = instance_id.upper()
    key = "PID_"
    i = iid.find(key)
    if i < 0:
        return None
    rest = iid[i + len(key):]
    end = min([p for p in (rest.find("&"), rest.find("\\")) if p >= 0] or [len(rest)])
    return rest[:end]


def classify(pid: str | None) -> tuple[str, str]:
    """Return (mode, description) for a product id."""
    if not pid:
        return ("unknown", "could not parse product id")
    if pid in DFU_PIDS:
        return ("dfu" if pid in ("1227", "1222") else "recovery", DFU_PIDS[pid])
    if pid in NORMAL_PIDS:
        # HID peripherals are not phones
        mode = "peripheral" if "HID" in NORMAL_PIDS[pid] else "normal"
        return (mode, NORMAL_PIDS[pid])
    return ("unknown", f"unrecognised PID {pid}")


def libimobiledevice_info() -> dict | None:
    """Query a booted+trusted device. Returns None when unavailable."""
    if not IDEVICEINFO.exists():
        return {"available": False, "error": f"not found: {IDEVICEINFO}"}
    try:
        r = subprocess.run([str(IDEVICEINFO)], capture_output=True, text=True, timeout=25)
    except Exception as e:
        return {"available": False, "error": str(e)}
    raw = (r.stdout or "") + (r.stderr or "")
    if "No device found" in raw or r.returncode != 0:
        return {"available": False, "error": raw.strip().splitlines()[-1] if raw.strip() else "no device"}
    kv = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            kv[k.strip()] = v.strip()
    return {
        "available": True,
        "device_name": kv.get("DeviceName"),
        "product_type": kv.get("ProductType"),
        "ios_version": kv.get("ProductVersion"),
        "build": kv.get("BuildVersion"),
        "hardware_model": kv.get("HardwareModel"),
        "udid": kv.get("UniqueDeviceID"),
        "battery_pct": kv.get("BatteryCurrentCapacity"),
    }


def main() -> int:
    as_json = "--json" in sys.argv

    usb = enum_apple_usb()
    findings = []
    for d in usb:
        pid = extract_pid(d.get("InstanceId", ""))
        mode, desc = classify(pid)
        findings.append({
            "pid": pid,
            "mode": mode,
            "mode_desc": desc,
            "class": d.get("Class"),
            "friendly_name": d.get("FriendlyName"),
            "instance_id": d.get("InstanceId"),
        })

    # Prefer a phone-ish device for the headline verdict.
    interesting = [f for f in findings if f["mode"] not in ("peripheral", "unknown")]
    peripheral = [f for f in findings if f["mode"] == "peripheral"]

    info = libimobiledevice_info() if any(f["mode"] == "normal" for f in findings) else None

    verdict = "no Apple device attached"
    if interesting:
        m = interesting[0]
        verdict = f"Apple device in {m['mode'].upper()} mode (PID {m['pid']}): {m['mode_desc']}"
    elif peripheral:
        verdict = f"Apple HID peripheral only (PID {peripheral[0]['pid']}) - not a phone"

    report = {
        "verdict": verdict,
        "apple_devices": findings,
        "interesting": interesting,
        "peripherals": len(peripheral),
        "libimobiledevice": info,
        "research_notes": {
            "target_soc": "A9",
            "checkm8_vulnerable": True,
            "why": "Mask-ROM bootrom bug; unpatchable by any software update.",
            "next_step": "Enter DFU, then read CPID/BDID to confirm SoC before any bootrom work.",
        },
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 68)
        print(" a9id - Apple device / research mode identification")
        print("=" * 68)
        print(f" VERDICT: {verdict}")
        print()
        if findings:
            print(f" {'PID':<6} {'MODE':<11} {'CLASS':<10} DESCRIPTION")
            print(f" {'-'*6} {'-'*11} {'-'*10} {'-'*40}")
            for f in findings:
                print(f" {str(f['pid']):<6} {f['mode']:<11} {str(f['class']):<10} {f['mode_desc']}")
        else:
            print(" (no Apple USB devices present)")
        print()
        if info:
            print(" libimobiledevice:")
            for k, v in info.items():
                print(f"   {k:<16} {v}")
        print()
        print(" research target: A9 (iPhone SE 1st gen) - checkm8 vulnerable: YES (permanent)")
        print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
