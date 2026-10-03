#!/usr/bin/env python3
"""Derive the USBPcap record header layout from real bytes instead of memory.

The pcap record header gives us incl_len. The USBPcap header must satisfy:

    headerLen + dataLength == incl_len

for every record. That is a hard constraint, so we can SOLVE for the layout
rather than trusting a remembered struct definition. The script tries
candidate layouts and scores each by how many records satisfy the constraint.
"""

import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else r"<REPO_ROOT>\a9lab\captures\probe-hub1.pcap"

blob = open(PATH, "rb").read()
endian = "<" if blob[:4] == b"\xd4\xc3\xb2\xa1" else ">"

records = []
off = 24
while off + 16 <= len(blob):
    ts_sec, ts_frac, incl, orig = struct.unpack_from(endian + "IIII", blob, off)
    off += 16
    if incl > len(blob) - off:
        break
    records.append((incl, blob[off : off + incl]))
    off += incl

print(f"file    : {PATH}")
print(f"records : {len(records)}")
print()

print("=== raw bytes of the first 8 record headers (48 bytes each) ===")
for i, (incl, raw) in enumerate(records[:8]):
    print(f"rec {i:>3}  incl_len={incl:<6}")
    for j in range(0, min(len(raw), 48), 16):
        chunk = raw[j : j + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"        +{j:02X}  {hexpart:<47}  {asc}")
    print()

print("=== candidate layout search ===")
print("constraint: headerLen + dataLength == incl_len for every record")
print()


def u16(buf, o):
    return struct.unpack_from(endian + "H", buf, o)[0] if o + 2 <= len(buf) else None


def u32(buf, o):
    return struct.unpack_from(endian + "I", buf, o)[0] if o + 4 <= len(buf) else None


# Where might dataLength live? Try every 4-byte aligned-ish offset and score.
print("scanning for a u32 at offset O such that headerLen + that == incl_len:")
best = []
for o in range(8, 40, 1):
    hits = 0
    for incl, raw in records:
        hl = u16(raw, 0)
        dl = u32(raw, o)
        if hl is None or dl is None:
            continue
        if hl + dl == incl:
            hits += 1
    if hits:
        best.append((hits, o))
best.sort(reverse=True)
for hits, o in best[:8]:
    print(f"  offset {o:>3}: {hits}/{len(records)} records match")
if not best:
    print("  no offset matched - the constraint model itself is wrong")

print()
print("=== headerLen value census ===")
from collections import Counter

c = Counter(u16(raw, 0) for _, raw in records)
for hl, n in sorted(c.items()):
    print(f"  headerLen={hl}: {n} records")

print()
print("=== does headerLen + dataLength == incl_len hold per headerLen value? ===")
for hl_val in sorted(c):
    sample = [(incl, raw) for incl, raw in records if u16(raw, 0) == hl_val][:3]
    for incl, raw in sample:
        print(f"  headerLen={hl_val} incl_len={incl}")
        for o in range(8, 40, 1):
            dl = u32(raw, o)
            if dl is not None and hl_val + dl == incl:
                print(f"      dataLength={dl} found at offset {o}")
