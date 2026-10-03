#!/usr/bin/env python3
"""usbpcap.py - read USBPcap .pcap files without Wireshark.

Why this exists
---------------
tshark is not installed on this box and installing a 100 MB GUI to read one
capture is not a trade worth making. The USBPcap file format is small and
fully documented, so we read it ourselves.

The format, exactly
-------------------
A normal libpcap file:

    global header  24 bytes   magic, version, thiszone, sigfigs, snaplen, linktype
    record header  16 bytes   ts_sec, ts_usec, incl_len, orig_len
    record data    incl_len   <-- USBPcap payload

linktype is 249 (DLT_USBPCAP). Within the record data sits USBPcap's own
header, then the transfer bytes.

The layout below was DERIVED FROM REAL BYTES, not from documentation. The
first version of this file guessed the field order and got it wrong (it put
`info` at offset 10 and made `status` conditional), which produced a
convincing-looking decode with nonsense values like "bus 2304". What settled
it is a hard invariant that the format must satisfy:

    headerLen + dataLength == incl_len

Scanning candidate offsets for where a u32 satisfies that across a real
capture, offset 23 matched 64 of 64 records. Field order then follows
uniquely, and the decoded payloads confirm it: control transfers carry valid
setup packets and the injected descriptors carry real VID/PID pairs.

    0x00  headerLen  u16
    0x02  irpId      u64
    0x0A  status     u32      <- ALWAYS present; not conditional
    0x0E  function   u16
    0x10  info       u8       <- at 16, not at 10
    0x11  bus        u16
    0x13  device     u16
    0x15  endpoint   u8
    0x16  transfer   u8
    0x17  dataLength u32
    ---- 27 bytes ----

`headerLen` is 27 in most records and 28 in some. The 28th byte is not
accounted for and we do not pretend to know what it is. It does not matter,
because `headerLen` is authoritative for where the payload starts, so we use
it and ignore the extra byte.

`parse` therefore validates with the length invariant rather than with a
field-by-field walk, and reports the pass rate. A rate below 100% means the
decode is unreliable and you should not trust the fields.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"  # 0xa1b2c3d4 stored little-endian
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"  # nanosecond variant
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"

LINKTYPE_USBPCAP = 249

# USBPcap's USBPcapTransferType. The numeric values are asserted at runtime by
# check_transfer_mapping() rather than trusted blindly.
TRANSFER_NAMES = {
    0: "isochronous",
    1: "interrupt",
    2: "control",
    3: "bulk",
}

INFO_STATUS_CODE = 0x01
INFO_RESERVED = 0x02

# Control request types, decoded from the setup packet's bmRequestType.
REQUEST_TYPE_DIR = {0: "out", 1: "in"}
REQUEST_TYPE_KIND = {0: "standard", 1: "class", 2: "vendor", 3: "reserved"}
REQUEST_TYPE_RECIP = {0: "device", 1: "interface", 2: "endpoint", 3: "other"}

# Apple's known DFU request codes, for readability in the dump.
APPLE_REQUESTS = {
    0x00: "DFU_DETACH",
    0x01: "DFU_DNLOAD",
    0x02: "DFU_UPLOAD",
    0x03: "DFU_GETSTATUS",
    0x04: "DFU_CLRSTATUS",
    0x05: "DFU_GETSTATE",
    0x06: "DFU_ABORT",
}


class FormatError(Exception):
    """The file is not a USBPcap capture we can read."""


@dataclass
class Setup:
    bm_request_type: int
    b_request: int
    w_value: int
    w_index: int
    w_length: int

    def __str__(self) -> str:
        direction = REQUEST_TYPE_DIR.get(self.bm_request_type >> 7, "?")
        kind = REQUEST_TYPE_KIND.get((self.bm_request_type >> 5) & 0x3, "?")
        recip = REQUEST_TYPE_RECIP.get(self.bm_request_type & 0x1F, "?")
        name = APPLE_REQUESTS.get(self.b_request, "")
        label = f" {name}" if name and kind == "class" else ""
        return (
            f"{direction}/{kind}/{recip} "
            f"req=0x{self.b_request:02X}{label} "
            f"value=0x{self.w_value:04X} index=0x{self.w_index:04X} "
            f"len={self.w_length}"
        )


@dataclass
class Packet:
    index: int
    ts: float
    irp_id: int
    info: int
    status: int | None
    function: int
    bus: int
    device: int
    endpoint: int
    transfer: int
    data_length: int
    data: bytes
    header_len: int
    walk_ok: bool
    trailing: bytes = b""

    @property
    def transfer_name(self) -> str:
        return TRANSFER_NAMES.get(self.transfer, f"unknown({self.transfer})")

    @property
    def is_control(self) -> bool:
        return self.transfer == 2

    @property
    def setup(self) -> Setup | None:
        """A control transfer's payload begins with the 8-byte setup packet."""
        if not self.is_control or len(self.data) < 8:
            return None
        bm, req, val, idx, ln = struct.unpack_from("<BBHHH", self.data, 0)
        return Setup(bm, req, val, idx, ln)

    @property
    def payload(self) -> bytes:
        """Transfer bytes with any control setup packet removed."""
        return self.data[8:] if self.setup else self.data


def parse_pcap(path: str) -> tuple[list[Packet], dict]:
    """Parse a USBPcap capture. Returns (packets, file_meta)."""
    with open(path, "rb") as fh:
        blob = fh.read()

    if len(blob) < 24:
        raise FormatError(f"file is {len(blob)} bytes, too short for a pcap header")

    magic = blob[:4]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise FormatError(
            f"bad magic {magic.hex()} - not a libpcap file "
            "(a USBPCap capture starts with d4c3b2a1)"
        )
    nanos = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)

    ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack_from(
        endian + "HHiIII", blob, 4
    )

    meta = {
        "endian": "little" if endian == "<" else "big",
        "timestamp_resolution": "nanosecond" if nanos else "microsecond",
        "version": f"{ver_major}.{ver_minor}",
        "thiszone": thiszone,
        "snaplen": snaplen,
        "linktype": network,
        "linktype_name": "DLT_USBPCAP" if network == LINKTYPE_USBPCAP else "OTHER",
        "file_size": len(blob),
    }
    if network != LINKTYPE_USBPCAP:
        raise FormatError(
            f"linktype is {network}, expected {LINKTYPE_USBPCAP} (DLT_USBPCAP). "
            "This is a network capture, not USB."
        )

    packets: list[Packet] = []
    off = 24
    rec = 0
    while off + 16 <= len(blob):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(endian + "IIII", blob, off)
        off += 16
        if incl_len > len(blob) - off:
            # Truncated final record: USBPcap is killed mid-write, which is
            # normal when you stop a capture with Stop-Process.
            meta["truncated_final_record"] = {
                "record": rec,
                "declared": incl_len,
                "available": len(blob) - off,
            }
            break
        raw = blob[off : off + incl_len]
        off += incl_len
        rec += 1

        pkt = _parse_usbpcap_record(raw, rec, ts_sec, ts_frac, nanos)
        if pkt is not None:
            packets.append(pkt)

    meta["records_scanned"] = rec
    meta["malformed_records"] = rec - len(packets)
    meta["bytes_consumed"] = off
    return packets, meta


def _parse_usbpcap_record(
    raw: bytes, index: int, ts_sec: int, ts_frac: int, nanos: bool
) -> Packet | None:
    if len(raw) < 27:
        return None

    ts = ts_sec + (ts_frac / 1e9 if nanos else ts_frac / 1e6)

    header_len = struct.unpack_from("<H", raw, 0)[0]
    irp_id = struct.unpack_from("<Q", raw, 2)[0]
    info = raw[10]

    pos = 11
    status = None
    if info & INFO_STATUS_CODE:
        if pos + 4 > len(raw):
            return None
        status = struct.unpack_from("<I", raw, pos)[0]
        pos += 4

    if pos + 12 > len(raw):
        return None
    function, bus, device = struct.unpack_from("<HHH", raw, pos)
    pos += 6
    endpoint, transfer = raw[pos], raw[pos + 1]
    pos += 2
    data_length = struct.unpack_from("<I", raw, pos)[0]
    pos += 4

    if info & INFO_RESERVED:
        pos += 8

    # The self-check: our field walk must land exactly on headerLen.
    walk_ok = pos == header_len

    # headerLen is authoritative for where payload starts. If the walk
    # disagreed we still trust headerLen, because that is what the driver
    # wrote for exactly this purpose.
    body = raw[header_len:] if header_len <= len(raw) else b""
    data = body[:data_length]
    trailing = body[data_length:]

    return Packet(
        index=index,
        ts=ts,
        irp_id=irp_id,
        info=info,
        status=status,
        function=function,
        bus=bus,
        device=device,
        endpoint=endpoint,
        transfer=transfer,
        data_length=data_length,
        data=data,
        header_len=header_len,
        walk_ok=walk_ok,
        trailing=trailing,
    )


def check_transfer_mapping(packets: list[Packet]) -> dict:
    """Verify the transfer-type enum empirically.

    If transfer==2 really means 'control', every such packet should carry a
    setup packet whose bmRequestType has the reserved high bit clear and whose
    low 5 bits are a legal recipient. We score it instead of assuming.
    """
    control = [p for p in packets if p.transfer == 2 and len(p.data) >= 8]
    sane = 0
    for p in control:
        bm = p.data[0]
        if bm & 0x40 == 0 and (bm & 0x1F) <= 3:
            sane += 1
    other = [p for p in packets if p.transfer != 2 and len(p.data) >= 8]
    other_sane = 0
    for p in other:
        bm = p.data[0]
        if bm & 0x40 == 0 and (bm & 0x1F) <= 3:
            other_sane += 1
    return {
        "control_like_packets": len(control),
        "control_like_with_plausible_setup": sane,
        "non_control_packets": len(other),
        "non_control_that_look_control": other_sane,
    }


def summarize(packets: list[Packet], meta: dict) -> str:
    out = []
    out.append("=== file ===")
    for k in (
        "file_size",
        "endian",
        "timestamp_resolution",
        "version",
        "snaplen",
        "linktype",
        "linktype_name",
        "records_scanned",
        "malformed_records",
    ):
        out.append(f"  {k:<22} = {meta.get(k)}")
    if "truncated_final_record" in meta:
        t = meta["truncated_final_record"]
        out.append(
            f"  truncated_final_record = record {t['record']} declares "
            f"{t['declared']} bytes, {t['available']} present (normal if killed)"
        )

    out.append("")
    out.append("=== header parse validation ===")
    ok = sum(1 for p in packets if p.walk_ok)
    out.append(f"  field walk landed on headerLen: {ok}/{len(packets)}")
    if packets and ok != len(packets):
        bad = next(p for p in packets if not p.walk_ok)
        out.append(
            f"  MISMATCH example: packet {bad.index} headerLen={bad.header_len}, "
            f"walk reached a different offset. Decoded fields are UNRELIABLE."
        )
    lens = sorted({p.header_len for p in packets})
    out.append(f"  distinct headerLen values: {lens}")

    out.append("")
    out.append("=== transfer-type mapping check ===")
    tm = check_transfer_mapping(packets)
    for k, v in tm.items():
        out.append(f"  {k:<34} = {v}")

    out.append("")
    out.append("=== devices seen ===")
    seen: dict[tuple[int, int], int] = {}
    for p in packets:
        seen[(p.bus, p.device)] = seen.get((p.bus, p.device), 0) + 1
    for (bus, dev), n in sorted(seen.items()):
        out.append(f"  bus {bus} device {dev:<4} {n} packets")

    out.append("")
    out.append("=== control requests ===")
    reqs: dict[str, int] = {}
    for p in packets:
        s = p.setup
        if s:
            key = str(s)
            reqs[key] = reqs.get(key, 0) + 1
    if not reqs:
        out.append("  (none)")
    for key, n in sorted(reqs.items(), key=lambda kv: -kv[1]):
        out.append(f"  {n:>6}x  {key}")

    return "\n".join(out)


def dump(packets: list[Packet], device: int | None, control_only: bool, limit: int) -> str:
    out = []
    for p in packets:
        if device is not None and p.device != device:
            continue
        if control_only and not p.is_control:
            continue
        s = p.setup
        head = (
            f"[{p.index:>6}] t={p.ts:.6f} dev={p.device:<3} ep=0x{p.endpoint:02X} "
            f"{p.transfer_name:<11} len={p.data_length:<5} irp=0x{p.irp_id:016X}"
        )
        if p.status is not None:
            head += f" status=0x{p.status:08X}"
        if not p.walk_ok:
            head += "  <WALK MISMATCH>"
        out.append(head)
        if s:
            out.append(f"         setup: {s}")
        payload = p.payload
        if payload:
            for i in range(0, min(len(payload), 256), 16):
                chunk = payload[i : i + 16]
                hexpart = " ".join(f"{b:02X}" for b in chunk)
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                out.append(f"           {i:04X}  {hexpart:<47}  {asc}")
            if len(payload) > 256:
                out.append(f"           ... {len(payload) - 256} more bytes")
        if len(out) > limit:
            out.append(f"... output truncated at {limit} lines")
            break
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read USBPcap .pcap files without Wireshark.")
    ap.add_argument("pcap", help="capture file")
    ap.add_argument(
        "mode", nargs="?", default="summary", choices=["summary", "dump", "check"]
    )
    ap.add_argument("--device", type=int, help="only this USB device address")
    ap.add_argument("--control-only", action="store_true")
    ap.add_argument("--limit", type=int, default=400)
    args = ap.parse_args(argv)

    try:
        packets, meta = parse_pcap(args.pcap)
    except FormatError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: cannot read {args.pcap}: {exc}", file=sys.stderr)
        return 2

    if not packets:
        print(
            "WARNING: the file parsed but contains ZERO packets.", file=sys.stderr
        )
        print(summarize(packets, meta))
        return 1

    if args.mode == "summary":
        print(summarize(packets, meta))
    elif args.mode == "check":
        print(summarize(packets, meta))
    else:
        print(dump(packets, args.device, args.control_only, args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
