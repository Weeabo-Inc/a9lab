#!/usr/bin/env python3
"""
research-log.py - append-only findings log for the A9 research project.

Why this exists: research without a log becomes a pile of notes nobody can
audit, including the person who wrote them. This enforces two habits that
matter more than they sound:

  1. Every finding records its CONFIDENCE (measured / inferred / secondhand).
     Mixing those silently is how a hypothesis becomes "known fact" in a doc.
  2. Every finding records its REPRODUCIBILITY - what a third party would need
     to see it themselves.

Storage:
  findings.jsonl  - one JSON object per line, append-only. Never rewritten.
  PLAN.md         - the human-readable table is regenerated from the JSONL.

Never log device-unique identifiers (ECID/UDID/serial). A --check flag scans an
entry for those patterns and refuses to write them.

Usage:
    python research-log.py add --rq RQ1 --title "DFU request X returns Y" \
        --detail "..." --confidence measured --repro "a9id.py, device in DFU"
    python research-log.py list
    python research-log.py export
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINDINGS = HERE / "findings.jsonl"
PLAN = HERE / "PLAN.md"

CONFIDENCE = ("measured", "inferred", "secondhand", "failed")

# Patterns that look like device-unique identifiers. We refuse to write these.
SECRET_PATTERNS = [
    (re.compile(r"\bECID[:\s=]+\d{6,}\b", re.I), "ECID"),
    (re.compile(r"\b[0-9a-f]{40}\b", re.I), "40-hex UDID"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{16}\b", re.I), "UDID-style"),
    (re.compile(r"\b(serial|srln)[:\s=]+[A-Z0-9]{10,}\b", re.I), "serial number"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_for_identifiers(text: str) -> list[str]:
    """Return descriptions of anything that looks like a device-unique id."""
    hits = []
    for rx, label in SECRET_PATTERNS:
        if rx.search(text):
            hits.append(label)
    return hits


def read_findings() -> list[dict]:
    if not FINDINGS.exists():
        return []
    out = []
    for line in FINDINGS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def next_id(entries: list[dict]) -> str:
    n = len(entries) + 1
    return f"F{n:03d}"


def cmd_add(args: argparse.Namespace) -> int:
    blob = " ".join(filter(None, [args.title, args.detail or "", args.repro or ""]))
    hits = scan_for_identifiers(blob)
    if hits:
        print("REFUSED: entry appears to contain device-unique identifiers:", file=sys.stderr)
        for h in hits:
            print(f"  - {h}", file=sys.stderr)
        print("Remove or mask them (use <ECID> / <UDID> placeholders).", file=sys.stderr)
        return 2

    entries = read_findings()
    entry = {
        "id": next_id(entries),
        "timestamp": utc_now(),
        "rq": args.rq,
        "title": args.title,
        "detail": args.detail or "",
        "confidence": args.confidence,
        "repro": args.repro or "",
        "source": args.source or "",
    }
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    with FINDINGS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"logged {entry['id']} ({entry['confidence']}): {entry['title']}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    entries = read_findings()
    if not entries:
        print("no findings logged yet")
        return 0
    print(f"{'ID':<6} {'WHEN':<21} {'RQ':<5} {'CONF':<11} TITLE")
    print(f"{'-'*6} {'-'*21} {'-'*5} {'-'*11} {'-'*45}")
    for e in entries:
        print(f"{e['id']:<6} {e['timestamp']:<21} {e.get('rq',''):<5} "
              f"{e['confidence']:<11} {e['title']}")
    print(f"\n{len(entries)} finding(s) in {FINDINGS}")
    return 0


def cmd_export(_: argparse.Namespace) -> int:
    """Regenerate the findings table inside PLAN.md."""
    entries = read_findings()
    if not PLAN.exists():
        print(f"PLAN.md not found at {PLAN}", file=sys.stderr)
        return 1
    text = PLAN.read_text(encoding="utf-8")

    rows = ["| # | Timestamp | RQ | Finding | Confidence |",
            "|---|---|---|---|---|"]
    if entries:
        for e in entries:
            title = e["title"].replace("|", "\\|")
            rows.append(f"| {e['id']} | {e['timestamp']} | {e.get('rq','')} | "
                        f"{title} | {e['confidence']} |")
    else:
        rows.append("| — | — | — | *(no findings logged yet)* | — |")
    table = "\n".join(rows)

    # Replace the table under "## 5. Findings log" up to the next "---"
    pattern = re.compile(
        r"(## 5\. Findings log.*?\n\n)(.*?)(\n\n---)",
        re.DOTALL,
    )
    if not pattern.search(text):
        print("could not locate the findings table in PLAN.md", file=sys.stderr)
        return 1
    text = pattern.sub(lambda m: m.group(1) + table + m.group(3), text)
    PLAN.write_text(text, encoding="utf-8")
    print(f"PLAN.md updated with {len(entries)} finding(s)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="A9 research findings log")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append a finding")
    a.add_argument("--rq", required=True, help="research question id, e.g. RQ1")
    a.add_argument("--title", required=True, help="one-line finding")
    a.add_argument("--detail", help="what was observed, in detail")
    a.add_argument("--confidence", choices=CONFIDENCE, default="measured")
    a.add_argument("--repro", help="how a third party reproduces this")
    a.add_argument("--source", help="primary source / tool used")
    a.set_defaults(func=cmd_add)

    l = sub.add_parser("list", help="show all findings")
    l.set_defaults(func=cmd_list)

    e = sub.add_parser("export", help="regenerate the PLAN.md findings table")
    e.set_defaults(func=cmd_export)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
