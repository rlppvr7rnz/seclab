#!/usr/bin/env python3
"""Seclab - minimal security research automation toolkit.

For authorized security testing only: analyze files you own or are
explicitly permitted to assess. No network activity, no dependencies.

Usage:
    python seclab.py hash  <file...>
    python seclab.py strings <file> [--min 6] [--unicode]
    python seclab.py pe    <file>
    python seclab.py entropy <file>
    python seclab.py report <file> [-o report.md]
"""
from __future__ import annotations

import argparse
import hashlib
import math
import re
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def read_file(path: str) -> bytes:
    data = Path(path).read_bytes()
    if not data:
        raise SystemExit(f"empty file: {path}")
    return data


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_hash(args: argparse.Namespace) -> int:
    for path in args.files:
        data = read_file(path)
        print(f"{path}")
        print(f"  size   {len(data)} bytes")
        print(f"  md5    {md5(data)}")
        print(f"  sha256 {sha256(data)}")
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    data = read_file(args.file)
    if args.unicode:
        text = data.decode("utf-16-le", errors="ignore")
    else:
        text = data.decode("latin-1")
    pattern = re.compile(r"[ -~]{%d,}" % args.min)
    hits = pattern.findall(text)
    for s in hits:
        print(s)
    print(f"-- {len(hits)} strings (min {args.min})", file=sys.stderr)
    return 0


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SystemExit("not a PE file (missing MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise SystemExit("not a PE file (missing PE signature)")
    coff = e_lfanew + 4
    machine, nsections = struct.unpack_from("<HH", data, coff)
    timestamp = struct.unpack_from("<I", data, coff + 4)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    characteristics = struct.unpack_from("<H", data, coff + 18)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<I", data, opt + 28)[0] if magic == 0x10B else struct.unpack_from("<Q", data, opt + 24)[0]
    section_table = opt + opt_size
    sections = []
    for i in range(nsections):
        off = section_table + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        s_entropy = entropy(data[rawptr:rawptr + rawsize]) if rawsize else 0.0
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "raw_size": rawsize, "raw_ptr": rawptr, "entropy": round(s_entropy, 3),
        })
    return {
        "machine": machine, "sections_count": nsections, "timestamp": timestamp,
        "characteristics": characteristics, "magic": magic,
        "entry_point": entry, "image_base": image_base, "sections": sections,
    }


MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}


def cmd_pe(args: argparse.Namespace) -> int:
    data = read_file(args.file)
    pe = parse_pe(data)
    print(f"file        {args.file}")
    print(f"size        {len(data)} bytes")
    print(f"sha256      {sha256(data)}")
    print(f"machine     {MACHINES.get(pe['machine'], hex(pe['machine']))}")
    print(f"pe_type     {'PE32+' if pe['magic'] == 0x20B else 'PE32'}")
    print(f"entrypoint  {pe['entry_point']:#x}  image_base {pe['image_base']:#x}")
    print(f"sections    {pe['sections_count']}")
    print(f"file_entropy {entropy(data):.3f}")
    print()
    print(f"{'name':10} {'vaddr':>10} {'vsize':>10} {'raw':>10} {'entropy':>8}")
    for s in pe["sections"]:
        print(f"{s['name']:10} {s['vaddr']:#010x} {s['vsize']:>10} {s['raw_size']:>10} {s['entropy']:>8.3f}")
    return 0


def cmd_entropy(args: argparse.Namespace) -> int:
    data = read_file(args.file)
    print(f"{args.file}: {entropy(data):.3f} bits/byte over {len(data)} bytes")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    data = read_file(args.file)
    try:
        pe = parse_pe(data)
        pe_text = (
            f"- Machine: {MACHINES.get(pe['machine'], hex(pe['machine']))}\n"
            f"- Sections: {pe['sections_count']}\n"
            f"- Entry point: {pe['entry_point']:#x} (image base {pe['image_base']:#x})\n"
            f"- Section entropy (max): {max((s['entropy'] for s in pe['sections']), default=0):.3f}\n"
        )
    except SystemExit:
        pe_text = "- Not a PE file\n"
    report = (
        f"# Analysis report: {Path(args.file).name}\n\n"
        f"## Sample\n\n"
        f"- Path: `{args.file}`\n"
        f"- Size: {len(data)} bytes\n"
        f"- MD5: `{md5(data)}`\n"
        f"- SHA256: `{sha256(data)}`\n"
        f"- Entropy: {entropy(data):.3f} bits/byte\n\n"
        f"## Static observations\n\n{pe_text}\n"
        f"## Workflow\n\n"
        f"1. Recon: hashes and file type recorded above.\n"
        f"2. Enumerate: sections and strings reviewed.\n"
        f"3. Analyze: suspicious regions noted with offsets.\n"
        f"4. Verify: findings reproduced with the exact commands below.\n\n"
        f"## Reproduction\n\n"
        f"```\npython seclab.py hash {args.file}\n"
        f"python seclab.py pe {args.file}\n"
        f"python seclab.py strings {args.file} --min 8\n```\n\n"
        f"## Notes\n\n"
        f"Only analyze samples you own or are authorized to assess.\n"
    )
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"report written to {args.output}")
    else:
        print(report)
    return 0


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seclab", description="Minimal security research automation toolkit (authorized testing only).")
    sub = p.add_subparsers(dest="command", required=True)

    ph = sub.add_parser("hash", help="file hashes and size")
    ph.add_argument("files", nargs="+")
    ph.set_defaults(func=cmd_hash)

    ps = sub.add_parser("strings", help="extract printable strings")
    ps.add_argument("file")
    ps.add_argument("--min", type=int, default=6)
    ps.add_argument("--unicode", action="store_true", help="decode UTF-16LE (crude wide strings)")
    ps.set_defaults(func=cmd_strings)

    pp = sub.add_parser("pe", help="parse PE headers and sections")
    pp.add_argument("file")
    pp.set_defaults(func=cmd_pe)

    pe = sub.add_parser("entropy", help="shannon entropy of a file")
    pe.add_argument("file")
    pe.set_defaults(func=cmd_entropy)

    pr = sub.add_parser("report", help="generate a markdown analysis report")
    pr.add_argument("file")
    pr.add_argument("-o", "--output")
    pr.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
