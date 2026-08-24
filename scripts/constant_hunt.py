#!/usr/bin/env python3
"""Locate the code that writes a format, using facts learned from the bytes.

This is the bridge between black-box and producer-side analysis. Black-box work
establishes constants -- a magic, a page size, a CRC polynomial, a struct
size. Those same constants are almost always present as immediates, table
data, or string literals inside the producing binary. Finding where they live
gives you the addresses of the serialisation code, which is a far better
starting point than scrolling a function list.

This does not disassemble anything. It reports file offsets and, where the
container can be parsed, virtual addresses, so you can jump straight there in
Ghidra, rizin, IDA, or Binary Ninja. Existing RE skills wrap those tools over
MCP; this one hands them coordinates.

Usage:
  constant_hunt.py producer.exe --magic 0xACCCABCD --stride 8192
  constant_hunt.py producer.dll --facts facts.json
  constant_hunt.py wbemcore.dll --magic 0xABCD --size 16,24 --crc-tables --strings
"""
import argparse
import collections
import json
import os
import struct
import sys

# CRC-32 table first entries, by polynomial. A table in .rdata is the loudest
# possible signal that a routine nearby computes that checksum.
CRC_TABLE_HEADS = {
    "CRC-32/ISO-HDLC (reflected 0xEDB88320)":
        [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419],
    "CRC-32 (normal 0x04C11DB7)":
        [0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC],
    "CRC-32C (reflected 0x82F63B78)":
        [0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4, 0xC79A971F],
    "CRC-16/ARC (reflected 0xA001)":
        [0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301],
    "CRC-16/CCITT (normal 0x1021)":
        [0x0000, 0x1021, 0x2042, 0x3063, 0x4084],
}


def read(path, cap):
    with open(path, "rb") as fh:
        return fh.read(cap)


# ------------------------------------------------------- container awareness

def pe_sections(data):
    """Minimal PE section table walk: (name, file_off, size, va, chars)."""
    if data[:2] != b"MZ":
        return None, None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None, None
        coff = e_lfanew + 4
        n_sect, = struct.unpack_from("<H", data, coff + 2)
        opt_size, = struct.unpack_from("<H", data, coff + 16)
        opt = coff + 20
        magic, = struct.unpack_from("<H", data, opt)
        image_base = (struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B
                      else struct.unpack_from("<I", data, opt + 28)[0])
        sect = opt + opt_size
        out = []
        for i in range(n_sect):
            off = sect + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            chars, = struct.unpack_from("<I", data, off + 36)
            out.append({"name": name, "raw": rawptr, "rawsize": rawsize,
                        "va": va, "vsize": vsize, "chars": chars})
        return out, image_base
    except (struct.error, IndexError):
        return None, None


def elf_sections(data):
    if data[:4] != b"\x7fELF":
        return None, None
    try:
        is64 = data[4] == 2
        little = data[5] == 1
        e = "<" if little else ">"
        if is64:
            e_shoff, = struct.unpack_from(e + "Q", data, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
        else:
            e_shoff, = struct.unpack_from(e + "I", data, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
        out = []
        strtab_off = None
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is64:
                nm, _ty, _fl, addr, offset, size = struct.unpack_from(
                    e + "IIQQQQ", data, off)
            else:
                nm, _ty, _fl, addr, offset, size = struct.unpack_from(
                    e + "IIIIII", data, off)
            out.append({"nm": nm, "raw": offset, "rawsize": size,
                        "va": addr, "vsize": size, "name": "", "chars": 0})
            if i == e_shstrndx:
                strtab_off = offset
        if strtab_off is not None:
            for s in out:
                end = data.find(b"\0", strtab_off + s["nm"])
                s["name"] = data[strtab_off + s["nm"]:end].decode("ascii", "replace")
        return out, 0
    except (struct.error, IndexError):
        return None, None


def locate(sections, image_base, off):
    if not sections:
        return None, None
    for s in sections:
        if s["rawsize"] and s["raw"] <= off < s["raw"] + s["rawsize"]:
            va = image_base + s["va"] + (off - s["raw"])
            return s["name"], va
    return None, None


# ------------------------------------------------------------------ scanning

def scan_value(data, value, widths=(2, 4, 8)):
    hits = []
    for w in widths:
        if value >= (1 << (w * 8)):
            continue
        for endian, tag in (("<", "LE"), (">", "BE")):
            try:
                needle = struct.pack(endian + {2: "H", 4: "I", 8: "Q"}[w], value)
            except struct.error:
                continue
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                hits.append((i, w, tag))
                start = i + 1
                if len(hits) > 4000:
                    return hits
    return hits


def scan_crc_tables(data):
    found = []
    for name, head in CRC_TABLE_HEADS.items():
        width = 4 if head[1] > 0xFFFF else 2
        fmt = "<I" if width == 4 else "<H"
        needle = b"".join(struct.pack(fmt, v) for v in head)
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            found.append((i, name, width))
            start = i + 1
    return found


def scan_strings(data, minlen=6, hints=()):
    """ASCII and UTF-16LE literals, optionally filtered to hint substrings."""
    import re
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append((m.start(), "ascii", m.group(0).decode("ascii", "replace")))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append((m.start(), "utf-16le",
                    m.group(0).decode("utf-16-le", "replace")))
    if hints:
        low = [h.lower() for h in hints]
        out = [s for s in out if any(h in s[2].lower() for h in low)]
    out.sort()
    return out


# Function names that commonly sit next to serialisation code. Present only in
# binaries with exports or symbols, but free to check.
SERIALIZE_HINTS = [
    "serial", "write", "save", "store", "persist", "flush", "commit",
    "marshal", "pack", "encode", "dump", "header", "checksum", "crc",
    "page", "record", "index", "repository", "format", "version",
]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="the producing executable, DLL, or driver")
    ap.add_argument("--magic", action="append", default=[],
                    help="a format constant, e.g. 0xACCCABCD (repeatable)")
    ap.add_argument("--stride", type=int, action="append", default=[],
                    help="page or record size, e.g. 8192 (repeatable)")
    ap.add_argument("--size", help="comma-separated struct sizes to hunt")
    ap.add_argument("--facts", help="JSON with keys magics/strides/sizes")
    ap.add_argument("--crc-tables", action="store_true",
                    help="scan for CRC lookup tables")
    ap.add_argument("--strings", action="store_true",
                    help="report strings matching serialisation-related hints")
    ap.add_argument("--max-bytes", type=int, default=256 << 20)
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--json", help="write findings for downstream tooling")
    args = ap.parse_args()

    data = read(args.binary, args.max_bytes)
    sections, image_base = pe_sections(data)
    kind = "PE"
    if sections is None:
        sections, image_base = elf_sections(data)
        kind = "ELF" if sections else "raw"

    values, strides, sizes = [], list(args.stride), []
    for m in args.magic:
        values.append(int(m, 0))
    if args.size:
        sizes = [int(x, 0) for x in args.size.split(",")]
    if args.facts:
        with open(args.facts) as fh:
            f = json.load(fh)
        values += [int(str(v), 0) for v in f.get("magics", [])]
        strides += [int(str(v), 0) for v in f.get("strides", [])]
        sizes += [int(str(v), 0) for v in f.get("sizes", [])]

    print(f"binary    {args.binary}  ({len(data)} bytes, {kind})")
    if sections:
        print(f"sections  " + ", ".join(
            f"{s['name']}@0x{image_base + s['va']:x}" for s in sections[:8]))
    else:
        print("sections  no container header parsed; reporting file offsets only")

    findings = {"binary": args.binary, "kind": kind, "hits": []}

    def report(label, hits, why):
        if not hits:
            print(f"\n{label}: no hits")
            print(f"  {why}")
            return
        by_sec = collections.Counter()
        rows = []
        for off, w, tag in hits:
            sec, va = locate(sections, image_base, off)
            by_sec[sec or "(unmapped)"] += 1
            rows.append((off, w, tag, sec, va))
        print(f"\n{label}: {len(hits)} hit(s) in " +
              ", ".join(f"{k}({v})" for k, v in by_sec.most_common(5)))
        for off, w, tag, sec, va in rows[:args.top]:
            loc = f"0x{va:x}" if va else "-"
            print(f"  file 0x{off:08x}  u{w*8} {tag}  {sec or '?':<10} va {loc}")
            findings["hits"].append({"kind": label, "file_offset": off,
                                     "width": w, "endian": tag,
                                     "section": sec, "va": va})
        if len(hits) > args.top:
            print(f"  ... {len(hits) - args.top} more")
        print(f"  {why}")

    for v in values:
        report(f"magic 0x{v:x}", scan_value(data, v),
               "Hits in a code section are immediates -- the instruction is "
               "probably\n  writing or comparing the signature. Hits in "
               "rdata/data are the constant\n  itself; xref it to find both the "
               "writer and the reader.")

    for s in strides:
        report(f"stride {s}", scan_value(data, s, widths=(4, 8)),
               "Page or record size appears in allocation, bounds checks, and "
               "offset\n  arithmetic. Cross-reference with the magic hits -- a "
               "function containing\n  both is very likely the serialiser.")

    for s in sizes:
        report(f"struct size {s}", scan_value(data, s, widths=(2, 4)),
               "Struct sizes show up in sizeof-style immediates, memset, and "
               "loop bounds.\n  Noisy for small values; treat as corroboration "
               "rather than a lead.")

    if args.crc_tables:
        tabs = scan_crc_tables(data)
        if tabs:
            print(f"\nCRC lookup tables: {len(tabs)} hit(s)")
            for off, name, w in tabs:
                sec, va = locate(sections, image_base, off)
                loc = f"0x{va:x}" if va else "-"
                print(f"  file 0x{off:08x}  {name}  {sec or '?'}  va {loc}")
            print("  A CRC table is the strongest single lead in this tool. The "
                  "function that\n  indexes it computes the checksum; its "
                  "callers are the writers, and its\n  arguments tell you "
                  "exactly which bytes are covered -- which is the\n  question "
                  "cksum_id.py answers by brute force.")
        else:
            print("\nCRC lookup tables: none found")
            print("  Table-free (bitwise) implementations and hardware CRC32 "
                  "instructions\n  leave no table. Absence is not evidence "
                  "against a CRC.")

    if args.strings:
        hits = scan_strings(data, hints=SERIALIZE_HINTS)
        print(f"\nserialisation-related strings: {len(hits)}")
        for off, enc, text in hits[:args.top]:
            sec, va = locate(sections, image_base, off)
            show = text if len(text) <= 60 else text[:57] + "..."
            print(f"  file 0x{off:08x}  {enc:<9} {show!r}")
        if hits:
            print("  Error messages, format strings, and registry paths near "
                  "the writer are\n  often the fastest way to name a function.")

    print("\nNext, in whichever disassembler you use:")
    print("  1. Go to the addresses above and xref the constant.")
    print("  2. The function that references both the magic and the stride is "
          "the\n     container writer; the one indexing the CRC table is the "
          "checksum.")
    print("  3. Recover the struct from member access offsets, then compare it "
          "against\n     the fieldmap.py layout. Agreement promotes fields from "
          "inferred to\n     established; disagreement means one of you is "
          "wrong and it is worth\n     finding out which.")
    print("  4. Record confirmations in the hypothesis ledger, citing the "
          "function\n     address as evidence.")
    print("\nSee references/producer-side.md for the full workflow, including "
          "Ghidra\nheadless automation and cross-version diffing.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\nwrote {args.json}")


def _quiet_pipe():
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass


if __name__ == "__main__":
    _quiet_pipe()
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        raise SystemExit(130)
