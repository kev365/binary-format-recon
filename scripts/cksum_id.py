#!/usr/bin/env python3
"""Identify an unknown checksum field: which algorithm, over which bytes.

fieldmap.py flags high-entropy near-unique columns as possible checksums.
This resolves them. It brute-forces a catalogue of CRC parameterisations and
simple accumulators against several candidate coverage ranges, then reports
only the combinations that reproduce the stored value for every record tested.

A confirmed checksum is worth a lot: it validates your record boundaries, it
tells you which bytes the format considers "the record", and it lets you
detect corruption instead of silently mis-parsing it.

Usage:
  cksum_id.py FILE --stride 16 --cksum-offset 12 --cksum-width 4
  cksum_id.py FILE --stride 8192 --cksum-offset 4 --cksum-width 4 --range 8:8192
"""
import argparse
import struct
import zlib

# name: (width, poly, init, refin, refout, xorout)
CRC_CATALOG = {
    "CRC-32/ISO-HDLC (zlib)":  (32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "CRC-32/BZIP2":            (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF),
    "CRC-32/MPEG-2":           (32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000),
    "CRC-32/JAMCRC":           (32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0x00000000),
    "CRC-32/POSIX (cksum)":    (32, 0x04C11DB7, 0x00000000, False, False, 0xFFFFFFFF),
    "CRC-32/XFER":             (32, 0x000000AF, 0x00000000, False, False, 0x00000000),
    "CRC-32C (Castagnoli)":    (32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "CRC-32D":                 (32, 0xA833982B, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "CRC-32/ISO-HDLC init0":   (32, 0x04C11DB7, 0x00000000, True, True, 0x00000000),
    "CRC-16/ARC":              (16, 0x8005, 0x0000, True, True, 0x0000),
    "CRC-16/MODBUS":           (16, 0x8005, 0xFFFF, True, True, 0x0000),
    "CRC-16/CCITT-FALSE":      (16, 0x1021, 0xFFFF, False, False, 0x0000),
    "CRC-16/XMODEM":           (16, 0x1021, 0x0000, False, False, 0x0000),
    "CRC-16/KERMIT":           (16, 0x1021, 0x0000, True, True, 0x0000),
    "CRC-16/GENIBUS":          (16, 0x1021, 0xFFFF, False, False, 0xFFFF),
    "CRC-8/SMBUS":             (8, 0x07, 0x00, False, False, 0x00),
    "CRC-8/MAXIM":             (8, 0x31, 0x00, True, True, 0x00),
    "CRC-64/XZ":               (64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, True, True, 0xFFFFFFFFFFFFFFFF),
    "CRC-64/ECMA-182":         (64, 0x42F0E1EBA9EA3693, 0x0000000000000000, False, False, 0x0000000000000000),
}

# check value = CRC of b"123456789"; used by --selftest to prove the
# implementation before any conclusion is drawn from it.
CHECK = {
    "CRC-32/ISO-HDLC (zlib)": 0xCBF43926, "CRC-32/BZIP2": 0xFC891918,
    "CRC-32/MPEG-2": 0x0376E6E7, "CRC-32/JAMCRC": 0x340BC6D9,
    "CRC-32/POSIX (cksum)": 0x765E7680, "CRC-32/XFER": 0xBD0BE338,
    "CRC-32C (Castagnoli)": 0xE3069283, "CRC-32D": 0x87315576,
    "CRC-16/ARC": 0xBB3D, "CRC-16/MODBUS": 0x4B37,
    "CRC-16/CCITT-FALSE": 0x29B1, "CRC-16/XMODEM": 0x31C3,
    "CRC-16/KERMIT": 0x2189, "CRC-16/GENIBUS": 0xD64E,
    "CRC-8/SMBUS": 0xF4, "CRC-8/MAXIM": 0xA1,
    "CRC-64/XZ": 0x995DC9BBDF1939FA, "CRC-64/ECMA-182": 0x6C40DF5F0B497347,
}

_TABLES = {}
_REFL8 = [int(f"{b:08b}"[::-1], 2) for b in range(256)]


def _reflect(v, n):
    r = 0
    for i in range(n):
        if v & (1 << i):
            r |= 1 << (n - 1 - i)
    return r


def _table(width, poly):
    key = (width, poly)
    if key in _TABLES:
        return _TABLES[key]
    top = 1 << (width - 1)
    mask = (1 << width) - 1
    tbl = []
    for b in range(256):
        reg = b << (width - 8)
        for _ in range(8):
            reg = ((reg << 1) ^ poly) & mask if reg & top else (reg << 1) & mask
        tbl.append(reg)
    _TABLES[key] = tbl
    return tbl


def crc(data, width, poly, init, refin, refout, xorout):
    """Generic table-driven CRC.

    Reflection applies to each *input byte* before it is mixed into the
    register, and to the final register -- not to the table index. Getting
    that wrong silently produces plausible-looking wrong answers.
    """
    mask = (1 << width) - 1
    tbl = _table(width, poly)
    reg = init & mask
    shift = width - 8
    if refin:
        for byte in data:
            reg = ((reg << 8) & mask) ^ tbl[((reg >> shift) ^ _REFL8[byte]) & 0xFF]
    else:
        for byte in data:
            reg = ((reg << 8) & mask) ^ tbl[((reg >> shift) ^ byte) & 0xFF]
    if refout:
        reg = _reflect(reg, width)
    return reg ^ xorout


def selftest():
    """Validate every catalogue entry against its published check value."""
    ok = True
    for name, params in CRC_CATALOG.items():
        if name not in CHECK:
            print(f"  ??  {name:<26} no published check value")
            continue
        got = crc(b"123456789", *params)
        exp = CHECK[name]
        w = params[0] // 4
        status = "ok " if got == exp else "FAIL"
        if got != exp:
            ok = False
        print(f"  {status} {name:<26} got 0x{got:0{w}x} expect 0x{exp:0{w}x}")
    print("\nself-test " + ("passed" if ok else "FAILED -- do not trust results"))
    return 0 if ok else 1


def simple_checksums(data, width):
    mask = (1 << width) - 1
    out = {}
    out["sum8 bytes"] = sum(data) & mask
    x = 0
    for b in data:
        x ^= b
    out["xor8 bytes"] = x & mask
    out["adler32"] = zlib.adler32(data) & mask
    out["zlib.crc32"] = zlib.crc32(data) & mask
    if len(data) % 2 == 0 and len(data) >= 2:
        words = struct.unpack(f"<{len(data)//2}H", data)
        out["sum u16le"] = sum(words) & mask
        a = b = 0
        for w in words:
            a = (a + w) & 0xFFFF
            b = (b + a) & 0xFFFF
        out["fletcher32"] = ((b << 16) | a) & mask
    if len(data) % 4 == 0 and len(data) >= 4:
        dwords = struct.unpack(f"<{len(data)//4}I", data)
        out["sum u32le"] = sum(dwords) & mask
        x = 0
        for d in dwords:
            x ^= d
        out["xor u32le"] = x & mask
    out["length"] = len(data) & mask
    return out


def parse_range(spec, stride):
    a, _, b = spec.partition(":")
    return int(a or 0, 0), int(b or stride, 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--selftest", action="store_true",
                    help="validate the CRC catalogue against published check "
                         "values and exit")
    ap.add_argument("--stride", type=int)
    ap.add_argument("--offset", type=int, default=0, help="record array start")
    ap.add_argument("--cksum-offset", type=int,
                    help="offset of the checksum field within the record")
    ap.add_argument("--cksum-width", type=int, default=4, choices=[1, 2, 4, 8])
    ap.add_argument("--big-endian", action="store_true")
    ap.add_argument("--range", action="append", default=[],
                    help="extra coverage range as START:END within the record "
                         "(repeatable, e.g. --range 8:8192)")
    ap.add_argument("--max-records", type=int, default=64)
    ap.add_argument("--min-hits", type=float, default=1.0,
                    help="fraction of records a candidate must satisfy (1.0 = all)")
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())
    if not (args.file and args.stride is not None and args.cksum_offset is not None):
        ap.error("file, --stride and --cksum-offset are required "
                 "(or use --selftest)")

    with open(args.file, "rb") as fh:
        data = fh.read()
    stride, co, cw = args.stride, args.cksum_offset, args.cksum_width
    fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[cw]
    fmt = (">" if args.big_endian else "<") + fmt

    recs = []
    k = 0
    while len(recs) < args.max_records:
        pos = args.offset + k * stride
        k += 1
        if pos + stride > len(data):
            break
        rec = data[pos:pos + stride]
        (stored,) = struct.unpack_from(fmt, rec, co)
        if stored == 0:
            continue          # unset checksum; skip rather than pollute the vote
        recs.append((pos, rec, stored))

    if not recs:
        raise SystemExit("no records with a non-zero checksum field. Note that "
                         "some formats leave the field present but unused on "
                         "certain OS versions -- verify before concluding.")

    print(f"file      {args.file}")
    print(f"records   {len(recs)} with non-zero checksum "
          f"(stride={stride}, cksum at +{co}, {cw*8}-bit "
          f"{'BE' if args.big_endian else 'LE'})")

    zeroed = bytearray(recs[0][1])
    ranges = {
        f"0:{co} (start..cksum)": (0, co),
        f"{co+cw}:{stride} (cksum..end)": (co + cw, stride),
        f"0:{stride} whole record": (0, stride),
        f"0:{stride} cksum zeroed": ("ZERO", None),
    }
    for spec in args.range:
        a, b = parse_range(spec, stride)
        ranges[f"{a}:{b} (user)"] = (a, b)

    def payload(rec, rng):
        if rng[0] == "ZERO":
            m = bytearray(rec)
            m[co:co + cw] = b"\x00" * cw
            return bytes(m)
        a, b = rng
        return rec[a:b] if b > a else b""

    # Stage 1: cheap screen on the first record.
    survivors = []
    pos0, rec0, stored0 = recs[0]
    for rname, rng in ranges.items():
        p = payload(rec0, rng)
        if not p:
            continue
        for aname, params in CRC_CATALOG.items():
            if params[0] != cw * 8:
                continue
            if crc(p, *params) == stored0:
                survivors.append((aname, rname, rng))
        for aname, v in simple_checksums(p, cw * 8).items():
            if v == stored0:
                survivors.append((aname, rname, rng))

    if not survivors:
        print("\nNo algorithm/range combination reproduces even the first "
              "record's value.\nThings to try:")
        print("  - the field may not be a checksum (a hash, a random id, or an "
              "encrypted value looks identical to fieldmap.py)")
        print("  - coverage may span more than one record, or include a header "
              "outside the record: pass --range explicitly")
        print("  - the width or endianness may be wrong: try --cksum-width 2/8 "
              "or --big-endian")
        print("  - a seed/salt may be mixed in (common in proprietary formats)")
        return

    print(f"\nstage 1: {len(survivors)} candidate(s) matched record 0; "
          f"validating across {len(recs)} records")
    print("-" * 92)
    confirmed = []
    for aname, rname, rng in survivors:
        hits = 0
        for pos, rec, stored in recs:
            p = payload(rec, rng)
            if aname in CRC_CATALOG:
                v = crc(p, *CRC_CATALOG[aname])
            else:
                v = simple_checksums(p, cw * 8).get(aname)
            if v == stored:
                hits += 1
        frac = hits / len(recs)
        confirmed.append((frac, hits, aname, rname))
    confirmed.sort(reverse=True)

    print(f"{'match':>8}  {'algorithm':<26} coverage")
    for frac, hits, aname, rname in confirmed:
        mark = "  <== CONFIRMED" if frac >= args.min_hits else ""
        print(f"{hits}/{len(recs)} ({frac:>5.1%})  {aname:<26} {rname}{mark}")

    best = confirmed[0]
    if best[0] >= args.min_hits:
        print(f"\nEstablished: the field at +{co} is {best[2]} over {best[3]}.")
        print("Record this as a confirmed field. It also confirms your stride "
              "and record start offset are correct -- a wrong boundary could "
              "not produce a consistent checksum.")
    else:
        print(f"\nPartial match only ({best[0]:.1%}). Either the format changed "
              "across the sample (version drift), or some records use a "
              "different coverage. Split the corpus and re-test each group.")



def _quiet_pipe():
    """Exit cleanly when output is piped into head/grep and the pipe closes."""
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass       # Windows has no SIGPIPE; the except in __main__ covers it


if __name__ == "__main__":
    _quiet_pipe()
    try:
        main()
    except BrokenPipeError:
        import os, sys
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        raise SystemExit(130)
