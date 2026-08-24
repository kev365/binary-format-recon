#!/usr/bin/env python3
"""Profile a fixed-stride record array column by column and propose a struct.

Once profile.py gives you a stride, treat the file as a table: every intra-record
offset is a column, and the *behaviour of a column across many records* tells you
what the field is. A column that is constant is a magic or a version. One that
increments by one is a record id. One whose values all land inside the file is a
pointer. One whose values all land inside the record is an internal offset.

This does not decode a format for you. It generates ranked, falsifiable
hypotheses that you then confirm with bindiff.py against controlled mutations.

Usage:
  fieldmap.py FILE --stride 8192 [--head 128] [--offset 0] [--max-records 2000]
  fieldmap.py FILE --stride 16 --head 16 --widths 1,2,4     # small TOC records
"""
import argparse
import collections
import datetime as dt
import json
import math
import struct

UTC = dt.timezone.utc
E1601 = dt.datetime(1601, 1, 1, tzinfo=UTC)
E1970 = dt.datetime(1970, 1, 1, tzinfo=UTC)
FT_LO = int((dt.datetime(1995, 1, 1, tzinfo=UTC) - E1601).total_seconds() * 1e7)
FT_HI = int((dt.datetime(2035, 1, 1, tzinfo=UTC) - E1601).total_seconds() * 1e7)
UX_LO = int((dt.datetime(1995, 1, 1, tzinfo=UTC) - E1970).total_seconds())
UX_HI = int((dt.datetime(2035, 1, 1, tzinfo=UTC) - E1970).total_seconds())

FMT = {1: ("<B", ">B"), 2: ("<H", ">H"), 4: ("<I", ">I"), 8: ("<Q", ">Q")}


def entropy(vals):
    c = collections.Counter(vals)
    n = len(vals)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def classify(vals, width, stride, filesize, nrec):
    """Return (tag, confidence, note) for one column of values.

    Confidence is not a probability -- it is a priority for the greedy layout
    builder, tuned so that informative wide fields beat the narrow fragments
    that slicing them produces. A FILETIME sliced into two dwords will make the
    upper half look like a constant; the u64 interpretation has to outrank that.
    """
    distinct = len(set(vals))
    lo, hi = min(vals), max(vals)
    tags = []

    if hi == 0:
        return ("zero", 1.0, "always zero -- reserved/padding, or a field only "
                             "used in record types absent from this sample")
    if distinct == 1:
        return ("constant", 1.0, f"always 0x{lo:x} -- magic, version, or type tag")

    diffs = [b - a for a, b in zip(vals, vals[1:])]

    # Timestamps first: they are the most informative reading of a column, and
    # a monotonic timestamp would otherwise be written off as a plain counter.
    if width == 8 and all(FT_LO <= v <= FT_HI for v in vals if v):
        tags.append(("filetime", 0.96, "every value is a plausible Windows "
                                       "FILETIME (100ns since 1601)"))
    if width == 4 and all(UX_LO <= v <= UX_HI for v in vals if v):
        tags.append(("unix32", 0.88, "every value is a plausible 32-bit epoch "
                                     "timestamp"))

    if all(d > 0 for d in diffs):
        if len(set(diffs)) == 1:
            step = diffs[0]
            # A u64 stepping by an exact power of 2^32 is really two u32 fields:
            # a constant low dword and a counter in the high dword.
            if width == 8 and step % (1 << 32) == 0:
                tags.append(("split_u32_pair", 0.30,
                             f"steps by {step} = k*2^32 -- almost certainly two "
                             f"u32 fields, not one u64"))
            else:
                tags.append(("counter_fixed", 0.95,
                             f"strictly increasing by {step} -- index, sequence, "
                             f"or stride-derived offset"))
        else:
            tags.append(("counter", 0.85,
                         f"strictly increasing {lo}..{hi} -- record id, "
                         f"sequence, or file offset"))
    elif all(d >= 0 for d in diffs) and distinct > 2:
        tags.append(("monotonic", 0.60, "non-decreasing -- sorted key or "
                                        "cumulative offset"))

    if distinct <= 8 and nrec >= 8:
        vs = ", ".join(f"0x{v:x}" for v in sorted(set(vals))[:8])
        # 64-bit enums are rare; a wide low-cardinality column is usually two
        # narrow fields that happen to co-vary.
        conf = 0.55 if width == 8 else 0.80
        tags.append(("enum_flags", conf,
                     f"{distinct} distinct values ({vs}) -- type code or bitfield"))

    if width >= 4:
        if 0 < lo and hi < filesize:
            tags.append(("file_offset", 0.70,
                         f"all values inside the file (max 0x{hi:x} < "
                         f"0x{filesize:x}) -- absolute pointer"))
        if 0 < hi <= stride:
            tags.append(("record_offset_or_len", 0.72,
                         f"all values <= stride ({hi} <= {stride}) -- "
                         f"intra-record offset or length"))

    ent = entropy(vals)
    if distinct > 0.9 * nrec and ent > math.log2(nrec) - 1 and width >= 4:
        conf = 0.45 if width == 8 else 0.62
        tags.append(("hash_or_crc", conf,
                     "near-unique high-entropy values -- checksum, hash, or "
                     "random id (resolve with cksum_id.py)"))

    if not tags:
        return ("varies", 0.30, f"{distinct} distinct, range {lo}..{hi}")
    tags.sort(key=lambda t: -t[1])
    tag, conf, note = tags[0]
    if len(tags) > 1:
        note += "  [also: " + ", ".join(t[0] for t in tags[1:4]) + "]"
    return (tag, conf, note)


def endianness_hint(data, base, stride, off, width, nrec):
    """Small unsigned values leave a zero pad on the high-order side."""
    if width < 2:
        return None
    hi_zero = lo_zero = 0
    for k in range(nrec):
        rec = base + k * stride + off
        if data[rec + width - 1] == 0:
            hi_zero += 1          # little-endian small value
        if data[rec] == 0:
            lo_zero += 1          # big-endian small value
    if hi_zero > 0.9 * nrec and hi_zero > lo_zero:
        return "LE"
    if lo_zero > 0.9 * nrec and lo_zero > hi_zero:
        return "BE"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--stride", type=int, required=True)
    ap.add_argument("--offset", type=int, default=0,
                    help="byte offset where the record array starts")
    ap.add_argument("--head", type=int, default=128,
                    help="bytes of each record to profile (raise for small records)")
    ap.add_argument("--max-records", type=int, default=2000)
    ap.add_argument("--widths", default="1,2,4,8")
    ap.add_argument("--big-endian", action="store_true",
                    help="interpret multi-byte fields as big-endian")
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--skip-zero", action="store_true",
                    help="omit always-zero columns from the report")
    ap.add_argument("--dump", type=int, default=0,
                    help="hex dump the first N records after the report")
    ap.add_argument("--json", help="write hypotheses as JSON for the ledger")
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read()
    filesize = len(data)
    stride = args.stride
    head = min(args.head, stride)
    avail = (filesize - args.offset) // stride
    nrec = min(avail, args.max_records)
    if nrec < 4:
        raise SystemExit(f"only {avail} whole records at stride {stride} -- "
                         f"check --stride/--offset")

    widths = [int(w) for w in args.widths.split(",")]
    print(f"file      {args.file} ({filesize} bytes)")
    print(f"records   {nrec} profiled of {avail} available, stride={stride}, "
          f"start=0x{args.offset:x}, head={head}, "
          f"endian={'BE' if args.big_endian else 'LE'}")

    rows = []
    for width in widths:
        if width not in FMT:
            continue
        fmt = FMT[width][1 if args.big_endian else 0]
        st = struct.Struct(fmt)
        for off in range(0, head - width + 1, width):
            vals = []
            for k in range(nrec):
                pos = args.offset + k * stride + off
                if pos + width > filesize:
                    break
                vals.append(st.unpack_from(data, pos)[0])
            if len(vals) < 4:
                continue
            tag, conf, note = classify(vals, width, stride, filesize, len(vals))
            if args.skip_zero and tag == "zero":
                continue
            if conf < args.min_confidence:
                continue
            hint = endianness_hint(data, args.offset, stride, off, width, len(vals))
            rows.append({"offset": off, "width": width, "tag": tag,
                         "confidence": conf, "note": note, "endian_hint": hint,
                         "distinct": len(set(vals)),
                         "min": min(vals), "max": max(vals),
                         "sample": vals[:6]})

    rows.sort(key=lambda r: (r["offset"], r["width"]))
    print(f"\n{'off':>5} {'w':>2} {'tag':<22} {'conf':>5} {'end':>4}  note")
    print("-" * 100)
    for r in rows:
        print(f"{r['offset']:>5} {r['width']:>2} {r['tag']:<22} "
              f"{r['confidence']:>5.2f} {r['endian_hint'] or '-':>4}  {r['note']}")

    le = sum(1 for r in rows if r["endian_hint"] == "LE")
    be = sum(1 for r in rows if r["endian_hint"] == "BE")
    if le or be:
        print(f"\nendianness  {le} column(s) look little-endian, {be} big-endian "
              f"-> format is probably {'little' if le >= be else 'big'}-endian")

    # Propose a non-overlapping struct from the highest-confidence columns.
    print("\nproposed layout (greedy, non-overlapping, highest confidence first)")
    taken = [False] * head
    chosen = []
    def _prio(r):
        # +0.05 per doubling of width: a u64 at 0.96 outranks a u16
        # at 1.00, but a genuine u32 magic still beats a weak u64.
        return -(r["confidence"] + 0.05 * math.log2(r["width"]))

    for r in sorted(rows, key=_prio):
        span = range(r["offset"], min(r["offset"] + r["width"], head))
        if any(taken[i] for i in span):
            continue
        for i in span:
            taken[i] = True
        chosen.append(r)
    chosen.sort(key=lambda r: r["offset"])
    cur = 0
    for r in chosen:
        if r["offset"] > cur:
            print(f"  +{cur:<5} u8[{r['offset']-cur}]".ljust(28) + "unclassified")
        print(f"  +{r['offset']:<5} u{r['width']*8}".ljust(28) +
              f"{r['tag']}  (conf {r['confidence']:.2f})")
        cur = r["offset"] + r["width"]
    if cur < head:
        print(f"  +{cur:<5} u8[{head-cur}]".ljust(28) + "unclassified")
    print("\nThese are hypotheses, not findings. Confirm each one by changing a "
          "single known input and running bindiff.py, then record the outcome "
          "in the hypothesis ledger.")

    if args.dump:
        print(f"\nfirst {args.dump} records")
        for k in range(min(args.dump, nrec)):
            pos = args.offset + k * stride
            chunk = data[pos:pos + head]
            print(f"  record {k} @ 0x{pos:x}")
            for i in range(0, len(chunk), 16):
                row = chunk[i:i + 16]
                hexs = " ".join(f"{b:02x}" for b in row)
                txt = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in row)
                print(f"    +{i:04x}  {hexs:<47}  {txt}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"file": args.file, "stride": stride,
                       "offset": args.offset, "records_profiled": nrec,
                       "columns": rows,
                       "proposed_layout": chosen}, fh, indent=2)
        print(f"\nwrote {args.json}")



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
