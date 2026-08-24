#!/usr/bin/env python3
"""Account for every byte of a known structure, then characterise what is left.

A documented layout is rarely complete. Specifications carry fields marked
reserved, unknown, or padding; reference implementations skip regions they
never needed; and your own analysis leaves gaps it could not close. Those
leftovers are where the remaining information is, and they are invisible
precisely because the structure is "known".

This subtracts the known fields from the bytes and characterises what remains,
across a whole corpus, so that a region can be told apart as:

  genuine padding        always zero everywhere -- nothing to find
  undocumented constant  a magic, version, or type tag nobody named
  live field             varies independently; carries information
  version-scoped field   used in some samples, zero in others
  derived value          moves in lockstep with a known field
  residual data          uninitialised memory, stale buffer contents, slack

The last is the forensically interesting one and the reason this exists. Bytes
a producer never initialises leak whatever was in that memory -- pointers,
fragments of other records, remnants of earlier writes -- and a spec calling
them padding is the reason nobody looks.

Usage:
  coverage.py sample.bin --stride 8192 --field 0:4:magic --field 4:4:page_id
  coverage.py ./corpus --stride 8192 --layout layout.json --corpus
  coverage.py sample.bin --stride 16 --offset 64 --layout fieldmap.json
"""
import argparse
import collections
import json
import math
import os
import struct
import sys

FMT = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}


def entropy(vals):
    if not vals:
        return 0.0
    c = collections.Counter(vals)
    n = len(vals)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def load_layout(path):
    """Accept a hand-written layout or fieldmap.py --json output."""
    with open(path) as fh:
        doc = json.load(fh)
    fields = []
    if isinstance(doc, list):
        rows = doc
    elif "fields" in doc:
        rows = doc["fields"]
    elif "proposed_layout" in doc:
        rows = doc["proposed_layout"]
    elif "columns" in doc:
        rows = doc["columns"]
    else:
        raise SystemExit(f"{path}: expected a list, or a dict with fields / "
                         f"proposed_layout / columns")
    for r in rows:
        off = r.get("offset")
        width = r.get("width") or r.get("size")
        name = r.get("name") or r.get("tag") or f"field_{off}"
        if off is None or width is None:
            continue
        fields.append((int(off), int(width), str(name)))
    return fields


def parse_field(spec):
    parts = spec.split(":")
    if len(parts) < 2:
        raise SystemExit(f"bad --field {spec!r}; expected OFFSET:WIDTH[:NAME]")
    off = int(parts[0], 0)
    width = int(parts[1], 0)
    name = parts[2] if len(parts) > 2 else f"field_{off}"
    return off, width, name


def unclaimed_runs(claimed, size):
    runs, start = [], None
    for i in range(size):
        if not claimed[i]:
            if start is None:
                start = i
        else:
            if start is not None:
                runs.append((start, i - start))
                start = None
    if start is not None:
        runs.append((start, size - start))
    return runs


def looks_like_pointer(vals64):
    """Detect leaked pointers by upper-half clustering, not per-value range.

    A per-value range test false-positives on any pair of small u32 fields
    read as one u64. Real leaked pointers have a different signature: they
    come from the same module or heap, so their upper halves cluster on a few
    values (an image base, a heap segment) while the low halves vary widely.
    That combination is what distinguishes a pointer from arithmetic.
    """
    vals = [v for v in vals64 if v]
    if len(vals) < 8:
        return 0.0, ""
    uppers = collections.Counter(v >> 32 for v in vals)
    top, count = uppers.most_common(1)[0]
    share = count / len(vals)
    if share < 0.5:
        return 0.0, ""
    # Plausible x64 user-mode upper halves: module images sit near 0x7FFx,
    # heap segments in the low hundreds. Anything above 0xFFFF is not canonical.
    if not (0x100 <= top <= 0xFFFF):
        return 0.0, ""
    lows = {v & 0xFFFFFFFF for v in vals if (v >> 32) == top}
    if len(lows) < max(4, count * 0.5):
        return 0.0, ""          # low half barely varies: a constant, not a pointer
    span = max(lows) - min(lows)
    if span < 0x1000:
        return 0.0, ""          # too tight to be separate allocations
    kind = "module image" if top >= 0x7000 else "heap segment"
    return share, (f"{share:.0%} share a high half of 0x{top:x} ({kind}) with "
                   f"{len(lows)} distinct low halves spanning 0x{span:x}")


def looks_like_pointer32(vals32):
    """Same clustering test for 32-bit pointers."""
    vals = [v for v in vals32 if v]
    if len(vals) < 8:
        return 0.0, ""
    uppers = collections.Counter(v >> 20 for v in vals)
    top, count = uppers.most_common(1)[0]
    share = count / len(vals)
    if share < 0.5 or not (0x4 <= top <= 0x7FF):
        return 0.0, ""
    lows = {v & 0xFFFFF for v in vals if (v >> 20) == top}
    if len(lows) < max(4, count * 0.5):
        return 0.0, ""
    return share, (f"{share:.0%} share a high half of 0x{top:x}xxxxx with "
                   f"{len(lows)} distinct low values -- 32-bit user addresses")


def looks_like_text(chunks):
    if not chunks:
        return 0.0
    printable = total = 0
    for c in chunks:
        for b in c:
            total += 1
            if 0x20 <= b < 0x7F:
                printable += 1
    return printable / total if total else 0.0


def fragment_reuse(chunks, whole, minlen=6):
    """Does the unclaimed data appear elsewhere in the file?

    Stale buffer reuse leaves fragments of earlier content in padding. If a
    non-trivial run also occurs outside its own record, the producer is
    recycling a buffer rather than zeroing it.
    """
    hits = 0
    tested = 0
    for c in chunks[:200]:
        c = c.rstrip(b"\x00").lstrip(b"\x00")
        if len(c) < minlen or len(set(c)) < 3:
            continue
        tested += 1
        if whole.count(c) > 1:
            hits += 1
    return (hits / tested) if tested else 0.0


def classify(chunks, width, whole, known_cols, nrec):
    """Return (label, confidence, note) for one unclaimed run."""
    flat = b"".join(chunks)
    if not flat:
        return ("empty", 1.0, "no data")

    distinct_chunks = len(set(chunks))
    nonzero = sum(1 for c in chunks if any(c))
    ent = entropy(flat)

    if not any(flat):
        return ("genuine padding", 0.95,
                f"zero in all {len(chunks)} record(s) -- consistent with real "
                f"padding or a reserved field never used in this corpus")

    if distinct_chunks == 1:
        val = chunks[0]
        return ("undocumented constant", 0.9,
                f"identical in all {len(chunks)} record(s): {val[:16].hex()} -- "
                f"a magic, version, or type tag the spec does not name")

    ptr, ptr_why = 0.0, ""
    if width >= 8:
        vals = []
        for c in chunks:
            for i in range(0, len(c) - 7, 8):
                vals.append(struct.unpack_from("<Q", c, i)[0])
        ptr, ptr_why = looks_like_pointer(vals)
    if ptr == 0.0 and width >= 4:
        vals = []
        for c in chunks:
            for i in range(0, len(c) - 3, 4):
                vals.append(struct.unpack_from("<I", c, i)[0])
        ptr, ptr_why = looks_like_pointer32(vals)

    reuse = fragment_reuse(chunks, whole)
    text = looks_like_text(chunks)

    if ptr > 0.4:
        return ("residual data (pointers)", 0.85,
                f"{ptr_why} -- the producer is writing uninitialised memory "
                f"here, not padding")
    if reuse > 0.5:
        return ("residual data (stale buffer)", 0.8,
                f"{reuse:.0%} of runs also occur elsewhere in the file -- a "
                f"buffer is being recycled without zeroing, so this holds "
                f"remnants of earlier content")
    if text > 0.7:
        return ("residual data (text)", 0.75,
                f"{text:.0%} printable -- string remnants in a region the "
                f"layout treats as unused")

    if nonzero < len(chunks) * 0.25:
        return ("conditional or version-scoped field", 0.7,
                f"non-zero in only {nonzero}/{len(chunks)} record(s) -- used "
                f"by a record type or producer version the corpus barely "
                f"covers")

    for name, col in known_cols.items():
        if len(col) != len(chunks):
            continue
        try:
            mine = [int.from_bytes(c[:min(8, len(c))], "little") for c in chunks]
        except ValueError:
            continue
        if len(set(mine)) < 3:
            continue
        deltas = {m - k for m, k in zip(mine, col)}
        if len(deltas) == 1:
            return ("derived value", 0.85,
                    f"always equals {name} + {deltas.pop()} -- not an "
                    f"independent field")
        ratios = {round(m / k, 6) for m, k in zip(mine, col) if k}
        if len(ratios) == 1 and ratios != {0.0}:
            return ("derived value", 0.8,
                    f"always {ratios.pop()}x {name} -- not an independent field")

    if ent > 7.0 and width >= 8:
        return ("live field (high entropy)", 0.7,
                f"entropy {ent:.2f} -- a hash, id, key, or compressed value; "
                f"resolve with crypto_scan.py before assuming it is a field")

    return ("live field", 0.75,
            f"{distinct_chunks} distinct value(s) across {len(chunks)} "
            f"record(s), entropy {ent:.2f} -- carries information")


PRIORITY = {
    "residual data (pointers)": 1,
    "residual data (stale buffer)": 1,
    "residual data (text)": 2,
    "live field": 2,
    "live field (high entropy)": 3,
    "conditional or version-scoped field": 3,
    "undocumented constant": 4,
    "derived value": 5,
    "genuine padding": 6,
    "empty": 7,
}

NEXT_STEP = {
    "residual data (pointers)":
        "Carve it. Uninitialised memory in a forensic artefact can contain "
        "pointers,\n      fragments of other records, or data from unrelated "
        "processes. Document it as\n      a leak, not a field.",
    "residual data (stale buffer)":
        "Extract and search the fragments -- they are remnants of earlier "
        "writes and may\n      recover deleted or overwritten content.",
    "residual data (text)":
        "Extract with strscan.py and check whether the strings correspond to "
        "records\n      that no longer exist in the allocated data.",
    "live field":
        "Run a controlled mutation targeting this offset (Phase 5), or find it "
        "in the\n      producer with constant_hunt.py. It is a real field "
        "nobody has named.",
    "live field (high entropy)":
        "Try cksum_id.py against it first -- an unexplained high-entropy field "
        "is more\n      often a checksum than anything else.",
    "conditional or version-scoped field":
        "Widen the corpus. corpus.py --cluster will show whether the samples "
        "that use it\n      form a distinct group, which usually means a "
        "producer version.",
    "undocumented constant":
        "Search the producer binary for the value with constant_hunt.py; a "
        "named constant\n      in code settles it immediately.",
    "derived value":
        "Record the relationship and move on. Nothing further to learn here.",
    "genuine padding":
        "Nothing to do, but say so explicitly in the spec -- 'zero across 52 "
        "samples' is\n      a finding, and different from 'not examined'.",
}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="sample file, or directory with --corpus")
    ap.add_argument("--corpus", action="store_true",
                    help="treat path as a directory of samples")
    ap.add_argument("--stride", type=int, required=True)
    ap.add_argument("--offset", type=int, default=0,
                    help="where the record array starts")
    ap.add_argument("--head", type=int,
                    help="only account for the first N bytes of each record")
    ap.add_argument("--field", action="append", default=[],
                    help="OFFSET:WIDTH[:NAME] of a KNOWN field (repeatable)")
    ap.add_argument("--layout",
                    help="JSON layout; accepts fieldmap.py --json output")
    ap.add_argument("--max-records", type=int, default=2000)
    ap.add_argument("--granularity", type=int, default=4, choices=[1, 2, 4, 8],
                    help="subdivide long unclaimed runs into windows this wide "
                         "before classifying; adjacent windows with the same "
                         "verdict are merged back")
    ap.add_argument("--min-run", type=int, default=1,
                    help="ignore unclaimed runs shorter than this")
    ap.add_argument("--map", action="store_true",
                    help="print a byte-level coverage map")
    ap.add_argument("--json")
    args = ap.parse_args()

    fields = [parse_field(f) for f in args.field]
    if args.layout:
        fields += load_layout(args.layout)
    if not fields:
        raise SystemExit(
            "no known fields given. This tool subtracts what you already know "
            "from the\nbytes -- with nothing declared, every byte is unclaimed "
            "and the output is just\nfieldmap.py with extra steps. Pass --field "
            "or --layout.")
    fields.sort()

    paths = []
    if args.corpus:
        for dirpath, _, files in os.walk(args.path):
            for f in sorted(files):
                paths.append(os.path.join(dirpath, f))
    else:
        paths = [args.path]
    if not paths:
        raise SystemExit("no samples found")

    stride = args.stride
    head = min(args.head or stride, stride)
    claimed = [False] * head
    overlaps = []
    for off, width, name in fields:
        for i in range(off, min(off + width, head)):
            if claimed[i]:
                overlaps.append((off, width, name))
                break
            claimed[i] = True

    runs = [r for r in unclaimed_runs(claimed, head) if r[1] >= args.min_run]
    known_bytes = sum(1 for c in claimed if c)

    print(f"records   {len(paths)} file(s), stride {stride}, "
          f"accounting for the first {head} byte(s)")
    print(f"known     {len(fields)} field(s) claiming {known_bytes}/{head} "
          f"bytes ({known_bytes/head:.0%})")
    print(f"unclaimed {head - known_bytes} byte(s) in {len(runs)} run(s)")
    if overlaps:
        print(f"\nWARNING: {len(overlaps)} declared field(s) overlap another. "
              f"Overlaps usually mean\na width is wrong or a union is being "
              f"read as a struct:")
        for off, width, name in overlaps[:6]:
            print(f"  +{off} u{width*8} {name}")

    if args.map:
        print("\ncoverage map  (# known, . unclaimed)")
        for row in range(0, head, 64):
            line = "".join("#" if claimed[i] else "."
                           for i in range(row, min(row + 64, head)))
            print(f"  +{row:<5} {line}")

    # Gather per-run chunks and known-field columns across the corpus.
    chunk_map = collections.defaultdict(list)
    known_cols = collections.defaultdict(list)
    whole_all = bytearray()
    nrec_total = 0
    for p in paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        whole_all += data[:1 << 22]
        avail = (len(data) - args.offset) // stride
        n = min(avail, args.max_records)
        nrec_total += n
        for k in range(n):
            base = args.offset + k * stride
            rec = data[base:base + head]
            if len(rec) < head:
                continue
            for (ro, rl) in runs:
                chunk_map[(ro, rl)].append(rec[ro:ro + rl])
            for off, width, name in fields:
                if width in FMT and off + width <= head:
                    known_cols[name].append(
                        struct.unpack_from(FMT[width], rec, off)[0])

    if not nrec_total:
        raise SystemExit("no whole records at that stride and offset")

    print(f"\nprofiled  {nrec_total} record(s)")
    print(f"granularity {args.granularity} byte(s) -- long runs are subdivided "
          f"and adjacent\n            windows sharing a classification are "
          f"merged back together\n")
    print(f"{'offset':>7} {'len':>4}  {'classification':<36} {'conf':>5}")
    print("-" * 100)

    g = args.granularity
    windows = []
    for (ro, rl) in runs:
        chunks = chunk_map[(ro, rl)]
        if rl <= g:
            spans = [(ro, rl)]
        else:
            # Cut on record-relative alignment so windows line up with plausible
            # field boundaries rather than with where the run happens to start.
            spans, pos = [], ro
            while pos < ro + rl:
                nxt = min(((pos // g) + 1) * g, ro + rl)
                if nxt == pos:
                    nxt = min(pos + g, ro + rl)
                spans.append((pos, nxt - pos))
                pos = nxt
        for (so, sl) in spans:
            sub = [c[so - ro:so - ro + sl] for c in chunks]
            label, conf, note = classify(sub, sl, bytes(whole_all),
                                         known_cols, nrec_total)
            windows.append({"offset": so, "length": sl, "classification": label,
                            "confidence": conf, "note": note})

    # Merge adjacent windows with the same classification.
    results = []
    for w in windows:
        if (results and results[-1]["classification"] == w["classification"]
                and results[-1]["offset"] + results[-1]["length"] == w["offset"]):
            prev = results[-1]
            prev["length"] += w["length"]
            prev["merged"] = prev.get("merged", 1) + 1
            if w["confidence"] > prev["confidence"]:
                prev["confidence"], prev["note"] = w["confidence"], w["note"]
        else:
            results.append(dict(w))
    for r in results:
        r["priority"] = PRIORITY.get(r["classification"], 9)

    results.sort(key=lambda r: (r["priority"], -r["confidence"], r["offset"]))
    for r in results:
        print(f"{r['offset']:>7} {r['length']:>4}  {r['classification']:<36} "
              f"{r['confidence']:>5.2f}")
        for line in wrap(r["note"], 92):
            print(f"        {line}")

    print("\nwhat to do next, highest value first")
    print("-" * 100)
    seen = set()
    for r in results:
        if r["classification"] in seen or r["classification"] in ("empty",):
            continue
        seen.add(r["classification"])
        offs = ", ".join(f"+{x['offset']}"
                         for x in results if x["classification"] == r["classification"])
        print(f"  {r['classification']}  ({offs})")
        print(f"      {NEXT_STEP.get(r['classification'], '')}")

    other = 8 if args.granularity == 4 else 4
    print(f"\nRun again with --granularity {other}. Granularity is a real "
          f"trade-off, not a\ntuning knob: 8 resolves wide structures -- "
          f"64-bit pointers, u64 fields, leaked\naddresses -- while 4 "
          f"separates narrow adjacent fields that 8 merges into one.\nA field "
          f"that appears at one setting and not the other is still a finding.")

    live = [r for r in results
            if r["classification"].startswith(("live", "residual",
                                               "conditional"))]
    if live:
        print(f"\n{len(live)} run(s) hold information the current layout does "
              f"not explain.\nEach is a candidate for the hypothesis ledger "
              f"with status `unknown` -- present,\npurpose undetermined -- "
              f"rather than being left out of the record entirely.")
    else:
        print("\nEvery unclaimed byte is padding, constant, or derived. The "
              "layout accounts for\nthe informative content of this corpus. "
              "Say that explicitly in the spec, with\nthe corpus size, because "
              "'zero across 52 samples' and 'not examined' read the\nsame in a "
              "document that omits both.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"stride": stride, "head": head, "records": nrec_total,
                       "known_fields": [{"offset": o, "width": w, "name": n}
                                        for o, w, n in fields],
                       "coverage": known_bytes / head,
                       "unclaimed": results}, fh, indent=2)
        print(f"\nwrote {args.json}")


def wrap(text, width):
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        out.append(line)
    return out


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
