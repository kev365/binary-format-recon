#!/usr/bin/env python3
"""Structural triage of an unknown binary: entropy, signatures, and stride.

Answers the three questions that gate everything else:
  1. Is this data compressed/encrypted, or is there structure to find?
  2. Is it a known container in disguise?
  3. Is it an array of fixed-size records or pages -- and how big are they?

Stride detection is the payoff. Most forensic artefacts are paged or
record-oriented; recovering the stride turns a flat byte soup into a table
you can profile column by column with fieldmap.py.

Usage:
  profile.py FILE [--window 4096] [--probe 64] [--json out.json]
"""
import argparse
import collections
import hashlib
import json
import math
import sys

# (signature, label). Kept deliberately DFIR-weighted.
MAGICS = [
    (b"PK\x03\x04", "ZIP / OOXML / JAR"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "DOS/PE executable"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE CFBF (doc/msi/jumplist)"),
    (b"SQLite format 3\x00", "SQLite 3"),
    (b"regf", "Windows registry hive"),
    (b"ElfFile\x00", "Windows EVTX"),
    (b"ElfChnk\x00", "EVTX chunk"),
    (b"\x0cLfLe", "Windows EVT (legacy)"),
    (b"\xef\xcd\xab\x89", "ESE/JET database (EDB)"),
    (b"FILE0", "NTFS $MFT record"),
    (b"INDX", "NTFS index record"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows LNK"),
    (b"SCCA", "Windows Prefetch (uncompressed)"),
    (b"MAM\x04", "Windows Prefetch (MAM compressed)"),
    (b"RIFF", "RIFF container"),
    (b"CD001", "ISO9660"),
    (b"\xcd\xab", "possible 0xABCD LE marker (WMI MAPPING start)"),
    (b"\xba\xdc", "possible 0xDCBA LE marker (WMI MAPPING end)"),
    (b"\xcc\xac", "possible 0xACCC LE marker (WMI index active page)"),
]

ZLIB_HEADS = {b"\x78\x01": "zlib (no/low compression)",
              b"\x78\x9c": "zlib (default)",
              b"\x78\xda": "zlib (best)"}

COMMON_STRIDES = [16, 32, 48, 64, 128, 256, 512, 1024, 2048, 4096,
                  8192, 16384, 32768, 65536]


def shannon(counts, total):
    if not total:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def windowed_entropy(data, window):
    out = []
    for off in range(0, len(data), window):
        chunk = data[off:off + window]
        if len(chunk) < 16:
            break
        counts = collections.Counter(chunk)
        out.append((off, shannon(counts.values(), len(chunk))))
    return out


def scan_magics(data, limit=64):
    hits = []
    for sig, label in MAGICS:
        start = 0
        found = 0
        while found < limit:
            i = data.find(sig, start)
            if i < 0:
                break
            hits.append((i, label, sig.hex()))
            start = i + 1
            found += 1
    for sig, label in ZLIB_HEADS.items():
        i = data.find(sig)
        if i >= 0:
            hits.append((i, label, sig.hex()))
    hits.sort()
    return hits


def signature_strides(by_label, min_hits=3):
    """Strides corroborated by a known container signature repeating on a
    fixed step, as {stride: {label, count, start}}.

    This is the strongest stride evidence the tool has. A recognised magic
    recurring at an exact interval *is* a record boundary; a stride inferred
    from token-gap votes is only the modal spacing of repeated bytes, which
    in a record-oriented format is usually the size of some common *inner*
    record, not the container. When the two disagree, the signature wins.
    """
    out = {}
    for label, offs in by_label.items():
        if len(offs) < min_hits:
            continue
        step = collections.Counter(b - a for a, b in zip(offs, offs[1:]))
        mg, mc = step.most_common(1)[0]
        if mg >= 8 and mc >= len(offs) // 2:
            prev = out.get(mg)
            if prev is None or mc > prev["count"]:
                out[mg] = {"label": label, "count": mc + 1, "start": offs[0]}
    return out


def gap_strides(data, token=4, sample=1 << 20, max_keys=400000):
    """Modal distance between repeated tokens -> candidate record stride.

    Page headers and record magics repeat at boundaries, so the spacing
    between identical tokens clusters hard on the true stride. Only the last
    sighting of each token is kept, which bounds memory on high-entropy input.
    """
    buf = data[:sample]
    last = {}
    gaps = collections.Counter()
    for i in range(len(buf) - token):
        tok = buf[i:i + token]
        if tok[0] == tok[1] == tok[2] == tok[3]:
            continue                      # constant runs carry no positional info
        prev = last.get(tok)
        if prev is not None:
            d = i - prev
            if 8 <= d <= (1 << 20):
                gaps[d] += 1
            last[tok] = i
        elif len(last) < max_keys:
            last[tok] = i
    return gaps


def stride_stats(data, stride, modal, probe=128, max_blocks=512,
                 start=0):
    """Score a candidate stride by anchor columns and non-trivial agreement.

    An *anchor column* is an intra-block position holding the same non-modal
    byte in every block -- a magic, a version, or a fixed type tag. Anchors are
    what distinguish a real stride from an accidental one: in a sparse file any
    stride makes zero-filled regions line up, but only the true stride makes
    the non-zero header bytes line up.
    """
    nb = (len(data) - start) // stride
    if nb < 4:
        return None
    nb = min(nb, max_blocks)
    probe = min(probe, stride)
    # A record array does not always begin at offset 0 -- EVTX chunks follow a
    # 4096-byte file header, for instance -- so score at the array's own phase.
    bases = [start + k * stride for k in range(nb)]
    # Blocks that are entirely modal across the probe window are unwritten
    # slack, not records. They are not evidence against a stride, and letting
    # them vote destroys every anchor column in any file allocated larger than
    # it is filled (a log with spare chunks, a preallocated database).
    live = [b for b in bases
            if any(data[b + j] != modal for j in range(probe))]
    if len(live) >= 4:
        bases = live
    anchors = informative = 0
    agree = denom = 0
    for j in range(probe):
        col = [data[b + j] for b in bases]
        uniq = set(col)
        all_modal = (len(uniq) == 1 and col[0] == modal)
        if not all_modal:
            informative += 1
            if len(uniq) == 1:
                anchors += 1
        for a, b in zip(col, col[1:]):
            if a != modal or b != modal:
                denom += 1
                if a == b:
                    agree += 1
    return {"anchor_cols": anchors,
            "anchor_score": anchors / probe,
            "start": start,
            "blocks_scored": len(bases),
            "informative_cols": informative,
            "nonmodal_agreement": (agree / denom) if denom else 0.0,
            "compared": denom}


def tail_padding_score(data, stride, tail=16):
    """Fraction of blocks whose final bytes are zero -- slack space."""
    nblocks = len(data) // stride
    if nblocks < 3:
        return None
    z = 0
    for k in range(min(nblocks, 4096)):
        end = (k + 1) * stride
        if data[end - tail:end] == b"\x00" * tail:
            z += 1
    return z / min(nblocks, 4096)


def long_runs(data, minlen=64):
    runs = []
    for val in (0x00, 0xFF):
        start = None
        for i, b in enumerate(data):
            if b == val:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= minlen:
                    runs.append((start, i - start, val))
                start = None
        if start is not None and len(data) - start >= minlen:
            runs.append((start, len(data) - start, val))
    runs.sort(key=lambda r: -r[1])
    return runs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--window", type=int, default=4096)
    ap.add_argument("--probe", type=int, default=64,
                    help="header bytes compared per block in stride scoring")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--json", help="write full results as JSON")
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read()
    n = len(data)
    if n == 0:
        print("empty file")
        return

    counts = collections.Counter(data)
    ent = shannon(counts.values(), n)
    we = windowed_entropy(data, args.window)
    ent_vals = [e for _, e in we] or [ent]

    print(f"file        {args.file}")
    print(f"size        {n} bytes ({n/1024:.1f} KiB)")
    print(f"sha256      {hashlib.sha256(data).hexdigest()}")
    print(f"entropy     {ent:.4f} bits/byte (global)")
    print(f"            window={args.window} min={min(ent_vals):.3f} "
          f"max={max(ent_vals):.3f} mean={sum(ent_vals)/len(ent_vals):.3f}")
    verdict = ("high -- compressed or encrypted; look for a container header "
               "before assuming a parseable struct" if ent > 7.5 else
               "moderate -- mixed binary, structure likely present" if ent > 5.5
               else "low -- sparse/padded/text-heavy, very parseable")
    print(f"            verdict: {verdict}")

    distinct = len(counts)
    top = counts.most_common(6)
    print(f"\nbyte histogram  {distinct}/256 values present")
    print("  most common: " + ", ".join(
        f"0x{v:02x}={c} ({100*c/n:.1f}%)" for v, c in top))
    printable = sum(c for v, c in counts.items() if 0x20 <= v < 0x7f or v in (9, 10, 13))
    print(f"  printable ASCII: {100*printable/n:.1f}%")
    nul16 = sum(1 for i in range(1, min(n, 1 << 20), 2) if data[i] == 0)
    print(f"  odd-offset NULs in first 1MiB: {100*nul16/max(1,min(n,1<<20)//2):.1f}%"
          "  (high => UTF-16LE text regions)")

    hits = scan_magics(data)
    by_label = collections.OrderedDict()
    for off, label, sig in hits:
        by_label.setdefault(label, []).append(off)
    print(f"\nsignature scan  {len(hits)} hit(s), {len(by_label)} distinct signature(s)")
    sig_strides = signature_strides(by_label)
    label_step = {v["label"]: k for k, v in sig_strides.items()}
    for label, offs in by_label.items():
        head = ", ".join(f"0x{o:x}" for o in offs[:4])
        extra = ""
        if label in label_step:
            extra = (f"  [repeats every {label_step[label]} bytes -- "
                     f"strong stride evidence]")
        print(f"  {label}")
        print(f"    {len(offs)}x at {head}{'...' if len(offs) > 4 else ''}{extra}")
    if not hits:
        print("  none -- no known container; proceed to stride analysis")

    modal = counts.most_common(1)[0][0]
    gaps = gap_strides(data)
    cands = {s for s, _ in gaps.most_common(24)}
    cands |= set(COMMON_STRIDES)
    cands |= set(sig_strides)
    for s, _ in gaps.most_common(8):
        for d in (2, 3, 4, 8, 16):
            if s % d == 0 and s // d >= 16:
                cands.add(s // d)
    scored = []
    for s in sorted(cands):
        if s < 8 or s > n // 4:
            continue
        phase = sig_strides[s]["start"] % s if s in sig_strides else 0
        st = stride_stats(data, s, modal, args.probe, start=phase)
        if st is None:
            continue
        pad = tail_padding_score(data, s)
        st.update({"stride": s, "gap_votes": gaps.get(s, 0),
                   "signature": (sig_strides[s]["label"]
                                 if s in sig_strides else None),
                   "tail_zero_frac": round(pad, 4) if pad is not None else None,
                   "blocks": n // s, "exact_multiple": n % s == 0})
        scored.append(st)
    scored.sort(key=lambda r: (-r["anchor_score"], -r["nonmodal_agreement"],
                               -r["gap_votes"], r["stride"]))

    print(f"\nstride candidates  (modal byte 0x{modal:02x} excluded from scoring)")
    print(f"  {'stride':>8} {'anchors':>8} {'agree':>7} {'gapvotes':>9} "
          f"{'tailzero':>9} {'blocks':>8}  exact  signature")
    for r in scored[:args.top]:
        tz = "-" if r["tail_zero_frac"] is None else f"{r['tail_zero_frac']:.3f}"
        print(f"  {r['stride']:>8} {r['anchor_cols']:>8} "
              f"{r['nonmodal_agreement']:>7.3f} {r['gap_votes']:>9} {tz:>9} "
              f"{r['blocks']:>8}  {'yes' if r['exact_multiple'] else 'no':<5}"
              f"  {r['signature'] or '-'}")

    smap = {r["stride"]: r for r in scored}
    best = scored[0] if scored else None
    sig_cands = [r for r in scored if r["signature"]]
    sig_pick = (max(sig_cands, key=lambda r: sig_strides[r["stride"]]["count"])
                if sig_cands else None)
    if sig_pick:
        s_ = sig_pick["stride"]
        phase = sig_pick["start"]
        print("")
        print(f"  => stride {s_}: {sig_strides[s_]['count']}x "
              f"{sig_pick['signature']} signature on an exact {s_}-byte step"
              + (f", record array starts at 0x{phase:x}" if phase else "")
              + f" ({sig_pick['anchor_cols']} anchor column(s) across "
              f"{sig_pick['blocks_scored']} written block(s))")
        if best is not sig_pick:
            b_ = best["stride"]
            if b_ % s_ == 0:
                why = (f"{b_} is {b_ // s_}x the signature step, and every "
                       f"multiple of a true stride lines up just as well")
            elif b_ < s_:
                why = (f"{b_} is unbacked by any signature and smaller -- "
                       f"typically the modal size of a record *inside* the "
                       f"container, not the container")
            else:
                why = f"{b_} is unbacked by any signature"
            print(f"     note: scoring ranked {b_} higher, but {why}. Worth "
                  f"checking once the {s_} layout is mapped, not before.")
        off = f" --offset {phase}" if phase else ""
        print(f"     fieldmap.py {args.file} --stride {s_}{off} --dump 2")
        print(f"     tsscan.py  {args.file} --stride {s_}")
    elif best and best["anchor_cols"] >= 2:
        # Every multiple of a true stride also scores well, and short block
        # counts inflate anchors by chance -- so walk down to the smallest
        # divisor that still holds up. That divisor is the record size.
        pick = best
        for d in sorted(x for x in smap if x < best["stride"]
                        and best["stride"] % x == 0):
            r = smap[d]
            if (r["anchor_cols"] >= max(2, best["anchor_cols"] * 0.5)
                    and r["nonmodal_agreement"] >= best["nonmodal_agreement"] * 0.7):
                pick = r
                break
        note = "" if pick is best else f" (reduced from {best['stride']})"
        print(f"\n  => stride {pick['stride']}{note}: {pick['anchor_cols']} "
              f"anchor column(s) constant across {pick['blocks']} blocks, "
              f"{pick['gap_votes']} token-gap votes")
        print(f"     fieldmap.py {args.file} --stride {pick['stride']} --dump 2")
        print(f"     tsscan.py  {args.file} --stride {pick['stride']}")
    elif best and best["nonmodal_agreement"] > 0.5 and best["gap_votes"] > 8:
        print(f"\n  => weak but plausible stride {best['stride']} (no constant "
              f"magic, but repeated tokens space out at this interval)")
    else:
        print("\n  => no convincing fixed stride. The file is probably "
              "variable-length records. Use strscan.py to find string anchors "
              "and check for a length prefix, then walk record to record.")

    runs = long_runs(data)
    if runs:
        print(f"\nlongest constant runs (padding/slack candidates)")
        for off, ln, val in runs[:5]:
            print(f"  0x{off:08x}  {ln} bytes of 0x{val:02x}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"file": args.file, "size": n,
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "entropy": ent,
                       "windowed_entropy": we,
                       "magics": [{"offset": o, "label": l} for o, l, _ in hits],
                       "strides": scored}, fh, indent=2)
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
