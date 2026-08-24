#!/usr/bin/env python3
"""Differential baselining: diff two snapshots and subtract the churn.

This is the only technique in the kit that produces *proof* rather than
inference. Take a snapshot, make exactly one known change, snapshot again,
and the bytes that moved are the bytes that encode that change.

The catch is background churn -- caches, sequence numbers, and free-space
maps move on their own. So take a control pair too (two snapshots with no
change between them) and pass it as --noise. Offsets that move in the control
pair are subtracted from the result, leaving only the signal.

Usage:
  bindiff.py BEFORE AFTER [--stride 8192] [--noise CTRL_A CTRL_B]
  bindiff.py BEFORE AFTER --stride 8192 --context 8 --max-runs 40
"""
import argparse
import struct


def load(path, cap):
    with open(path, "rb") as fh:
        return fh.read(cap)


def changed_offsets(a, b):
    n = min(len(a), len(b))
    return {i for i in range(n) if a[i] != b[i]}


def runs_from(offsets, gap=4):
    """Group scattered changed offsets into contiguous-ish runs."""
    if not offsets:
        return []
    xs = sorted(offsets)
    runs = []
    start = prev = xs[0]
    for x in xs[1:]:
        if x - prev <= gap:
            prev = x
        else:
            runs.append((start, prev - start + 1))
            start = prev = x
    runs.append((start, prev - start + 1))
    return runs


def decode(buf, off, length):
    """Show a changed run under several plausible interpretations."""
    out = []
    chunk = buf[off:off + length]
    out.append("hex=" + " ".join(f"{c:02x}" for c in chunk[:16]) +
               ("..." if length > 16 else ""))
    for width, fmt, name in ((2, "<H", "u16le"), (4, "<I", "u32le"),
                             (8, "<Q", "u64le")):
        if length >= width and off + width <= len(buf):
            (v,) = struct.unpack_from(fmt, buf, off)
            out.append(f"{name}={v}")
    txt = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk[:24])
    if sum(1 for c in chunk[:24] if 0x20 <= c < 0x7f) > len(chunk[:24]) * 0.6:
        out.append(f"ascii={txt!r}")
    return "  ".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--noise", nargs=2, metavar=("CTRL_A", "CTRL_B"),
                    help="control pair with no intended change; its deltas are "
                         "treated as background churn and subtracted")
    ap.add_argument("--stride", type=int,
                    help="page/record size, for block-level summarisation")
    ap.add_argument("--gap", type=int, default=4,
                    help="max gap between changed bytes still counted as one run")
    ap.add_argument("--max-runs", type=int, default=40)
    ap.add_argument("--context", type=int, default=0,
                    help="extra bytes shown around each run")
    ap.add_argument("--max-bytes", type=int, default=256 << 20)
    args = ap.parse_args()

    a = load(args.before, args.max_bytes)
    b = load(args.after, args.max_bytes)

    print(f"before  {args.before}  {len(a)} bytes")
    print(f"after   {args.after}  {len(b)} bytes")
    if len(a) != len(b):
        print(f"size delta  {len(b)-len(a):+d} bytes "
              f"({'grew' if len(b) > len(a) else 'shrank'}) -- the format "
              f"appends or reallocates; compare the common prefix only")

    sig = changed_offsets(a, b)
    print(f"\nraw changed bytes  {len(sig)} of {min(len(a), len(b))} "
          f"({100*len(sig)/max(1,min(len(a),len(b))):.4f}%)")

    if args.noise:
        na = load(args.noise[0], args.max_bytes)
        nb = load(args.noise[1], args.max_bytes)
        noise = changed_offsets(na, nb)
        print(f"control churn      {len(noise)} bytes move with no input change")
        before_n = len(sig)
        sig = sig - noise
        print(f"signal after subtraction  {len(sig)} bytes "
              f"({before_n - len(sig)} suppressed as churn)")
        if not sig:
            print("\nNothing survives noise subtraction. Either the mutation "
                  "did not reach this file, or it landed inside a region that "
                  "churns anyway -- repeat with a larger or more distinctive "
                  "mutation (e.g. a long unique marker string).")
            return

    if args.stride:
        blocks = {}
        for o in sig:
            blocks.setdefault(o // args.stride, 0)
            blocks[o // args.stride] += 1
        print(f"\nblocks touched (stride {args.stride})  {len(blocks)} block(s)")
        for blk in sorted(blocks)[:20]:
            print(f"  block {blk:<8} offset 0x{blk*args.stride:08x}  "
                  f"{blocks[blk]} byte(s) changed")
        mods = {}
        for o in sig:
            mods[o % args.stride] = mods.get(o % args.stride, 0) + 1
        hot = sorted(mods.items(), key=lambda kv: -kv[1])[:8]
        print("  positions within block: " +
              ", ".join(f"+{m}({c})" for m, c in hot))
        if hot and hot[0][1] >= 3:
            print("  a repeated intra-block position means the mutation touched "
                  "the same field in several blocks -- that field is your target")

    rs = runs_from(sig, args.gap)
    print(f"\n{len(rs)} changed run(s); showing up to {args.max_runs}")
    print("-" * 100)
    for off, length in rs[:args.max_runs]:
        lo = max(0, off - args.context)
        ln = length + args.context * 2
        loc = f"0x{off:08x}"
        if args.stride:
            loc += f"  (blk {off//args.stride} +{off%args.stride})"
        print(f"{loc}  len={length}")
        print(f"  before  {decode(a, lo, ln)}")
        print(f"  after   {decode(b, lo, ln)}")

    if len(rs) > args.max_runs:
        print(f"\n... {len(rs)-args.max_runs} more runs suppressed "
              f"(raise --max-runs)")

    print("\nNext: for each run, decide whether it is your mutation, a "
          "derived value (length, count, checksum), or an index update. "
          "A run that changes by exactly +1 across trials is a counter; a run "
          "that changes unpredictably but always alongside a payload edit is a "
          "checksum -- feed it to cksum_id.py.")



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
