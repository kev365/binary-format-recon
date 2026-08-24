#!/usr/bin/env python3
"""Sweep a binary for every common timestamp encoding.

Timestamps are the best structural anchors in an unknown format: they are
dense, self-validating (a plausibility window rejects almost all noise), and
they usually sit inside the record header you are trying to map.

The high-value output is not the hit list -- it is the offset-modulo-stride
histogram. If FILETIME candidates cluster at offset 24 of every 8192-byte
page, you have found a field, not a coincidence.

Usage:
  tsscan.py FILE [--stride 8192] [--align 4] [--from 2000] [--to 2030]
"""
import argparse
import collections
import datetime as dt
import re
import struct
import sys

UTC = dt.timezone.utc
EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=UTC)
EPOCH_1904 = dt.datetime(1904, 1, 1, tzinfo=UTC)
EPOCH_1970 = dt.datetime(1970, 1, 1, tzinfo=UTC)
EPOCH_2001 = dt.datetime(2001, 1, 1, tzinfo=UTC)
EPOCH_OLE = dt.datetime(1899, 12, 30, tzinfo=UTC)


def d_filetime(v):
    return EPOCH_1601 + dt.timedelta(microseconds=v / 10)


def d_webkit(v):
    return EPOCH_1601 + dt.timedelta(microseconds=v)


def d_unix_s(v):
    return EPOCH_1970 + dt.timedelta(seconds=v)


def d_unix_ms(v):
    return EPOCH_1970 + dt.timedelta(milliseconds=v)


def d_hfs(v):
    return EPOCH_1904 + dt.timedelta(seconds=v)


def d_cocoa(v):
    return EPOCH_2001 + dt.timedelta(seconds=v)


def d_ole(v):
    return EPOCH_OLE + dt.timedelta(days=v)


def d_dos(v):
    """FAT/DOS: low u16 = time, high u16 = date."""
    t, d = v & 0xFFFF, (v >> 16) & 0xFFFF
    year = 1980 + ((d >> 9) & 0x7F)
    month = (d >> 5) & 0x0F
    day = d & 0x1F
    hour = (t >> 11) & 0x1F
    minute = (t >> 5) & 0x3F
    sec = (t & 0x1F) * 2
    return dt.datetime(year, month, day, hour, minute, min(sec, 59), tzinfo=UTC)


def _raw(dtv, epoch, unit):
    return (dtv - epoch).total_seconds() * unit


# name -> (fmt, decoder, raw-bounds fn, value-space size, note)
def _sp(bits):
    return float(1 << bits)


CODECS = [
    ("filetime_le", "<Q", d_filetime, (EPOCH_1601, 1e7, _sp(64)),
     "Windows FILETIME, 100ns since 1601"),
    ("filetime_be", ">Q", d_filetime, (EPOCH_1601, 1e7, _sp(64)),
     "FILETIME, big-endian"),
    ("webkit_le", "<Q", d_webkit, (EPOCH_1601, 1e6, _sp(64)),
     "Chrome/WebKit, microseconds since 1601"),
    ("unix64ms_le", "<Q", d_unix_ms, (EPOCH_1970, 1e3, _sp(64)),
     "Java/JS epoch milliseconds"),
    ("unix64_le", "<Q", d_unix_s, (EPOCH_1970, 1.0, _sp(64)),
     "64-bit epoch seconds"),
    ("unix32_le", "<I", d_unix_s, (EPOCH_1970, 1.0, _sp(32)),
     "32-bit epoch seconds"),
    ("unix32_be", ">I", d_unix_s, (EPOCH_1970, 1.0, _sp(32)),
     "32-bit epoch seconds, big-endian"),
    ("hfs32_le", "<I", d_hfs, (EPOCH_1904, 1.0, _sp(32)),
     "HFS+/Mac, seconds since 1904"),
    ("cocoa32_le", "<I", d_cocoa, (EPOCH_2001, 1.0, _sp(32)),
     "Cocoa/Apple, seconds since 2001"),
    ("dosdate_le", "<I", d_dos, None, "FAT/DOS packed date+time"),
    ("oledate_f64", "<d", d_ole, None,
     "OLE automation date, days since 1899-12-30"),
    ("cocoa_f64", "<d", d_cocoa, None, "Cocoa absolute time, float seconds"),
]

# Textual timestamps. CIM_DATETIME is the WMI/DMTF form.
TEXT_PATTERNS = [
    ("cim_datetime",
     re.compile(rb"[12]\d{3}[01]\d[0-3]\d[0-2]\d[0-5]\d[0-6]\d\.\d{6}[+\-*]\d{3}")),
    ("iso8601",
     re.compile(rb"[12]\d{3}-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d:[0-6]\d")),
    ("compact14", re.compile(rb"(?<![0-9])[12]\d{3}[01]\d[0-3]\d[0-2]\d[0-5]\d[0-6]\d(?![0-9])")),
]


def chance_rate(bounds, lo_dt, hi_dt):
    """Fraction of the raw value space that lands in the window.

    A 32-bit epoch field has ~29% of its space inside a 40-year
    window, so a third of all random dwords "look like" timestamps.
    A 64-bit FILETIME has ~0.07%. Lift over this baseline is what
    separates a real field from arithmetic coincidence.
    """
    if bounds is None:
        return None
    epoch, unit, space = bounds
    lo = _raw(lo_dt, epoch, unit)
    hi = _raw(hi_dt, epoch, unit)
    lo = max(lo, 0.0)
    return max(0.0, (hi - lo)) / space


def sweep_numeric(data, name, fmt, decode, lo_dt, hi_dt, align, limit):
    size = struct.calcsize(fmt)
    hits = []
    unpack = struct.Struct(fmt).unpack_from
    end = len(data) - size
    for off in range(0, end + 1, align):
        try:
            (v,) = unpack(data, off)
        except struct.error:
            break
        if v == 0 or v != v:      # zeros and NaN decode to the epoch itself
            continue
        if isinstance(v, float) and abs(v) < 1000:
            continue              # denormals from non-float data decode to ~epoch
        try:
            when = decode(v)
        except (OverflowError, ValueError, OSError):
            continue
        if lo_dt <= when <= hi_dt:
            hits.append((off, v, when))
            if len(hits) >= limit:
                break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--stride", type=int,
                    help="record/page size; enables offset%%stride clustering")
    ap.add_argument("--align", type=int, default=4,
                    help="scan alignment in bytes (1 = exhaustive, slower)")
    ap.add_argument("--from", dest="lo", type=int, default=1995,
                    help="earliest plausible year")
    ap.add_argument("--to", dest="hi", type=int, default=2035,
                    help="latest plausible year")
    ap.add_argument("--max-bytes", type=int, default=32 << 20,
                    help="cap on bytes scanned (numeric sweep is O(n) per codec)")
    ap.add_argument("--limit", type=int, default=200000,
                    help="max hits recorded per codec")
    ap.add_argument("--show", type=int, default=5, help="sample hits printed")
    ap.add_argument("--only", help="comma-separated codec names to test")
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read(args.max_bytes)
    truncated = len(data) == args.max_bytes

    lo_dt = dt.datetime(args.lo, 1, 1, tzinfo=UTC)
    hi_dt = dt.datetime(args.hi, 1, 1, tzinfo=UTC)
    wanted = set(args.only.split(",")) if args.only else None

    print(f"file    {args.file}  ({len(data)} bytes scanned"
          f"{', TRUNCATED' if truncated else ''})")
    print(f"window  {lo_dt.date()} .. {hi_dt.date()}   align={args.align}"
          f"{'  stride=' + str(args.stride) if args.stride else ''}")
    print(f"\n{'codec':<14} {'hits':>7} {'density':>9} {'chance':>8} {'lift':>7}  samples")
    print("-" * 110)

    results = {}
    lifts = {}
    for name, fmt, dec, bounds, note in CODECS:
        if wanted and name not in wanted:
            continue
        hits = sweep_numeric(data, name, fmt, dec, lo_dt, hi_dt,
                             args.align, args.limit)
        results[name] = hits
        if not hits:
            continue
        density = len(hits) / (len(data) / args.align)
        ch = chance_rate(bounds, lo_dt, hi_dt)
        if ch and ch > 0:
            lift = density / ch
            lifts[name] = lift
            cs, ls = f"{ch:.2%}", f"{lift:>6.1f}x"
        else:
            cs, ls = "n/a", "n/a"
        samples = "; ".join(f"@0x{o:x}={w:%Y-%m-%d %H:%M:%S}"
                            for o, _, w in hits[:args.show])
        print(f"{name:<14} {len(hits):>7} {density:>8.3%} {cs:>8} {ls:>7}  {samples}")

    print("\n'chance' is the share of the raw value space inside your window: a "
          "32-bit\nepoch field matches random data ~29% of the time, so its hits "
          "mean little\nunless lift is well above 1. A 64-bit FILETIME has almost "
          "no false positives.")

    for name, pat in TEXT_PATTERNS:
        if wanted and name not in wanted:
            continue
        hits = [(m.start(), m.group(0), None) for m in pat.finditer(data)]
        results[name] = hits
        if hits:
            samples = "; ".join(f"@0x{o:x}={v.decode('ascii','replace')}"
                                for o, v, _ in hits[:args.show])
            print(f"{name:<14} {len(hits):>8}  {'text':>9}  {samples}")
        # UTF-16LE variant of the same pattern
        wide = pat.pattern.replace(b"[", b"(?:\\x00)?[")
        try:
            hits16 = [(m.start(), m.group(0), None)
                      for m in re.finditer(wide, data)]
        except re.error:
            hits16 = []
        if hits16 and len(hits16) > len(hits):
            print(f"{name + '_utf16':<14} {len(hits16):>8}  {'text':>9}  "
                  f"(possible wide-char encoding)")

    if not any(results.values()):
        print("(no plausible timestamps -- widen --from/--to, try --align 1, "
              "or the values may be relative/delta-encoded rather than absolute)")

    if args.stride:
        positions = max(1, args.stride // args.align)
        print(f"\noffset % {args.stride} clustering")
        print(f"  {positions} possible aligned positions per block, so a codec "
              f"with n hits\n  expects n/{positions} at any one position by "
              f"chance. Concentration far above\n  that is a struct field. This "
              f"is the strongest signal in the tool.")
        print("-" * 100)
        ranked = sorted(results.items(),
                        key=lambda kv: -lifts.get(kv[0], 0))
        for name, hits in ranked:
            if len(hits) < 4:
                continue
            mod = collections.Counter(o % args.stride for o, _, _ in hits)
            top = mod.most_common(5)
            expected = len(hits) / positions
            ratio = top[0][1] / expected if expected else 0
            lift = lifts.get(name)
            flag = ""
            if top[0][1] >= 4 and ratio >= 5 and (lift is None or lift >= 1.0):
                flag = f"  <== FIELD at +{top[0][0]} ({ratio:.0f}x expected)"
            elif lift is not None and lift < 1.0:
                flag = (f"  (lift {lift:.1f}x -- probably other field "
                        f"types misread as dates)")
            pos = ", ".join(f"+{m}({c})" for m, c in top)
            print(f"{name:<14} n={len(hits):<7} {pos}{flag}")
        print("\nA flagged field is a strong hypothesis, not a finding. Confirm "
              "it by changing\na single known input and re-running bindiff.py "
              "before recording it as established.")



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
