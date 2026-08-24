#!/usr/bin/env python3
"""Extract strings and infer how the format stores them.

Finding strings is trivial; the useful part is deciding whether they are
length-prefixed or NUL-terminated, and which width the prefix is. That single
fact usually unlocks the whole record layout, because the same convention is
reused for every variable-length member.

Usage:
  strscan.py FILE [--min 5] [--stride 8192] [--encoding all|ascii|utf16]
"""
import argparse
import collections
import re
import struct

ASCII_RE = rb"[\x20-\x7e\t]{%d,}"
UTF16_RE = rb"(?:[\x20-\x7e][\x00]){%d,}"


def find_ascii(data, minlen):
    out = []
    for m in re.finditer(ASCII_RE % minlen, data):
        out.append((m.start(), len(m.group(0)), "ascii",
                    m.group(0).decode("ascii", "replace")))
    return out


def find_utf16le(data, minlen):
    out = []
    for m in re.finditer(UTF16_RE % minlen, data):
        raw = m.group(0)
        out.append((m.start(), len(raw), "utf-16le",
                    raw.decode("utf-16-le", "replace")))
    return out


def find_utf8(data, minlen):
    """Multi-byte UTF-8 runs only -- ASCII is covered separately."""
    out = []
    pat = re.compile(rb"(?:[\xc2-\xdf][\x80-\xbf]|"
                     rb"\xe0[\xa0-\xbf][\x80-\xbf]|"
                     rb"[\xe1-\xef][\x80-\xbf]{2}|"
                     rb"\xf0[\x90-\xbf][\x80-\xbf]{2}|"
                     rb"[\xf1-\xf4][\x80-\xbf]{3}|[\x20-\x7e]){%d,}" % minlen)
    for m in pat.finditer(data):
        raw = m.group(0)
        if all(b < 0x80 for b in raw):
            continue
        out.append((m.start(), len(raw), "utf-8", raw.decode("utf-8", "replace")))
    return out


def prefix_evidence(data, strings):
    """Does an integer immediately before each string equal its length?

    Tests char-count and byte-count interpretations for u8/u16/u32, LE and BE.
    Whichever convention wins by a wide margin is the format's convention.
    """
    tests = {
        "u8": (1, "<B"), "u16le": (2, "<H"), "u16be": (2, ">H"),
        "u32le": (4, "<I"), "u32be": (4, ">I"),
    }
    votes = collections.Counter()
    tried = collections.Counter()
    for off, blen, enc, text in strings:
        chars = len(text)
        for name, (width, fmt) in tests.items():
            if off - width < 0:
                continue
            tried[name] += 1
            (v,) = struct.unpack_from(fmt, data, off - width)
            if v == blen:
                votes[name + ":bytes"] += 1
            if v == chars and chars != blen:
                votes[name + ":chars"] += 1
            if v == chars + 1 or v == blen + 1:
                votes[name + ":len+1"] += 1
    return votes, tried


def terminator_evidence(data, strings):
    nul1 = nul2 = neither = 0
    for off, blen, enc, _ in strings:
        end = off + blen
        if enc == "utf-16le":
            if data[end:end + 2] == b"\x00\x00":
                nul2 += 1
            else:
                neither += 1
        else:
            if data[end:end + 1] == b"\x00":
                nul1 += 1
            else:
                neither += 1
    return nul1, nul2, neither


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--min", type=int, default=5, help="minimum string length")
    ap.add_argument("--stride", type=int, help="report offset%%stride clustering")
    ap.add_argument("--encoding", default="all",
                    choices=["all", "ascii", "utf16", "utf8"])
    ap.add_argument("--show", type=int, default=25)
    ap.add_argument("--grep", help="only report strings matching this regex")
    ap.add_argument("--max-bytes", type=int, default=64 << 20)
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read(args.max_bytes)

    strings = []
    if args.encoding in ("all", "utf16"):
        strings += find_utf16le(data, args.min)
    if args.encoding in ("all", "ascii"):
        u16_spans = [(o, o + l) for o, l, e, _ in strings]
        for s in find_ascii(data, args.min):
            # a UTF-16LE run also matches ASCII on its even bytes; skip overlaps
            if any(a <= s[0] < b for a, b in u16_spans):
                continue
            strings.append(s)
    if args.encoding in ("all", "utf8"):
        strings += find_utf8(data, args.min)
    strings.sort()

    if args.grep:
        rx = re.compile(args.grep, re.I)
        strings = [s for s in strings if rx.search(s[3])]

    by_enc = collections.Counter(s[2] for s in strings)
    print(f"file      {args.file}  ({len(data)} bytes)")
    print(f"strings   {len(strings)} total  " +
          ", ".join(f"{k}={v}" for k, v in by_enc.most_common()))
    if by_enc.get("utf-16le") and by_enc.get("ascii"):
        print("          mixed encodings -- common in Windows formats where "
              "identifiers are UTF-16LE but internal keys are ASCII")

    if strings:
        votes, tried = prefix_evidence(data, strings)
        print(f"\nlength-prefix test  ({sum(tried.values())//max(1,len(tried))} "
              f"strings tested per width)")
        if votes:
            total = len(strings)
            for k, v in votes.most_common(6):
                bar = "#" * int(30 * v / total)
                print(f"  {k:<14} {v:>6}/{total} ({v/total:>6.1%}) {bar}")
            best, bv = votes.most_common(1)[0]
            if bv / total > 0.6:
                print(f"  => strings are length-prefixed: {best}")
            elif bv / total > 0.2:
                print(f"  => weak signal for {best}; may apply to one record "
                      f"class only. Re-run with --grep to isolate.")
        else:
            print("  no prefix matches at all")

        n1, n2, neither = terminator_evidence(data, strings)
        print(f"\nterminator test   NUL1={n1}  NUL2={n2}  none={neither}")
        if neither > (n1 + n2):
            print("  => strings are NOT NUL-terminated; length must come from "
                  "a prefix or an out-of-band field (check fieldmap.py for a "
                  "length column)")

    if args.stride and len(strings) >= 8:
        mod = collections.Counter(s[0] % args.stride for s in strings)
        print(f"\noffset % {args.stride}  top positions: " +
              ", ".join(f"+{m}({c})" for m, c in mod.most_common(6)))

    print(f"\nfirst {min(args.show, len(strings))} strings")
    for off, blen, enc, text in strings[:args.show]:
        show = text if len(text) <= 70 else text[:67] + "..."
        print(f"  0x{off:08x} {enc:<9} len={blen:<5} {show!r}")



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
