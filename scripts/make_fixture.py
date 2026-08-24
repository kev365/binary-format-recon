#!/usr/bin/env python3
"""Generate synthetic fixtures with known ground truth, to self-test the kit.

Produces a paged format (8192-byte pages) whose layout is known exactly, so
every script can be checked against the right answer:

  page header   +0  u32 magic 0xACCCABCD
                +4  u32 page id (increments by 1)
                +8  u16 page type (enum)
                +10 u16 record count
                +12 u32 reserved (zero)
                +16 u64 FILETIME
                +24 u32 CRC-32/ISO-HDLC over bytes 32..8192
                +28 u32 data offset (constant 64)
  TOC           +64 16-byte entries: record id, offset, length, CRC-32 of body
  bodies        u32 byte-length prefix, UTF-16LE name, u64 FILETIME

Writes before/after (one mutated record) and ctrl_a/ctrl_b (idle churn only),
so bindiff.py's noise subtraction can be exercised end to end.

Usage:  make_fixture.py [outdir]
"""
import argparse
import datetime as dt
import os
import random
import struct
import zlib

PAGE, NPAGES = 8192, 24
E1601 = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
BASE = dt.datetime(2024, 3, 1, tzinfo=dt.timezone.utc)
NAMES = ["__EventFilter", "CommandLineEventConsumer", "ROOT\\subscription",
         "MyClassAlpha", "SystemDriverInfo", "EvilPersist"]


def ft(when):
    return int((when - E1601).total_seconds() * 1e7)


def build(mutate=None, churn=0):
    random.seed(1337)
    out = bytearray()
    for p in range(NPAGES):
        pg = bytearray(PAGE)
        struct.pack_into("<I", pg, 0, 0xACCCABCD)
        struct.pack_into("<I", pg, 4, p)
        struct.pack_into("<H", pg, 8, 0x0002 if p % 3 else 0x0001)
        nrec = 4 + (p % 3)
        struct.pack_into("<H", pg, 10, nrec)
        struct.pack_into("<Q", pg, 16, ft(BASE + dt.timedelta(hours=p * 7 + churn)))
        struct.pack_into("<I", pg, 28, 64)
        cur = 1024
        for r in range(nrec):
            name = NAMES[(p + r) % len(NAMES)]
            if mutate is not None and p == 7 and r == 1:
                name = mutate
            enc = name.encode("utf-16-le")
            body = (struct.pack("<I", len(enc)) + enc +
                    struct.pack("<Q", ft(BASE + dt.timedelta(days=p, minutes=r * 13))))
            struct.pack_into("<I", pg, 64 + r * 16 + 0, p * 100 + r)
            struct.pack_into("<I", pg, 64 + r * 16 + 4, cur)
            struct.pack_into("<I", pg, 64 + r * 16 + 8, len(body))
            struct.pack_into("<I", pg, 64 + r * 16 + 12, zlib.crc32(body))
            pg[cur:cur + len(body)] = body
            cur += len(body) + random.randint(0, 8)
        struct.pack_into("<I", pg, 24, zlib.crc32(bytes(pg[32:])))
        out += pg
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir", nargs="?", default="fixtures",
                    help="directory to write fixtures into (default: fixtures)")
    args = ap.parse_args()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    files = {
        "before.bin": build(),
        "after.bin": build(mutate="ZZTOPMARKER99", churn=1),
        "ctrl_a.bin": build(),
        "ctrl_b.bin": build(churn=1),
    }
    for name, data in files.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"{path}  {len(data)} bytes")
    print("\nGround truth: stride 8192, LE, FILETIME at +16, CRC-32 at +24 over "
          "32..8192,\nu32 byte-length-prefixed UTF-16LE strings, mutation "
          "confined to page 7 record 1.")



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
