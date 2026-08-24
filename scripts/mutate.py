#!/usr/bin/env python3
"""Generate mutated samples, for testing your parser and probing the producer.

Fuzzing runs in two directions here, and the second is the interesting one.

Outward: feed mutants to your parser. A forensic parser meets corrupt evidence
routinely, and one that raises on a truncated record has failed at its job.
This is robustness testing, and it is not optional for a tool that will run on
real cases.

Inward: feed mutants back to the *producer* and see what it rejects. A
producer that refuses a file is telling you a validation rule, and validation
rules reveal field semantics faster than passive observation ever does. If
changing offset 12 makes the application refuse to load the file but changing
offset 16 does not, you have learned something no amount of staring at bytes
would give you.

Mutations are deterministic under --seed, so a crash is reproducible.

Usage:
  mutate.py sample.bin -o mutants/ --count 200
  mutate.py sample.bin -o mutants/ --stride 8192 --field 16:8 --field 24:4
  mutate.py sample.bin -o mutants/ --count 50 --run "python myparser.py {}"
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys

# Values that disproportionately trigger bugs: boundaries, sign flips,
# overflow edges, and the sentinels formats use for "absent".
EDGE_VALUES = {
    1: [0x00, 0x01, 0x7F, 0x80, 0xFF],
    2: [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE],
    4: [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0xFFFFFFFE, 0x3FFFFFFF, 0x0000FFFF],
    8: [0, 1, 1 << 31, (1 << 63) - 1, 1 << 63, (1 << 64) - 1],
}


def h(data):
    return hashlib.sha256(data).hexdigest()[:16]


class Mutator:
    def __init__(self, data, rng, stride=None, fields=None, record=None):
        self.data = data
        self.rng = rng
        self.stride = stride
        self.fields = fields or []
        self.record = record

    def bitflip(self):
        b = bytearray(self.data)
        pos = self.rng.randrange(len(b))
        bit = 1 << self.rng.randrange(8)
        b[pos] ^= bit
        return bytes(b), f"bitflip at 0x{pos:x} bit {bit.bit_length()-1}"

    def byteset(self):
        b = bytearray(self.data)
        pos = self.rng.randrange(len(b))
        val = self.rng.choice([0x00, 0xFF, 0x41, self.rng.randrange(256)])
        old = b[pos]
        b[pos] = val
        return bytes(b), f"byte at 0x{pos:x}: 0x{old:02x} -> 0x{val:02x}"

    def field_edge(self):
        """Replace a declared field with a boundary value. The highest-yield
        mutation, because length and offset fields are where parsers break."""
        if not self.fields:
            return self.byteset()
        off, width = self.rng.choice(self.fields)
        if self.stride:
            rec = (self.record if self.record is not None
                   else self.rng.randrange(max(1, len(self.data) // self.stride)))
            off = rec * self.stride + off
        if off + width > len(self.data):
            return self.byteset()
        val = self.rng.choice(EDGE_VALUES.get(width, EDGE_VALUES[4]))
        b = bytearray(self.data)
        fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
        struct.pack_into(fmt, b, off, val)
        return bytes(b), f"field at 0x{off:x} (u{width*8}) := 0x{val:x}"

    def truncate(self):
        n = self.rng.randrange(1, len(self.data))
        return self.data[:n], f"truncated to {n} bytes"

    def extend(self):
        pad = bytes(self.rng.randrange(256) for _ in range(self.rng.randrange(1, 512)))
        return self.data + pad, f"appended {len(pad)} bytes"

    def chunk_swap(self):
        if not self.stride or len(self.data) < self.stride * 3:
            return self.bitflip()
        n = len(self.data) // self.stride
        a, c = self.rng.randrange(n), self.rng.randrange(n)
        if a == c:
            return self.bitflip()
        b = bytearray(self.data)
        pa, pc = a * self.stride, c * self.stride
        b[pa:pa + self.stride], b[pc:pc + self.stride] = \
            b[pc:pc + self.stride], b[pa:pa + self.stride]
        return bytes(b), f"swapped records {a} and {c}"

    def chunk_zero(self):
        if not self.stride:
            return self.byteset()
        n = max(1, len(self.data) // self.stride)
        r = self.rng.randrange(n)
        b = bytearray(self.data)
        b[r * self.stride:(r + 1) * self.stride] = b"\x00" * self.stride
        return bytes(b), f"zeroed record {r}"

    def header_only(self):
        n = self.stride or 64
        return self.data[:n], f"header only, {n} bytes"


STRATEGIES = ["field_edge", "bitflip", "byteset", "truncate", "extend",
              "chunk_swap", "chunk_zero", "header_only"]
# field_edge weighted heavily: declared fields are where parsers actually break.
WEIGHTS = [6, 3, 2, 2, 1, 2, 2, 1]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("seed_file", help="a valid sample to mutate")
    ap.add_argument("-o", "--outdir", required=True)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1337,
                    help="RNG seed; identical seeds reproduce identical mutants")
    ap.add_argument("--stride", type=int, help="record/page size")
    ap.add_argument("--field", action="append", default=[],
                    help="OFFSET:WIDTH within a record, e.g. 16:8 (repeatable) "
                         "-- take these from fieldmap.py output")
    ap.add_argument("--record", type=int,
                    help="pin field mutations to this record index instead of "
                         "choosing one at random")
    ap.add_argument("--strategy", action="append", default=[],
                    choices=STRATEGIES)
    ap.add_argument("--run",
                    help="command to run per mutant, {} replaced by the path; "
                         "records exit code, stderr, and timeouts")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--keep-passing", action="store_true",
                    help="keep mutants whose command succeeded (default keeps "
                         "only interesting ones)")
    args = ap.parse_args()

    with open(args.seed_file, "rb") as fh:
        data = fh.read()
    if not data:
        raise SystemExit("empty seed file")

    fields = []
    for f in args.field:
        off, _, w = f.partition(":")
        fields.append((int(off, 0), int(w or 4, 0)))

    os.makedirs(args.outdir, exist_ok=True)
    rng = random.Random(args.seed)
    mut = Mutator(data, rng, args.stride, fields, args.record)
    strategies = args.strategy or STRATEGIES
    weights = ([WEIGHTS[STRATEGIES.index(s)] for s in strategies]
               if not args.strategy else [1] * len(strategies))

    print(f"seed file {args.seed_file} ({len(data)} bytes)")
    print(f"mutants   {args.count}, rng seed {args.seed}"
          + (f", stride {args.stride}" if args.stride else "")
          + (f", {len(fields)} declared field(s)" if fields else ""))
    if not fields:
        print("  No --field given. Field-targeted mutation is by far the most\n"
              "  productive strategy -- pass the offsets and widths that\n"
              "  fieldmap.py proposed and rerun.")

    manifest, results = [], []
    seen = set()
    for i in range(args.count):
        name = rng.choices(strategies, weights=weights, k=1)[0]
        blob, desc = getattr(mut, name)()
        d = h(blob)
        if d in seen:
            continue
        seen.add(d)
        fname = f"mut_{i:05d}_{name}_{d}.bin"
        path = os.path.join(args.outdir, fname)
        with open(path, "wb") as fh:
            fh.write(blob)
        manifest.append({"file": fname, "strategy": name, "description": desc,
                         "sha256_16": d, "size": len(blob)})

    print(f"\nwrote {len(manifest)} unique mutant(s) to {args.outdir}")
    by = {}
    for m in manifest:
        by[m["strategy"]] = by.get(m["strategy"], 0) + 1
    for k, v in sorted(by.items(), key=lambda kv: -kv[1]):
        print(f"  {v:>4}  {k}")

    if args.run:
        print(f"\nrunning: {args.run}")
        buckets = {"ok": 0, "error": 0, "timeout": 0, "crash": 0}
        interesting = []
        for m in manifest:
            path = os.path.join(args.outdir, m["file"])
            cmd = args.run.replace("{}", path)
            try:
                p = subprocess.run(cmd, shell=True, capture_output=True,
                                   timeout=args.timeout)
                rc = p.returncode
                err = p.stderr.decode("utf-8", "replace")[-400:]
            except subprocess.TimeoutExpired:
                rc, err = None, ""
                buckets["timeout"] += 1
                interesting.append((m, "timeout", ""))
                results.append({**m, "outcome": "timeout"})
                continue
            if rc == 0:
                buckets["ok"] += 1
                outcome = "ok"
            elif rc is not None and rc < 0:
                buckets["crash"] += 1
                outcome = f"signal {-rc}"
                interesting.append((m, outcome, err))
            else:
                buckets["error"] += 1
                outcome = f"exit {rc}"
                # an unhandled traceback is a bug; a clean refusal is correct
                if "Traceback" in err or "Segmentation" in err:
                    interesting.append((m, outcome, err))
            results.append({**m, "outcome": outcome, "stderr": err})
            if outcome == "ok" and not args.keep_passing:
                pass

        print(f"  clean {buckets['ok']}   handled error {buckets['error']}   "
              f"timeout {buckets['timeout']}   crash {buckets['crash']}")
        if interesting:
            print(f"\n{len(interesting)} interesting result(s):")
            for m, outcome, err in interesting[:12]:
                print(f"  [{outcome}] {m['description']}")
                print(f"           {m['file']}")
                if err.strip():
                    print(f"           {err.strip().splitlines()[-1][:100]}")
            print("\n  A clean non-zero exit is correct behaviour -- the parser\n"
                  "  rejected bad input. An unhandled traceback, a hang, or a\n"
                  "  signal is a bug, and in a forensic parser it means a corrupt\n"
                  "  artefact takes the whole analysis down.")
        elif buckets["error"]:
            print(f"\n  {buckets['error']} mutant(s) were rejected cleanly and "
                  f"none crashed.\n  That is the correct outcome: the parser "
                  f"refused bad input without\n  falling over. Sample the "
                  f"rejections to confirm it refused for the\n  right reason "
                  f"rather than by accident.")
        else:
            print("  Nothing interesting: every mutant was accepted. Before "
                  "concluding the\n  parser is robust, check that it actually "
                  "reads the mutated region --\n  field mutations land in a "
                  "randomly chosen record, so a parser that\n  only reads the "
                  "first one will report clean no matter what. Use\n  --record "
                  "0 to pin mutations to a specific record, widen --count, or\n"
                  "  add --field entries from fieldmap.py.")

    with open(os.path.join(args.outdir, "manifest.json"), "w") as fh:
        json.dump({"seed_file": args.seed_file, "rng_seed": args.seed,
                   "stride": args.stride, "fields": fields,
                   "mutants": results or manifest}, fh, indent=2)
    print(f"\nmanifest: {os.path.join(args.outdir, 'manifest.json')}")

    print("\nFeeding mutants back to the PRODUCER is the other half of this, and\n"
          "usually the more informative half. Put a mutant where the "
          "application expects\nits data file and see whether it loads, "
          "repairs, or refuses. What it rejects\ndefines the validation rules, "
          "and validation rules tell you what fields mean.\nDo that in a "
          "disposable VM, never against anything you care about, and never\n"
          "against evidence.")


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
