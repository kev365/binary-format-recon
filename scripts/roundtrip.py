#!/usr/bin/env python3
"""Round-trip a corpus through your parser and serialiser to find silent errors.

Parse success is a weak test. A parser that reads a u32 where the format has
two u16s succeeds on every file and is wrong about all of them. Round-tripping
catches this: parse a file, serialise it back, and compare bytes. Any field you
misread, ignored, or silently normalised shows up as a divergence at a specific
offset.

It is the strongest validation available without the producer, and it is
strictly better than a parse-rate number. A parser that round-trips a corpus
byte-for-byte has demonstrably accounted for every byte in it.

You supply a module with two functions:

    def parse(data: bytes) -> object      # your parsed representation
    def serialize(obj) -> bytes           # back to bytes

`construct` gives you both from one definition, which is why it is worth using
for this even if the shipped parser is Kaitai-generated.

Usage:
  roundtrip.py --module myparser.py --corpus ./samples
  roundtrip.py --module myparser.py --corpus ./samples --stride 8192 --report rt.md
"""
import argparse
import importlib.util
import json
import os
import sys
import traceback


def load_module(path):
    spec = importlib.util.spec_from_file_location("rt_target", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    missing = [f for f in ("parse", "serialize") if not hasattr(mod, f)]
    if missing:
        raise SystemExit(
            f"{path} is missing {', '.join(missing)}.\n\n"
            "The module must define:\n"
            "    def parse(data: bytes) -> object\n"
            "    def serialize(obj) -> bytes\n\n"
            "If your parser cannot serialise, this test cannot run -- consider "
            "expressing\nthe format in `construct`, which builds as well as "
            "parses from one definition.")
    return mod


def diff_runs(a, b, gap=4, limit=40):
    n = min(len(a), len(b))
    offs = [i for i in range(n) if a[i] != b[i]]
    runs = []
    if offs:
        start = prev = offs[0]
        for o in offs[1:]:
            if o - prev <= gap:
                prev = o
            else:
                runs.append((start, prev - start + 1))
                start = prev = o
        runs.append((start, prev - start + 1))
    if len(a) != len(b):
        runs.append((n, abs(len(a) - len(b))))
    return runs[:limit], len(offs)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--module", required=True,
                    help="python file exposing parse() and serialize()")
    ap.add_argument("--corpus", required=True, help="directory of samples")
    ap.add_argument("--stride", type=int,
                    help="record size; localises divergence to a record and "
                         "an offset within it")
    ap.add_argument("--ext")
    ap.add_argument("--max-files", type=int, default=1000)
    ap.add_argument("--show", type=int, default=6)
    ap.add_argument("--report", help="write a markdown validation record")
    ap.add_argument("--json")
    args = ap.parse_args()

    mod = load_module(args.module)
    root = os.path.abspath(args.corpus)
    paths = []
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            if args.ext and not f.lower().endswith(args.ext.lower().lstrip(".")):
                continue
            paths.append(os.path.join(dirpath, f))
    paths = paths[:args.max_files]
    if not paths:
        raise SystemExit("no samples found")

    print(f"module    {args.module}")
    print(f"corpus    {root}  ({len(paths)} file(s))\n")

    results = []
    identical = parse_fail = ser_fail = diverged = 0
    field_hist = {}

    for p in paths:
        rel = os.path.relpath(p, root)
        with open(p, "rb") as fh:
            original = fh.read()
        rec = {"file": rel, "size": len(original)}
        try:
            obj = mod.parse(original)
        except Exception as e:
            parse_fail += 1
            rec.update(outcome="parse_error", error=f"{type(e).__name__}: {e}")
            results.append(rec)
            continue
        try:
            rebuilt = mod.serialize(obj)
        except Exception as e:
            ser_fail += 1
            rec.update(outcome="serialize_error", error=f"{type(e).__name__}: {e}")
            results.append(rec)
            continue

        if rebuilt == original:
            identical += 1
            rec.update(outcome="identical")
        else:
            diverged += 1
            runs, nbytes = diff_runs(original, rebuilt)
            rec.update(outcome="diverged", changed_bytes=nbytes,
                       size_delta=len(rebuilt) - len(original),
                       runs=[{"offset": o, "length": l} for o, l in runs])
            if args.stride:
                for o, _l in runs:
                    field_hist[o % args.stride] = field_hist.get(o % args.stride, 0) + 1
        results.append(rec)

    total = len(results)
    print(f"{'identical':<18} {identical:>5}/{total}  "
          f"({identical/total:.1%})")
    print(f"{'diverged':<18} {diverged:>5}/{total}")
    print(f"{'parse errors':<18} {parse_fail:>5}/{total}")
    print(f"{'serialize errors':<18} {ser_fail:>5}/{total}")

    if identical == total:
        print("\nEvery sample round-tripped byte-for-byte. That is the strongest\n"
              "evidence available short of the producer accepting your output:\n"
              "every byte in the corpus is accounted for by the layout.")
    if diverged:
        print(f"\ndivergences (showing {min(args.show, diverged)})")
        shown = 0
        for r in results:
            if r["outcome"] != "diverged" or shown >= args.show:
                continue
            shown += 1
            print(f"  {r['file']}  {r['changed_bytes']} byte(s) differ, "
                  f"size delta {r['size_delta']:+d}")
            for run in r["runs"][:5]:
                loc = f"0x{run['offset']:08x}"
                if args.stride:
                    loc += (f"  (record {run['offset']//args.stride} "
                            f"+{run['offset']%args.stride})")
                print(f"    {loc}  len {run['length']}")
        if field_hist:
            hot = sorted(field_hist.items(), key=lambda kv: -kv[1])[:6]
            print("\n  divergence positions within a record: " +
                  ", ".join(f"+{o}({c})" for o, c in hot))
            print("  A position that recurs across files is one specific field "
                  "being\n  misread, not general noise. Fix that field and "
                  "re-run.")
        print("\n  Common causes, in rough order of frequency: a field read at "
              "the wrong\n  width; padding regenerated as zeros when the "
              "original held stale bytes;\n  a checksum recomputed rather than "
              "preserved; string padding normalised;\n  a reserved field "
              "dropped on parse. Only the checksum case is benign, and\n  only "
              "if you meant it.")

    if parse_fail:
        print(f"\nparse failures")
        for r in results:
            if r["outcome"] == "parse_error":
                print(f"  {r['file']}: {r['error']}")
                if parse_fail > 8:
                    break
        print("  Characterise these before dismissing them -- a failure cluster "
              "usually\n  means a second record type or an untested producer "
              "version, which is a\n  finding rather than a defect.")

    if args.report:
        with open(args.report, "w") as fh:
            fh.write("# Round-trip validation record\n\n")
            fh.write(f"Module: `{args.module}`  \nCorpus: `{root}`  \n")
            fh.write(f"Samples: {total}\n\n")
            fh.write(f"| Outcome | Count | Rate |\n|---|---|---|\n")
            for label, n in (("Identical", identical), ("Diverged", diverged),
                             ("Parse error", parse_fail),
                             ("Serialize error", ser_fail)):
                fh.write(f"| {label} | {n} | {n/total:.1%} |\n")
            fh.write("\n## Interpretation\n\n")
            fh.write("Byte-identical round-trip demonstrates every byte in the "
                     "sample is accounted\nfor by the layout. Divergences "
                     "localise misread fields. Parse failures are\n"
                     "characterised below rather than excluded.\n\n")
            fh.write("## Per-sample\n\n| File | Size | Outcome | Detail |\n"
                     "|---|---|---|---|\n")
            for r in results:
                detail = r.get("error", "")
                if r["outcome"] == "diverged":
                    detail = (f"{r['changed_bytes']} bytes, "
                              f"delta {r['size_delta']:+d}")
                fh.write(f"| `{r['file']}` | {r['size']} | {r['outcome']} | "
                         f"{detail} |\n")
        print(f"\nwrote {args.report}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"module": args.module, "corpus": root,
                       "identical": identical, "diverged": diverged,
                       "parse_errors": parse_fail,
                       "serialize_errors": ser_fail,
                       "results": results}, fh, indent=2)
        print(f"wrote {args.json}")

    print("\nRound-trip identity is necessary, not sufficient: a parser can "
          "round-trip\nperfectly while assigning the wrong *meaning* to a "
          "field it copies faithfully.\nSemantics still come from controlled "
          "mutation and from the producer.")


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
