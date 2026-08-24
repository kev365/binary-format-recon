#!/usr/bin/env python3
"""Record and verify provenance for a corpus of binary samples.

Every recon session starts here. Nothing downstream is trustworthy if you
cannot prove the bytes you analysed are the bytes you were given.

Usage:
  provenance.py record <path> [<path>...] -o manifest.json [--note TEXT]
  provenance.py verify manifest.json
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import sys

BUF = 1 << 20
TOOL_VERSION = "binary-format-recon/1.0"


def digest(path):
    h256, h1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    n = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(BUF)
            if not chunk:
                break
            n += len(chunk)
            h256.update(chunk)
            h1.update(chunk)
            md5.update(chunk)
    return {"size": n, "sha256": h256.hexdigest(),
            "sha1": h1.hexdigest(), "md5": md5.hexdigest()}


def walk(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    out.append(os.path.join(root, f))
        else:
            out.append(p)
    return sorted(set(out))


def record(args):
    entries = []
    for path in walk(args.paths):
        st = os.stat(path)
        e = {"path": os.path.abspath(path), "name": os.path.basename(path)}
        e.update(digest(path))
        e["mtime_utc"] = dt.datetime.fromtimestamp(
            st.st_mtime, dt.timezone.utc).isoformat()
        e["mode"] = oct(st.st_mode & 0o777)
        e["writable"] = os.access(path, os.W_OK)
        entries.append(e)

    manifest = {
        "tool": TOOL_VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "note": args.note,
        "file_count": len(entries),
        "files": entries,
    }
    text = json.dumps(manifest, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.output}  ({len(entries)} files)")
    else:
        print(text)

    hot = [e["name"] for e in entries if e["writable"]]
    if hot:
        print("\nWARNING: these inputs are writable in place. Copy to a "
              "read-only working set before analysis so evidence cannot be "
              "mutated by a buggy parser:", file=sys.stderr)
        for n in hot:
            print(f"  - {n}", file=sys.stderr)
    return 0


def verify(args):
    with open(args.manifest) as fh:
        manifest = json.load(fh)
    bad = missing = 0
    for e in manifest["files"]:
        if not os.path.exists(e["path"]):
            print(f"MISSING  {e['name']}")
            missing += 1
            continue
        now = digest(e["path"])
        if now["sha256"] != e["sha256"]:
            print(f"ALTERED  {e['name']}")
            print(f"         expected {e['sha256']}")
            print(f"         actual   {now['sha256']}")
            bad += 1
        else:
            print(f"ok       {e['name']}")
    print(f"\n{len(manifest['files'])} checked, {bad} altered, {missing} missing")
    return 1 if (bad or missing) else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record", help="hash inputs and write a manifest")
    r.add_argument("paths", nargs="+")
    r.add_argument("-o", "--output")
    r.add_argument("--note", default="", help="case/source/acquisition note")
    r.set_defaults(func=record)

    v = sub.add_parser("verify", help="re-hash and compare against a manifest")
    v.add_argument("manifest")
    v.set_defaults(func=verify)

    args = ap.parse_args()
    sys.exit(args.func(args))



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
