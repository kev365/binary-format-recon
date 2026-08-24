#!/usr/bin/env python3
"""Build and characterise a sample corpus, and find its version boundaries.

The skill repeatedly says "validate against the whole corpus" and then assumes
a corpus exists. Assembling one is real work, and doing it badly produces the
most common false result in format research: a layout that appears to hold
across fifty files that are actually three files duplicated.

This deduplicates exactly, then clusters what remains by structural similarity,
which matters because the clusters usually correspond to producer versions --
and you can find those boundaries before you know what the versions are.

Similarity uses shingled hashing over normalised n-grams. It is deliberately
crude compared to ssdeep or TLSH, but it is stdlib-only and good enough to
separate "same format, different version" from "different format".

Usage:
  corpus.py ./samples
  corpus.py ./samples --cluster --threshold 0.7 --report corpus.md
  corpus.py ./samples --header-bytes 512     # cluster on headers only
"""
import argparse
import collections
import hashlib
import math
import os
import sys

SOURCES = """Where corpora come from, roughly in order of how defensible the
provenance is:

  Lab generation      You control the producer, so the ground truth is known.
                      The only source that supports differential baselining.
  Institutional       Digital Corpora (digitalcorpora.org), NIST CFReDS,
                      cases and disclosure sets. Reference material with
                      documented provenance.
  Your own estate     Test machines, retired hardware, VM snapshots across
                      OS builds. Best source of version spread.
  Public repositories MalwareBazaar, VirusShare, VirusTotal retrohunt, the
                      Internet Archive, software archives for old versions.
  Vendor artefacts    Installers and update packages, which often contain
                      the producer binary for several versions at once.

Provenance and licensing follow the sample. Note where each file came from
before it goes in the corpus, not afterwards -- and see
references/legal-and-ethics.md before collecting from public malware
repositories or redistributing anything."""


def sha256_of(path, cap=None):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            if cap and n + len(chunk) > cap:
                h.update(chunk[:cap - n])
                break
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest()


def shingles(data, k=8, stride=4, keep=256):
    """Min-hash-style sketch: the `keep` smallest hashes of k-byte windows.

    Sampling by smallest hash makes the sketch independent of where the
    windows fall, so insertions and deletions shift content without
    destroying the similarity estimate.
    """
    if len(data) < k:
        return frozenset()
    hs = []
    for i in range(0, len(data) - k, stride):
        h = hashlib.blake2b(data[i:i + k], digest_size=8).digest()
        hs.append(int.from_bytes(h, "big"))
    hs.sort()
    return frozenset(hs[:keep])


def jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def entropy(data):
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def cluster(items, threshold):
    """Single-linkage clustering on sketch similarity."""
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    pairs = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            s = jaccard(items[i]["sketch"], items[j]["sketch"])
            if s >= threshold:
                union(i, j)
            if s > 0:
                pairs.append((s, i, j))
    groups = collections.defaultdict(list)
    for i in range(len(items)):
        groups[find(i)].append(i)
    return list(groups.values()), pairs


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="directory of samples")
    ap.add_argument("--cluster", action="store_true",
                    help="group by structural similarity")
    ap.add_argument("--threshold", type=float, default=0.6,
                    help="similarity threshold for clustering (0-1)")
    ap.add_argument("--header-bytes", type=int,
                    help="sketch only the first N bytes -- clusters by header "
                         "shape, which tracks format version more closely than "
                         "whole-file content does")
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--ext", help="only files with this extension")
    ap.add_argument("--report", help="write a markdown corpus record")
    ap.add_argument("--sources", action="store_true",
                    help="print notes on where to obtain samples")
    args = ap.parse_args()

    if args.sources or not args.path:
        print(SOURCES)
        if not args.path:
            return

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        raise SystemExit(f"not a directory: {root}")

    paths = []
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            if args.ext and not f.lower().endswith(args.ext.lower().lstrip(".")):
                continue
            try:
                if os.path.getsize(p) < args.min_size:
                    continue
            except OSError:
                continue
            paths.append(p)

    if not paths:
        raise SystemExit("no files matched")

    items, by_hash = [], collections.defaultdict(list)
    for p in paths:
        try:
            with open(p, "rb") as fh:
                head = fh.read(args.header_bytes or (1 << 20))
            digest = sha256_of(p)
        except OSError as e:
            print(f"skip {p}: {e}", file=sys.stderr)
            continue
        by_hash[digest].append(p)
        items.append({"path": p, "rel": os.path.relpath(p, root),
                      "size": os.path.getsize(p), "sha256": digest,
                      "entropy": entropy(head[:65536]),
                      "sketch": shingles(head)})

    uniq = {}
    for it in items:
        uniq.setdefault(it["sha256"], it)
    unique = list(uniq.values())

    print(f"corpus    {root}")
    print(f"files     {len(items)} found, {len(unique)} unique by SHA-256")
    dupes = {h: ps for h, ps in by_hash.items() if len(ps) > 1}
    if dupes:
        print(f"\nexact duplicates: {len(dupes)} group(s)")
        for h, ps in list(dupes.items())[:6]:
            print(f"  {h[:16]}  x{len(ps)}")
            for p in ps[:3]:
                print(f"    {os.path.relpath(p, root)}")
        print("  Duplicates inflate apparent corpus size and make a layout look\n"
              "  better supported than it is. Count unique files, not files.")

    sizes = sorted(it["size"] for it in unique)
    ents = [it["entropy"] for it in unique]
    print(f"\nsize      min {sizes[0]}  median {sizes[len(sizes)//2]}  "
          f"max {sizes[-1]}")
    print(f"entropy   min {min(ents):.2f}  max {max(ents):.2f}")
    if max(ents) - min(ents) > 1.5:
        print("  Wide entropy spread -- the corpus may contain more than one "
              "format,\n  or some samples are compressed and others are not. "
              "Check before\n  treating them as one population.")

    if args.cluster:
        groups, pairs = cluster(unique, args.threshold)
        groups.sort(key=len, reverse=True)
        basis = f"first {args.header_bytes} bytes" if args.header_bytes else "whole file"
        print(f"\nclusters  {len(groups)} at threshold {args.threshold} "
              f"(basis: {basis})")
        for gi, g in enumerate(groups, 1):
            members = [unique[i] for i in g]
            gs = sorted(m["size"] for m in members)
            print(f"\n  cluster {gi}: {len(members)} file(s), "
                  f"size {gs[0]}..{gs[-1]}")
            for m in members[:5]:
                print(f"    {m['rel']}  ({m['size']} bytes)")
            if len(members) > 5:
                print(f"    ... {len(members)-5} more")
        singles = [g for g in groups if len(g) == 1]
        if len(groups) > 1:
            print(f"\n  {len(groups)} clusters usually means {len(groups)} "
                  f"format variants or producer\n  versions. Validate the "
                  f"layout against each cluster separately and report\n  per-"
                  f"cluster pass rates -- a field that holds in one cluster and "
                  f"fails in\n  another is a versioned field, not a broken "
                  f"hypothesis.")
        if singles:
            print(f"\n  {len(singles)} singleton(s). Outliers are worth opening "
                  f"first: they are\n  either a different format, a different "
                  f"version, or corrupt, and all three\n  are informative.")

    if args.report:
        with open(args.report, "w") as fh:
            fh.write("# Corpus record\n\n")
            fh.write(f"Root: `{root}`  \n")
            fh.write(f"Files: {len(items)} found, {len(unique)} unique\n\n")
            fh.write("| File | Size | SHA-256 | Entropy |\n|---|---|---|---|\n")
            for it in sorted(unique, key=lambda x: x["rel"]):
                fh.write(f"| `{it['rel']}` | {it['size']} | "
                         f"`{it['sha256'][:16]}...` | {it['entropy']:.2f} |\n")
            fh.write("\n## Provenance\n\n")
            fh.write("Record where each sample came from and under what terms. "
                     "A corpus without\nprovenance cannot support a defensible "
                     "finding.\n")
        print(f"\nwrote {args.report}")

    print("\nRun provenance.py record over the corpus before analysis, and keep "
          "lab-generated\nsamples in a separate tree from case data -- they look "
          "identical and mixing\nthem is the mistake that is hardest to undo.")


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
