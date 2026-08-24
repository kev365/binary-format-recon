#!/usr/bin/env python3
"""Turn an established format layout into signatures other tools can consume.

Analysis that ends in a document helps one person. The same knowledge emitted
as a Yara rule, a libmagic entry, a PRONOM-style byte sequence, and a
collection artefact is usable by everyone else's tooling, which for threat
intelligence work is usually the point.

Only established facts belong in a signature. A speculative magic produces
false positives in somebody else's pipeline months later, with no way to trace
them back to the guess that caused them.

Usage:
  siggen.py --name wmi_objects --magic 0:ACCCABCD --ext data \\
      --desc "WMI CIM repository objects" --all
  siggen.py --name foo --magic 0:504B0304 --magic 4:1400 --yara --magic-file
  siggen.py --spec facts.json --all
"""
import argparse
import datetime as dt
import json
import os
import re
import sys

TYPES = ["yara", "libmagic", "pronom", "velociraptor", "sigma-note"]


def parse_magic(spec):
    """'offset:hexbytes' -> (offset, bytes). Offset may be negative for EOF."""
    if ":" not in spec:
        raise SystemExit(f"bad --magic {spec!r}; expected OFFSET:HEXBYTES, "
                         f"e.g. 0:ACCCABCD")
    off_s, hex_s = spec.split(":", 1)
    hex_s = hex_s.replace(" ", "").replace("0x", "")
    if len(hex_s) % 2:
        raise SystemExit(f"odd hex digit count in {spec!r}")
    try:
        raw = bytes.fromhex(hex_s)
    except ValueError:
        raise SystemExit(f"bad hex in {spec!r}")
    return int(off_s, 0), raw


def ident(name):
    s = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return s if not s[:1].isdigit() else "f_" + s


def yara_rule(cfg):
    n = ident(cfg["name"])
    lines = [f"rule {n}", "{", "    meta:"]
    lines.append(f'        description = "{cfg["desc"]}"')
    lines.append(f'        author = "{cfg["author"]}"')
    lines.append(f'        date = "{cfg["date"]}"')
    if cfg.get("version_scope"):
        lines.append(f'        version_scope = "{cfg["version_scope"]}"')
    if cfg.get("corpus"):
        lines.append(f'        corpus = "{cfg["corpus"]}"')
    lines.append('        confidence = "established fields only"')
    lines.append("")
    lines.append("    strings:")
    for i, (off, raw) in enumerate(cfg["magics"]):
        hexs = " ".join(f"{b:02X}" for b in raw)
        lines.append(f"        $m{i} = {{ {hexs} }}")
    for i, s in enumerate(cfg.get("strings", [])):
        lines.append(f'        $s{i} = "{s}" ascii wide')
    lines.append("")
    lines.append("    condition:")
    conds = []
    for i, (off, raw) in enumerate(cfg["magics"]):
        if off >= 0:
            conds.append(f"$m{i} at {off}")
        else:
            conds.append(f"$m{i} in (filesize{off} .. filesize)")
    if cfg.get("strings"):
        conds.append("all of ($s*)")
    if cfg.get("min_size"):
        conds.append(f"filesize >= {cfg['min_size']}")
    if cfg.get("stride"):
        conds.append(f"filesize % {cfg['stride']} == 0")
    lines.append("        " + " and\n        ".join(conds))
    lines.append("}")
    return "\n".join(lines)


def magic_entry(cfg):
    """libmagic / file(1) format: offset type test message."""
    out = [f"# {cfg['desc']}",
           f"# generated {cfg['date']} by {cfg['author']}"]
    if cfg.get("version_scope"):
        out.append(f"# version scope: {cfg['version_scope']}")
    first, rest = cfg["magics"][0], cfg["magics"][1:]
    off, raw = first
    esc = "".join(f"\\x{b:02x}" for b in raw)
    out.append(f"{off}\tstring\t{esc}\t{cfg['desc']}")
    for off, raw in rest:
        esc = "".join(f"\\x{b:02x}" for b in raw)
        out.append(f">{off}\tstring\t{esc}\t(confirmed)")
    if cfg.get("ext"):
        out.append(f"!:ext\t{cfg['ext']}")
    if cfg.get("mime"):
        out.append(f"!:mime\t{cfg['mime']}")
    return "\n".join(out)


def pronom_signature(cfg):
    """PRONOM-style internal signature, as XML close to DROID's shape.

    Submit through The National Archives rather than using this directly; the
    point here is to have the byte sequences in the expected form.
    """
    seqs = []
    for off, raw in cfg["magics"]:
        pos = "BOFoffset" if off >= 0 else "EOFoffset"
        val = "".join(f"{b:02X}" for b in raw)
        seqs.append(
            f'      <ByteSequence Reference="{pos}">\n'
            f'        <SubSequence Position="1" SubSeqMinOffset="{abs(off)}" '
            f'SubSeqMaxOffset="{abs(off)}">\n'
            f'          <Sequence>{val}</Sequence>\n'
            f'        </SubSequence>\n'
            f'      </ByteSequence>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!-- Draft internal signature. PUIDs are assigned by The National\n'
        '     Archives; do not invent one. Submit via the PRONOM contact form. -->\n'
        '<FFSignatureFile>\n'
        '  <InternalSignatureCollection>\n'
        f'    <InternalSignature ID="1" Specificity="Specific">\n'
        + "\n".join(seqs) + "\n"
        '    </InternalSignature>\n'
        '  </InternalSignatureCollection>\n'
        '  <FileFormatCollection>\n'
        f'    <FileFormat ID="1" Name="{cfg["desc"]}" '
        f'PUID="TBD" MIMEType="{cfg.get("mime", "")}">\n'
        f'      <InternalSignatureID>1</InternalSignatureID>\n'
        + (f'      <Extension>{cfg["ext"]}</Extension>\n' if cfg.get("ext") else "")
        + '    </FileFormat>\n'
        '  </FileFormatCollection>\n'
        '</FFSignatureFile>')


def velociraptor_artifact(cfg):
    n = ident(cfg["name"])
    globs = cfg.get("glob") or f"C:/**/*.{cfg.get('ext', 'bin')}"
    first_off, first_raw = cfg["magics"][0]
    hexs = "".join(f"{b:02x}" for b in first_raw)
    return f"""name: Custom.Forensics.{n}
description: |
  Locate and hash {cfg['desc']}.

  Generated from reverse-engineered format analysis on {cfg['date']}.
  Version scope: {cfg.get('version_scope') or 'UNSTATED -- fill this in'}

  This artefact identifies candidate files by signature and records hashes for
  offline parsing. It deliberately does not parse the format on the endpoint:
  a parser built from an inferred layout should run against a preserved copy,
  not against live evidence.

type: CLIENT

parameters:
  - name: TargetGlob
    default: '{globs}'
  - name: MagicHex
    default: '{hexs}'
  - name: MagicOffset
    type: int
    default: {first_off}

sources:
  - query: |
      LET candidates = SELECT OSPath, Size, Mtime
        FROM glob(globs=TargetGlob)
        WHERE NOT IsDir AND Size >= {cfg.get('min_size', len(first_raw))}

      SELECT OSPath, Size, Mtime,
             hash(path=OSPath) AS Hashes,
             format(format="%x", args=read_file(
               filename=OSPath, offset=MagicOffset,
               length=len(list=MagicHex) / 2)) AS Magic
      FROM candidates
      WHERE Magic =~ MagicHex
"""


def sigma_note(cfg):
    return f"""# Detection notes -- {cfg['desc']}
#
# Format knowledge does not by itself make a detection rule. What it gives you
# is the set of observable events worth writing rules against. Fill these in
# from the analysis and delete what does not apply.
#
# generated {cfg['date']} by {cfg['author']}
# version scope: {cfg.get('version_scope') or 'UNSTATED'}
#
# 1. Creation or modification of the artefact by an unexpected process.
#    Which process legitimately writes it? Anything else is notable.
#
# 2. Records whose fields fall outside the ranges the corpus established.
#    Values a legitimate producer never emits are a strong signal, and the
#    corpus is what tells you the legitimate range.
#
# 3. Deleted or tombstoned records, if the format retains them. Their presence
#    is often the finding.
#
# 4. Timestamps inconsistent with the container or the filesystem. See
#    references/producer-side.md on what the producer actually sets.
#
# 5. Size or stride anomalies -- files not a whole multiple of the page size,
#    truncation, or unexpected growth.
#
# Write these as Sigma rules against the telemetry you actually collect, not
# against fields you wish existed.
"""


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", help="short identifier, e.g. wmi_objects")
    ap.add_argument("--desc", default="", help="human-readable description")
    ap.add_argument("--magic", action="append", default=[],
                    help="OFFSET:HEXBYTES, negative offset = from EOF "
                         "(repeatable)")
    ap.add_argument("--string", action="append", default=[],
                    help="literal string that must be present (repeatable)")
    ap.add_argument("--ext", help="file extension without the dot")
    ap.add_argument("--mime", help="media type, if one is registered")
    ap.add_argument("--stride", type=int, help="page size, adds a modulo check")
    ap.add_argument("--min-size", type=int, help="minimum plausible file size")
    ap.add_argument("--glob", help="Velociraptor target glob")
    ap.add_argument("--author", default=os.environ.get("USER", "analyst"))
    ap.add_argument("--version-scope",
                    help="producer versions the signature was validated on")
    ap.add_argument("--corpus", help="corpus the signature was tested against")
    ap.add_argument("--spec", help="JSON file supplying all of the above")
    ap.add_argument("--type", action="append", default=[], choices=TYPES)
    ap.add_argument("--all", action="store_true", help="emit every type")
    for t in TYPES:
        ap.add_argument(f"--emit-{t}", dest="type", action="append_const",
                        const=t, help=f"emit the {t} form")
    ap.add_argument("-o", "--outdir", help="write files instead of stdout")
    args = ap.parse_args()

    cfg = {}
    if args.spec:
        with open(args.spec) as fh:
            cfg.update(json.load(fh))
    cfg.setdefault("name", args.name)
    cfg.setdefault("desc", args.desc or args.name or "")
    cfg.setdefault("ext", args.ext)
    cfg.setdefault("mime", args.mime)
    cfg.setdefault("stride", args.stride)
    cfg.setdefault("min_size", args.min_size)
    cfg.setdefault("glob", args.glob)
    cfg.setdefault("strings", args.string)
    cfg.setdefault("version_scope", args.version_scope)
    cfg.setdefault("corpus", args.corpus)
    cfg["author"] = args.author
    cfg["date"] = dt.date.today().isoformat()

    raw_magics = args.magic or cfg.get("magic_specs", [])
    if not cfg.get("magics"):
        cfg["magics"] = [parse_magic(m) for m in raw_magics]
    else:
        cfg["magics"] = [parse_magic(m) if isinstance(m, str) else tuple(m)
                         for m in cfg["magics"]]

    if not cfg["name"]:
        raise SystemExit("--name is required")
    if not cfg["magics"]:
        raise SystemExit(
            "no --magic given. A signature needs at least one byte sequence "
            "that is\nestablished, not inferred -- a speculative magic becomes "
            "somebody else's\nfalse positives months from now, untraceable back "
            "to the guess.")

    wanted = set(TYPES) if args.all else set(args.type or ["yara"])
    builders = {"yara": (yara_rule, f"{ident(cfg['name'])}.yar"),
                "libmagic": (magic_entry, f"{ident(cfg['name'])}.magic"),
                "pronom": (pronom_signature, f"{ident(cfg['name'])}_signature.xml"),
                "velociraptor": (velociraptor_artifact,
                                 f"Custom.Forensics.{ident(cfg['name'])}.yaml"),
                "sigma-note": (sigma_note, f"{ident(cfg['name'])}_detection_notes.txt")}

    if not cfg.get("version_scope"):
        print("WARNING: no --version-scope given. A signature without a stated "
              "version\nscope will be applied to producer versions you never "
              "tested.\n", file=sys.stderr)

    for t in TYPES:
        if t not in wanted:
            continue
        fn, fname = builders[t]
        text = fn(cfg)
        if args.outdir:
            os.makedirs(args.outdir, exist_ok=True)
            path = os.path.join(args.outdir, fname)
            with open(path, "w") as fh:
                fh.write(text + "\n")
            print(f"wrote {path}")
        else:
            print(f"===== {fname} " + "=" * max(0, 60 - len(fname)))
            print(text)
            print()

    if not args.outdir:
        print("Validate before publishing: run the Yara rule across the corpus "
              "AND across\nunrelated files, and report both the true positive "
              "rate and the false\npositive rate. A rule tested only on files "
              "you know match has not been tested.")


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
