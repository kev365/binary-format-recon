#!/usr/bin/env python3
"""Emit an X-Ways/WinHex template (.tpl) from an established layout, and lint
existing templates against the documented grammar.

A template is the visualisation half of a finding: applied in WinHex/X-Ways it
overlays names on bytes, so a reviewer can check a claimed layout against a
real sample in seconds. It is also how the working state of an analysis is
kept honest -- every field carries its evidence status as a comment, and
unknown gaps are emitted as labelled hex runs rather than omitted, so the
template shows what has *not* been established just as clearly.

The grammar implemented here is Appendix A of the X-Ways/WinHex manual
(templates start with a header of keywords, then `begin`, variable
declarations, `end`). See references/xways-templates.md for the distilled
syntax and the judgement calls.

Usage:
  tplgen.py --name "WMI page header" --requires 0:ACCCABCD --stride 8192 \\
      --field 0:4:uint32:magic:established \\
      --field 16:8:filetime:"last write":inferred -o out.tpl
  tplgen.py --spec layout.json -o out.tpl
  tplgen.py --check templates/imported/**/*.tpl
  tplgen.py --selftest

Spec JSON (coverage.py/fieldmap.py field shape, plus template metadata):
  {"name": "...", "desc": "...", "applies_to": "file",
   "requires": [{"offset": 0, "hex": "ACCCABCD"}],
   "record_size": 8192, "big_endian": false, "editable": false,
   "fields": [{"offset": 0, "size": 4, "type": "uint32", "name": "magic",
               "status": "established", "comment": "..."}]}
"""
import argparse
import glob
import json
import os
import re
import sys

# ---------------------------------------------------------------- generation

# accepted field type -> (tpl type, fixed size or None)
TYPES = {
    "int8": ("int8", 1), "uint8": ("uint8", 1), "byte": ("byte", 1),
    "int16": ("int16", 2), "uint16": ("uint16", 2),
    "int24": ("int24", 3), "uint24": ("uint24", 3),
    "int32": ("int32", 4), "uint32": ("uint32", 4),
    "uint48": ("uint48", 6),
    "int64": ("int64", 8),
    # no uint64 in the template language; int64 is the widest integer
    "uint64": ("int64", 8),
    "float": ("float", 4), "single": ("single", 4),
    "double": ("double", 8), "longdouble": ("longdouble", 10),
    "boole8": ("boole8", 1), "boolean": ("boolean", 1),
    "boole16": ("boole16", 2), "boole32": ("boole32", 4),
    "dosdatetime": ("DOSDateTime", 4),
    "filetime": ("FileTime", 8),
    "oledatetime": ("OLEDateTime", 8),
    "sqldatetime": ("SQLDateTime", 8),
    "unixdatetime": ("UNIXDateTime", 4), "time_t": ("time_t", 4),
    "javadatetime": ("JavaDateTime", 8),
    "guid": ("GUID", 16),
    # sized types: size comes from the field entry
    "hex": ("hex", None), "string": ("string", None),
    "string16": ("string16", None), "binary": ("binary", None),
    "char": ("char", None), "char16": ("char16", None),
}

STATUSES = ("established", "inferred", "speculative", "unknown")


def parse_field(spec):
    """'offset:size:type:name[:status]' -> field dict."""
    parts = spec.split(":")
    if len(parts) not in (4, 5):
        raise SystemExit(f"bad --field {spec!r}; expected "
                         f"OFFSET:SIZE:TYPE:NAME[:STATUS]")
    off, size, typ, name = int(parts[0], 0), int(parts[1], 0), \
        parts[2].lower(), parts[3]
    status = parts[4].lower() if len(parts) == 5 else "inferred"
    if typ not in TYPES:
        raise SystemExit(f"unknown type {typ!r} in --field {spec!r}; "
                         f"one of: {', '.join(sorted(TYPES))}")
    if status not in STATUSES:
        raise SystemExit(f"unknown status {status!r} in --field {spec!r}")
    tpl_type, fixed = TYPES[typ]
    if fixed is not None and size != fixed:
        raise SystemExit(f"--field {spec!r}: {typ} is {fixed} bytes, "
                         f"got size {size}")
    return {"offset": off, "size": size, "type": typ, "name": name,
            "status": status}


def parse_requires(spec):
    """'offset:hexbytes' -> dict (same shape as siggen.py --magic)."""
    if ":" not in spec:
        raise SystemExit(f"bad --requires {spec!r}; expected OFFSET:HEXBYTES")
    off_s, hex_s = spec.split(":", 1)
    hex_s = hex_s.replace(" ", "").replace("0x", "")
    if len(hex_s) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", hex_s):
        raise SystemExit(f"bad hex in --requires {spec!r}")
    return {"offset": int(off_s, 0), "hex": hex_s.upper()}


def emit_field(f):
    """One variable declaration, status carried as a comment."""
    tpl_type, fixed = TYPES[f["type"]]
    name = f["name"]
    quoted = f'"{name}"' if " " in name else name
    if tpl_type in ("string", "string16", "hex", "binary"):
        n = f["size"] // 2 if tpl_type == "string16" else f["size"]
        decl = f"    {tpl_type} {n} {quoted}"
    elif tpl_type in ("char", "char16"):
        n = f["size"] // 2 if tpl_type == "char16" else f["size"]
        decl = f"    {tpl_type}[{n}] {quoted}"
    else:
        decl = f"    {tpl_type} {quoted}"
    notes = [f["status"]]
    if f.get("comment"):
        notes.append(f["comment"])
    return f"{decl:<44}// {'; '.join(notes)}"


def generate(cfg):
    fields = sorted(cfg["fields"], key=lambda f: f["offset"])
    lines = [f'template "{cfg["name"]}"']
    if cfg.get("desc"):
        lines.append(f'description "{cfg["desc"]}"')
    lines.append("")
    lines.append(f"// Generated by tplgen.py (binary-format-recon)"
                 f"{' on ' + cfg['date'] if cfg.get('date') else ''}.")
    lines.append("// Field statuses: established = survived a controlled-"
                 "change test; inferred =")
    lines.append("// consistent with the corpus but unproven; speculative = "
                 "hypothesis only;")
    lines.append("// unknown = bounded but undetermined. See the hypothesis "
                 "ledger for evidence.")
    if cfg.get("version_scope"):
        lines.append(f"// Version scope: {cfg['version_scope']}")
    lines.append("")
    lines.append(f"applies_to {cfg.get('applies_to', 'file')}")
    for r in cfg.get("requires", []):
        lines.append(f'requires 0x{r["offset"]:X} "{r["hex"]}"')
    if cfg.get("big_endian"):
        lines.append("big-endian")
    if not cfg.get("editable"):
        lines.append("read-only")
    if cfg.get("record_size"):
        lines.append(f"multiple {cfg['record_size']}")
    lines.append("")
    lines.append("begin")
    pos = 0
    for f in fields:
        if f["offset"] > pos:
            gap = f["offset"] - pos
            lines.append(f'    hex {gap} "unknown +0x{pos:X}"')
            pos = f["offset"]
        elif f["offset"] < pos:
            lines.append(f"    move {f['offset'] - pos}"
                         f"{'':<24}// re-read as another type")
            pos = f["offset"]
        lines.append(emit_field(f))
        pos += f["size"]
    if cfg.get("record_size") and pos < cfg["record_size"]:
        gap = cfg["record_size"] - pos
        lines.append(f'    hex {gap} "unknown +0x{pos:X}"')
    lines.append("end")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------- linting

# "appliesto" is undocumented but accepted by X-Ways and used in published
# templates; same for statements whose quoted title continues on the next
# line, "applies_to file/disk", nested IfEqual, and "end" as an early-exit
# inside a conditional. The linter follows observed parser behaviour, not
# just the manual.
HEADER_KEYWORDS = {"description", "applies_to", "appliesto", "fixed_start",
                   "sector-aligned", "requires", "big-endian",
                   "little-endian", "hexadecimal", "octal", "read-only",
                   "multiple"}
MODIFIERS = {"big-endian", "little-endian", "hexadecimal", "decimal", "octal",
             "read-only", "read-write", "hidden", "local"}
BODY_TYPES = ({t.lower() for t, _ in TYPES.values()}
              | {"uint_flex", "zstring", "zstring16", "appledatetime"})
SIZED = {"string", "string16", "hex"}


def strip_comment(line):
    """Remove // comments, respecting quoted strings."""
    out, i, inq = [], 0, False
    while i < len(line):
        c = line[i]
        if c == '"':
            inq = not inq
        elif not inq and c == "/" and line[i:i + 2] == "//":
            break
        out.append(c)
        i += 1
    return "".join(out).rstrip()


def tokens(line):
    """Split into tokens, keeping quoted strings whole and bracket
    expressions (which may contain spaces: char[Description length])
    attached to their type. A quote always starts a new token even without
    preceding whitespace."""
    return re.findall(r'"[^"]*"|[^"\s\[]+\[[^\]]*\]|[^"\s]+', line)


def check_file(path):
    """Lint one template. Returns (errors, warnings) as lists of strings."""
    errs, warns = [], []
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
    except OSError as e:
        return [f"unreadable: {e}"], []
    lines = raw.splitlines()
    state = "header"
    seen_template = seen_begin = seen_end = False
    depth_brace = if_depth = 0
    in_section = False
    for ln, line in enumerate(lines, 1):
        text = strip_comment(line).strip()
        if not text:
            continue
        # a line that is only a quoted string is the continuation title of
        # the previous declaration (observed in published templates)
        if re.fullmatch(r'"[^"]*"', text):
            continue
        # leading '{' opens a repeat block; may also trail a statement
        while text.startswith("{"):
            if state != "body":
                errs.append(f"{ln}: block outside body")
            depth_brace += 1
            if depth_brace > 1:
                errs.append(f"{ln}: nested {{}} blocks are not supported")
            text = text[1:].strip()
        if text.endswith("{"):
            if state != "body":
                errs.append(f"{ln}: block outside body")
            depth_brace += 1
            if depth_brace > 1:
                errs.append(f"{ln}: nested {{}} blocks are not supported")
            text = text[:-1].strip()
        # '}' closes it, optionally with a repeat count: }[10] }[n]
        # }["var name"] }[unlimited] -- but only a '}' outside quotes counts
        close = -1
        inq = False
        for i, c in enumerate(text):
            if c == '"':
                inq = not inq
            elif c == "}" and not inq:
                close = i
        if close >= 0 and re.fullmatch(r"\s*(\[[^\]]*\])?",
                                       text[close + 1:]):
            text = text[:close].strip()
            if depth_brace == 0:
                errs.append(f"{ln}: '}}' without matching '{{'")
            else:
                depth_brace -= 1
        if not text:
            continue
        toks = tokens(text)
        head = toks[0].lower()
        if not seen_template:
            if head != "template":
                errs.append(f"{ln}: first statement must be template "
                            f"\"title\", found {toks[0]!r}")
                seen_template = True  # avoid cascading
            else:
                seen_template = True
                if len(toks) < 2:
                    errs.append(f"{ln}: template keyword without a title")
            continue
        if state == "header":
            if head == "begin":
                state, seen_begin = "body", True
            elif head in HEADER_KEYWORDS:
                if head == "requires":
                    if len(toks) < 3:
                        errs.append(f"{ln}: requires needs offset and hex")
                    else:
                        hx = toks[2].strip('"').replace(" ", "")
                        if len(hx) % 2 or not re.fullmatch(
                                r"[0-9A-Fa-f]+", hx):
                            errs.append(f"{ln}: requires hex chain "
                                        f"{toks[2]!r} is not even-length hex")
                elif head in ("applies_to", "appliesto"):
                    vals = (toks[1].lower().split("/") if len(toks) > 1
                            else [])
                    if not vals or any(v not in ("file", "disk", "ram")
                                       for v in vals):
                        errs.append(f"{ln}: applies_to must be file, disk, "
                                    f"or RAM (or a / combination)")
            else:
                errs.append(f"{ln}: unknown header keyword {toks[0]!r}")
            continue
        # body ------------------------------------------------------------
        if head == "end":
            # inside a conditional or repeat block, "end" terminates
            # interpretation early (like Exit); published templates also
            # leave else-if chains unclosed, so any end may be the real one
            seen_end = True
            if if_depth == 0 and depth_brace == 0:
                state = "after-end"
            continue
        if state == "after-end":
            errs.append(f"{ln}: content after end")
            continue
        # strip modifiers
        while head in MODIFIERS and len(toks) > 1:
            toks = toks[1:]
            head = toks[0].lower()
        if head == "const":
            if len(toks) < 4:
                errs.append(f"{ln}: const needs type, value, and name")
            continue
        base = re.match(r"([a-z_0-9]+)(\[.*\])?$", head)
        base_t = base.group(1) if base else head
        if base_t in BODY_TYPES:
            if base_t in SIZED and (not base or not base.group(2)):
                if len(toks) < 2:
                    errs.append(f"{ln}: {base_t} needs a size parameter")
            elif base_t == "uint_flex":
                if len(toks) < 2 or not re.fullmatch(
                        r"[0-9,\s]+", toks[1].strip('"')):
                    errs.append(f"{ln}: uint_flex needs a quoted bit list")
            name = toks[-1].strip('"')
            if len(toks) >= 2 and toks[-1].startswith('"') \
                    and len(name) > 41:
                warns.append(f"{ln}: variable name over 41 chars is "
                             f"truncated: {name[:30]}...")
            if len(toks) >= 2 and name.isdigit() and len(toks) == 2 \
                    and base_t not in SIZED:
                errs.append(f"{ln}: variable title must not be only digits")
            continue
        if head in ("ifequal", "ifgreater"):
            if if_depth:
                warns.append(f"{ln}: nested {toks[0]} (undocumented; "
                             f"verify against a current X-Ways build)")
            if_depth += 1
            if len(toks) < 3:
                errs.append(f"{ln}: {toks[0]} needs two operands")
            continue
        if head == "endif":
            if not if_depth:
                warns.append(f"{ln}: stray endif (no open "
                             f"ifequal/ifgreater; X-Ways ignores it)")
            else:
                if_depth -= 1
            continue
        if head == "else":
            if not if_depth:
                warns.append(f"{ln}: else outside ifequal/ifgreater")
            continue
        if head == "section":
            if in_section:
                warns.append(f"{ln}: section inside section")
            in_section = True
            continue
        if head == "endsection":
            if not in_section:
                warns.append(f"{ln}: endsection without section")
            in_section = False
            continue
        if head in ("move", "goto", "gotoex", "numbering", "multiple"):
            if len(toks) < 2:
                errs.append(f"{ln}: {toks[0]} needs a parameter")
            continue
        if head in ("exitloop", "exit"):
            continue
        errs.append(f"{ln}: unrecognised statement {toks[0]!r}")
    if not seen_template:
        errs.append("no template header found")
    if seen_template and not seen_begin:
        errs.append("no begin statement")
    if seen_begin and not seen_end:
        errs.append("no end statement")
    if depth_brace:
        errs.append("unclosed { block")
    if if_depth:
        # X-Ways tolerates unterminated else-if chains (published templates
        # rely on it), so this is style, not structure
        warns.append("unclosed ifequal/ifgreater at end of template")
    return errs, warns


# ------------------------------------------------------------------ selftest

FIXTURE_SPEC = {
    # the make_fixture.py page header -- known ground truth
    "name": "Fixture page header (selftest)",
    "desc": "Page header of the make_fixture.py synthetic format",
    "applies_to": "file",
    "requires": [{"offset": 0, "hex": "CDABCCAC"}],  # LE bytes on disk
    "record_size": 8192,
    "fields": [
        {"offset": 0, "size": 4, "type": "hex", "name": "magic",
         "status": "established"},
        {"offset": 4, "size": 4, "type": "uint32", "name": "page id",
         "status": "established"},
        {"offset": 8, "size": 2, "type": "uint16", "name": "page type",
         "status": "established"},
        {"offset": 10, "size": 2, "type": "uint16", "name": "record count",
         "status": "established"},
        {"offset": 16, "size": 8, "type": "filetime", "name": "last write",
         "status": "established"},
        {"offset": 24, "size": 4, "type": "uint32", "name": "crc32",
         "status": "established", "comment": "CRC-32/ISO-HDLC over 32..8192"},
        {"offset": 28, "size": 4, "type": "uint32", "name": "data offset",
         "status": "inferred"},
    ],
}

BAD_TPL = """\
template "Broken"
applies_two file
requires 0 "ABC"
begin
    uint32 count
    ifequal count 1
    ifequal count 2
    endif
    mystery 4 "what"
"""


def selftest():
    import tempfile
    ok = True
    text = generate(FIXTURE_SPEC)
    with tempfile.TemporaryDirectory() as td:
        good = os.path.join(td, "good.tpl")
        bad = os.path.join(td, "bad.tpl")
        with open(good, "w", encoding="utf-8") as f:
            f.write(text)
        with open(bad, "w", encoding="utf-8") as f:
            f.write(BAD_TPL)
        errs, warns = check_file(good)
        if errs:
            ok = False
            print("FAIL generated template did not lint clean:")
            for e in errs:
                print("   ", e)
        else:
            print("ok   generated fixture template lints clean "
                  f"({len(text.splitlines())} lines)")
        errs, _ = check_file(bad)
        expect = ["applies_two", "not even-length hex",
                  "mystery", "no end statement"]
        missing = [e for e in expect if not any(e in x for x in errs)]
        if missing:
            ok = False
            print(f"FAIL bad template: expected complaints about {missing}, "
                  f"got {errs}")
        else:
            print(f"ok   bad template caught ({len(errs)} errors)")
    # gap filling: a sparse layout must produce contiguous coverage
    sparse = dict(FIXTURE_SPEC, fields=[FIXTURE_SPEC["fields"][0],
                                        FIXTURE_SPEC["fields"][4]])
    t = generate(sparse)
    if 'hex 12 "unknown +0x4"' in t and 'hex 8168 "unknown +0x18"' in t:
        print("ok   gaps emitted as bounded unknowns")
    else:
        ok = False
        print("FAIL gap filling missing:\n" + t)
    print("selftest", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Generate X-Ways templates from established layouts; "
                    "lint existing .tpl files.")
    ap.add_argument("--name", help="template title")
    ap.add_argument("--desc", default="", help="one-line description")
    ap.add_argument("--applies-to", default="file",
                    choices=["file", "disk", "RAM"])
    ap.add_argument("--requires", action="append", default=[],
                    metavar="OFF:HEX", help="magic guard (repeatable)")
    ap.add_argument("--field", action="append", default=[],
                    metavar="OFF:SIZE:TYPE:NAME[:STATUS]",
                    help="field (repeatable); status defaults to inferred")
    ap.add_argument("--stride", type=int, default=0,
                    help="record size; enables multiple-record navigation "
                         "and pads the tail as unknown")
    ap.add_argument("--big-endian", action="store_true")
    ap.add_argument("--editable", action="store_true",
                    help="omit read-only (default templates are read-only)")
    ap.add_argument("--version-scope", default="",
                    help="producer versions the layout was established on")
    ap.add_argument("--date", default="", help="generation date for the "
                    "header comment (omitted if not given; keeps output "
                    "deterministic)")
    ap.add_argument("--spec", help="JSON layout file (see docstring)")
    ap.add_argument("-o", "--out", help="output .tpl path (default stdout)")
    ap.add_argument("--check", nargs="+", metavar="TPL",
                    help="lint template files (globs ok) instead of "
                         "generating")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.check:
        paths = []
        for pat in args.check:
            hits = glob.glob(pat, recursive=True)
            paths.extend(hits if hits else [pat])
        total_e = total_w = 0
        for p in paths:
            errs, warns = check_file(p)
            total_e += len(errs)
            total_w += len(warns)
            status = "ok  " if not errs else "FAIL"
            print(f"{status} {p}"
                  + (f"  ({len(errs)} errors, {len(warns)} warnings)"
                     if errs or warns else ""))
            for e in errs:
                print(f"      error   {e}")
            for w in warns:
                print(f"      warning {w}")
        print(f"{len(paths)} files, {total_e} errors, {total_w} warnings")
        sys.exit(1 if total_e else 0)

    if args.spec:
        with open(args.spec, encoding="utf-8") as f:
            cfg = json.load(f)
        cfg.setdefault("fields", [])
        for f_ in cfg["fields"]:
            f_.setdefault("status", "inferred")
            typ = f_.get("type", "hex").lower()
            if typ not in TYPES:
                raise SystemExit(f"spec field {f_.get('name')!r}: unknown "
                                 f"type {typ!r}")
            f_["type"] = typ
            fixed = TYPES[typ][1]
            if fixed is not None:
                f_.setdefault("size", fixed)
    else:
        if not args.name or not args.field:
            ap.error("need --name and at least one --field "
                     "(or --spec / --check / --selftest)")
        cfg = {"name": args.name, "desc": args.desc,
               "applies_to": args.applies_to,
               "requires": [parse_requires(r) for r in args.requires],
               "record_size": args.stride or None,
               "big_endian": args.big_endian,
               "editable": args.editable,
               "version_scope": args.version_scope,
               "date": args.date,
               "fields": [parse_field(f) for f in args.field]}

    out = generate(cfg)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
