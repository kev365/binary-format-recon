#!/usr/bin/env python3
"""Track source review so nothing gets skimmed and nothing gets abandoned.

Two failure modes this exists to prevent.

The first is skimming: reading the three sections of a specification that
look relevant, missing the fourth that redefines a field, and building a
parser on a partial reading. The fix is to enumerate the units of a source
*before* reading, so the denominator is fixed in advance and coverage is
measurable against it rather than against what happened to seem interesting.

The second is drift: while reading source A you hit a reference to B, chase
B, and never come back. Cross-references are recorded here as explicit
obligations attached to the unit that raised them, and a source cannot be
closed while any remain open.

Nothing here reads a document for you. It holds you to finishing one.

Usage:
  review_tracker.py add "MS-CFB" --kind spec --locator URL \\
      --scope "sections 2.1-2.6" --units "2.1 Sectors,2.2 Header,2.3 FAT"
  review_tracker.py mark src-1 1 --note "512/4096 byte sectors" \\
      --finding "sector size is a header field, not fixed"
  review_tracker.py xref src-1 --from-unit 2 --target "MS-DTYP FILETIME"
  review_tracker.py status
  review_tracker.py open
  review_tracker.py close src-1
"""
import argparse
import datetime as dt
import json
import os
import sys

DEFAULT_STATE = ".review-state.json"
KINDS = ["spec", "implementation", "gallery-entry", "wiki", "paper",
         "corpus", "tool-output", "other"]

# How a unit came to be skipped. The split that matters is whether the unit was
# ASSESSED and ruled out, or never looked at -- because only the second kind
# represents material that might still change the conclusions. Anything marked
# unassessed is surfaced as a candidate for further investigation so the
# decision to stop belongs to the reader, not to whoever ran out of time.
SKIP_CLASSES = {
    "not-relevant":  (True,  "assessed and found not to bear on the question"),
    "superseded":    (True,  "covered by another source or a later version"),
    "duplicate":     (True,  "same material already reviewed elsewhere"),
    "out-of-scope":  (False, "outside the declared scope; may hold relevant material"),
    "deferred":      (False, "likely relevant, not yet examined"),
    "low-yield":     (False, "judged unlikely to be relevant, without reading it"),
    "inaccessible":  (False, "paywalled, missing, corrupt, or otherwise unavailable"),
}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def load(path):
    if not os.path.exists(path):
        return {"created": now(), "case": "", "sources": {}, "seq": 0}
    with open(path) as fh:
        return json.load(fh)


def save(path, state):
    with open(path, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")


def get_source(state, sid):
    src = state["sources"].get(sid)
    if not src:
        ids = ", ".join(sorted(state["sources"])) or "(none)"
        raise SystemExit(f"no such source '{sid}'. Known: {ids}")
    return src


def counts(src):
    done = sum(1 for u in src["units"] if u["status"] == "done")
    skipped = sum(1 for u in src["units"] if u["status"] == "skipped")
    pending = sum(1 for u in src["units"] if u["status"] == "pending")
    open_x = sum(1 for x in src["xrefs"] if x["status"] == "open")
    return done, skipped, pending, open_x


def bar(done, skipped, total, width=24):
    if not total:
        return "-" * width
    d = int(width * done / total)
    s = int(width * skipped / total)
    return "#" * d + "~" * s + "." * (width - d - s)


# ------------------------------------------------------------------ commands

def cmd_add(args, state, path):
    state["seq"] += 1
    sid = args.id or f"src-{state['seq']}"
    if sid in state["sources"]:
        raise SystemExit(f"source id '{sid}' already exists")

    units = []
    raw = []
    if args.units:
        raw += [u.strip() for u in args.units.split(",")]
    if args.units_file:
        with open(args.units_file) as fh:
            raw += [ln.strip() for ln in fh if ln.strip()]
    raw = [u for u in raw if u]
    if not raw:
        raise SystemExit(
            "a source needs its units enumerated up front -- pass --units or\n"
            "--units-file. Fixing the denominator before reading is the whole\n"
            "point: coverage measured against what you happened to read is not\n"
            "coverage. Use section headings, chapter numbers, page ranges,\n"
            "function names, or sample filenames, whatever the natural unit is.")
    for i, label in enumerate(raw, 1):
        units.append({"n": i, "label": label, "status": "pending",
                      "note": "", "reason": "", "class": ""})

    state["sources"][sid] = {
        "id": sid, "name": args.name, "kind": args.kind,
        "locator": args.locator or "", "scope": args.scope or "",
        "status": "in_progress", "opened": now(), "closed": "",
        "close_reason": "", "units": units, "findings": [], "xrefs": [],
    }
    save(path, state)
    print(f"{sid}  {args.name}  [{args.kind}]  {len(units)} unit(s) to review")
    if args.scope:
        print(f"  declared scope: {args.scope}")
    print("\nScope is a commitment, not an estimate. If it turns out to be wrong,\n"
          "widen it explicitly with `units --add` rather than quietly reading less.")


def cmd_units(args, state, path):
    src = get_source(state, args.source)
    if args.add:
        start = len(src["units"])
        for i, label in enumerate([u.strip() for u in args.add.split(",") if u.strip()],
                                  start + 1):
            src["units"].append({"n": i, "label": label, "status": "pending",
                                 "note": "", "reason": "", "class": ""})
        save(path, state)
        print(f"{src['id']}: now {len(src['units'])} unit(s)")
    for u in src["units"]:
        flag = {"done": "[x]", "pending": "[ ]", "skipped": "[~]"}[u["status"]]
        print(f"  {flag} {u['n']:>3}. {u['label']}")
        if u["note"]:
            print(f"          {u['note']}")
        if u["reason"]:
            print(f"          skipped: {u['reason']}")


def cmd_mark(args, state, path):
    src = get_source(state, args.source)
    matches = [u for u in src["units"] if u["n"] == args.unit]
    if not matches:
        raise SystemExit(f"unit {args.unit} not in {src['id']} "
                         f"(1..{len(src['units'])})")
    u = matches[0]
    if u["status"] == "done" and not args.reopen:
        print(f"note: unit {u['n']} was already marked done; updating it")
    u["status"] = "done"
    if args.note:
        u["note"] = args.note

    for text, kind in ([(f, "fact") for f in args.finding] +
                       [(c, "conflict") for c in args.conflict] +
                       [(g, "gap") for g in args.gap]):
        src["findings"].append({"unit": u["n"], "kind": kind, "text": text,
                                "at": now()})
    for target in args.xref:
        src["xrefs"].append({"n": len(src["xrefs"]) + 1, "from_unit": u["n"],
                             "target": target, "status": "open",
                             "resolution": "", "at": now()})

    save(path, state)
    done, skipped, pending, open_x = counts(src)
    total = len(src["units"])
    print(f"{src['id']} unit {u['n']} done: {u['label']}")
    print(f"  {bar(done, skipped, total)}  {done}/{total} done, "
          f"{skipped} skipped, {pending} pending, {open_x} open xref(s)")
    if args.conflict:
        print("  conflict recorded -- a source disagreeing with another source or\n"
              "  with your samples is a finding in its own right. Do not silently\n"
              "  pick a winner; record which one your corpus supports.")
    if pending == 0 and open_x == 0:
        print(f"  all units covered -- run `close {src['id']}`")
    elif pending:
        nxt = next(x for x in src["units"] if x["status"] == "pending")
        print(f"  next: {nxt['n']}. {nxt['label']}")


def cmd_skip(args, state, path):
    src = get_source(state, args.source)
    matches = [u for u in src["units"] if u["n"] == args.unit]
    if not matches:
        raise SystemExit(f"unit {args.unit} not in {src['id']}")
    u = matches[0]
    u["status"] = "skipped"
    u["reason"] = args.reason
    u["class"] = args.cls
    save(path, state)
    assessed, meaning = SKIP_CLASSES[args.cls]
    print(f"{src['id']} unit {u['n']} skipped [{args.cls}]: {u['label']}")
    print(f"  reason: {args.reason}")
    print(f"  class:  {meaning}")
    if assessed:
        print("  Assessed and ruled out -- recorded as a bounded limitation.")
    else:
        print("  NOT assessed. This unit could still change the conclusions, so it\n"
              "  is surfaced in `status`, `close`, and `report` as a candidate for\n"
              "  further investigation. Whether to pursue it is the reader's call,\n"
              "  which is why it has to reach them rather than stopping here.")


def cmd_xref(args, state, path):
    src = get_source(state, args.source)
    if args.resolve is not None:
        hits = [x for x in src["xrefs"] if x["n"] == args.resolve]
        if not hits:
            raise SystemExit(f"no xref {args.resolve} in {src['id']}")
        x = hits[0]
        x["status"] = "resolved"
        x["resolution"] = args.note or ""
        save(path, state)
        print(f"{src['id']} xref {x['n']} resolved: {x['target']}")
        if x["resolution"]:
            print(f"  {x['resolution']}")
        remaining = sum(1 for y in src["xrefs"] if y["status"] == "open")
        print(f"  {remaining} open xref(s) remain on this source")
        return
    if not args.target:
        for x in src["xrefs"]:
            flag = "[ ]" if x["status"] == "open" else "[x]"
            print(f"  {flag} {x['n']:>3}. from unit {x['from_unit']}: {x['target']}")
            if x["resolution"]:
                print(f"          -> {x['resolution']}")
        return
    src["xrefs"].append({"n": len(src["xrefs"]) + 1,
                         "from_unit": args.from_unit or 0,
                         "target": args.target, "status": "open",
                         "resolution": "", "at": now()})
    save(path, state)
    print(f"{src['id']} xref {len(src['xrefs'])} opened: {args.target}")
    print("  Chase it when the current source is finished, not mid-unit.\n"
          "  Following a citation immediately is how a review gets abandoned\n"
          "  three levels deep with nothing completed.")


def cmd_status(args, state, path):
    srcs = ([get_source(state, args.source)] if args.source
            else [state["sources"][k] for k in sorted(state["sources"])])
    if not srcs:
        print("no sources registered. Add one with `add`.")
        return
    print(f"review state: {path}")
    if state.get("case"):
        print(f"case: {state['case']}")
    print()
    tot_pending = tot_open = 0
    for src in srcs:
        done, skipped, pending, open_x = counts(src)
        total = len(src["units"])
        tot_pending += pending if src["status"] == "in_progress" else 0
        tot_open += open_x if src["status"] == "in_progress" else 0
        mark = {"in_progress": "OPEN", "complete": "DONE",
                "abandoned": "ABND"}[src["status"]]
        print(f"[{mark}] {src['id']}  {src['name']}  ({src['kind']})")
        if src["locator"]:
            print(f"       {src['locator']}")
        if src["scope"]:
            print(f"       scope: {src['scope']}")
        print(f"       {bar(done, skipped, total)}  {done}/{total} done"
              + (f", {skipped} skipped" if skipped else "")
              + (f", {pending} pending" if pending else "")
              + (f", {open_x} open xref(s)" if open_x else ""))
        if args.verbose:
            for u in src["units"]:
                if u["status"] != "done" or args.verbose > 1:
                    flag = {"done": "[x]", "pending": "[ ]", "skipped": "[~]"}[u["status"]]
                    print(f"         {flag} {u['n']:>3}. {u['label']}")
        unassessed = [u for u in src["units"]
                      if u["status"] == "skipped"
                      and not SKIP_CLASSES.get(u.get("class"), (True, ""))[0]]
        if unassessed:
            print(f"       {len(unassessed)} skipped without assessment "
                  f"(open avenue): " +
                  ", ".join(f"{u['class']}" for u in unassessed[:4]))
        kinds = {}
        for f in src["findings"]:
            kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
        if kinds:
            print("       findings: " +
                  ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
        print()
    if tot_pending or tot_open:
        print(f"OUTSTANDING: {tot_pending} unit(s) unread, {tot_open} "
              f"cross-reference(s) unresolved.")
        print("Finish these before starting a new source or writing conclusions.")
    else:
        print("All registered sources are fully covered.")


def cmd_open(args, state, path):
    rows = []
    for sid in sorted(state["sources"]):
        src = state["sources"][sid]
        if src["status"] != "in_progress":
            continue
        for u in src["units"]:
            if u["status"] == "pending":
                rows.append((sid, src["name"], f"unit {u['n']}", u["label"]))
        for x in src["xrefs"]:
            if x["status"] == "open":
                rows.append((sid, src["name"], f"xref {x['n']}",
                             f"-> {x['target']} (from unit {x['from_unit']})"))
    if not rows:
        print("Nothing outstanding. Every started review is finished.")
        return
    print(f"{len(rows)} outstanding item(s)\n")
    cur = None
    for sid, name, what, label in rows:
        if sid != cur:
            print(f"{sid}  {name}")
            cur = sid
        print(f"   {what:<10} {label}")
    print("\nThis is the list of things started and not finished. Work it down\n"
          "before opening anything new.")


def cmd_close(args, state, path):
    src = get_source(state, args.source)
    done, skipped, pending, open_x = counts(src)
    unclassified = [u for u in src["units"]
                    if u["status"] == "skipped" and not u.get("class")]
    if unclassified and not args.force:
        print(f"cannot close {src['id']}: {len(unclassified)} skipped unit(s) "
              f"have no classification.\n")
        for u in unclassified:
            print(f"  unit {u['n']:>3}. {u['label']}")
        print("\nRe-skip each with --class so the report can distinguish material\n"
              "that was assessed and ruled out from material nobody looked at.")
        raise SystemExit(1)
    if (pending or open_x) and not args.force:
        print(f"cannot close {src['id']}: {pending} unit(s) unread, "
              f"{open_x} cross-reference(s) unresolved.\n")
        for u in src["units"]:
            if u["status"] == "pending":
                print(f"  unit {u['n']:>3}. {u['label']}")
        for x in src["xrefs"]:
            if x["status"] == "open":
                print(f"  xref {x['n']:>3}. -> {x['target']}")
        print("\nFinish them, or `skip` each with a reason, or re-run with\n"
              "--force --reason '...' to abandon the review on the record.")
        raise SystemExit(1)
    src["status"] = "abandoned" if (pending or open_x) else "complete"
    src["closed"] = now()
    src["close_reason"] = args.reason or ""
    save(path, state)
    total = len(src["units"])
    print(f"{src['id']} {src['status']}: {done}/{total} reviewed, {skipped} skipped")
    unassessed = [u for u in src["units"]
                  if u["status"] == "skipped"
                  and not SKIP_CLASSES.get(u.get("class"), (True, ""))[0]]
    if unassessed:
        print(f"\n  {len(unassessed)} unit(s) skipped WITHOUT assessment -- carry\n"
              f"  these into the report as open avenues, not as closed questions:")
        for u in unassessed:
            print(f"    [{u['class']}] {u['label']} -- {u['reason']}")
    if src["status"] == "abandoned":
        print(f"  reason: {src['close_reason']}")
        print("  An abandoned review is a limitation of your analysis. Carry it\n"
              "  into the report rather than leaving it in this file.")
    else:
        print("  Full coverage of the declared scope.")


def cmd_report(args, state, path):
    print("# Source review record\n")
    if state.get("case"):
        print(f"Case: {state['case']}\n")
    for sid in sorted(state["sources"]):
        src = state["sources"][sid]
        done, skipped, pending, open_x = counts(src)
        total = len(src["units"])
        print(f"## {src['name']}  ({src['kind']})")
        if src["locator"]:
            print(f"Source: {src['locator']}")
        if src["scope"]:
            print(f"Declared scope: {src['scope']}")
        print(f"Status: {src['status']} -- {done}/{total} units reviewed, "
              f"{skipped} skipped, {pending} unread, {open_x} xrefs open")
        if src["close_reason"]:
            print(f"Close reason: {src['close_reason']}")
        skips = [u for u in src["units"] if u["status"] == "skipped"]
        ruled_out = [u for u in skips
                     if SKIP_CLASSES.get(u.get("class"), (True, ""))[0]]
        open_av = [u for u in skips if u not in ruled_out]
        if ruled_out:
            print("\nAssessed and excluded:")
            for u in ruled_out:
                print(f"- {u['label']} [{u.get('class') or 'unclassified'}] "
                      f"-- {u['reason']}")
        if open_av:
            print("\nNot examined -- available for further investigation:")
            for u in open_av:
                print(f"- {u['label']} [{u.get('class') or 'unclassified'}] "
                      f"-- {u['reason']}")
        if pending:
            label = ("Unread at close" if src["status"] != "in_progress"
                     else "Still unread (review not finished)")
            print(f"\n{label}:")
            for u in src["units"]:
                if u["status"] == "pending":
                    print(f"- {u['label']}")
        for kind, header in (("conflict", "Conflicts found"),
                             ("gap", "Gaps in the source"),
                             ("fact", "Findings")):
            items = [f for f in src["findings"] if f["kind"] == kind]
            if items:
                print(f"\n{header}:")
                for f in items:
                    print(f"- (unit {f['unit']}) {f['text']}")
        unres = [x for x in src["xrefs"] if x["status"] == "open"]
        if unres:
            print("\nUnresolved cross-references:")
            for x in unres:
                print(f"- {x['target']} (raised at unit {x['from_unit']})")
        print()
    print("Material listed under \"Not examined\" was never assessed, so it may\n"
          "still bear on the conclusions. It is reported as an available avenue\n"
          "rather than a closed question, so that the decision to pursue it or\n"
          "not sits with the reader. Everything above belongs in the analysis's\n"
          "limitations section, not only in this file.")


def _quiet_pipe():
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass


def build_parser():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default=DEFAULT_STATE,
                    help=f"state file (default: {DEFAULT_STATE})")
    ap.add_argument("--case", help="set a case/investigation note")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="register a source and enumerate its units")
    a.add_argument("name")
    a.add_argument("--id", help="explicit source id (default: src-N)")
    a.add_argument("--kind", default="spec", choices=KINDS)
    a.add_argument("--locator", help="URL or path")
    a.add_argument("--scope", help="what you are committing to review")
    a.add_argument("--units", help="comma-separated unit labels")
    a.add_argument("--units-file", help="file with one unit label per line")
    a.set_defaults(func=cmd_add)

    u = sub.add_parser("units", help="list or extend a source's units")
    u.add_argument("source")
    u.add_argument("--add", help="comma-separated labels to append")
    u.set_defaults(func=cmd_units)

    m = sub.add_parser("mark", help="mark a unit reviewed")
    m.add_argument("source")
    m.add_argument("unit", type=int)
    m.add_argument("--note", help="what this unit actually said")
    m.add_argument("--finding", action="append", default=[],
                   help="a fact established (repeatable)")
    m.add_argument("--conflict", action="append", default=[],
                   help="a disagreement with another source or your samples")
    m.add_argument("--gap", action="append", default=[],
                   help="something the source leaves undefined")
    m.add_argument("--xref", action="append", default=[],
                   help="a reference this unit raises that must be chased")
    m.add_argument("--reopen", action="store_true")
    m.set_defaults(func=cmd_mark)

    s = sub.add_parser(
        "skip", help="skip a unit, on the record, classified",
        description="Classify every skip. The split that matters is whether the "
                    "unit was assessed and ruled out, or never examined -- only "
                    "the second kind can still change your conclusions.\n\n" +
                    "\n".join(f"  {k:<14} {v[1]}" for k, v in SKIP_CLASSES.items()),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("source")
    s.add_argument("unit", type=int)
    s.add_argument("--reason", required=True)
    s.add_argument("--class", dest="cls", required=True, choices=list(SKIP_CLASSES),
                   help="why it was skipped, from the fixed vocabulary")
    s.set_defaults(func=cmd_skip)

    x = sub.add_parser("xref", help="open, list, or resolve cross-references")
    x.add_argument("source")
    x.add_argument("--target", help="what must be checked")
    x.add_argument("--from-unit", type=int)
    x.add_argument("--resolve", type=int, metavar="N")
    x.add_argument("--note", help="how it was resolved")
    x.set_defaults(func=cmd_xref)

    st = sub.add_parser("status", help="coverage across sources")
    st.add_argument("source", nargs="?")
    st.add_argument("-v", "--verbose", action="count", default=0)
    st.set_defaults(func=cmd_status)

    o = sub.add_parser("open", help="everything started and not finished")
    o.set_defaults(func=cmd_open)

    c = sub.add_parser("close", help="close a source; refuses if work remains")
    c.add_argument("source")
    c.add_argument("--force", action="store_true")
    c.add_argument("--reason")
    c.set_defaults(func=cmd_close)

    r = sub.add_parser("report", help="markdown record for the writeup")
    r.set_defaults(func=cmd_report)
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    state = load(args.file)
    if args.case:
        state["case"] = args.case
    if args.cmd == "close" and args.force and not args.reason:
        ap.error("--force requires --reason")
    args.func(args, state, args.file)


if __name__ == "__main__":
    _quiet_pipe()
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        raise SystemExit(130)
