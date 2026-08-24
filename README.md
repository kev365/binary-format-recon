# binary-format-recon

A [Claude Code](https://claude.com/claude-code) skill for reverse engineering
undocumented or partially documented binary file formats, built for forensic
parsing and tool building: WMI repositories, registry hives, event logs,
proprietary application data, firmware blobs — anything opaque that needs to
become a documented, testable parser.

The discipline it encodes is simple to state and easy to abandon under time
pressure: **a field is not real until a controlled change proves it real.**
Pattern-matching produces plausible layouts quickly, and plausible layouts
are how forensic tools end up silently mis-reporting evidence. Everything
here is organised around generating hypotheses cheaply, then trying hard to
kill them.

## What's inside

- **[SKILL.md](SKILL.md)** — the method: an eight-phase loop from provenance
  and triage through anchors, structure, differential confirmation,
  specification, corpus validation, and reporting, plus three ways into a
  format (from bytes, from the producing binary, from the gaps in a known
  spec).
- **scripts/** — 21 tools, all Python 3 stdlib, no installs, no network:
  entropy/stride profiling, timestamp and string scanning with
  false-positive baselines, column-wise record profiling, checksum
  identification, differential baselining with control-pair noise
  subtraction, corpus clustering, round-trip validation, signature emission
  (Yara/libmagic/PRONOM/Velociraptor), and X-Ways template
  generation/linting. Every non-trivial tool self-tests; `make_fixture.py`
  builds a synthetic format with known ground truth to verify the whole kit.
- **references/** — thirteen deep-dive documents loaded as needed: where
  formats are already documented, the full workflow, producer-side analysis,
  residual-data analysis, validation, evidentiary standards (ISO 27037/27041,
  SWGDE), encodings, and the X-Ways template language.
- **templates/** — a curated X-Ways/WinHex template collection:
  [INDEX.md](templates/INDEX.md) catalogues 117 community templates with
  per-template trust status and a list of documented structures that still
  lack one. The template files themselves are third-party and are **not
  redistributed here** — `python templates/fetch_templates.py` rebuilds the
  local working copy from the original sources (see Licensing below).
- **assets/** — fill-in skeletons: a libyal-style format spec, a hypothesis
  ledger, and Kaitai `.ksy` / ImHex `.hexpat` / X-Ways `.tpl` starting
  points.

## Install

Clone into your Claude Code skills directory — personal:

```bash
git clone https://github.com/kev365/binary-format-recon ~/.claude/skills/binary-format-recon
```

or per-project under `.claude/skills/`. Claude triggers it when a task
involves unknown binary formats, hex-level analysis, or the forensic
artefacts named in the skill description.

The scripts also work standalone, without Claude:

```bash
python scripts/make_fixture.py ./fx        # synthetic format, known answers
python scripts/profile.py fx/before.bin    # entropy, signatures, stride
python scripts/tsscan.py fx/before.bin --stride 8192
python scripts/bindiff.py fx/before.bin fx/after.bin --stride 8192 \
    --noise fx/ctrl_a.bin fx/ctrl_b.bin
```

Requirements: Python 3.8+. Nothing else.

## The X-Ways template collection

`templates/INDEX.md` doubles as a prior-art gallery (don't reverse what a
working template already documents) and a to-make list (documented structures
with no template yet). `scripts/tplgen.py` turns an established layout into a
`.tpl` with every field's evidence status as a comment and every gap as a
labelled unknown, and lints any template against the real grammar — the
documented syntax corrected against the observed behaviour of the published
corpus (`references/xways-templates.md`).

## Licensing

Original content (the skill, scripts, references, assets, and our own
templates) is [MIT](LICENSE). The imported X-Ways templates indexed in
`templates/INDEX.md` are third-party work with mixed or unstated licensing
and are deliberately excluded from this repository; the fetch script pulls
them from their original locations, and
`templates/imported/PROVENANCE.json` records source, contributor, and licence
for every file. Credits: Costas Katsavounidis
([kacos2000/WinHex_Templates](https://github.com/kacos2000/WinHex_Templates),
GPL-3.0), the contributors to the
[x-ways.net template page](https://www.x-ways.net/winhex/templates/), and
X-Ways Software Technology AG for the template language and the shipped
default templates.
