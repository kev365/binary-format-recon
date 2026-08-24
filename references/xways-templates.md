# X-Ways / WinHex templates

A template (`.tpl`) is a small declarative script that X-Ways Forensics and
WinHex overlay onto bytes at the cursor: each declaration reads a typed value
and shows it, named, in a dialog. Applied to a sample, a template is the
fastest way to *show* a claimed layout against real data — which makes it two
things for this skill:

- **Prior art.** Somebody who published a working template has already done
  part of the job. The collection in `templates/imported/` (117 templates
  from kacos2000's WinHex_Templates repository and the x-ways.net
  contributions page) is checked before reversing anything, alongside the
  galleries in `format-galleries.md`. `templates/INDEX.md` is the master
  index; regenerate it with `tpl_index.py --write` and record judgements in
  `templates/curation.json`, never in the generated file.
- **A findings ledger you can execute.** `tplgen.py` emits a template from
  the current layout hypothesis, with every field's evidence status as a
  comment and every unexamined gap as a labelled `hex` run. Applying it in
  X-Ways over several corpus samples is a fast visual Phase 7 check, and
  handing it to another examiner is publishing the finding in a form their
  tooling already reads.

## The language, distilled

Source: Appendix A of the X-Ways/WinHex manual (x-ways.net/winhex/manual.pdf),
corrected against the observed behaviour of 117 published templates — the
manual understates what the parser accepts; divergences are marked
*(observed)* below.

### Header

```text
template "Title"                  // mandatory, first statement
description "..."
applies_to file                   // file | disk | RAM; "file/disk" (observed)
fixed_start 0                     // absolute start offset, else cursor
sector-aligned                    // disk templates: snap to sector start
requires 0x1FE "55 AA"            // magic guard; repeatable; all are checked
big-endian                        // default is little-endian
hexadecimal                       // display integers in hex (or: octal)
read-only                         // examine only; edit controls grayed out
multiple [size]                   // enable prev/next record navigation
begin
    ...declarations...
end
```

`appliesto` (no underscore) is accepted *(observed)*. Comments are `//` and
may appear anywhere. Keyword order in the header is free.

### Types

| Declaration | Bytes | Notes |
|---|---|---|
| `int8`/`uint8`/`byte`, `int16`/`uint16`, `int24`/`uint24`, `int32`/`uint32`, `uint48`, `int64` | 1–8 | no `uint64`; `int64` is the widest |
| `float`/`single`, `double`, `longdouble`/`extended`, `real` | 4/8/10 | |
| `boole8`/`boolean`, `boole16`, `boole32` | 1/2/4 | |
| `hex N` | N | raw bytes, hex display |
| `binary` | 1 | bit display *(observed: no size parameter)* |
| `char[N]`, `string N` | N | ANSI text; parameter may be a variable or `(formula)` |
| `char16[N]`, `string16 N` | 2N | UTF-16LE; N is characters, not bytes; max editable string 8192 bytes |
| `zstring`, `zstring16` | dyn | null-terminated |
| `DOSDateTime`, `FileTime`, `OLEDateTime`, `SQLDateTime`, `UNIXDateTime`/`time_t`, `JavaDateTime` | 4/8/8/8/4/8 | `local` modifier converts to display timezone (except DOSDateTime) |
| `AppleDateTime` | 4 | *(observed: undocumented, used by the shipped HFS+ template)* |
| `GUID` | 16 | |
| `uint_flex "7,15,23,31"` | 4 | integer assembled from arbitrary bits of a 32-bit window, first-listed bit is the MSB; bit 0 = LSB of first byte |

Per-declaration modifiers (at most one per group, before the type):
`big-endian`/`little-endian`, `hexadecimal`/`decimal`/`octal`,
`read-only`/`read-write`/`hidden`, `local`. `hidden` reads a value for use in
later formulas without displaying it.

Titles need quotes only when they contain spaces; a title must not be all
digits; only 41 characters identify a variable. A declaration's quoted title
may continue on the following line *(observed)*.

### Constants, arrays, formulas

```text
const int16 100 "My constant"
uint8      len
char[len]  "A string"            // size from a prior variable
string (len1/(len2+4)) "Name"    // formula: + - * / % & | ^, no spaces
char[7]    "Seven each"[4]       // array of 4; "~" in title = element number
```

Predefined constants: `Bytes_per_sector`, `Bytes_per_cluster`,
`Bytes_per_record`, `Base_offset`. Array size `unlimited` repeats to end of
file.

### Control flow and movement

```text
{                                 // repeat block; no nesting
    byte flag
    IfEqual flag 0
        ExitLoop                  // break; "Exit" aborts the whole template
    EndIf
}[16]                             // count, variable, formula, or unlimited

numbering 1                       // start value for "~" substitution
section "TOC"                     // visual grouping; no data movement
endsection
move -4                           // relative skip, may be negative (re-read)
goto 0x40                         // absolute, from template start
gotoex (Base_offset+512)          // absolute, from start of file/disk
multiple (RecordSize)             // in body: record span for navigation
```

`IfEqual a b` / `IfGreater a b` compare numbers, quoted strings, or `0x`
hex chains (`Else` optional, closed by `EndIf`). The manual forbids nesting,
but published templates nest them and leave else-if chains unclosed, and
X-Ways tolerates both *(observed)* — as does an `end` used inside a
conditional as an early exit. `tplgen.py --check` follows the observed
grammar: structural breakage is an error, manual-violations-that-work are
warnings.

## Working with the collection

- Everything under `templates/imported/` is third-party work, kept verbatim
  (fixes belong in a copy under `templates/own/`). Origin, contributor, and
  licence per file: `templates/imported/PROVENANCE.json`. kacos2000's
  templates are GPL-3.0 (`LICENSE-kacos2000`); the x-ways.net contributions
  carry no stated licence and are credited to their authors.
- **The imported files are local-only.** Because the x-ways.net set has no
  stated licence, the project does not redistribute the files: what ships
  publicly is `INDEX.md`, `curation.json`, and `PROVENANCE.json` (the
  pointer record), with `templates/imported/*` gitignored. A fresh checkout
  rebuilds the working copy with `python templates/fetch_templates.py`
  (`--check` verifies an existing copy against the provenance record). That
  script is the project's one deliberate network step, which is why it lives
  under `templates/` rather than `scripts/`. If upstream adds templates the
  placement table does not know, they land in `imported/_unsorted/` with a
  warning rather than being dropped.
- A template is *evidence about the producer's era*, not ground truth: most
  were written against a handful of samples, some a decade ago. Treat an
  unreviewed template like a spec in Phase 0 — run it across the corpus,
  record where it disagrees, then set its status in `curation.json`
  (`complete`, `partial` with notes, or leave `unreviewed`).
- Before reversing any structure, check `templates/INDEX.md` — both the
  per-template tables and the "no template yet" list, which names structures
  already documented elsewhere that only need transcribing with `tplgen.py`.

## Emitting templates from findings

```bash
python scripts/tplgen.py --name "WMI page header" --desc "OBJECTS.DATA page" \
    --requires 0:ACCCABCD --stride 8192 \
    --field 0:4:hex:magic:established \
    --field 4:4:uint32:"page id":established \
    --field 16:8:filetime:"last write":inferred \
    -o "templates/own/WMI page header.tpl"
python scripts/tplgen.py --spec layout.json -o out.tpl   # same JSON field
                                                         # shape as coverage.py
python scripts/tplgen.py --check "templates/own/*.tpl"
```

Conventions the generator enforces, and the reasons to keep them when editing
by hand:

- **Gaps become `hex N "unknown +0xOFF"`.** A template that renders only the
  named fields makes the layout look finished; the unknown runs keep the
  unexamined bytes visible in the dialog, which is where residual data and
  missed fields get noticed.
- **Statuses ride along as comments** (`established` / `inferred` /
  `speculative` / `unknown`), so a reader of the .tpl can tell which names
  are proven and which are working hypotheses. The hypothesis ledger holds
  the evidence; the template only mirrors its conclusions.
- **`read-only` by default.** A findings template is for examining evidence;
  emit `--editable` only for fixture-building work.
- **`requires` guards from established magics only** — the same rule as
  `siggen.py`: a speculative guard misapplies the template silently on
  someone else's machine.
- **Version-scope in the header comment.** A layout claim is shorthand for
  "the layout in the builds sampled"; say which.

Templates generated from a finished analysis belong in `templates/own/` with
status `draft` until they have been applied to samples outside the
development corpus (Phase 7); record promotion to `complete` in
`curation.json`. If the structure is one the imported collection already
covers partially, extend a *copy* of the imported template in `own/` and note
the lineage in a comment.

## Limits worth knowing

- No real expressions beyond the integer formula parser; no checksum
  verification, no decompression, no following of offsets across files. A
  template visualises one contiguous region (plus `goto` reach) — anything
  needing computation stays in a parser and the template documents the
  static layout.
- Unicode display is limited to the first 256 ANSI-equivalent characters;
  `string16` is fine for names, not for arbitrary text.
- Fixup-carrying structures (NTFS FILE records, $LogFile pages, index
  records) read wrong on disk wherever a fixup replaced live bytes — a
  template cannot undo fixups. The imported NTFS templates share this
  caveat; it is inherent, not a defect to fix.
- `multiple` navigation needs a record size (parameter or deducible); for
  variable-length records without one, navigation to preceding records is
  unavailable.
