---
name: binary-format-recon
description: Reverse engineering of undocumented or partially documented binary file formats, for forensic parsing and tool building. Use whenever the user wants to work out how a binary file is put together -- record or page layout, field boundaries, endianness, string or timestamp encodings, checksums, compression -- or mentions an unknown, proprietary, or legacy format, hex-level analysis, entropy, or byte diffing. Use it when they name an artefact (WMI OBJECTS.DATA, registry hives, EVTX, prefetch, firmware, proprietary logs) and want to know what it contains or how to parse it. Also use it for finding where a format is already documented, for analysing a producing binary to locate its serialisation code, for investigating fields a spec leaves reserved or unknown, for validating or emitting signatures from a parser, and for creating, linting, or consulting X-Ways/WinHex template (.tpl) files.
---

# Binary Format Recon

A method and a toolkit for turning an opaque binary into a documented,
testable parser -- without guessing.

The discipline this encodes is simple to state and easy to abandon under time
pressure: **a field is not real until a controlled change proves it real.**
Pattern-matching produces plausible layouts quickly, and plausible layouts are
how forensic tools end up silently mis-reporting evidence. Everything here is
organised around generating hypotheses cheaply, then trying hard to kill them.

## Phase 0 — Prior art, before anything else

Reverse engineering a solved format wastes days and produces a worse parser
than the one that already exists. This phase is cheap, and it is the one most
often skipped because knowing *which* of two dozen galleries to check is
itself friction. Remove the friction:

```bash
python scripts/gallery_lookup.py sample.bin
python scripts/gallery_lookup.py --name OBJECTS.DATA --terms "wmi,cim repository"
```

That prints an ordered lookup plan with working URLs and pre-built search
strings, routed by what the sample appears to be. The plan distinguishes
**executable specs** you can run immediately (Kaitai `.ksy`, ImHex `.hexpat`,
010 `.bt`, fq decoders, DFDL schemas, poke pickles) from **prose corpora** you
must hand-implement (Microsoft Open Specifications, libyal, PRONOM, the
preservation and RE community wikis). Query both — they fail differently.
Executable galleries skew toward popular formats; prose corpora skew toward
whatever somebody had an institutional reason to document, which is exactly
where forensic artefacts live.

Identify before you search: run **Siegfried** or **fido** (both consume the
PRONOM registry) and `file -k`. A confident PUID short-circuits most of the
list below it.

One gallery is local: `templates/INDEX.md` indexes 117 X-Ways/WinHex
templates (filesystems, partition tables, EVTX, LNK, virtual disks, and
more) with per-template trust status, plus a list of documented structures
that still lack one. The template files themselves are not redistributed
(mixed third-party licensing) — if `templates/imported/` holds only
`PROVENANCE.json`, populate it with `python templates/fetch_templates.py`.
A hit there is a working, executable layout to verify against the corpus —
and its `requires` line is the magic to feed `constant_hunt.py`. See
`references/xways-templates.md`.

If a spec or reference implementation exists, the job becomes *verification*
rather than discovery — easier, but not trivial: specs are written from a
handful of samples on a handful of producer versions, so run one across your
whole corpus and record where it disagrees. `references/format-galleries.md`
covers what each source is good and bad at, which have died, and the licence
terms that matter.

**Whatever you find, read it properly.** Format documents punish partial
reading specifically: field definitions are non-local, the value concentrates
in the version and exception sections nobody reaches, and a spec's *silence*
is meaningful but invisible if you skipped that page. Enumerate a source's
units before reading so coverage has a fixed denominator:

```bash
python scripts/review_tracker.py add "MS-CFB" --kind spec --scope "sections 2.1-2.6" \
    --units "2.1 Sectors,2.2 Header,2.3 FAT,..."
python scripts/review_tracker.py open      # started and not finished
python scripts/review_tracker.py close src-1
```

`close` refuses while units are unread or cross-references unresolved — it
turns "did I finish that?" into queryable state rather than recall. Read
`references/source-review.md` before any substantial source: traversal order,
handling sources too large to read whole, and chasing citations without
abandoning the review you are in.

## Three ways in

Most of this skill reasons from bytes. If you have the **producing binary**,
read the code that writes the format instead: a serialisation routine settles
in an hour what inference approximates over days, and it yields semantics —
not "a dword at +12 is a length" but "the uncompressed size before LZNT1". For
Windows artefacts you almost always have the producer, since the DLL or
service that writes the file is on the same machine.

The bridge is that black-box work produces the constants producer-side work
searches for:

```bash
python scripts/constant_hunt.py producer.dll \
    --magic 0xACCCABCD --stride 8192 --crc-tables --strings
```

Hits come back with a section and virtual address to paste into a
disassembler. A function referencing both the magic and the stride is almost
certainly the container writer; a CRC table in `.rdata` is the strongest lead
of all, because the function indexing it shows exactly which bytes the
checksum covers.

Run both tracks and compare. Agreement promotes a field from `inferred` to
`established`; disagreement means one method is wrong, and finding out which
is usually the most valuable hour in the analysis. Full workflow, including
Ghidra headless automation, dynamic observation, cross-version diffing, and
symbolic execution, is in `references/producer-side.md`.

The third way in is that **the structure is already known and you want what it
leaves out** — fields marked reserved or unknown, regions called padding, and
anything the spec skipped because nobody needed it. That is a different
problem from starting cold, and the gaps are invisible precisely because the
format is considered solved.

```bash
python scripts/coverage.py ./corpus --corpus --stride 8192 --head 128 --map \
    --field 0:4:magic --field 4:4:page_id --field 16:8:timestamp
```

It classifies what remains across the corpus: genuine padding, undocumented
constants, derived values, live fields nobody named, version-scoped fields,
and **residual data** — uninitialised memory the producer wrote without
zeroing, which a spec calls padding and an investigator calls a disclosure.
Leaked pointers, stale buffer fragments, and text remnants surface here, and
are often the most probative content in the artefact.

`--layout` takes `fieldmap.py --json` directly. Run at both `--granularity 4`
and `8`; a field visible at one and not the other is still a finding. See
`references/residual-analysis.md`.

## The loop

Eight phases; each produces artefacts the next consumes. Do not skip Phase 1,
and do not report a finding that has not survived Phase 5. Full detail — how
to read each tool's output, and the judgement calls — is in
`references/workflow.md`; read it before running a phase you have not run
before.

**1. Provenance.** Hash everything, work on copies only.

```bash
python scripts/provenance.py record ./samples -o manifest.json --note "source, acquisition"
```

**2. Triage.** Is there structure, and what size is it?

```bash
python scripts/profile.py sample.bin --json profile.json
python scripts/binviz.py sample.bin --stride 8192 -o viz/
```

Entropy above ~7.5 means compressed or encrypted — stop looking for structs.
Stride is scored by *anchor columns*, since in a sparse file any stride aligns
the zero regions and only the true one aligns the header bytes — but a known
signature repeating on an exact step outranks that, and outranks token-gap
votes, which tend to surface the size of a record *inside* the container. The
array is scored at the phase the signature starts on, so a leading file header
does not hide it. No stride means variable-length records; go to Phase 3 and
find the length prefix.
`crypto_scan.py` handles regions that stay opaque.

**3. Anchors.** Timestamps and strings validate themselves, so they are the
way in.

```bash
python scripts/tsscan.py sample.bin --stride 8192
python scripts/strscan.py sample.bin --stride 8192
```

Weigh hits against the **lift** figure: a 32-bit epoch field matches random
data ~29% of the time, a 64-bit FILETIME ~0.07%. The decisive signal is
offset-modulo-stride clustering, not hit count.

**4. Structure.** Profile the record as a table, column by column.

```bash
python scripts/fieldmap.py sample.bin --stride 8192 --head 128 --skip-zero --dump 2
python scripts/cksum_id.py --selftest    # prove the catalogue before trusting it
python scripts/cksum_id.py sample.bin --stride 8192 --cksum-offset 24 --range 32:8192
```

Confidence numbers are priority ordering, not probability. Resolve any
`hash_or_crc` column before continuing — a confirmed checksum proves the
record boundary, because a wrong boundary cannot produce a consistent one.

**5. Confirmation.** The only phase that produces proof rather than inference.

```bash
python scripts/bindiff.py before.bin after.bin --stride 8192 --noise ctrl_a.bin ctrl_b.bin
```

Snapshot, make **exactly one** known change, snapshot again — plus a control
pair with no change, so background churn is subtracted. Then classify every
surviving run as your mutation, a derived value, or an index update. Mutation
design is in `references/methodology.md` §1.

**6. Specification.** Write it down where it can be checked.

Four artefacts, each with one job: the format spec
(`assets/format-spec-template.md`, libyal structure), a machine-readable
`.ksy`, the hypothesis ledger, and the source review record. A fifth is
optional but cheap once the layout exists: an X-Ways template
(`tplgen.py`, below) that renders the layout over live evidence, statuses
and bounded unknowns included. Check governing
conventions *before* authoring — `house_style.py .` and
`house_style.py --target kaitai`; the KSY style guide mandates key order, so
finding out afterwards means rewriting. See `references/documentation.md`.

**7. Corpus validation.** Against every sample, not the one you developed on.

```bash
python scripts/corpus.py ./samples --cluster --report corpus.md
python scripts/roundtrip.py --module myparser.py --corpus ./samples --stride 8192
python scripts/mutate.py sample.bin -o mutants/ --stride 8192 --field 16:8 --run "python myparser.py {}"
```

Count *unique* files. Clusters usually mark producer versions, so report
per-cluster rates. Round-trip identity is the strongest test available without
the producer; parse success is the weakest. Fuzz both directions — inward, to
the producer in a disposable VM, is the more informative half. See
`references/validation.md`.

**8. Reporting.** Fill in the ledger and run `review_tracker.py report`. Every
field gets a status — `established`, `inferred`, `speculative`, `unknown` —
and support as a fraction with the denominator visible. Name the standards
followed; `references/documentation.md` §7–8 maps this method onto ISO/IEC
27037, 27041, and SWGDE validation practice.

## Scripts

All are stdlib-only Python 3, no network, no installs.

| Script | Purpose |
|---|---|
| `gallery_lookup.py` | Generate a prior-art lookup plan: which galleries to check, in what order, with URLs |
| `review_tracker.py` | Track coverage of a source unit by unit; refuses to close while work remains |
| `house_style.py` | Find the contribution and style conventions governing an artefact before authoring it |
| `provenance.py` | Hash a corpus, warn on writable inputs, verify integrity afterwards |
| `profile.py` | Entropy, byte histogram, signature scan, stride/page-size detection |
| `tsscan.py` | Sweep 12 timestamp encodings with false-positive baselines and stride clustering |
| `strscan.py` | Extract ASCII/UTF-8/UTF-16LE, infer length-prefix width and termination |
| `fieldmap.py` | Profile a fixed-stride record array column by column, propose a struct |
| `cksum_id.py` | Identify checksum algorithm and coverage range; self-tests its CRC catalogue |
| `bindiff.py` | Differential baselining with control-pair noise subtraction |
| `binviz.py` | Render the file as PNG (bytemap, digraph, Hilbert, entropy) to see structure |
| `crypto_scan.py` | Crypto constants, XOR key recovery, encodings, compression incl. silent Windows families |
| `constant_hunt.py` | Find your format's constants inside the producing binary, with section and virtual address |
| `coverage.py` | Subtract known fields from the bytes; classify padding, undocumented fields, and residual data |
| `corpus.py` | Deduplicate and cluster samples; clusters usually mark producer versions |
| `roundtrip.py` | Parse/serialise a corpus and localise every misread field |
| `mutate.py` | Deterministic mutants for parser robustness and producer probing |
| `siggen.py` | Emit Yara, libmagic, PRONOM, and Velociraptor signatures from established facts |
| `tplgen.py` | Emit an X-Ways/WinHex .tpl from a layout, statuses and bounded unknowns included; `--check` lints any template |
| `tpl_index.py` | Regenerate `templates/INDEX.md` from the collection, provenance, and curation judgements |
| `make_fixture.py` | Generate a synthetic file with known ground truth, to verify the toolkit |

Run any of them with `-h` for full options.

To sanity-check the kit — or to practise the loop on a file whose answer is
known — generate a fixture and run the phases against it:

```bash
python scripts/make_fixture.py /tmp/fx
python scripts/cksum_id.py --selftest
```

The fixture is a paged format with a documented layout, a FILETIME, a CRC-32,
length-prefixed UTF-16LE strings, and a mutation confined to one page, so
every phase has a right answer to check against.

## Publishing what you found

An analysis that ends in a document helps one person. The same knowledge as
signatures is usable by everyone else's tooling, which for threat intelligence
work is usually the point:

```bash
python scripts/siggen.py --name wmi_objects --magic 0:ACCCABCD --ext data \
    --desc "WMI CIM repository objects" --version-scope "Win10 19045, Win11 22631" --all
```

That emits a Yara rule, libmagic entry, draft PRONOM signature, Velociraptor
artefact, and detection notes. For examiners rather than pipelines, emit an
X-Ways template of the layout as well — it is the visualisation half of the
same knowledge:

```bash
python scripts/tplgen.py --name "WMI page header" --requires 0:ACCCABCD \
    --stride 8192 --field 0:4:hex:magic:established \
    --field 16:8:filetime:"last write":inferred \
    -o "templates/own/WMI page header.tpl"
python scripts/tplgen.py --check "templates/own/*.tpl"
python scripts/tpl_index.py --write    # keep the master index current
```

Generated templates carry every field's evidence status as a comment and
every gap as a labelled unknown, land in `templates/own/` with status
`draft`, and are promoted in `templates/curation.json` only after surviving
samples outside the development corpus. Only **established** facts belong in a
signature — a speculative magic becomes somebody else's false positives months
later, untraceable. Validate against the corpus *and* against unrelated files
and report both rates; a rule tested only on files you know match has not been
tested.

## Rules that keep this honest

- **Finish what you start reading.** A source worth consulting is worth
  covering completely, or covering to a scope you declared in advance and
  stated afterwards. Enumerate its units before reading, record cross-
  references as obligations rather than chasing them mid-unit, and never
  draw a conclusion from a review that was never closed. Partial readings
  feel complete from the inside, which is why coverage is tracked rather
  than recalled.
- **An unknown you have bounded beats a silent gap.** A field whose purpose
  is undetermined still belongs in the layout with its offset and width and a
  status of `unknown`. Omitting it makes the layout look complete when it is
  not, and the next person cannot tell the difference between inert and
  unexamined.
- **Do not infer structure from ciphertext.** If entropy stays near 8.0 and no
  transform is identified, record the region as opaque. An inferred struct
  over compressed or encrypted bytes is worse than an honest gap.
- **Classify what you skip.** Narrowing scope on a large source is fine and
  often necessary. Silently narrowing it is not. Every skipped unit records
  whether it was assessed and ruled out or simply never examined, because only
  the second kind can still change the conclusions — and that distinction
  belongs to the reader, not to whoever ran out of time.
- **Report what was tested, not what was assumed.** If the sample only
  contains two record types, say so; do not present the layout as complete.
- **A statistic is not a finding.** High confidence from `fieldmap.py` means
  "worth testing next", nothing more.
- **Prefer falsification.** When two readings fit, find the sample that
  distinguishes them rather than collecting more evidence for the favourite.
  A wrong stride that happens to work on one file is the classic failure.
- **Never silently drop a record.** Partial, corrupt, and unparseable records
  get emitted with a flag. Silent drops in a forensic tool are how evidence
  goes missing.
- **Keep parses deterministic.** Stable ordering, pinned tool versions, no
  dependence on dict iteration or wall-clock time.
- **Version-check every claim.** Formats change between producer releases.
  "This is the layout" is nearly always shorthand for "this is the layout in
  the builds I sampled".

## Reference files

Read these as needed rather than upfront:

- `references/format-galleries.md` — where to look before reversing anything:
  executable spec galleries, forensic documentation corpora, signature
  registries, preservation and RE community wikis, plus what has died or gone
  stale and the licence terms that matter.
- `references/workflow.md` — the eight phases in full: what each is looking
  for, how to read its output, and the judgement calls.
- `references/residual-analysis.md` — attacking the gaps in a structure that
  is already mostly known: coverage accounting, reserved fields, and residual
  data left behind in bytes the spec calls padding.
- `references/producer-side.md` — reading the code that writes the format:
  finding the serialiser, recovering structs, dynamic observation,
  cross-version diffing, and when symbolic execution earns its cost.
- `references/validation.md` — the ladder of evidence: corpus building,
  round-trip testing, and fuzzing in both directions.
- `references/legal-and-ethics.md` — interoperability exemptions, contract
  terms, sample handling, and publication. Not legal advice; read it before
  scoping, not after.
- `references/documentation.md` — the documentation process: the libyal spec
  structure, table and uncertainty conventions, Kaitai `meta`/`xref` for
  machine-readable output and citation, what ISO/SWGDE/ACPO require of the
  evidentiary record, and which parts of this are adopted versus invented.
- `references/source-review.md` — how to read a source thoroughly: enumerating
  units, traversal order, handling sources too large to read whole, chasing
  cross-references without drift, and what completion means.
- `references/methodology.md` — the full method: mutation design, hypothesis
  falsification, confidence scoring, working from an existing spec, and what
  to do when there is no stride.
- `references/encodings.md` — timestamp epochs and their raw ranges, string
  encoding conventions, integer and float layouts, checksum families,
  compression magics, and the DFIR-relevant signature table.
- `references/forensic-soundness.md` — provenance, reproducibility, handling
  ambiguity and corruption, and how to state evidentiary limits.
- `references/tooling.md` — when to hand off to Kaitai Struct, ImHex, 010
  Editor, binwalk, `construct`, Hachoir, or an existing DFIR framework, and
  what each is actually good at.
- `references/xways-templates.md` — the X-Ways/WinHex template language
  distilled (manual Appendix A, corrected against observed parser
  behaviour), the local collection under `templates/` and its curation
  workflow, and the conventions for emitting templates from findings.
