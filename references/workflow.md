# Workflow: The Eight Phases

SKILL.md carries the short form of this loop -- what to run and why. This is
the long form: what each phase is actually looking for, how to read its
output, and the judgement calls that do not fit in a summary.

Work in order. Each phase produces artefacts the next one consumes. Do not
skip Phase 1, and do not report a finding that has not survived Phase 5.

Entry points other than a cold start are covered elsewhere: producer-side
analysis in `producer-side.md`, and extending an already-known structure in
`residual-analysis.md`.

---

Work in phases. Each phase produces artefacts the next one consumes. Do not
skip Phase 1, and do not report a finding that has not survived Phase 5.

## Phase 1 — Provenance

```bash
python scripts/provenance.py record ./samples -o manifest.json --note "case ref, source, acquisition method"
```

Hash everything, work only on copies, and re-run `provenance.py verify` at the
end. The script warns when inputs are writable in place, which is the single
most common way analysis contaminates evidence.

## Phase 2 — Triage: is there structure, and what size is it?

```bash
python scripts/profile.py sample.bin --json profile.json
```

Read three things:

- **Entropy.** Above ~7.5 bits/byte the payload is compressed or encrypted —
  look for a container header, not a struct. Between ~5.5 and 7.5, structure
  is present but packed. Below ~5.5, sparse and highly parseable.
- **Signature scan.** A known container ends the investigation early, and a
  signature *repeating at a fixed interval* is the strongest stride evidence
  there is.
- **Stride candidates.** Scored by *anchor columns* — positions holding the
  same non-modal byte in every block. In a sparse file any stride makes zero
  regions line up; only the true one aligns the header bytes. Multiples of a
  true stride score equally, so the tool reduces to the smallest divisor that
  holds. Two corrections the scoring applies, because without them real
  artefacts score wrong: the record array is phased to where the signature
  actually starts (EVTX chunks begin after a 4096-byte file header, so
  scoring from offset 0 finds no anchors at all), and blocks that are
  entirely modal are dropped as unwritten slack rather than counted as
  evidence against the stride — a log allocated larger than it is filled
  would otherwise destroy every anchor column.
- **When the two disagree, the signature wins.** A gap-vote winner unbacked
  by a signature is usually the modal size of a record *inside* the
  container, not the container: on a real EVTX log the token-gap scorer
  prefers 328 (a common event record size) over the true 65536. The tool
  reports the disagreement rather than silently picking one.

If no stride emerges, the format uses variable-length records. Jump to Phase 3
and find the length prefix instead.

Look at the file as well as measuring it — the eye catches periodicity and
region boundaries a summary statistic misses, and with `--stride` set each
bytemap row is one record, so constant fields become vertical stripes.

```bash
python scripts/binviz.py sample.bin --stride 8192 -o viz/
python scripts/crypto_scan.py sample.bin --region 0x2000:0x4000 --xor
```

`crypto_scan.py` is for when entropy is high and no structure appears: crypto
constants, XOR recovery, encodings, and compression — including the Windows
LZNT1/Xpress families, which carry no magic, so absence of a signature is not
absence of compression.

## Phase 3 — Anchors: timestamps and strings

These are the two field types that validate themselves, so they are the way in.

```bash
python scripts/tsscan.py sample.bin --stride 8192
python scripts/strscan.py sample.bin --stride 8192
```

`tsscan.py` reports a **lift** figure per encoding. Take it seriously: a
32-bit epoch field matches random data roughly 29% of the time, so raw hit
counts for `unix32` mean almost nothing, while a 64-bit FILETIME has a false
positive rate near 0.07%. The decisive output is the offset-modulo-stride
clustering — if candidates concentrate at one position across many blocks far
above chance, that is a field.

`strscan.py` answers the question that unlocks variable-length layouts: are
strings length-prefixed or terminated, and at what width? Formats reuse one
convention throughout, so establishing it once pays off everywhere. It also
reports the ASCII/UTF-16LE mix, which is diagnostic — Windows formats commonly
store identifiers as UTF-16LE while keeping internal keys ASCII.

## Phase 4 — Structure: profile the record as a table

```bash
python scripts/fieldmap.py sample.bin --stride 8192 --head 128 --skip-zero --dump 2
```

This is the core generator. It treats each intra-record offset as a column and
classifies the column by how it behaves *across* records: constant means magic
or version; strictly incrementing means an id or sequence; all values inside
the file means a pointer; all values under the stride means an internal offset
or length; near-unique high entropy means a checksum or hash.

Read the per-column table for detail and the **proposed layout** for a
starting struct. The layout builder deliberately prefers wide fields over the
narrow fragments that slicing them produces, so a FILETIME is not reported as
a dword plus two words.

Everything it emits is a hypothesis. Treat the confidence numbers as priority
ordering, not probability.

Resolve any `hash_or_crc` column before going further:

```bash
python scripts/cksum_id.py sample.bin --stride 8192 --cksum-offset 24 --cksum-width 4 --range 32:8192
python scripts/cksum_id.py --selftest     # prove the CRC catalogue first
```

A confirmed checksum is worth more than the field itself: it proves the record
boundary and start offset are right, because a wrong boundary cannot produce a
consistent checksum across a corpus.

## Phase 5 — Confirmation: differential baselining

This is the only phase that produces proof rather than inference, and it is
the one people skip. Generate the data yourself in a lab:

1. Snapshot the artefact. Call it `ctrl_a`.
2. Wait / let the system idle. Snapshot again as `ctrl_b`. This pair captures
   **background churn** — sequence numbers, caches, free-space maps.
3. Restore, snapshot as `before`, make **exactly one** known change, snapshot
   as `after`.

```bash
python scripts/bindiff.py before.bin after.bin --stride 8192 \
    --noise ctrl_a.bin ctrl_b.bin
```

Offsets that move in the control pair are subtracted, leaving signal. Then
classify every surviving run as one of three things:

- **your mutation** — the bytes you introduced,
- **a derived value** — a length, count, or checksum that moved because your
  mutation moved,
- **an index update** — offsets elsewhere shifting to accommodate it.

Make the mutation distinctive and long enough to find (a unique marker string
beats flipping one flag). If nothing survives subtraction, the change did not
reach this file, or it landed inside a region that churns anyway.

Advice on designing mutation sets, including how many trials to run and how to
vary one variable at a time, is in `references/methodology.md`.

## Phase 6 — Specification and documentation

Write the layout down in a form that can be checked, and keep the layout
separate from the evidence for it. Four artefacts, each with one job:

| Document | Question it answers |
|---|---|
| Format specification (`assets/format-spec-template.md`) | How is this laid out? |
| Machine-readable spec (`assets/template.ksy`, `.hexpat`) | Can a parser be generated and re-run? |
| Hypothesis ledger (`assets/hypothesis-ledger.md`) | How do we know, and how sure are we? |
| Source review record (`review_tracker.py report`) | What was consulted, covered, skipped? |

The specification follows the **libyal/dtformats convention** — an Overview
with a characteristics table fixing byte order and date/string encoding, a
**test versions** list naming the exact producer builds examined, then one
numbered section per structure with `Offset | Size | Value | Description`
tables, with uncertainty marked **in bold, inline** so it travels with the
field. An existing convention with dozens of worked examples, not something to
reinvent.

Ship a `.ksy` alongside the prose with `meta` and `xref` populated — PRONOM,
LoC FDD, Wikidata, MIME — since prose cannot be executed against the corpus
and registry identifiers cost nothing.

**Check the governing conventions before writing, not after.** If the artefact
might land in a repo — the person's own, a team's, or eventually a gallery —
the conventions that govern it are an input to authoring. Kaitai's KSY style
guide, for instance, is normative and mandates an attribute key order; finding
that out after writing several hundred lines means rewriting them.

```bash
python scripts/house_style.py .                    # what governs this repo
python scripts/house_style.py --target kaitai      # upstream authoring rules
```

Authority runs target repo → the person's own standing conventions → upstream
convention for the artefact type → this skill's defaults. Where a repo has
nothing written down, its existing artefacts are the style guide. Say in the
deliverable which was followed, so a maintainer can tell a deliberate choice
from an accident. Submission mechanics are out of scope.

`references/documentation.md` has the full structure, the table conventions,
what the forensic standards require of the surrounding record, and an explicit
statement of which parts of this process are adopted from existing conventions
versus invented here. `references/tooling.md` covers when to hand off to
Kaitai, ImHex, binwalk, or an existing DFIR framework rather than writing more
Python.

## Phase 7 — Corpus validation

Run the spec against every sample, not the one you developed on.

```bash
python scripts/corpus.py ./samples --cluster --report corpus.md
python scripts/roundtrip.py --module myparser.py --corpus ./samples --stride 8192
python scripts/mutate.py sample.bin -o mutants/ --stride 8192 \
    --field 16:8 --run "python myparser.py {}"
```

Count *unique* files — duplicates make a layout look far better evidenced than
it is. `corpus.py`'s clusters usually correspond to producer versions you have
not identified yet, so validate against each separately and report per-cluster
rates: a field that holds in one cluster and fails in another is a versioned
field, not a broken hypothesis.

Round-tripping is the strongest test available without the producer: parse
success is weak, since a parser reading a u32 where the format has two u16s
succeeds on every file and is wrong about all of them. Byte-identical
round-trip proves every byte is accounted for, and divergences localise the
misread field.

Fuzz both directions — outward so corrupt evidence flags one bad record
instead of stopping the analysis, and inward, feeding mutants back to the
producer in a disposable VM, which is the more informative half: what it
rejects defines the validation rules, and those reveal field semantics.

Register the corpus in `review_tracker.py` with one unit per sample or version
group. Validating on the samples that parse cleanly is validating on nothing;
the ones that fail have something to say. `references/validation.md` has the
full ladder of evidence. A field that holds on Windows
10 and fails on Windows 7 is a versioned field, not a broken hypothesis —
document both variants.

## Phase 8 — Reporting

Fill in `assets/hypothesis-ledger.md`, and run `review_tracker.py report` for
the source-coverage record. Skipped units, unresolved cross-references, and
conflicts between sources all bound what the analysis can claim, and the
report distinguishes material that was assessed and ruled out from material
nobody examined — the second kind stays open so the reader decides whether to
pursue it. Every field gets a status:

| Status | Meaning |
|---|---|
| `established` | Confirmed by controlled mutation, or by a spec plus corpus agreement |
| `inferred` | Consistent across the corpus, never directly tested |
| `speculative` | Fits the samples but has an untested alternative reading |
| `unknown` | Present, purpose undetermined — say so rather than omitting it |

Distinguishing these in the output is what makes an inferred parser
defensible. Note that this four-level vocabulary is this skill's own, not
standard terminology — define it wherever it appears.

Name the standards the method follows. The mapping is close enough to state
directly: differential baselining with lab-generated inputs is SWGDE's
known-data-set validation, provenance manifests and deterministic parsing
serve ISO/IEC 27037's repeatability and reproducibility principles, and the
ledger plus review record together are the audit trail ACPO Principle 3
describes. ISO/IEC 27041 also gives you the language to justify validation
depth — *sufficient* validation for a one-off parser, more for one that will
be reused. `references/documentation.md` § 7-8 covers this;
`references/forensic-soundness.md` covers reproducibility, partial and corrupt
records, and the limits worth stating explicitly.
