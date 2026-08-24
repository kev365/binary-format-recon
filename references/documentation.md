# Documentation

Contents: §1 adopted vs invented · §2 the document set · §3 spec structure
(libyal) · §4 structure tables and uncertainty · §5 machine-readable output
(Kaitai meta/xref) · §6 cross-registry citation · §7 evidentiary record
(ISO, SWGDE, ACPO) · §8 validation depth · §9 confidence vocabulary ·
§10 house conventions and publication targets · §11 citing the methodology

There is no single published standard for documenting reverse-engineered
binary formats. There are, however, two mature conventions worth adopting
wholesale rather than reinventing, and a set of forensic standards that
specify what the surrounding evidentiary record must contain. This document
assembles them into one process and is explicit about which parts are
adopted, which are assembled, and which are convention this skill invents.

Contents:
1. What is adopted, assembled, and invented
2. The document set
3. Format specification structure (libyal convention)
4. Structure tables and how to mark uncertainty
5. Machine-readable output (Kaitai meta and xref)
6. Cross-registry citation
7. Evidentiary record (ISO, SWGDE, ACPO)
8. Validation depth and how to justify it
9. Confidence vocabulary
10. What to cite in a methodology section

---

## 1. What is adopted, assembled, and invented

| Element | Status | Basis |
|---|---|---|
| Spec document skeleton | **Adopted** | libyal / Joachim Metz documentation convention |
| `Offset / Size / Value / Description` tables | **Adopted** | libyal |
| Bold text marks uncertain material | **Adopted** | libyal |
| "Test versions" section | **Adopted** | libyal |
| Machine-readable spec with populated `meta`/`xref` | **Adopted** | Kaitai Struct |
| Cross-registry citation keys | **Adopted** | Kaitai `xref` well-known keys |
| Provenance, audit trail, reproducibility requirements | **Adopted** | ISO/IEC 27037, 27041, 27042; ACPO; SWGDE |
| Validation against known/generated data | **Adopted** | SWGDE validation guidance |
| Document set and how the pieces reference each other | **Assembled** | — |
| KSY authoring rules (key order, explicit endianness, `-orig-id`) | **Adopted** | Kaitai KSY Style Guide |
| Order of authority for house conventions | **Assembled** | — |
| Four-level confidence vocabulary (established/inferred/speculative/unknown) | **Invented** | libyal has a two-level convention only |
| Skip classification vocabulary | **Invented** | no precedent found |

The invented parts are flagged as such in this skill's output so nobody
mistakes them for standard terminology.

---

## 2. The document set

Four artefacts, each with one job. Keep them separate; merging them produces
a document that serves none of its readers.

| Document | Question it answers | Produced by |
|---|---|---|
| **Format specification** | How is this format laid out? | `assets/format-spec-template.md` |
| **Machine-readable spec** | Can a parser be generated and re-run? | `assets/template.ksy` / `.hexpat` |
| **Hypothesis ledger** | How do we know, and how sure are we? | `assets/hypothesis-ledger.md` |
| **Source review record** | What was consulted, covered, and skipped? | `review_tracker.py report` |

The specification states the layout. The ledger states the evidence for it.
Keeping them apart is what lets the specification read cleanly while the
uncertainty stays visible and auditable — a spec cluttered with confidence
annotations is unusable, and a spec with the uncertainty removed is dishonest.

The analysis report then draws on all four, with its limitations section fed
directly by the ledger and the review record.

---

## 3. Format specification structure (libyal convention)

Joachim Metz's `libyal/dtformats` documents are the most consistent body of
reverse-engineered format documentation in existence, and the structure is
uniform across dozens of formats. It is not written down as a style guide, but
it is unambiguous from the corpus. Adopt it:

```
Title

Summary                    what the format is; what the spec is based on;
                           that this is a working document
Document information       author, abstract, classification, keywords
License
Revision history           version | author | date | comments

1. Overview
   Characteristics table   byte order | date and time values | character strings
   1.x Test versions       the exact producer versions examined

2..N  One numbered section per structure
      prose: "The X (StructName) is N bytes in size and consists of:"
      Offset | Size | Value | Description table
      sub-sections for enums, flags, and examples

N+1. Notes                 anything not yet placed in the structure

Appendix A: References     [TAG] keys with Title/URL tables
Appendix B: License text
```

Three details worth copying exactly, because they carry meaning:

- **"This document is intended as a working document for the X format
  specification."** The convention states in the summary that the document is
  provisional. Adopt that sentence. A reverse-engineered spec is never final.
- **The Characteristics table** fixes byte order, date/time encoding, and
  string encoding once, at the top, so individual structures do not restate
  them. These are exactly the three things `profile.py`, `tsscan.py`, and
  `strscan.py` establish.
- **Test versions** lists the specific producer builds examined — Metz lists
  seventeen Chrome versions for the Chrome Cache format. This is the
  version-scoping discipline made concrete, and it is what stops a reader
  assuming the layout is universal.

Example to read before writing your own: the Chrome Cache, WMI repository, and
Windows Shortcut (LNK) documents in `libyal/dtformats/documentation/`.

---

## 4. Structure tables and how to mark uncertainty

The libyal structure table has four columns:

| Offset | Size | Value | Description |
|---|---|---|---|
| 0 | 4 | "\xc3\xca\x03\xc1" | Signature |
| 4 | 2 | | Minor version |
| 8 | 4 | | Number of entries |
| 12 | 4 | | **Stored data size** |
| 48 | 52 x 8 = 208 | | Padding  Contains 0-byte values |

Conventions inside it:

- **Offset** is decimal from the structure start. For sub-byte fields the
  notation is `byte.bit` — `3.4` is bit 4 of byte 3. Useful for packed fields
  such as bitfielded addresses.
- **Size** shows the arithmetic for arrays: `52 x 8 = 208`, `4 x 4 = 16`. This
  makes the element count visible rather than making the reader factor it.
- **Value** carries expected constants — signatures, fixed versions. Empty
  when the field varies.
- **Description** names the field. Additional explanation follows on a
  continuation line rather than in a separate column.

**Bold marks uncertainty.** This is the convention's most valuable feature and
the one most often missed. In libyal documents, `**Stored data size**` means
the field's purpose is inferred rather than established; `**Unknown; seen on
Mac OS X 0x6f430074**` records an observation without a conclusion; `**TODO**`
marks a known gap. Bold is used inline so uncertainty travels with the field
rather than being relegated to a caveats section nobody reads.

Adopt this, and use this skill's four-level vocabulary in the ledger where the
finer distinction is needed. Bold in the spec, graded confidence in the ledger.

Enumerations get their own tables, `Value | Identifier | Description`, where
Identifier is the symbol used by the producing code when known.

---

## 5. Machine-readable output (Kaitai meta and xref)

Prose alone cannot be tested. Ship a `.ksy` alongside the document so the
layout is executable, re-runnable across the corpus, and compilable into
whatever language the eventual tool needs. `assets/template.ksy` is the
starting point.

Populate `meta` properly — most hand-written `.ksy` files skip this, and it is
where the provenance lives:

```yaml
meta:
  id: wmi_repository
  title: WMI CIM repository (OBJECTS.DATA)
  file-extension: data
  endian: le
  xref:
    forensicswiki: windows_management_instrumentation_(wmi)
    wikidata: Q...
    pronom: fmt/...
  license: CC0-1.0
doc: |
  Reverse engineered from N samples across producer versions X, Y.
  Fields whose doc string is marked INFERRED have not been confirmed by
  controlled mutation. See the hypothesis ledger for status and support.
doc-ref:
  - https://github.com/libyal/dtformats/blob/main/documentation/...
```

Use `doc` on individual fields to carry the same uncertainty marking the prose
spec uses, and `doc-ref` to point at the source that established the field.
`-orig-id` records the producing code's own name for a field when you have it
from an implementation — that traceability is worth preserving.

---

## 6. Cross-registry citation

Kaitai's `xref` block is effectively a cross-registry citation standard, with
well-known keys documented in the Kaitai user guide. Use it in the `.ksy` and
mirror it in the prose spec's references appendix:

| Key | Points at |
|---|---|
| `forensicswiki` | Forensics Wiki article name |
| `justsolve` | Just Solve the File Format Problem article |
| `loc` | Library of Congress FDD identifier, e.g. `fdd000153` |
| `pronom` | PRONOM PUID, e.g. `fmt/13` (array if several) |
| `mime` | Registered media type |
| `rfc` | Raw RFC number |
| `iso` | ISO/IEC standard number |
| `wikidata` | Wikidata item, e.g. `Q178051` |

Recording a PUID and an LoC FDD identifier costs nothing and makes the format
findable by anyone else who identifies the same bytes. If no registry entry
exists — common for forensic artefacts — say so explicitly rather than leaving
the block absent, since absence is ambiguous between "none exists" and "nobody
looked".

For prose references, libyal's `[TAG]` convention with Title/URL tables is
adequate and consistent. No need for a formal citation style.

---

## 7. Evidentiary record (ISO, SWGDE, ACPO)

The format specification documents the artefact. These standards govern the
record of how you produced it. None is specific to reverse engineering; all
apply to the analysis it supports.

- **ISO/IEC 27037:2012** covers identification, collection, acquisition, and
  preservation, and defines four quality principles that the surrounding
  documentation exists to satisfy: **auditability, repeatability,
  reproducibility, and justifiability**.
- **ISO/IEC 27041:2015** covers assurance that an investigative method is fit
  for purpose — validation and verification. This is the standard that
  actually speaks to a custom parser.
- **ISO/IEC 27042:2015** covers analysis and interpretation, addressing
  continuity, validity, reproducibility, and repeatability.
- **ISO/IEC 27043:2015** provides the overall investigation process framework.
- **ACPO Good Practice Guide, Principle 3** requires an audit trail of all
  processes applied to digital evidence, such that an independent third party
  can examine those processes and achieve the same result. This is the
  clearest single statement of what the documentation is for.
- **SWGDE** guidance on tool and method validation requires that testing of new
  procedures use **known data sets, so the expected outcome is known in
  advance**. Relevant documents include *Minimum Requirements for Testing Tools
  Used in Digital and Multimedia Forensics* (18-Q-001), the *Guide for the
  Validation of Digital Forensic Tools and Methods*, and the *Model Standard
  Operating Procedures for Computer Forensics*.
- **NIST** CFTT and NISTIR 8265 provide tool-testing methodology, though CFTT
  targets tool categories with reference implementations, which a novel parser
  by definition lacks.

The ISO standards are paywalled; the principles above are established from
their published abstracts, previews, and secondary sources. Read the actual
text before citing clause numbers in anything consequential.

**The mapping to this skill's method is close, and worth stating explicitly in
a report:** differential baselining with lab-generated inputs *is* SWGDE's
known-data-set validation — you construct the input, so the expected output is
known before the test. Provenance manifests and deterministic parsing serve
27037's repeatability and reproducibility. The hypothesis ledger and source
review record together *are* the ACPO Principle 3 audit trail.

---

## 8. Validation depth and how to justify it

A reverse-engineered parser cannot be comprehensively validated — there is no
reference implementation to compare against, and the input space is unbounded.
ISO/IEC 27041 anticipates this. It distinguishes **comprehensive validation**,
which tests a process under all possible conditions and which it describes as
not essential and likely prohibitively expensive, from **sufficient
validation**, which it treats as adequate for a one-off process intended to
solve an immediate problem and not likely to be reused. It also advises that
post-deployment validation should be avoided unless absolutely necessary.

That gives a principled way to state what you did:

- A **one-off parser** for a single investigation warrants sufficient
  validation: state the corpus, the mutation trials, the parse rate, and the
  limits.
- A parser that will be **reused across cases** warrants more, because 27041
  treats processes deployed regularly as candidates for comprehensive
  validation. Widen the corpus, cover more producer versions, and revalidate
  when the format or the tool changes.

Either way, validate before use rather than after, and document the error
rate you actually observed: parse success rate across the corpus, broken out
by producer version, with failures characterised rather than counted. Where
findings may face adversarial scrutiny, a documented and testable method with
a known error rate is materially stronger than an undocumented one, whatever
admissibility framework applies.

---

## 9. Confidence vocabulary

The four-level vocabulary this skill uses is **invented** — libyal marks
uncertainty in a binary way (bold or not), and no published standard offers a
finer scale for format research. Because it is not standard terminology,
define it wherever it appears rather than assuming a reader knows it:

| Status | Meaning |
|---|---|
| `established` | Confirmed by controlled mutation, or by an independent spec plus corpus agreement |
| `inferred` | Holds across the corpus, never directly manipulated |
| `speculative` | Fits the samples; an alternative reading has not been excluded |
| `unknown` | Present, purpose undetermined |

Report support as a fraction with the denominator visible (`47/52`), never a
bare percentage, so sample size cannot hide.

For normative language in a specification, RFC 2119 keywords (MUST, SHOULD,
MAY) are standard and well understood — but they describe what an
*implementation* is required to do, not how confident you are in an
observation. Do not use them to signal confidence.

---

## 10. House conventions and publication targets

Everything above describes a default. A specific repository's conventions
outrank it, and the check belongs at the start of Phase 6 rather than the end,
because these conventions constrain how the artefact is written.

```bash
python scripts/house_style.py .                 # what governs this repo
python scripts/house_style.py --target kaitai   # upstream authoring rules
python scripts/house_style.py --list-targets
```

**Order of authority:**

1. **The target repository's own documents.** `CONTRIBUTING.md`, `STYLE.md`,
   `AGENTS.md`, PR templates, linter configs, and the licence. Rank-1
   documents are read before writing anything.
2. **The person's standing conventions**, for their own repos and for repos
   with none of their own. Anyone producing format documentation regularly
   benefits from writing these down once: preferred spec structure, licence,
   how uncertainty is marked, whether specs ship with a `.ksy`.
3. **The upstream convention for the artefact type** — the KSY style guide for
   `.ksy`, the libyal skeleton for prose specs, the ImHex pattern layout.
4. **This skill's defaults**, which are just (3) generalised.

**Where a repo has no written style guide, its existing artefacts are the
style guide.** Read two or three in the same category and match their shape.
This is the common case for internal and team repos, and matching by example
is a legitimate answer rather than a fallback to be apologised for.

Known upstream conventions worth reading before authoring:

| Target | What binds |
|---|---|
| Kaitai gallery | The **KSY Style Guide** is normative and uses RFC 2119 keywords. Attribute keys MUST follow a specified order. Types SHOULD carry explicit `be`/`le` suffixes so the spec is unambiguous alone. `-orig-id` records the original identifier when transcribing from software or an official spec — for reverse-engineered work that is the traceability link back to the producing code. `doc` SHOULD NOT restate the `id`. |
| ImHex-Patterns | Patterns, includes, and magic files live in separate trees. House layout is conveyed by example. If the work produced signatures, the magic files may be the more valuable contribution. |
| libyal / dtformats | The asciidoc skeleton in §3, GNU FDL 1.3 documentation licence. |
| plaso | Parsers require test data and tests; a much larger commitment than a format document. Consider contributing documentation and parser separately. |
| 010 Editor | Templates carry a standard header comment block; submission is via Sweetscape, not a public VCS. |

**Licence compatibility is the one that bites.** libyal documentation is GNU
FDL 1.3, Kaitai gallery entries are commonly CC0-1.0, Microsoft Open
Specifications are licensed for implementation. Deriving a layout and
reimplementing it is normally fine; carrying text across licence boundaries is
a different question. Check before assembling a deliverable from several
sources.

Submission mechanics — forking, pull requests, issue etiquette — are the
repository's business and deliberately outside this skill. The concern here
ends at the shape of the artefact.

---

## 11. What to cite in a methodology section

A methodology section that names its standards is substantially harder to
dismiss than one that describes ad hoc practice. Reasonable minimum:

```
Evidence handling and integrity:   ISO/IEC 27037:2012
Method validation:                 ISO/IEC 27041:2015 (sufficient validation)
Analysis and interpretation:       ISO/IEC 27042:2015
Investigation process:             ISO/IEC 27043:2015
Audit trail:                       ACPO Good Practice Guide, Principle 3
Tool/method validation practice:   SWGDE 18-Q-001; SWGDE Guide for the
                                   Validation of Digital Forensic Tools and Methods
Format documentation convention:   libyal/dtformats
Machine-readable specification:    Kaitai Struct
```

State plainly which of these were followed and which were only consulted. A
skill cannot make a claim of conformance on your behalf, and overstating
conformance to a standard is worse than not citing it.
