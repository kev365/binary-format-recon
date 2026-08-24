# Tooling: what to use, and when to stop writing Python

The scripts in this skill are deliberately stdlib-only and deliberately
limited to *discovery*. Once a layout is understood, hand off. Writing another
bespoke parser is usually the wrong move: the tools below are better tested,
and a declarative spec is worth more than code because it can be re-run,
diffed, and shared.

For *finding an existing spec* rather than writing one, see
`references/format-galleries.md`, which covers the galleries, registries, and
documentation corpora worth checking before any reversing starts, and
`scripts/gallery_lookup.py`, which generates the lookup plan for a given
sample.

---

## Declarative format specifications

**Kaitai Struct** — the default choice for writing a format down.
A `.ksy` YAML file compiles to parsers in Python, C++, Java, Go, Rust, and
more, so one spec serves both your analysis and any tool you ship. The Web IDE
renders a parse tree over a hex view, which makes debugging a spec far faster
than debugging code. Best for: fixed and variable-length records, nested
structures, conditionals, enums, cross-references within a file. Weakest at:
formats needing arbitrary computation, or resolving an external mapping layer
before addressing makes sense — those need a host-language wrapper around the
generated parser. Start from `assets/template.ksy`.

**fq** — jq for binary formats: a single Go binary carrying roughly 150
decoders, with an interactive REPL and a query language for navigating parsed
structures. Two distinct uses. First, as the fastest possible hypothesis
check: `fq -d <format> d sample.bin` either decodes or fails in one command,
which beats writing a spec to find out. Second, its decoder list is itself a
browsable format index. Weakest where you need to *define* a new format —
decoders are Go, not a declarative DSL, so for authoring go to Kaitai. MIT,
actively developed.

**construct** (Python) — declarative parsing *and* building in one
definition. Because it round-trips, it is excellent for the mutation phase:
you can synthesise a record, write it, and see how the producer reacts. Better
than Kaitai when the work stays in Python and you need to generate files as
well as read them. No cross-language output, and note that despite appearing
in "awesome" lists alongside Kaitai it has no meaningful format gallery — it
is a library for writing specs, not a place to look one up. The same caveat
applies to the Rust `binrw` and `deku` crates.

**ImHex pattern language** — a C-like DSL evaluated live against a hex view,
with built-in entropy visualisation, data-processor graphs, and diffing. The
best interactive environment for the exploratory middle phase, when you are
still forming hypotheses. Start from `assets/template.hexpat`.

**010 Editor binary templates** (`.bt`) — the long-established commercial
equivalent, with the largest curated template library of any of these tools.
Worth checking the template repository before starting: if a `.bt` exists for
your format, it is a specification you can read even if you never run it,
since `.bt` is C-like plaintext and the editor is only needed to execute it.

**Apache Daffodil / DFDL** — an Open Grid Forum standard, expressed as an XSD
subset, that both parses *and* unparses. The unparse direction is the reason
to care: it lets you synthesise valid inputs for mutation trials rather than
hand-assembling bytes. Coverage skews to scientific, financial, healthcare,
and MIL-STD formats, which is exactly where the other galleries are thin.
Schemas live at `github.com/DFDLSchemas`.

**GNU poke** — an interactive editor built around `.pk` "pickles", with the
strongest coverage of object and debug formats (ELF, DWARF, CTF, BTF). Reach
for it when the artefact is a compiled object or something adjacent to one.

**Synalyze It! / Hexinator** — XML grammars with a graphical grammar editor.
Hexinator has a usable free tier on Windows and Linux; Synalyze It! is macOS.
A good middle ground when you want a visual structure editor but not ImHex's
programming model.

**Hex Fiend templates** — Tcl-based, macOS only, bundled with the editor.
Small library, but the templates are readable and the editor handles very
large files well.

**Wuffs** (Google) — narrow coverage (roughly a dozen image codecs, several
compression formats, CBOR/JSON, hashes) but the highest-assurance
implementations available: memory-safe by construction, with bounds proven at
compile time. Not a discovery tool. Its value here is as a reference decoder
to check your own parser against when correctness matters.

---

## Discovery and triage tools

**binwalk** — signature scanning, entropy graphing, and extraction of embedded
files. The natural next step when `profile.py` reports high entropy or when a
container signature appears mid-file. Strongest on firmware and anything with
concatenated payloads.

**Hachoir** — Python library that walks known formats field by field and
reports each with its offset and description. Useful as a cross-check: if
Hachoir knows your format, you were reverse engineering a solved problem.

**Siegfried / fido** — the production file-format identifiers, both built on
the PRONOM registry. These should be your actual first command on an unknown
sample, ahead of `file`: a confident PUID resolves the identification question
against an authoritative registry rather than a heuristic magic rule, and
gives you a stable identifier to search the other corpora with.

**TrID / `file` / python-magic** — file type identification from signature
databases. Cheap and worth running alongside Siegfried, since they disagree in
useful ways; TrID's statistical database is broader than `file`'s for obscure
formats. Use `file -k` to see every matching rule rather than just the first.

**radare2 / rizin / Ghidra** — the right tools when the format is not
documented anywhere *and* you have the binary that produces it. Reading the
serialisation routine settles in an hour what byte-level inference takes days
to approximate. If a producer executable is available, this beats every
statistical method in this skill. Ghidra's decompiler on a `Write*` or
`Serialize*` function is often the fastest path to a complete layout.

**Hex editors** — ImHex, 010, xxd, hexyl. Do not underestimate simply looking
at the bytes with a colour-coded view; humans are good at spotting periodicity
that a statistic misses.

---

## DFIR frameworks

Reach for these when the artefact is a known forensic file type, or when
results need to land in an existing pipeline.

**libyal** (`libyal/dtformats`, plus the `lib*` parser family) — Joachim
Metz's format documentation and reference implementations cover a very large
share of Windows and macOS artefacts. Check `dtformats` for a written spec
before assuming a format is undocumented; it is the single highest-yield place
to look.

**plaso / log2timeline** — timeline generation across many artefact types. The
right output target if the goal is a super-timeline rather than a standalone
parser. Writing a plaso parser plugin makes your work reusable by others.

**dfVFS** — storage-media and file-system abstraction. Use it so a parser can
read from a disk image, a VSS snapshot, or an archive without special-casing
each. Saves reimplementing image access badly.

**Velociraptor** — live collection and triage, with VQL artefacts for
enumerating and extracting at scale. Use it for the *acquisition* half of the
problem; note that a live query and a dead-disk parse can legitimately
disagree, because the live subsystem may hold state not yet flushed to disk.

**Volatility 3 / MemProcFS** — memory analysis. Relevant when the on-disk
artefact is a serialisation of something that also lives in memory, where the
in-memory form is often easier to interpret and can validate your disk layout.

**KAPE / RECmd / EZ Tools** — targeted collection and Windows artefact
parsing, widely used and worth comparing your output against where the formats
overlap.

---

## Choosing between them

| Situation | Reach for |
|---|---|
| First contact with an unknown sample | Siegfried/fido, then `gallery_lookup.py` |
| You have the producing binary | Ghidra / rizin — read the serialiser |
| Format may already be documented | `references/format-galleries.md` — libyal, Microsoft Open Specs, Kaitai, fq, ImHex, 010 |
| Need to confirm a format guess in one command | fq |
| Still forming hypotheses | ImHex, plus this skill's scripts |
| Layout understood, need a spec | Kaitai Struct |
| Need to generate files for mutation trials | construct |
| High entropy or embedded payloads | binwalk |
| Output must feed a timeline | plaso parser plugin |
| Must read from images and snapshots | dfVFS |
| Need scale collection across hosts | Velociraptor |
| Format is an object/debug artefact | GNU poke |
| Need to synthesise valid inputs for mutation trials | construct, or DFDL unparse |
| Need a high-assurance reference decoder | Wuffs |

---

## A note on environment

The scripts here run anywhere Python 3 does, with no installs and no network,
which is intentional: analysis environments are frequently isolated, and a
sandbox without package installation is common. The tools above mostly are not
available under those constraints. Check what is actually present before
planning a workflow around Ghidra or binwalk, and fall back to the stdlib
scripts plus a written spec when they are not.
