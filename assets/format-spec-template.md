# <Format name>

Structure follows the libyal/dtformats documentation convention (Joachim Metz),
which is the most consistent body of reverse-engineered format documentation
available. Keep the section order; it is what makes these documents
comparable to each other.

Conventions used below:
- **Bold** marks material that is inferred, uncertain, or unknown — libyal's
  convention. Uncertainty stays inline with the field so it travels with it.
- Offsets are decimal from the structure start; `byte.bit` notation (`3.4`)
  for sub-byte fields.
- Array sizes show their arithmetic: `52 x 8 = 208`.
- Graded confidence lives in the hypothesis ledger, not here. This document
  states the layout; the ledger states how well it is known.

---

## Summary

<What the format is and what produces it. What this specification is based on:
samples, an existing spec, a reference implementation, or original analysis.>

This document is intended as a working document for the <format> specification.

## Document information

| | |
| --- | --- |
| Author(s): | <name> |
| Abstract: | This document contains information about the <format> |
| Classification: | <Public / Internal / Case-restricted> |
| Keywords: | <format>, <artefact>, <platform> |

## License

<Licence for this document. If any part derives from a licensed source, note
it here -- libyal documentation is GNU FDL 1.3, Microsoft Open Specifications
are licensed for implementation, Kaitai .ksy files are per-file licensed.>

## Revision history

| Version | Author | Date | Comments |
| --- | --- | --- | --- |
| 0.0.1 | <name> | <date> | Initial version. |

---

## 1. Overview

<One paragraph: what the format stores and where it sits on disk.>

| Characteristics | Description |
| --- | --- |
| Byte order | <little-endian / big-endian / mixed -- note where it differs> |
| Date and time values | <e.g. FILETIME, 100ns since 1601-01-01 UTC> |
| Character strings | <e.g. UTF-16LE, u32 byte-length prefix, no terminator> |

### 1.1. File set

<For multi-file formats, the files involved and their roles.>

| Filename | Description |
| --- | --- |
| | |

### 1.2. Test versions

<The exact producer versions examined. This is the version scope of everything
below. libyal lists every build tested -- do the same, because a reader
otherwise assumes the layout is universal.>

- <Product version, platform, architecture>

### 1.3. Format versions

<If the format is versioned, the versions and how they are distinguished.>

| Value | Description |
| --- | --- |
| | |

---

## 2. <Container structure -- page, block, or file header>

The <structure> (<StructName>) is <N> bytes in size and consists of:

| Offset | Size | Value | Description |
| --- | --- | --- | --- |
| 0 | 4 | "\x??\x??\x??\x??" | Signature |
| 4 | 4 | | <Field> |
| 8 | 2 | | **<Inferred field -- bold marks uncertainty>** |
| 10 | 2 | | <Field>   See section: [<Enum>](#enum) |
| 12 | 8 | | <Timestamp field> |
| 20 | 4 x 4 = 16 | | Array of <element> |
| 36 | | | Padding   Contains 0-byte values |

### 2.1. <Enumeration>

| Value | Identifier | Description |
| --- | --- | --- |
| 0 | <CODE_NAME> | <meaning> |

### 2.2. Examples

| Value | Description |
| --- | --- |
| 0x???????? | <worked example decoding a real value> |

---

## 3. <Record structure>

<Repeat the pattern above for each structure.>

---

## 4. <Indirection or addressing>

<If logical-to-physical mapping, page chaining, or an index applies, document
the translation here. A reader cannot resolve a single pointer without it.
Include the mask applied to packed page numbers and any sentinel values.>

---

## 5. Deleted and unallocated data

<Forensically the highest-value section, and the one most often missing.
How deletion is represented -- tombstone flag, unlinking, compaction. Where
slack survives. How to enumerate unreferenced space.>

---

## 6. Notes

<Anything observed but not yet placed: struct definitions recovered from an
implementation, unexplained constants, byte patterns seen once. Recording an
unplaced observation is better than discarding it.>

---

## Appendix A: References

`[TAG]`

| Title: | <title> |
| --- | --- |
| URL: | <url> |

`[LIBYAL]`

| Title: | <format> |
| --- | --- |
| URL: | https://github.com/libyal/dtformats |

## Appendix B: Cross-registry identifiers

<Mirror of the Kaitai meta/xref block. Record "none found" explicitly rather
than omitting a key -- absence is otherwise ambiguous between "none exists"
and "nobody looked".>

| Registry | Identifier |
| --- | --- |
| PRONOM PUID | <fmt/... or none found> |
| LoC FDD | <fdd000... or none found> |
| Wikidata | <Q... or none found> |
| MIME | <type or none found> |
| Forensics Wiki | <article or none found> |
| Just Solve | <article or none found> |

## Appendix C: Analysis record

| | |
| --- | --- |
| Corpus | <N samples, versions covered, how obtained> |
| Provenance manifest | <sha256 of manifest.json> |
| Mutation trials | <count; see hypothesis ledger> |
| Parse rate | <n/N, with failures characterised> |
| Sources reviewed | <see review_tracker report> |
| Validation depth | <sufficient / comprehensive, per ISO/IEC 27041> |
| Tool versions | <binary-format-recon x.y, Python x.y> |
| Conventions followed | <target repo's CONTRIBUTING/STYLE, own standing conventions, libyal + KSY style guide, or matched to existing artefacts in the repo -- say which> |
