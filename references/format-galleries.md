# Format Galleries and Prior Art

The cheapest phase of any format investigation is finding out somebody already
did it. A morning spent here routinely saves a week, and even a partial hit is
worth having: a spec that covers 60% of the layout turns discovery into
verification, which is a far easier problem.

Finding a source is only half of it. Once you have one, `references/source-review.md`
covers reading it thoroughly rather than skimming the sections that look
relevant -- which, for format documents specifically, is how parsers end up
wrong in ways that surface late.

Contents:
1. The one distinction that matters
2. Lookup order: Windows / forensic artefact
3. Lookup order: non-forensic unknown
4. Executable spec galleries
5. Prose and documentation corpora
6. Signature and identification databases
7. Preservation and archival
8. Reverse engineering community wikis
9. Filesystem and protocol references
10. Dead, stale, and overrated
11. Licensing

---

## 1. The one distinction that matters

**Executable specs** (Kaitai `.ksy`, ImHex `.hexpat`, 010 `.bt`, fq decoders,
DFDL schemas, poke pickles, Hachoir/Construct/Wuffs code) can be run against
your sample immediately. A hit means you have a parser in minutes and a
hypothesis check for free.

**Prose corpora** (Microsoft Open Specifications, libyal, PRONOM, LoC FDDs,
the community wikis) are authoritative but must be hand-implemented. They are
what you reach for when no executable spec exists, when one exists but
disagrees with your bytes, or when you need to know what a field *means*
rather than where it sits.

Query both. They fail in different ways: executable galleries skew toward
popular formats, prose corpora skew toward formats somebody had an
institutional reason to document — which is exactly where forensic artefacts
live.

---

## 2. Lookup order: Windows / forensic artefact

1. **Identify.** Run Siegfried or fido (both consume PRONOM), plus
   `file`/libmagic. Cross-check TrID and the Kessler signature table. A
   confident PUID short-circuits everything below.
2. **libyal** — the whole org, not just `dtformats`. Deepest forensic-artefact
   documentation in existence.
3. **Microsoft Open Specifications** — authoritative ground truth for Windows
   and Office structures.
4. **Kaitai gallery, ImHex-Patterns, fq** — if any has an executable spec you
   get an instant parser to validate against.
5. **Forensics Wiki**, plus tool source (plaso, Velociraptor, Eric Zimmerman's
   tools) as knowledge-encoded-as-code.
6. **LoC FDDs / Just Solve** for provenance and obsolescence context.

`scripts/gallery_lookup.py` generates this list with working URLs for a
specific sample, so you do not have to reconstruct it by hand.

---

## 3. Lookup order: non-forensic unknown

Game asset, firmware blob, proprietary application data.

1. **fq** and the **Kaitai gallery** for executable confirmation; `file` and
   TrID for identification.
2. **MultimediaWiki** for anything audio/video/codec/container;
   **ModdingWiki** for game, DOS, asset, and archive formats.
3. **Just Solve the File Format Problem** — the breadth index for obscure and
   vintage formats, usually with links onward to primary sources.
4. **010 Editor templates, ImHex-Patterns, Synalyze/Hexinator grammars,
   Hex Fiend templates** — community specs you can read or run.
5. **GNU poke pickles, Hachoir, Wuffs** for executable reference
   implementations.
6. **Internet Archive snapshots of XentaX** for anything only ever documented
   there. See §10.

For firmware specifically, add binwalk's signature set and the OSDev wiki for
executable and boot structures.

---

## 4. Executable spec galleries

| Resource | Where | Scale | Notes |
|---|---|---|---|
| **Kaitai Struct** | formats.kaitai.io · github.com/kaitai-io/kaitai_struct_formats | 180+ in the gallery | Compiles to a dozen languages. The baseline. Per-file licensing. |
| **fq** | github.com/wader/fq | ~150 decoders | Single Go binary, jq query language over binary. `fq -d <fmt> d file` confirms or kills a hypothesis in one command. Its `doc/formats.md` is itself a browsable format index. MIT, very active. |
| **ImHex-Patterns** | github.com/WerWolv/ImHex-Patterns | Patterns, includes, magic files | Community `.hexpat` gallery *and* custom libmagic magic files, so it doubles as a signature source. |
| **010 Editor templates** | sweetscape.com/010editor/repository/templates/ | 200+ `.bt` | Largest curated template corpus. `.bt` is C-like plaintext — readable without the (proprietary) editor even if you cannot execute it. |
| **Synalyze It! / Hexinator** | synalysis.net/grammars · github.com/synalysis/Grammars | Community XML grammars | Hexinator has a free tier on Windows/Linux; Synalyze It! is macOS. |
| **Hex Fiend templates** | github.com/HexFiend/HexFiend | Bundled community set | Tcl templates, macOS only. |
| **Apache Daffodil / DFDLSchemas** | daffodil.apache.org · github.com/DFDLSchemas | Per-format repos | DFDL is an OGF standard. Schemas both parse *and* unparse, which makes them useful for generating mutation inputs. Strong on scientific, financial, healthcare, and MIL-STD formats. |
| **GNU poke** | pokology.org/pickles.html | Bundled ELF/DWARF/CTF/BTF/LEB128 plus external | `.pk` pickles; strongest on object and debug formats. |
| **Hachoir** | github.com/vstinner/hachoir | 91 parsers | Python, walks known formats field by field with offsets. If Hachoir knows your format you were solving a solved problem. |
| **Wuffs** | github.com/google/wuffs | ~12 image, ~8 compression, CBOR/JSON, 7 hash | Narrow but the highest-assurance implementations available — memory-safe by construction. Good as a reference decoder to check your own against. |
| **binspector** | github.com/binspector/binspector | Small | Analysis DSL with a REPL. Low activity. |

**Not galleries, despite appearing in lists:** `construct` (Python) and the
Rust `binrw` / `deku` crates are parsing *libraries* with only example
directories. Use them to write a spec, not to look one up.

---

## 5. Prose and documentation corpora

**libyal — github.com/libyal.** Joachim Metz's ~100 repos. `dtformats` is the
general collection, but the per-artefact knowledge bases are frequently
better: `winreg-kb` (registry), `esedb-kb` (ESE/EDB), plus parser libraries
like libbde (BitLocker), libfvde (FileVault), libewf (EnCase), libvshadow
(VSS). Documentation is GNU FDL 1.3. Where a written spec and its
implementation disagree, the implementation usually knows what real files
contain and the spec usually knows what the fields mean — read both.

**Microsoft Open Specifications — learn.microsoft.com/openspecs.** The single
largest authoritative corpus for Windows forensics, and consistently
underused. Directly relevant documents include MS-CFB (compound file / OLE),
MS-SHLLINK (`.lnk`), MS-PST (Outlook, with worked examples), MS-XCA (Xpress
compression), and the Office binary formats. Search with
`[MS-XXXX] site:learn.microsoft.com`, or browse the Windows Protocols and
Office File Formats indices; everything is downloadable as PDF. Microsoft
copyright, licensed for implementation use.

**Forensics Wiki — forensics.wiki.** Note the history when chasing old links:
the original `forensicswiki.org` was lost, reconstructed at
`forensicswiki.xyz`, then migrated to GitHub-backed `forensics.wiki`. The
`.xyz` mirror is frozen but still reachable. Good for orientation, thinner on
byte-level layout than libyal.

**Tool source as documentation.** plaso parsers, Velociraptor artefacts, and
Eric Zimmerman's tools encode a great deal of format knowledge that was never
written up as prose. Reading a parser is slower than reading a spec but often
the only option, and it reflects what real files actually contain.

---

## 6. Signature and identification databases

| Resource | Where | Notes |
|---|---|---|
| **PRONOM / DROID** | nationalarchives.gov.uk/PRONOM | The authoritative registry. `fmt/` series passed fmt/2000 in April 2024, plus the `x-fmt/` series. Machine-readable XML per PUID. Monthly signature releases. |
| **Siegfried / fido** | github.com/richardlehane/siegfried | The production identifiers built on PRONOM. Run one of these before hand-matching magics. |
| **libmagic / `file`** | bundled | Thousands of rules, the CLI baseline. |
| **TrID** | mark0.net/soft-trid-e.html | Statistical signature database, strong on obscure formats. |
| **Gary Kessler File Signature Table** | garykessler.net/library/file_sigs.html | Maintained since 2002; also ships signature files for FTK, Scalpel, and TrID. One-way lookup, not exhaustive. |
| **Wikipedia list of file signatures** | en.wikipedia.org | Curated common magics, surprisingly serviceable as a first check. |

Older DROID coverage figures such as "over 1,400 formats" are outdated; check
the live count rather than quoting a number from a blog post.

---

## 7. Preservation and archival

**Library of Congress — Sustainability of Digital Formats.**
loc.gov/preservation/digital/formats/. 470+ format description documents,
HTML plus downloadable XML, curated and citation-backed. Actively expanded.
Best-in-class for provenance, obsolescence risk, and the "what produced this
and is it still supported" question that often matters as much as the layout.

**Just Solve the File Format Problem.** fileformats.archiveteam.org. Archive
Team's wiki, roughly 6,680 articles, CC0. Enormous breadth and uneven depth —
treat it as an index that points onward rather than a specification. Live but
low-velocity.

**Open Preservation Foundation / JHOVE** for validation modules, **COPTR**
(coptr.digipres.org) as a tool registry, **Bitsavers** for vintage hardware
and format manuals.

---

## 8. Reverse engineering community wikis

**MultimediaWiki — wiki.multimedia.cx.** The FFmpeg community's wiki, online
since 2005, with 128 container-format pages plus extensive codec coverage,
often including C struct definitions. The deepest free resource for
multimedia formats, and it covers a lot of game audio/video too.

**ModdingWiki — moddingwiki.shikadi.net.** 427 documented formats, heavily
DOS and early-PC games, with genuine byte-level detail and reversing credits.
Backed by the Camoto tooling. Live and curated.

**Ghidra `.gdt` archives, IDA `.til` type libraries, Binary Ninja type
libraries.** Struct and enum knowledge for OS APIs and executables. Oriented
to code rather than files, but when the format is a serialised in-memory
structure — which is common — these are exactly the right reference.

**Awesome lists** (`awesome-file-formats`, `awesome-binary-parsing`,
`awesome-reversing`, `awesome-forensics`) are useful discovery seeds and
unreliable authorities. They accumulate dead links faster than they prune
them; see §10.

---

## 9. Filesystem and protocol references

Filesystems: The Sleuth Kit documentation and Carrier's *File System Forensic
Analysis* remain the reference for NTFS/FAT/ext/HFS+. libyal covers volume and
container formats (BitLocker, FileVault, QCOW, VHDI, VMDK). Kaitai, ImHex, and
poke all ship runnable filesystem specs.

Protocols, because the same technique applies to wire formats: **Wireshark
dissector source** is the largest executable corpus of protocol knowledge
anywhere, and `tshark -T json` gives you structured output to compare against.
DFDLSchemas includes a PCAP schema; fq decodes pcap with TCP reassembly.
Zeek, Suricata, and Nmap service probes encode wire fingerprints. IANA
registries are authoritative for assignments and naming.

---

## 10. Dead, stale, and overrated

- **XentaX is gone.** The wiki and forums shut down in 2023 and archival was
  actively discouraged. Several "awesome" lists still link to
  `wiki.xentax.com`. Use Internet Archive snapshots, and prefer ModdingWiki
  for overlapping coverage.
- **filesignatures.net, FILExt, fileinfo.com** and similar extension-lookup
  sites are stale and SEO-driven. Prefer PRONOM, libmagic, TrID, or Kessler.
- **Old ForensicsWiki links** (`forensicswiki.org`, and increasingly `.xyz`)
  point at dead or frozen versions. The live one is `forensics.wiki`.
- **Construct and binrw/deku** listed as "format galleries" — they are
  libraries. Real, useful, not lookup resources.
- **Format counts quoted from blog posts** drift badly. Kaitai, fq, PRONOM,
  and the wikis all grow; verify before citing a number in a report.

---

## 11. Licensing

Worth checking before you copy a spec into a deliverable or redistribute one
inside a tool:

| Resource | Terms |
|---|---|
| Kaitai `.ksy` | Per-file; each contributor licenses their own description |
| libyal documentation | GNU FDL 1.3 |
| Microsoft Open Specifications | Microsoft copyright, licensed for implementation; schemas and code samples redistributable |
| GNU poke | GPLv3 |
| Hachoir | GPLv2 |
| Wuffs | MIT and Apache-2.0 |
| fq | MIT |
| Just Solve | CC0 |
| 010 Editor templates | Free to download; the editor is proprietary |
| Synalyze It! / Hexinator | Free grammars; Hexinator free tier, Pro paid |

Deriving a layout from a licensed spec and reimplementing it is normally fine;
pasting the spec text into a report is a different question. Check the terms
rather than assuming, particularly for anything GNU FDL, which has
requirements most people do not expect.
