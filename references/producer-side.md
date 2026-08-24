# Producer-Side Analysis

Everything else in this skill reasons from bytes. This reasons from the code
that wrote them, and when the producer is available it is not a marginal
improvement — reading a serialisation routine settles in an hour what
byte-level inference approximates over days, and it yields *semantics*, which
inference never fully does. Inference tells you a dword at +12 is a length.
The code tells you it is the uncompressed size of the payload before LZNT1,
which is a different and far more useful fact.

Use it whenever you have the producing binary. For Windows forensic artefacts
you almost always do: the DLL or service that writes the file is on the same
machine as the artefact.

Contents:
1. Convention: orchestrate, don't reimplement
2. Getting oriented
3. Finding the serialiser
4. Recovering structures
5. Dynamic observation
6. Cross-version diffing
7. Symbolic execution
8. Feeding results back
9. Environment reality

---

## 1. Convention: orchestrate, don't reimplement

Every mature RE skill in the ecosystem — the Ghidra MCP servers, the
rizin/Ghidra triage plugins, the IDA bridges — converges on the same shape,
and this skill follows it rather than inventing an alternative:

- **Wrap the tool, do not rebuild it.** Ghidra, IDA, rizin, and angr already
  do this work. The integration point is MCP or a headless CLI.
- **`analyzeHeadless` is the automation entry point** for Ghidra: import,
  auto-analyse, run a script, export. Everything scriptable goes through it.
- **Export artefacts to disk, then analyse them with ordinary tools.**
  Exporting decompiled C and grepping it is unglamorous, dependency-light, and
  works when a live MCP bridge is unavailable.
- **Structure recovery is a first-class workflow**, not a side effect. Ghidra's
  structure editor, applied data types, and `.gdt` archives make recovered
  layouts durable and reusable across binaries.
- **Detect tool availability rather than assuming it.** These tools are absent
  from most sandboxes.

What this skill adds that a general RE skill does not: **the black-box
analysis has already produced the constants**. You know the magic, the stride,
the struct sizes, possibly the CRC polynomial. Those constants are in the
producer binary, and searching for them jumps you straight to the relevant
code instead of scrolling a function list. That is what `constant_hunt.py` is
for, and it is the bridge between the two halves of the method.

---

## 2. Getting oriented

Identify the producer first. For a Windows artefact, the writer is usually the
service or DLL that owns the subsystem — find it from the file path, the
owning process, the registry key that configures it, or Procmon showing who
holds the handle.

Collect every version you can. Producer binaries from several OS builds are
the raw material for §6, and installers and update packages often contain
several at once.

```bash
python scripts/constant_hunt.py producer.dll \
    --magic 0xACCCABCD --stride 8192 --crc-tables --strings
```

This parses PE and ELF section tables, so hits come back with a section name
and a virtual address you can paste straight into a disassembler. Read the
results as follows:

- **A hit in `.text`** is an immediate in an instruction — the code is writing
  or comparing that constant. This is the lead.
- **A hit in `.rdata`/`.data`** is the constant itself. Xref it to find both
  the writer and the reader.
- **A function containing both the magic and the stride** is almost certainly
  the container writer.
- **A CRC lookup table** is the single strongest lead the tool produces. The
  function indexing it computes the checksum, its callers are the writers, and
  its arguments tell you exactly which bytes are covered — the question
  `cksum_id.py` otherwise answers by brute force.

---

## 3. Finding the serialiser

Beyond constants, the productive searches:

| Search | Why |
|---|---|
| Imports of `WriteFile`, `NtWriteFile`, `fwrite`, `memcpy` to a mapped view | The write itself; walk up the call graph |
| `CreateFileMapping` / `MapViewOfFile` | Paged formats are usually written through a mapping, not stream writes |
| `RtlCompressBuffer` / `RtlDecompressBuffer` | The format argument tells you *which* Windows compression, which `crypto_scan.py` cannot |
| Error strings and format strings | Fastest way to name a function |
| Exported or symbol names matching serial/write/save/flush/commit/marshal | Free when symbols exist |
| Registry paths and file paths as literals | Confirms you have the right binary |

Symbols change everything. For Microsoft binaries, public PDBs from the symbol
server give you real function names, and the difference between
`sub_180012340` and `CWbemPageSource::WritePage` is most of the work.

Once you have a candidate, read it for: the constant it writes at offset zero,
the size it allocates, the loop bounds, what it passes to the checksum
routine, and which fields it fills versus leaves zero. Every one of those maps
onto a row in your hypothesis ledger.

---

## 4. Recovering structures

The decompiler shows member access as offsets: `*(_DWORD *)(a1 + 12)`. Those
offsets *are* the layout.

1. Create a structure in Ghidra sized to the stride you established.
2. Apply it to the pointer in the writing function. The decompiler rewrites
   accesses as named field references and the layout becomes readable.
3. Name fields as you confirm them; export to a `.gdt` archive so the work
   carries to the next binary and the next version.
4. Compare against `fieldmap.py`'s proposed layout.

That comparison is the point. **Agreement promotes a field from `inferred` to
`established`** — two independent methods reaching the same answer is strong
evidence. **Disagreement means one of you is wrong**, and finding out which is
usually the most valuable hour in the whole analysis. Record the function
address as evidence in the ledger either way.

Watch for compiler artefacts: padding inserted for alignment appears in the
struct but means nothing semantically; unions show as overlapping accesses;
bitfields appear as shifts and masks rather than fields.

---

## 5. Dynamic observation

Static analysis tells you what the code can do. Dynamic tells you what it did.

- **Procmon** — which process, which handle, what offsets, in what order.
  Cheapest possible first step on Windows, and it identifies the producer when
  you are not sure.
- **API monitoring / Frida** — hook the write path and capture the buffer plus
  the call stack. This turns your Phase 5 mutation trials from black-box into
  white-box: instead of diffing before and after, you watch the field being
  written and see the stack that produced it.
- **Debugger breakpoints on the writer** — inspect the in-memory structure
  immediately before serialisation. The in-memory form is frequently cleaner
  than the on-disk form and easier to read.
- **Memory forensics** — Volatility or MemProcFS on a live capture. Useful
  when the artefact is a serialisation of something that also lives in memory.

Do all of this in a disposable VM, never on evidence, and never on a machine
you care about.

---

## 6. Cross-version diffing

This is the systematic answer to the version-drift problem the rest of the
skill flags constantly and otherwise solves only by sampling.

Take producer binaries from two OS builds and diff them with **BinDiff**,
**Diaphora**, or Ghidra's Version Tracking. Function-level matching (several
Ghidra MCP servers do this by hashing function content) tells you which
serialisation routines changed between releases — which is exactly the set of
format changes that shipped.

That gives you something inference cannot: a *bounded* statement about version
differences. Instead of "the layout held on the four builds we sampled," you
can say "the writer is unchanged between these builds, and changed here, in
this way." It also tells you which versions are worth sampling, so corpus
collection stops being guesswork.

Propagate names and structures from the analysed version to the others rather
than redoing the work; that is what the `.gdt` archive is for.

---

## 7. Symbolic execution

Reach for **angr** or **Z3** when a value is computed rather than stored, and
brute force is not tractable:

- **Checksum or hash parameters** that `cksum_id.py` fails to identify. Model
  the routine, constrain it to produce the observed value, and solve for the
  polynomial, seed, or coverage range.
- **Obfuscated or derived constants** — a magic assembled at runtime from
  arithmetic rather than stored as a literal, which is why `constant_hunt.py`
  found nothing.
- **Validation predicates** — solve for an input the producer will accept,
  which tells you the field's valid range directly instead of inferring it
  from a corpus.
- **Key derivation** where a region is encrypted with a key computed from
  file contents.

Keep expectations calibrated: symbolic execution is powerful on small, pure,
self-contained routines and struggles with loops of unbounded length, heavy
system interaction, and large state. A checksum function is close to the ideal
case. A whole serialiser is not. Extract the routine of interest and model
that alone.

If you are reaching for this before trying `cksum_id.py --selftest` and a
corpus sweep, you are almost certainly reaching too early.

---

## 8. Feeding results back

Producer-side findings are not a separate deliverable. They enter the same
record as everything else:

- Fields confirmed from code move to `established` in the hypothesis ledger,
  citing the function address and binary version as evidence.
- Version differences found by diffing go in the ledger's version table and
  bound the spec's "Test versions" section.
- Original identifiers recovered from symbols or the decompiler go into the
  `.ksy` as `-orig-id`, which is precisely what that field is for.
- Semantics recovered from code — what event sets a timestamp, what a flag
  actually gates — go into the spec's field descriptions, and are the thing
  black-box work is worst at supplying.
- Anything the code does that your parser does not handle (a second record
  type, a repair path, a legacy branch) becomes a corpus-validation target.

---

## 9. Environment reality

None of Ghidra, IDA, rizin, angr, Frida, or BinDiff is present in a bare
sandbox, and several need substantial setup. Before planning a workflow around
them, check what actually exists. Where they are unavailable, the fallback
chain is: `constant_hunt.py` for coordinates, a hex editor for the bytes at
those coordinates, and the black-box loop for everything else — which is
slower but not blocked.

Where the tools *are* available, prefer an existing MCP integration over
shelling out ad hoc: the Ghidra MCP servers expose decompilation, xrefs,
structure creation, and script execution as tools, and that is a better
interface than parsing `analyzeHeadless` output by hand.
