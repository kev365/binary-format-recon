# Residual Analysis: Attacking What a Known Structure Leaves Out

Most format work does not start from zero. You have a specification, a
reference parser, or your own earlier analysis, and it mostly works. What it
has are gaps: fields the spec calls reserved, regions marked unknown, bytes
described as padding, and areas nobody documented because nobody needed them.

Those gaps are where the remaining information is, and they are invisible
precisely *because* the structure is considered known. A parser that works is
the strongest possible disincentive to look at the bytes it ignores.

This is the method for going after them.

Contents:
1. Why gaps persist
2. Coverage accounting
3. What the leftovers turn out to be
4. Residual data, and why it matters most
5. Attacking a specific unknown
6. Reserved fields
7. When the answer is "nothing"
8. Recording it

---

## 1. Why gaps persist

Four reasons, and the fix differs for each:

**Nobody needed it.** A parser written to extract timestamps ignores
everything else. The field is documented as unknown because the author had no
reason to care, not because it resisted analysis. These are often easy wins.

**The corpus did not exercise it.** A field used only by a record type, locale,
or producer version absent from the original samples looks like dead padding.
Widening the corpus is the whole fix.

**It genuinely resisted.** Some fields are opaque without the producer —
derived values, hashes, encrypted regions. These need producer-side analysis
or symbolic execution, not more staring.

**It was never a field.** Alignment padding, and slack the format does not
define. Real, but the answer is "nothing there", which is a finding that
should be stated rather than left ambiguous.

The important consequence: **a spec saying "unknown" tells you nothing about
which of these four applies.** Assume nothing about how hard a gap is until
you have looked.

---

## 2. Coverage accounting

Subtract what you know from the bytes, then characterise what is left.

```bash
python scripts/coverage.py sample.bin --stride 8192 --head 128 --map \
    --field 0:4:magic --field 4:4:page_id --field 16:8:timestamp
python scripts/coverage.py ./corpus --corpus --stride 8192 --layout fieldmap.json
```

`--layout` accepts `fieldmap.py --json` output directly, so a layout you
derived can be fed back in as the known set. `--map` prints a byte-level
coverage picture, which is often the moment people realise their "complete"
layout accounts for 40% of the record.

The classification runs across the whole corpus, not one file, because most of
these verdicts are only visible across many records. A constant is only a
constant if it is constant everywhere.

**Granularity is a real trade-off, not a tuning knob.** Run both settings.
`--granularity 8` resolves wide structures — 64-bit pointers, u64 fields,
leaked addresses — while `--granularity 4` separates narrow adjacent fields
that 8 merges together. A field that shows at one setting and not the other is
still a finding; it means you have two adjacent things, or one wide thing, and
knowing which is progress.

Overlapping declared fields are flagged. An overlap usually means a width is
wrong or a union is being read as a struct, and it is worth fixing before
trusting anything else in the output.

---

## 3. What the leftovers turn out to be

| Verdict | Signature | What to do |
|---|---|---|
| Genuine padding | Zero across the entire corpus | Nothing — but say so explicitly, with the corpus size |
| Undocumented constant | Identical in every record | Search the producer for the value; a named constant in code settles it |
| Derived value | Tracks a known field by a fixed offset or ratio | Record the relationship; nothing independent to learn |
| Live field | Varies independently, moderate entropy | Controlled mutation, or find it in the producer. A real field nobody named |
| Live field, high entropy | Near-random, wide | Try `cksum_id.py` first — an unexplained high-entropy field is more often a checksum than anything else |
| Conditional or version-scoped | Non-zero in a minority of records | Widen the corpus; `corpus.py --cluster` will show whether users of it form a distinct group |
| Residual data | Pointers, stale fragments, or text where the layout says nothing lives | See below |

The ordering in the tool's output is by investigative value, not by offset.
Padding is listed last on purpose.

---

## 4. Residual data, and why it matters most

This is the part specific to forensics, and the reason this workflow earns its
place.

When a producer writes a structure without zeroing the buffer first, whatever
was previously in that memory goes to disk. A specification calls the region
padding because from the format's point of view it is. From an investigator's
point of view it is a memory disclosure written to persistent storage.

What turns up there:

- **Pointers.** Detected by upper-half clustering rather than per-value range:
  real leaked pointers come from the same module or heap, so their high halves
  cluster on an image base or heap segment while the low halves vary. This
  also reveals whether the producer is 32- or 64-bit, and sometimes ASLR base
  addresses.
- **Stale buffer contents.** Fragments that also occur elsewhere in the file
  mean a buffer is being recycled without clearing. Those fragments are
  remnants of earlier writes, and may contain records that have since been
  deleted or overwritten in the allocated data.
- **Text remnants.** Strings in a region the layout treats as unused. Compare
  them against the strings in live records: anything present here and absent
  there is a candidate for recovered deleted content.

Treat all of this as **carved data, not fields**. It has no defined semantics,
its presence is incidental, and it should be reported separately from cleanly
parsed content with its own confidence caveat. But it is frequently the most
probative material in the artefact, and it is sitting in bytes labelled
"reserved".

---

## 5. Attacking a specific unknown

Once coverage accounting points at a run worth chasing, in rough order of
cost:

1. **Correlate it against known fields.** `coverage.py` tests fixed offsets
   and ratios automatically; also check deltas against timestamps, record
   counts, and lengths by hand. A derived value is the cheapest possible
   answer.
2. **Widen the corpus.** If it is zero in every sample, no amount of analysis
   will help — you need samples that use it. `corpus.py --cluster` will show
   whether the samples that populate it are a distinct group, which usually
   means a producer version or a record type.
3. **Controlled mutation.** Phase 5, but targeted: change one thing in the lab
   and watch this specific offset. If the unknown moves when you change a
   known input, you have its semantics.
4. **Producer-side search.** `constant_hunt.py` on the producer, then read the
   writer. A field's meaning is often one decompiled line. This is usually the
   fastest route for anything that resisted steps 1 to 3.
5. **Producer probing.** Mutate the unknown and feed it back. If the producer
   rejects the file, the field is validated and you have learned its domain;
   if the producer rewrites it, you have been handed the correct value by the
   authoritative implementation.
6. **Symbolic execution.** Only for computed values that resisted everything
   above.

Steps 1 and 2 cost minutes. Do not start at step 4.

---

## 6. Reserved fields

"Reserved" in a specification means one of several things and the document
rarely says which:

- Reserved for future use, currently always zero — genuine padding today, a
  live field in a later version. Check newer producer versions specifically.
- Reserved because the author did not know — functionally identical to
  "unknown", and worth attacking normally.
- Reserved and *used*, because the implementation diverged from the spec.
  Common, and coverage accounting finds it immediately: a "reserved" field
  with varying values is one of the highest-yield findings available.
- Alignment padding the spec dignified with a name.

The test is empirical and takes one command. Never assume a reserved field is
inert on a specification's say-so; a spec is a claim about the format, and the
corpus is evidence about the implementation.

---

## 7. When the answer is "nothing"

Frequently the leftovers really are padding, and that outcome deserves to be
recorded as carefully as a discovery. "Zero across 52 samples spanning four
producer versions" and "not examined" are different statements that read
identically in a document that omits both.

State the corpus size and version scope alongside the negative result. It
tells the next person the ground has been covered and under what conditions —
and it tells them when their new samples fall outside that scope and the
question is open again.

---

## 8. Recording it

Everything found this way enters the normal record:

- A confirmed field moves from `unknown` to `inferred` or `established` in the
  hypothesis ledger, with the evidence noted.
- A field that remains opaque stays `unknown` and is listed **in** the layout,
  with its offset and width, rather than omitted. An unknown you have located
  and bounded is far more useful than a silent gap.
- Residual data is documented in the specification's deleted-and-unallocated
  section, flagged as carved rather than parsed.
- Negative results — regions confirmed inert — are stated with corpus scope.
- Anything not chased gets a classified skip in `review_tracker.py`, so the
  distinction between "assessed and inert" and "never examined" survives into
  the report and the reader can decide whether to pursue it.
