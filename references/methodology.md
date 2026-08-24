# Methodology

Contents:
1. Designing the mutation set
2. Hypothesis falsification
3. Confidence scoring
4. When there is no stride
5. Multi-page and indirection layers
6. Working from an existing spec
7. Deleted and slack data
8. Common traps

---

## 1. Designing the mutation set

Differential baselining only works if the mutations are designed. Ad hoc
poking produces diffs you cannot attribute.

**One variable per trial.** If you create a record *and* rename another in the
same trial, every changed byte has two possible causes. Run separate trials.

**Make mutations findable.** Use a distinctive marker — `ZZTOPMARKER99`,
`AAAAAAAABBBBBBBB` — rather than a realistic value. You want the payload to be
greppable in the diff output and impossible to confuse with existing content.

**Vary one dimension at a time across a series.** To learn how a length field
works, create records whose payload is 4, 8, 16, and 32 bytes. The field that
takes the values 4, 8, 16, 32 (or 8, 16, 32, 64 if it counts something else)
is the length. One trial cannot distinguish a length from a coincidence; four
trials with a known progression can.

**Recommended minimum series for a record-oriented format:**

| Trial | Change | Reveals |
|---|---|---|
| A | Add one record with a unique marker | Record insertion point, allocation, count field |
| B | Add a second record | Count increments, index growth, whether records are appended or sorted |
| C | Modify one field of an existing record in place | Field offset, whether edits are in-place or copy-on-write |
| D | Delete a record | Tombstoning vs compaction, free-space tracking |
| E | Repeat A with a payload 2x longer | Length field, offset cascade |
| F | Repeat A with a payload 4x longer | Confirms the length field is linear, not an enum |
| G | Two idle snapshots, no change | The control pair — background churn |

Trial G is not optional. Run it first and run it again at the end; churn can
differ depending on system state.

**Timing matters.** Many artefacts are written lazily. Flush or stop the
producing service before snapshotting, or you will diff a partially written
file and attribute the difference to your mutation.

**Record the trial metadata.** Timestamp, exact input, service state, OS
build. The diff is meaningless six months later without it.

---

## 2. Hypothesis falsification

The failure mode in format RE is confirmation: you form a reading early,
every subsequent sample is interpreted through it, and the contradicting
sample is dismissed as corrupt.

Counter it structurally:

**State the alternative.** For every field, write down the second-most-likely
reading. "u32 at +8 is a length" has the alternative "u32 at +8 is an offset to
the next record". They agree on many samples and disagree on some.

**Find the discriminating sample, not more supporting ones.** In the example
above, a record that is not the last in its block distinguishes length from
offset immediately. Ten more records that fit both readings add nothing.

**Predict before you look.** Write the expected bytes for a new sample, then
check. A hypothesis that only ever explains data retrospectively is not doing
work.

**Treat a checksum as an oracle.** Once `cksum_id.py` confirms coverage, any
boundary hypothesis that breaks the checksum is dead immediately. This is the
cheapest falsification available — prioritise finding the checksum early.

**Corrupt records are evidence, not noise.** If 3% of records fail to parse,
find out why before writing them off. Frequently they are a second record
type, an older version, or slack from a prior write.

---

## 3. Confidence scoring

Assign every field a status and defend it. Suggested rubric:

| Status | Requires |
|---|---|
| `established` | A controlled mutation produced the predicted change, **or** an independent published spec agrees and the corpus confirms it |
| `inferred` | Holds across the full corpus with no counterexample, but never directly manipulated |
| `speculative` | Fits the samples; a plausible alternative reading has not been excluded |
| `unknown` | Present and non-zero, purpose undetermined |

Two quantities are worth recording per field:

- **Corpus support** — fraction of samples where the reading holds. Report it
  as a fraction with the denominator visible (`47/52`), never as a bare
  percentage, so the sample size is not hidden.
- **Version scope** — which producer versions were actually tested. A field
  established on two Windows 11 builds is not established on Windows 7.

When corpus support is below 1.0, split the corpus and test whether the
failures cluster by version, locale, architecture, or producing application.
Clustering means a version variant; scatter means the hypothesis is wrong.

---

## 4. When there is no stride

`profile.py` reports no convincing stride for variable-length formats. Switch
strategy:

1. **Find the anchors.** Run `strscan.py` and `tsscan.py` without `--stride`.
   Strings and timestamps will scatter, but their *positions* map out where
   records live.
2. **Establish the length convention.** `strscan.py`'s prefix test usually
   settles this. Whatever width prefixes strings almost always prefixes
   records too.
3. **Walk the chain.** Pick the first plausible record start. Read the
   candidate length. Jump. If you land on something that looks like another
   record header, the hypothesis is good; if you land mid-string, it is wrong.
   A correct length field walks the entire file and lands exactly on EOF —
   that is a very strong confirmation and worth scripting as a one-off.
4. **Watch for alignment.** Records are often padded to 4, 8, or 16 bytes.
   If the walk drifts by a small amount each step, add rounding.
5. **Check for a terminator.** Some formats end the array with an all-zero
   record rather than storing a count. If the walk ends on a zero block rather
   than EOF, that block is the terminator, not corruption.

Once the walk succeeds, extract the record headers into a synthetic
fixed-stride file (concatenate the first N bytes of each record) and run
`fieldmap.py` on that. The column profiler needs a table; giving it one
manually is often the fastest path.

---

## 5. Multi-page and indirection layers

Serious formats rarely address bytes directly. Watch for:

**Logical-to-physical mapping.** A separate map file or map region translates
logical page numbers to physical page offsets. Symptoms: pointer fields whose
values are small integers rather than byte offsets; a second file whose size
scales with the main file; page numbers that do not match physical positions.
You must resolve the map before any pointer means anything. The WMI CIM
repository, ESE databases, and many journalling formats all work this way.

**Masked page numbers.** Pointer dwords frequently pack flags into the high
bits, so the page number is only the low 30, 28, or 24 bits. If pointers look
almost-but-not-quite right, mask progressively and see which mask makes them
land on boundaries.

**Sentinel values.** `0xFFFFFFFF` and `0x3FFFFFFF` conventionally mean
unallocated or unavailable. Do not decode them as offsets.

**Multiple map generations.** Formats that need crash consistency keep two or
three map copies and select the newest by a sequence or version field. Parsing
the wrong one yields a stale, self-consistent, and completely wrong view. Find
the selection rule before trusting anything downstream.

**Records that span pages.** A record longer than a page continues on the
next *logical* page, which is not the next physical page. Continuation pages
usually carry no header, so a parser that assumes a header per page will
mis-read them.

---

## 6. Working from an existing spec

Finding the spec is covered in `references/format-galleries.md`, and reading
one properly -- enumerating its units, covering them all, chasing citations
without abandoning the review -- is covered in `references/source-review.md`.
This section is about what a spec is worth once you have read it.

When a published spec or reference implementation exists, the work is
verification, and the temptation is to trust it wholesale. Specs are usually
written from a handful of samples on a handful of versions.

- **Diff the spec against the code.** Where a written spec and a working
  parser disagree, the parser is usually right about what real files contain
  and the spec is right about what the fields mean. Note fields the spec marks
  "unknown" that the implementation has since named — and vice versa.
- **Re-derive at least one field yourself** with a controlled mutation. It
  validates your whole pipeline and occasionally catches a spec error.
- **Check the version coverage of the spec** against your corpus. Older specs
  often predate a format revision.
- **Watch for fields that are present but unused** on some versions — a
  checksum field that is populated on one OS release and left zero on another
  is a real and common pattern. Do not conclude the field does not exist.

Record spec-derived fields as `established` only once your corpus agrees;
until then they are `inferred` from someone else's samples.

---

## 7. Deleted and slack data

Forensically the most valuable content is often the content the format
considers deleted.

- **Tombstones.** Deletion frequently flips a type or status byte rather than
  erasing the record. Compare the type enum values in `fieldmap.py` output
  against a trial-D diff to find the deleted marker.
- **Slack.** Records shrink, but the tail of the old record remains. Scan the
  region between a record's declared length and the next record's start.
- **Unallocated pages.** Pages the map no longer references still hold their
  previous contents. Enumerate physical pages, subtract mapped ones, and carve
  the remainder.
- **Carving fallback.** When structure is unrecoverable, signature-scan for
  record magics across the whole file including unmapped space, and parse each
  hit independently. Results are lower confidence — label them as carved and
  do not present them alongside cleanly parsed records without distinction.

---

## 8. Common traps

- **Zero-dominated files defeat naive similarity scoring.** Any stride makes
  padding line up. Score on non-modal bytes only.
- **Small integers look like timestamps.** A dword holding `64` is a valid
  Cocoa timestamp. Always weigh hit counts against the encoding's chance rate.
- **Doubles read from non-float data decode to the epoch.** Denormals from
  integer or ASCII bytes become dates a fraction of a second after 1899 or
  2001. Impose a magnitude floor.
- **A u64 that steps by exactly 2^32 is two u32 fields**, one constant and one
  counting.
- **Multiples of the true stride score identically.** Always reduce to the
  smallest divisor that still holds.
- **Endianness can be mixed** within one format, particularly where a network
  protocol structure has been embedded in a host-order file.
- **Timestamps may be local, not UTC**, and some formats store an offset
  separately. Cross-check one timestamp against a known-time event in the lab.
- **The first record is often special** — a header masquerading as record 0.
  Profile with and without `--offset` set past it.
- **Do not calibrate on a single file.** A stride that works on one sample and
  is off by a header's length on the rest is the classic error.
