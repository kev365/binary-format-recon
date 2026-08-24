# Forensic Soundness

An inferred parser is a hypothesis rendered as code. Everything here exists to
keep that distinction visible, so that a finding produced by the parser can be
defended, reproduced, and — where appropriate — doubted.

Contents:
1. Provenance and handling
2. Reproducibility
3. Ambiguity, partial records, and corruption
4. Stating evidentiary limits
5. Reporting template
6. Anti-patterns

---

## 1. Provenance and handling

- **Hash on receipt, hash on release.** `provenance.py record` at the start,
  `provenance.py verify` at the end. If a hash changed during analysis,
  something wrote to the evidence and the analysis is contaminated.
- **Work on copies only.** `provenance.py` warns when inputs are writable in
  place. A parser bug that opens a file `r+b` instead of `rb` will silently
  modify evidence, and that is not a hypothetical failure mode.
- **Preserve the acquisition context.** Source system, acquisition method,
  operator, time, and tool versions. The bytes without that context can
  establish what a file contains but not whose it was or when.
- **Keep the lab corpus separate from case data.** Mutation trials generate
  files that look exactly like evidence. Directory hygiene and naming that
  makes the distinction obvious prevents the worst kind of mix-up.
- **Record the negative space.** Note which artefacts were expected but
  absent, and which regions were unreadable. Absence is a finding.

---

## 2. Reproducibility

A result that cannot be regenerated is an assertion, not evidence.

- **Pin the environment.** Python version, script versions, and the manifest
  hash of the input set. All scripts here are stdlib-only specifically so that
  a dependency tree cannot drift underneath a result.
- **Make output deterministic.** Sort explicitly rather than relying on set or
  dict iteration order. Do not embed wall-clock time in analytic output; put
  it in the manifest instead, where it belongs.
- **Log the exact invocation.** Including every flag. `--stride 8192` versus
  `--stride 4096` produces entirely different conclusions from the same file.
- **Keep the intermediate artefacts**, not just the final report: the
  `profile.json`, the `fieldmap` JSON, the diff outputs. They are the working
  that lets someone else check the conclusion.
- **Re-run on a clean machine** before reporting. Analyses that depend on
  leftover state in the working directory are common and invisible until
  someone else tries to repeat them.

---

## 3. Ambiguity, partial records, and corruption

The rule: **surface it, never swallow it.**

- **Never silently drop a record.** Every input record produces an output
  record, even if that output is `{"status": "unparsed", "offset": ..., "reason": ...}`.
  A parser that quietly skips 4% of records will produce a report that omits
  evidence with no indication anything is missing.
- **Distinguish absent from zero from unparsed.** These mean different things
  and collapsing them destroys information. A missing timestamp field, a
  timestamp field containing zero, and a timestamp field that failed to decode
  are three different findings.
- **Flag carved and reconstructed data separately** from cleanly parsed data.
  Records recovered from slack, unallocated pages, or signature carving carry
  lower confidence in both content and context, and must not be presented
  in the same table as cleanly parsed records without a distinguishing column.
- **Do not repair silently.** If a length field is implausible and the parser
  clamps it, the output must say so. Silent repair is how a corrupt record
  becomes a confident false statement.
- **Bound the damage.** A corrupt record should not desynchronise the whole
  parse. Re-anchor on the next record boundary using a magic or the stride,
  and record the gap.
- **Report both readings when a field is genuinely ambiguous.** If a dword is
  equally consistent with a length and an offset and no sample distinguishes
  them, say that, rather than picking one.

---

## 4. Stating evidentiary limits

Every report on an inferred format should be explicit about the following,
because a reader cannot infer them from the output:

- **Which fields are established, inferred, speculative, or unknown**, using
  the rubric in `methodology.md` §3.
- **Which producer versions were tested.** A layout confirmed on two builds is
  not a layout confirmed generally. Name the builds.
- **Corpus size and composition**, with the denominator visible. "47 of 52
  samples" not "90%".
- **What the timestamps mean.** Whether they are UTC or local, what generates
  them, and what event they record. A timestamp field whose *semantics* are
  unknown ("some time was recorded here") is far weaker evidence than one
  whose trigger is understood, and the difference matters enormously in
  interpretation.
- **What the artefact does not prove.** Presence of a record shows the
  producing subsystem wrote it; it does not by itself establish user action,
  intent, or attribution. Keep the inferential chain explicit.
- **Known unknowns.** Regions of the format not yet understood, and whether
  they could plausibly contain information relevant to the question asked.

Where analysis may be relied upon in a legal or disciplinary process, the
methodology, the tool versions, the error rates observed on the corpus, and
the limits above should all be available for review. Standards for what is
admissible vary by jurisdiction and are outside the scope of this skill —
this is about producing work that can withstand scrutiny, not about
certifying that it will.

---

## 5. Reporting template

For the format specification itself and the conventions it follows, see
`references/documentation.md`; this template covers the analysis report that
cites it.

```
## Artefact
Name, path, size, SHA-256, source system, acquisition method and time.

## Format determination
How the format was identified. Existing specification consulted (with
version), or reverse engineered. Tool versions used.

## Corpus
Number of samples, producer versions covered, how they were obtained.
Lab-generated vs case data, kept distinct.

## Layout
Field table with offset, width, type, semantics, and status
(established / inferred / speculative / unknown), plus corpus support
as a fraction for anything below `established`.

## Validation
Mutations performed and what each confirmed. Checksum coverage confirmed,
if any. Parse rate across the corpus, with failures characterised.

## Findings
What the parsed data shows. Carved and reconstructed items flagged
separately from cleanly parsed items.

## Limitations
Untested versions. Unresolved fields. Ambiguous readings. Timestamp
semantics and timezone basis. What the artefact does not establish.

## Reproduction
Exact commands, input manifest hash, environment.
```

---

## 6. Anti-patterns

- **Presenting inference as fact.** "The file was created on 3 March" when
  what is established is "a FILETIME field at +16 holds a value decoding to
  3 March, semantics undetermined."
- **Hiding the sample size.** Percentages without denominators.
- **Version-blind claims.** Asserting a layout generally from one OS build.
- **Silent error handling.** `try/except: continue` in a forensic parser is
  a decision to discard evidence without recording that it happened.
- **Calibrating and validating on the same file.** The layout will always fit
  the file it was derived from.
- **Trusting a single tool.** Where a second implementation exists, run it and
  compare. Disagreement between two parsers is a finding worth chasing, and it
  is usually the more careful one that is wrong about something interesting.
- **Analysing evidence in place.** Every parse should be against a verified
  copy.
- **Losing the chain from bytes to claim.** Every statement in a report should
  be traceable to a specific offset in a specific file.
