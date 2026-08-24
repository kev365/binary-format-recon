# Validation and Corpus

The core loop establishes a layout. This is how you find out whether it is
right, using tests that can actually fail. A parse-rate number is the weakest
of these and the one most often quoted alone.

Contents:
1. The ladder of evidence
2. Building a corpus
3. Round-trip testing
4. Fuzzing outward: parser robustness
5. Fuzzing inward: probing the producer
6. Reporting validation

---

## 1. The ladder of evidence

Roughly in increasing order of strength:

| Test | What it demonstrates | Weakness |
|---|---|---|
| Parses without error | The layout is not obviously wrong | A parser that misreads a field succeeds on every file |
| Parses the whole corpus | It generalises across samples | Silent misreads survive; duplicate samples inflate it |
| Checksum validates | Record boundaries and coverage are right | Only where the format has one |
| Round-trips byte-for-byte | Every byte is accounted for | Faithful copying is not understanding |
| Survives fuzzing | It fails safely on corrupt evidence | Says nothing about correctness |
| Producer accepts your output | The producer's own validation agrees | Needs the producer, and a disposable VM |
| Controlled mutation predicted | Field semantics are correct | Slow; one field at a time |

Report where on this ladder each field sits. "Round-trips across 52 samples,
three fields confirmed by mutation" is a far more useful claim than "parser
works".

---

## 2. Building a corpus

```bash
python scripts/corpus.py ./samples --cluster --threshold 0.6 --report corpus.md
python scripts/corpus.py --sources        # where to obtain samples
```

Two failures matter. **Duplicates inflate apparent support** — fifty files
that are three files copied make a layout look far better evidenced than it
is, so count unique hashes and never raw file counts. **Clusters are usually
versions**: the tool groups by structural similarity, and those groups
typically correspond to producer versions you have not identified yet. Validate
against each cluster separately and report per-cluster rates; a field that
holds in one cluster and fails in another is a versioned field, not a broken
hypothesis.

Clustering on `--header-bytes 512` tracks format version more closely than
whole-file similarity, because headers change with the format while payload
changes with the content.

Singletons are worth opening first. An outlier is a different format, a
different version, or corrupt, and all three are informative.

Keep lab-generated samples in a separate tree from case data. They look
identical, and mixing them is the hardest mistake to undo.

---

## 3. Round-trip testing

Parse, serialise, compare. Any field you misread, ignored, or normalised shows
up as a divergence at a specific offset.

```bash
python scripts/roundtrip.py --module myparser.py --corpus ./samples --stride 8192
```

Supply a module with `parse(data) -> obj` and `serialize(obj) -> bytes`.
`construct` gives you both from one definition, which is reason enough to use
it for validation even when the shipped parser is Kaitai-generated.

The diagnostic value is in *where* divergences land. A position that recurs at
the same intra-record offset across many files is one specific field being
misread, not noise. Common causes, roughly by frequency: a field read at the
wrong width; padding regenerated as zeros where the original held stale bytes;
a checksum recomputed rather than preserved; string padding normalised; a
reserved field dropped on parse. Only the checksum case is benign, and only if
you meant it.

Byte-identical round-trip across a corpus is the strongest evidence available
without the producer. It is still not sufficient: a parser can round-trip
perfectly while assigning the wrong *meaning* to a field it copies faithfully.
Semantics come from mutation trials and from code.

---

## 4. Fuzzing outward: parser robustness

A forensic parser meets corrupt evidence routinely. One that raises an
unhandled exception on a truncated record has failed at its job, because the
whole analysis stops rather than flagging one bad record.

```bash
python scripts/mutate.py sample.bin -o mutants/ --count 200 --stride 8192 \
    --field 10:2 --field 16:8 --run "python myparser.py {}"
```

Pass `--field` entries from `fieldmap.py` output: field-targeted mutation is
far more productive than random bit flips, because length and offset fields
are where parsers break. Mutations are deterministic under `--seed`, so any
crash is reproducible.

Read the outcomes carefully. **A clean non-zero exit is correct behaviour** —
the parser rejected bad input. An unhandled traceback, a hang, or a signal is
a bug. If every mutant is accepted, check the parser actually reads the
mutated region before concluding it is robust: field mutations land in a
randomly chosen record, so a parser that only reads the first one reports
clean regardless. `--record 0` pins them.

---

## 5. Fuzzing inward: probing the producer

The more informative direction, and the one people skip.

Put a mutant where the application expects its data file and see what happens.
A producer that refuses a file is telling you a validation rule, and
validation rules reveal field semantics faster than passive observation ever
does. If changing offset 12 makes the application refuse to load but changing
offset 16 does not, you have learned something no amount of staring at bytes
would give you.

Three outcomes, all useful:

- **Rejected** — that field is validated. Narrow the range by bisection to
  find the accepted bounds, which gives you the field's domain directly.
- **Repaired** — the producer rewrote it. Diff what it wrote: you have just
  been handed the correct value for a field, computed by the authoritative
  implementation.
- **Accepted** — either the field is not validated, or you did not change
  anything meaningful. Check the second before believing the first.

Do this in a disposable VM. Never against evidence, never against a machine
that matters, and never against a system you do not own.

---

## 6. Reporting validation

State, for the record:

- Corpus size as unique files, with cluster and version breakdown.
- Parse rate per cluster, with failures characterised rather than counted.
- Round-trip identity rate, and where divergences localised.
- Fuzzing: number of mutants, strategies, crashes found and fixed.
- Which fields were confirmed by controlled mutation, and which by code.
- Which validation depth was chosen and why — ISO/IEC 27041's *sufficient*
  versus *comprehensive*, per `references/documentation.md` §8.

An error rate you measured is worth more than a claim of correctness you did
not.
