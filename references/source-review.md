# Reviewing Sources Thoroughly

Finding a relevant source is the easy part. The failure that follows is
predictable and expensive: read the sections that look relevant, form a
picture, stop. The fourth section you did not read redefines a field the
first three described, and now the parser is wrong in a way that will only
surface when it matters.

This is the discipline for reading a source properly. It applies to
specifications, reference implementations, gallery entries, wikis, papers,
and to your own sample corpus — anything where partial coverage would produce
a confident conclusion resting on an incomplete reading.

Contents:
1. Why skimming fails specifically here
2. Enumerate before reading
3. Plan the traversal
4. Read a unit properly
4a. When retrieval misfires
5. Cross-references without drift
6. Completion, and what counts as done
7. Reviewing a corpus of samples
8. Reviewing an implementation
9. What lands in the report

---

## 1. Why skimming fails specifically here

Binary format documents are not prose you can sample. Three properties make
partial reading unusually dangerous:

**Definitions are non-local.** A field's width appears in one section, its
valid values in another, its version-dependent meaning in a third, and the
condition under which it is ignored entirely in an appendix. Reading the
section that names the field tells you the least interesting thing about it.

**The exceptions carry the weight.** The main body describes the common case.
The forensic value is usually in the uncommon case — the deleted record, the
version that behaves differently, the field that is present but unused on one
OS release. That material lives in the sections nobody reads.

**Silence is meaningful and invisible.** A spec that does not say a field is
optional, or does not state a byte order, is telling you something. You cannot
notice an absence in a section you skipped.

The compounding problem is that a partial reading feels complete. Nothing in
the experience of reading three of five sections signals that you are missing
something, which is why coverage needs to be tracked mechanically rather than
by recall.

---

## 2. Enumerate before reading

Before reading anything, enumerate the units of the source and register them.
This fixes the denominator in advance, so coverage is measured against the
whole source rather than against what you happened to find interesting.

```bash
python scripts/review_tracker.py add "MS-CFB" --kind spec \
  --locator "https://learn.microsoft.com/openspecs/windows_protocols/ms-cfb/" \
  --scope "sections 2.1-2.6, header through FAT" \
  --units "2.1 Sectors,2.2 Header,2.3 FAT,2.4 MiniFAT,2.5 Directory,2.6 Streams"
```

The natural unit varies: section headings for a spec, functions or classes for
an implementation, page ranges for a scanned document, article sections for a
wiki page, individual files for a corpus. Any consistent division works. What
matters is that the list exists before reading starts and does not get
quietly shortened afterwards.

**Declare the scope, and treat it as a commitment.** For a very large source —
MS-PST is not going to be read cover to cover for a question about message
headers — the answer is not to skim the whole thing. It is to declare a
narrower scope explicitly, enumerate the units *within* that scope, and cover
those completely. A stated partial scope is an honest limitation. An
undeclared partial reading presented as a complete one is not.

**Enumerate the excluded material too, and classify it.** Narrowing scope is
only honest if the reader can see what fell outside. Register the whole source
where practical and skip the out-of-scope units with a classification, rather
than pretending the source is smaller than it is. The distinction that matters
is not what you read — it is whether the material you did not read was
*assessed and ruled out* or *never examined*:

| Class | Assessed? | Meaning |
|---|---|---|
| `not-relevant` | yes | read enough to establish it does not bear on the question |
| `superseded` | yes | covered by another source or a later version |
| `duplicate` | yes | same material reviewed elsewhere |
| `out-of-scope` | no | outside the declared scope; may hold relevant material |
| `deferred` | no | likely relevant, not yet examined |
| `low-yield` | no | judged unlikely to be relevant, without reading it |
| `inaccessible` | no | paywalled, missing, corrupt, unavailable |

The four unassessed classes are surfaced separately in `status`, `close`, and
`report` as **available avenues rather than closed questions**. That is the
whole point of the vocabulary: the decision to investigate further belongs to
the person reading the analysis, and they can only make it if the unexamined
material reaches them. `close` refuses while any skip is unclassified.

If the scope turns out to be wrong, widen it on the record with
`units --add` rather than reading less than you said you would.

---

## 3. Plan the traversal

Decide the order before starting, because the order determines what you can
understand as you go:

1. **Structural material first.** Overview, terminology, version history,
   and any conventions section. Byte order, base types, and how the document
   expresses optionality are usually defined once, early, and assumed
   everywhere after.
2. **Then the container.** Headers, page or block structure, allocation, and
   any indirection layer. Nothing downstream can be located without these.
3. **Then the records.** Individual structure definitions.
4. **Then the exceptions.** Versioning, deprecated fields, error handling,
   deleted or free space, and anything labelled appendix or "notes". This is
   where forensic value concentrates and where a tired reader stops.
5. **Then the examples.** Worked examples last, as validation: you should be
   able to predict them before reading them. If you cannot, something earlier
   was misread.

Announce this plan before starting so the shape of the review is visible, then
work it in order. Resist reordering toward whatever looks most relevant to the
immediate question — that is skimming with extra steps.

---

## 4. Read a unit properly

For each unit, and before marking it done, resolve:

- **What does it actually say**, in your own words, at the byte level.
- **What does it not say.** Undefined behaviour, unstated defaults, missing
  byte order, silent version assumptions. Record these as gaps — they are
  findings, not omissions on your part.
- **Does it contradict anything already read**, in this source or another.
  Conflicts get recorded, not resolved by preference. Which source your corpus
  supports is an empirical question to settle later.
- **What must be checked elsewhere.** Every citation, every "see section X",
  every referenced document becomes a cross-reference obligation.

```bash
python scripts/review_tracker.py mark src-1 2 \
  --note "header is 512 bytes; sector size is a header field" \
  --finding "sector size is not fixed -- 512 or 4096 per header" \
  --gap "byte order not stated for the version field" \
  --conflict "libyal names this field; spec calls it reserved" \
  --xref "MS-DTYP for FILETIME semantics"
```

Marking a unit done is a claim that you could answer questions about it
without rereading. If that is not true, it is not done.

---

## 4a. When retrieval misfires

Before a unit can be read it has to arrive, and the failure that precedes
skimming is quieter than skimming: the fetch returns *something*, so it feels
like the source was consulted. It was not. Treat each of these as a retrieval
of nothing:

| Symptom | What actually came back |
|---|---|
| Table of contents, revision history, download links | the document's index page, not the document |
| Product landing page, "Overview", marketing copy | the site, not the spec |
| HTTP 403 / 401 / 404, a login wall, a CAPTCHA | nothing |
| Text that stops mid-table, or a summary shorter than the section should be | a truncated render; the field table is missing |
| A cross-host redirect you did not follow | nothing |
| The right document, wrong version (a 2013 revision when the field was added in 2018) | a different source |

The rule is blunt because the temptation is strong: **a source that did not
arrive has not been read, and what you remember of it is not a substitute.**
Recall of a specification is a hypothesis with no evidence attached — exactly
the kind of plausible layout the rest of this method is built to distrust. It
is most dangerous for well-known formats, where confidence is highest and a
wrong field label (swapped timestamps, an off-by-one in a reserved run)
survives longest because nobody thinks to check.

Escalate in this order, and record each attempt:

1. **The same source, addressed properly.** Index pages link to the real
   thing: a PDF download, per-section pages, a "source" link to the docs
   repository. Microsoft Open Specifications are the canonical case — the
   top-level `[MS-XXXX]` page is an index with a PDF link and a GitHub
   source path; the structure tables live in the section pages beneath it
   or in the PDF. Fetch the section, or download the PDF and extract the
   pages you need.
2. **A mirror of the same text.** Docs repositories on GitHub (raw
   markdown), the Internet Archive, a vendor's older documentation host.
3. **A different authority on the same structure.** libyal's asciidoc for
   the format, a reference parser's source (`liblnk`, `libevtx`, plaso's
   dtfabric definitions), the producing binary's headers if published.
   Two independent sources that agree are stronger than one anyway.
4. **The bytes.** A controlled sample with known values settles a field
   order regardless of what any document says — but it settles it for one
   producer on one build, so it complements the document rather than
   replacing it.

Only when those are exhausted does the unit become `inaccessible`, and the
tracker entry should list the routes tried so the next reader does not
repeat them. Any claim that was going to rest on that source is capped at
`speculative` until it is read; if you already wrote a stronger status on
the strength of memory, downgrade it now and say why in the note.

## 5. Cross-references without drift

The second failure mode is the opposite of skimming: you read source A
thoroughly, hit a reference to B, chase it, hit a reference to C from there,
and three hours later have three partial reviews and no complete ones.

The rule is simple: **record the reference, finish the current source, then
chase it.** Cross-references are held as explicit obligations attached to the
unit that raised them, and a source cannot be closed while any are open.

```bash
python scripts/review_tracker.py open        # everything started, not finished
python scripts/review_tracker.py xref src-1 --resolve 1 \
  --note "FILETIME is 100ns since 1601 UTC; confirmed against MS-DTYP 2.3.3"
```

The exception is a reference you cannot proceed without — a base-types
document that defines the primitives the current source is written in. Chase
that immediately, because continuing without it means misreading everything
after. Register it as its own source so it gets the same treatment, and note
that you are suspending the first review rather than abandoning it.

Depth is worth bounding. Two levels of chasing is usually productive; by the
third you are reading a standards document about a standards document, and
the obligation is better recorded as an open question than pursued.

---

## 6. Completion, and what counts as done

A source is complete when every enumerated unit is either **reviewed** or
**explicitly skipped with a stated reason**, and every cross-reference is
resolved or explicitly deferred.

```bash
python scripts/review_tracker.py close src-1
```

`close` refuses while work remains, and lists exactly what. That refusal is
the mechanism — it converts "did I finish that?" from a memory question into a
state you can query.

Three legitimate outcomes:

- **Complete.** Full coverage of the declared scope.
- **Complete with skips.** Units deliberately not read, each with a reason and
  a classification. Assessed skips are bounded limitations; unassessed skips
  are open avenues and are reported as such.
- **Abandoned.** Requires `--force --reason`. Sometimes correct — the source
  turned out to be irrelevant, or superseded, or about a different version
  entirely. Abandoning on the record is fine. Abandoning silently is what this
  is designed to prevent.

What is never acceptable is drawing a conclusion from a source whose review
was never closed. Before writing up, `status` should show nothing outstanding,
or the outstanding items should appear in the limitations section.

---

## 7. Reviewing a corpus of samples

The same discipline applies to your own data, and the failure is identical:
profile three files, generalise to fifty. Register the corpus as a source with
one unit per sample, or per producer version if the corpus is large.

This matters because the interesting samples are the ones that do not fit. A
parser validated on the samples that parse cleanly has been validated on
nothing. When a sample fails, that failure is a unit to be understood — a
second record type, an older version, slack from a prior write — not a file to
be dropped from the set.

Record per-group coverage. "47 of 52 samples, failures cluster on Windows 7"
is a finding. "Works on our samples" is not.

---

## 8. Reviewing an implementation

Reading a reference implementation is often more productive than reading a
spec, because it reflects what real files contain rather than what the format
was supposed to be. Enumerate by function or class, and read in dependency
order — the parsing entry point last, since it will make sense only after the
primitives it calls.

Pay particular attention to material that never appears in specs: constants
and magic values, the error handling and what it tolerates, comments marking
uncertainty, version branches, and any special-casing. A branch on OS version
in a parser is a documented format difference that somebody found the hard
way.

Where a spec and an implementation disagree, the implementation usually knows
what real files contain and the spec usually knows what the fields mean.
Record the conflict; do not pick a winner without corpus evidence.

---

## 9. What lands in the report

```bash
python scripts/review_tracker.py report
```

Sources reviewed, with declared scope and actual coverage. Skipped units split
into *assessed and excluded* versus *not examined — available for further
investigation*. Unread units. Conflicts between sources. Gaps where sources
leave things undefined. Unresolved cross-references.

All of these belong in the limitations section of the analysis, because they
bound what the analysis can claim. A reader cannot otherwise tell whether
"the spec does not define this field" means the spec is silent or means you
did not read that part — and those support very different conclusions.
