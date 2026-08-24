# Legal and Ethical Considerations

**This is not legal advice, and nobody involved in producing it is your
lawyer.** It exists because reverse engineering a proprietary format has a
legal dimension that is easy to not notice until it matters, and because the
right moment to notice is before the work starts, not after publication.

Why this is a reference and not a README line: the questions below change what
you *do*, not just what you disclose. Whether you may publish, whether you may
redistribute samples, whether an interoperability exemption covers you, and
whether an EULA clause binds you are all decisions that shape scope, corpus,
and deliverable. A README notice reaches nobody at the point of decision.

Contents:
1. What generally makes this lawful
2. Where it gets complicated
3. Sample handling
4. Publication
5. When to stop and ask

---

## 1. What generally makes this lawful

Reverse engineering for interoperability is broadly recognised in law, though
the shape differs by jurisdiction and the details matter.

- **United States.** DMCA §1201(f) provides an exemption for reverse
  engineering to achieve interoperability of an independently created program.
  The Librarian of Congress also grants triennial §1201 exemptions, some of
  which have covered security research. Fair use and the line of cases holding
  intermediate copying during reverse engineering to be fair are relevant
  background.
- **European Union.** The Software Directive (2009/24/EC) Article 6 permits
  decompilation for interoperability under stated conditions; Article 5(3)
  permits observing, studying, and testing a program to determine its
  underlying ideas. Notably, these rights cannot be contracted away in the
  EU — an EULA term purporting to remove them is generally unenforceable,
  which is not the position everywhere.
- **Elsewhere.** Similar interoperability provisions exist in many
  jurisdictions with meaningfully different conditions. Do not assume the US
  or EU position travels.

Digital forensics adds a separate basis: examining artefacts on systems you
own, or are authorised to examine under a lawful investigation, is ordinary
practice. The format research is incidental to a legitimate examination.

---

## 2. Where it gets complicated

The situations that warrant a conversation with counsel rather than a
judgement call:

- **Contract terms.** EULAs and terms of service frequently prohibit reverse
  engineering outright. Whether such a term is enforceable varies by
  jurisdiction and by whether a statutory right overrides it — in the EU
  generally not enforceable against Article 6 rights, in the US often
  enforceable. If you accepted terms to obtain the software, read them.
- **Circumventing protection.** If the format is encrypted or obfuscated and
  your analysis defeats that protection, you may be in anti-circumvention
  territory rather than plain reverse engineering, and the interoperability
  exemptions are narrower there. This is the single most common way format
  research crosses a line without anyone intending to.
- **Trade secrets.** Reverse engineering is a recognised means of acquiring
  information lawfully in most trade-secret regimes, but this weakens
  considerably if you obtained the software or documentation under an NDA or
  other confidence.
- **Scope of authorisation.** In an investigation, the authority to examine
  a system is not unlimited. Format research on artefacts outside the
  authorised scope is outside the scope.
- **Export control.** Cryptographic analysis and some security tooling attract
  export restrictions in several jurisdictions.
- **Employment and client agreements.** Who owns the resulting specification
  is frequently answered in a contract you have already signed.

---

## 3. Sample handling

Corpus collection has its own constraints, separate from the analysis:

- **Malware repositories** (MalwareBazaar, VirusShare, VirusTotal) have terms
  governing use and redistribution. Live malware needs an isolated
  environment, and in some jurisdictions possession or distribution is
  regulated regardless of intent.
- **Personal data.** Forensic artefacts are dense with it. GDPR and equivalent
  regimes apply to a research corpus as much as to a case, and a corpus
  assembled from real systems is a personal data holding with retention and
  minimisation obligations.
- **Case data is not corpus data.** Samples from an engagement are governed by
  that engagement's terms. Using them to develop a parser you publish is a
  question to ask before doing it, not after.
- **Licensed samples.** Institutional corpora (Digital Corpora, NIST CFReDS)
  come with terms that are usually permissive and occasionally not.

Record provenance and terms per sample. `corpus.py --report` leaves a section
for it because retrofitting provenance is close to impossible.

---

## 4. Publication

Publishing a format specification is normal, valuable, and how most of the
resources in `references/format-galleries.md` came to exist. Things worth
settling first:

- **Whose specification is it?** Employment and client agreements often
  answer this.
- **Licence compatibility.** If the work derives from libyal documentation
  (GNU FDL 1.3), Microsoft Open Specifications (licensed for implementation),
  or a Kaitai gallery entry (per-file), those terms follow into your
  deliverable. See `references/documentation.md` §10.
- **Coordinated disclosure.** If the analysis revealed a security weakness
  rather than only a layout — a weak checksum used as integrity protection,
  unencrypted credentials in an artefact — that is a disclosure question with
  its own norms and timelines, not a publication question.
- **Attribution.** Prior work that got you there should be cited. It is also
  simply how this field sustains itself.

---

## 5. When to stop and ask

Escalate to counsel, rather than deciding alone, when:

- An EULA or NDA covers the software and you intend to publish.
- The analysis involves defeating encryption or an obfuscation layer.
- Samples came from a client engagement and the output will be public.
- The corpus contains personal data and will be retained or shared.
- You are working across jurisdictions with different rules.
- The producer has a history of pursuing researchers.

None of this is a reason not to do the work. Format research is legitimate,
routine, and much of the DFIR tooling ecosystem depends on it. It is a reason
to know which of these apply *before* the scope is set, because they change
what you collect, what you publish, and under what terms.
