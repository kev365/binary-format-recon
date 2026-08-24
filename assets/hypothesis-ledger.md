# Hypothesis Ledger — <FORMAT NAME>

Analyst: <name>   Started: <date>   Tools: binary-format-recon 1.0, Python <ver>
Input manifest: <manifest.json sha256>

## Corpus

| Sample | SHA-256 (short) | Producer version | Source | Role |
|---|---|---|---|---|
| | | | | reference / validation / lab-generated |

Keep lab-generated files distinct from case data. Never mix them in one table.

## Container facts

| Property | Value | Status | Evidence |
|---|---|---|---|
| Page/record stride | | | profile.py anchor columns, N blocks |
| Endianness | | | fieldmap.py padding-side inference |
| String encoding | | | strscan.py |
| String length convention | | | strscan.py prefix test, X/Y strings |
| Checksum | | | cksum_id.py, X/Y records |
| Indirection layer | | | see methodology.md section 5 |

## Field ledger

Status values: `established` (confirmed by controlled mutation, or spec plus
corpus agreement), `inferred` (holds across corpus, never manipulated),
`speculative` (alternative reading not excluded), `unknown` (present, purpose
undetermined).

| Off | Width | Type | Semantics | Status | Support | Alternative reading | Evidence |
|---|---|---|---|---|---|---|---|
| +0 | u32 | magic | | established | 52/52 | — | constant across corpus |
| | | | | | | | |

Support is a fraction with the denominator visible, never a bare percentage.

## Mutation trials

| # | Change made | Predicted | Observed | Outcome |
|---|---|---|---|---|
| A | | | | confirms / refutes / inconclusive |

Include the control pair (two idle snapshots, no change made) as its own row.

## Version differences

| Field | Version A behaviour | Version B behaviour | Notes |
|---|---|---|---|

## Open questions

- Regions not yet understood, and whether they could hold relevant data.
- Ambiguous readings with no discriminating sample yet identified.
- Timestamp semantics: what event sets each one, and whether UTC or local.

## Limitations for the report

- Producer versions actually tested:
- Parse rate across corpus, with failures characterised:
- What this artefact does not establish:
