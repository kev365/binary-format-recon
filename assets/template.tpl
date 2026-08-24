// X-Ways / WinHex template skeleton for a paged / record-oriented format.
// Apply in X-Ways: View | Template Manager, or Alt+F12 at the cursor.
// Syntax: references/xways-templates.md.  Lint: scripts/tplgen.py --check.
// Prefer generating from findings (tplgen.py --spec / --field) and editing
// the result; this skeleton is for starting by hand.
//
// Replace every <> placeholder. Keep the status comments: a template that
// says which names are proven and which are guesses is worth far more than
// one that only paints labels on bytes.

template "<Format name> page header"
description "<one line: structure, artefact, producer>"

// Version scope: <producer builds this layout was established on>
// Evidence: see hypothesis ledger <path>; statuses are
//   established = survived a controlled-change test (Phase 5)
//   inferred    = consistent with the corpus, unproven
//   speculative = hypothesis only
//   unknown     = bounded but undetermined

applies_to file
requires 0x0 "CDABCCAC"           // <-- your magic; established only
read-only                         // findings templates examine, not edit
multiple 8192                     // record/page size, if fixed

begin
    hex 4       Magic                     // established
    uint32      "Page id"                 // established; increments by 1
    uint16      "Page type"               // inferred; enum: 1=<a>, 2=<b>
    uint16      "Record count"            // inferred; matches TOC entries
    hex 4       "unknown +0xC"            // unknown; zero in all samples
    FileTime    "Timestamp"               // inferred; setting event unproven
    hexadecimal uint32 "CRC-32"           // established; ISO-HDLC over 32..end
    uint32      "Data offset"             // inferred
    hex 32      "unknown +0x20"           // unknown -- bounded, not omitted

    section "TOC"
    numbering 1
    {
        uint32  "Record id ~"             // inferred
        uint32  "Record offset ~"         // inferred; within this page
        uint32  "Record length ~"         // inferred
        hex 4   "Record CRC ~"            // speculative; unused on some versions
    }["Record count"]
    endsection
end
