// ImHex pattern skeleton for a paged / record-oriented format.
// Open the file in ImHex, paste this in the pattern editor, and iterate.
// ImHex evaluates live, so this is the fastest way to test a hypothesis
// against real bytes before committing it to a Kaitai spec.
//
// Useful ImHex views while working: Data Information (entropy, byte
// distribution), Diffing (for mutation trials), Data Processor (for
// mapping layers and decompression).

#pragma endian little

#define PAGE_SIZE 0x2000    // confirm with profile.py before trusting

enum PageType : u16 {
    TypeA = 0x0001,
    TypeB = 0x0002,
};

struct TocEntry {
    u32 record_id;
    u32 offset;     // within page -- INFERRED
    u32 length;
    u32 crc;        // may be zero/unused on some producer versions
};

struct PageHeader {
    u32 magic;              // ESTABLISHED: constant across corpus
    u32 page_id;            // ESTABLISHED: increments by 1
    PageType page_type;
    u16 record_count;       // INFERRED
    u32 reserved;           // UNKNOWN: always zero in this corpus
    u64 timestamp;          // INFERRED: FILETIME; semantics undetermined
    u32 checksum;           // ESTABLISHED: CRC-32 over bytes 32..end
    u32 data_offset;
};

struct Page {
    PageHeader hdr;
    padding[32 - sizeof(hdr)];
    TocEntry toc[hdr.record_count];
    // Anything not described above is left unclassified on purpose.
    // Do not invent a field to fill a gap -- record it as unknown.
};

Page pages[while(!std::mem::eof())] @ 0x00;
