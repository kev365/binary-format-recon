template "Compound File Header (OLE2 / CFB)"
description "OLE2 compound file header, 512 bytes at offset 0 - MS-CFB 2.2"

// Reference: [MS-CFB] Compound File Binary File Format, v20200701, section 2.2
// (header) with 2.1 (sector numbers). Containers using this format include
// jump list automaticDestinations-ms files, thumbs.db, MSI packages and the
// pre-2007 Office formats.
//
// Sector n begins at file offset (n + 1) * sector size, so with 512-byte
// sectors the first directory sector is at (FirstDirectorySector + 1) * 512.
// Apply "Compound File Directory Entry" there. Sector numbers 0xFFFFFFFA and
// above are reserved: FFFFFFFC DIFAT sector, FFFFFFFD FAT sector,
// FFFFFFFE end of chain, FFFFFFFF free.

applies_to file
fixed_start 0
requires 0 "D0CF11E0A1B11AE1"
read-only

begin
section "Compound file header (2.2)"
    hex 8 "Header signature"                 // MUST be D0 CF 11 E0 A1 B1 1A E1
    hex 16 "Header CLSID"                    // MUST be all zero
    hexadecimal uint16 "Minor version"       // SHOULD be 0x003E
    uint16 MajorVersion                      // 3 (512-byte sectors) or 4 (4096-byte)
    hexadecimal uint16 "Byte order"          // MUST be 0xFFFE, little-endian
    uint16 SectorShift                       // 9 for version 3, 12 for version 4
    uint16 "Mini sector shift"               // MUST be 6: 64-byte mini sectors
    hex 6 "Reserved"                         // MUST be zero
    uint32 "Number of directory sectors"     // MUST be zero in version 3
    uint32 "Number of FAT sectors"
    hexadecimal uint32 "First directory sector"
    uint32 "Transaction signature"           // zero unless transactions are used
    hexadecimal uint32 "Mini stream cutoff"  // MUST be 0x1000: smaller streams
                                             // live in the mini stream
    hexadecimal uint32 "First mini FAT sector"
    uint32 "Number of mini FAT sectors"
    hexadecimal uint32 "First DIFAT sector"  // FFFFFFFE when the 109 entries
                                             // below suffice (files under 6.875 MB)
    uint32 "Number of DIFAT sectors"
endsection
section "DIFAT (first 109 FAT sector locations)"
    numbering 0
    {
        hexadecimal uint32 "DIFAT ~"         // FFFFFFFF marks an unused entry
    }[109]
endsection
end
