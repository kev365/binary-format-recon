template "Jump List DestList Entry v3"
description "DestList entry, format version 3 and 4 (Windows 10 and later)"

// Reference: libyal dtformats, Jump lists format, "DestList entry - version 2
// or later". Community documentation; Microsoft has not published this
// structure.
//
// Apply at the first entry, 32 bytes into the DestList stream, when the header
// reports format version 3 or 4. Navigation moves entry by entry. Identical to
// version 1 up to the pin status; then three fields were inserted before the
// path, and four bytes follow it. The entry number names the OLE2 stream (in
// hexadecimal) holding the corresponding shell link. Hostname may be empty for
// entries whose path is a URL rather than a file.

applies_to file
read-only

begin
section "DestList entry (version 3+)"
    hex 8 "Unknown"
    hex 16 "Droid volume identifier"         // GUID; NTFS $OBJECT_ID
    hex 16 "Droid file identifier"
    hex 16 "Birth droid volume identifier"
    hex 16 "Birth droid file identifier"
    string 16 "Hostname"                     // NetBIOS name, zero padded
    uint32 "Entry number"                    // stream name in hexadecimal
    uint32 "Unknown"                         // observed 0
    float "Unknown"                          // decodes as a float
    FileTime "Last modification (UTC)"
    int32 "Pin status"                       // -1 unpinned; 0 and above pinned
    hexadecimal uint32 "Unknown (status)"    // observed FFFFFFFF
    uint32 "Unknown (access count)"          // observed small integers
    hex 8 "Unknown"                          // observed 0
    uint16 PathChars                         // characters, not bytes
    string16 PathChars "Path"                // no terminator; path or URL
    hex 4 "Unknown"                          // observed 0; alignment padding
endsection
multiple (134+PathChars*2)
end
