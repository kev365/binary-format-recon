template "Jump List DestList Entry v1"
description "DestList entry, format version 1 (Windows 7)"

// Reference: libyal dtformats, Jump lists format, "DestList entry - version 1".
// Community documentation; Microsoft has not published this structure.
//
// Apply at the first entry, 32 bytes into the DestList stream, when the header
// reports format version 1. Navigation moves entry by entry. The entry number
// names the OLE2 stream (in hexadecimal) holding the corresponding shell link:
// entry 11 is stream "b". The four droid GUIDs and the hostname are the same
// link-tracking data as a shell link's TrackerDataBlock; the file identifiers
// are version-1 UUIDs whose last six bytes carry a MAC address.

applies_to file
read-only

begin
section "DestList entry (version 1)"
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
    uint16 PathChars                         // characters, not bytes
    string16 PathChars "Path"                // no terminator; may be a path or
                                             // a ::{CLSID} shell namespace item
endsection
multiple (114+PathChars*2)
end
