template "Jump List DestList Header"
description "Header of the DestList stream in an automaticDestinations-ms file"

// Reference: libyal dtformats, Jump lists format, "DestList header" and
// "Format versions". Community documentation; Microsoft has not published
// this structure.
//
// The DestList stream is a stream inside the OLE2 container (see "Compound
// File Header" and "Compound File Directory Entry" to locate it; it is usually
// under 4096 bytes and therefore in the mini stream). Apply this template at
// the first byte of the stream. Entries follow immediately: apply "Jump List
// DestList Entry v1" for format version 1 (Windows 7) or "... Entry v3" for
// versions 3 and 4 (Windows 10 and later). A DestList stream may be 0 bytes
// in an empty file.

applies_to file
read-only

begin
section "DestList header"
    uint32 "Format version"                  // 1 Windows 7; 3 or 4 Windows 10+
    uint32 "Number of entries"
    uint32 "Number of pinned entries"
    float "Unknown"                          // decodes as a small float
    uint32 "Last entry number"               // highest entry number issued
    uint32 "Unknown"                         // observed 0
    uint32 "Last revision number"
    uint32 "Unknown"                         // observed 0
endsection
end
