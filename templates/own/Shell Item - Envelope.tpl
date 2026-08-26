template "Shell Item - Envelope"
description "Any shell item: size, class type and bounded payload - libfwsi"

// Reference: libyal libfwsi, Windows Shell Item format, sections "Shell Item"
// and "Class type indicator". Community documentation.
//
// Apply at the start of any shell item to identify its type, then apply the
// matching template: Root Folder (0x1F), Volume (0x20-0x2F), File Entry
// (0x30-0x3F). Other types - network location 0x40-0x4F, URI 0x61, control
// panel 0x71, and the signature-based items - are shown here as bounded
// payload. A size of 0 is the terminal identifier that ends the list.
// Navigation moves item by item through the list.

applies_to file
read-only

begin
section "Shell item"
    uint16 ItemSize                          // includes these two bytes; 0 ends the list
    IfEqual ItemSize 0
        Exit
    EndIf
    hex 1 "Class type indicator"
    move -1
    uint_flex "6,5,4" TypeNibble             // 1 root, 2 volume, 3 file entry,
    move -4                                  // 4 network location
    uint_flex "3,2,1,0" "  Flags (low bits)"
    move -3
    hex (ItemSize-3) "Class type specific data"
endsection
multiple ItemSize
end
