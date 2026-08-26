template "Shell Item - Volume (0x2x)"
description "Shell item for a volume such as C:\ - libfwsi"

// Reference: libyal libfwsi, Windows Shell Item format, section "Volume shell
// item". Community documentation; the item identifier format is not published
// by Microsoft.
//
// Apply at the start of a shell item whose class type indicator is 0x20-0x2F
// (0x20 after masking with 0x70). The low bits are flags; bit 0 selects the
// named form, which is the one written for local drives. Observed indicators:
// 0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F.

applies_to file
read-only

begin
section "Volume shell item"
    uint16 ItemSize                          // includes these two bytes
    hex 1 "Class type indicator"             // 0x20 plus the flags below
    move -1
    uint_flex "0" HasName                    // uint_flex reads a 4-byte window;
    move -4                                  // bits 0-7 are this byte
    uint_flex "3" "  Is removable media"
    move -3
    IfEqual HasName 1
        string 20 "Volume name"              // ASCII, null-terminated, zero padded
        hex 2 "Unknown"
    Else
        hex 1 "Unknown flags"
        hex 16 "Volume identifier"           // GUID
    EndIf
    // Named items larger than 25 bytes carry a shell folder identifier and
    // possibly an extension block (0xbeef0025, 0xbeef0026 or 0xbeef0027).
    IfGreater ItemSize 25
        goto 25
        hex (ItemSize-25) "Shell folder identifier / extension block"
    EndIf
endsection
multiple ItemSize
end
