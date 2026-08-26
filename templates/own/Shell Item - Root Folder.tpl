template "Shell Item - Root Folder (0x1F)"
description "Shell item for a shell namespace root such as This PC - libfwsi"

// Reference: libyal libfwsi, Windows Shell Item format, section "Root folder
// shell item". Community documentation; the item identifier format is not
// published by Microsoft.
//
// Apply at the start of a shell item whose class type indicator is 0x1F. This
// is normally the first item of an IDList. The shell folder identifier is a
// CLSID whose display name lives under HKCR\CLSID; for example
// 20d04fe0-3aea-1069-a2d8-08002b30309d is My Computer / This PC. A list of
// identifiers: https://winshl-kb.readthedocs.io/en/latest/sources/shell-folders/

applies_to file
requires 2 "1F"
read-only

begin
section "Root folder shell item"
    uint16 ItemSize                          // includes these two bytes
    hex 1 "Class type indicator"             // 0x1F
    hexadecimal uint8 "Sort index"           // 0x50 My Computer, 0x48 My Documents,
                                             // 0x58 Network, 0x60 Recycle Bin,
                                             // 0x42 Libraries, 0x44 Users
    hex 16 "Shell folder identifier"         // GUID, mixed-endian packet form
    IfGreater ItemSize 20
        hex (ItemSize-20) "Extension block"  // 0xbeef0017 or 0xbeef0026
    EndIf
endsection
multiple ItemSize
end
