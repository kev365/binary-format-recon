template "Shell Item - File Entry (0x3x)"
description "Shell item for a file or directory, Windows XP and later - libfwsi"

// Reference: libyal libfwsi, Windows Shell Item format, sections "File entry
// shell item - Windows XP and later" and "File entry extension block
// (0xbeef0004)". Community documentation; the item identifier format is not
// published by Microsoft.
//
// Apply at the start of a shell item whose class type indicator is 0x30-0x3F
// (0x30 after masking with 0x70). Shell items occur in LNK LinkTargetIDList,
// jump lists, shellbag registry values and VistaAndAboveIDListDataBlock.
// Navigation to the next item is enabled; apply the matching type template
// there (root folder 0x1F, volume 0x2x, file entry 0x3x).
//
// The last two bytes of the item hold the offset of the first extension block,
// which is used here to reach it without computing string alignment.

applies_to file
read-only

begin
section "File entry shell item"
    uint16 ItemSize                          // includes these two bytes
    hex 1 "Class type indicator"             // 0x30 plus the flags below
    move -1
    uint_flex "0" IsDirectory                // uint_flex reads a 4-byte window;
    move -4                                  // bits 0-7 are this byte
    uint_flex "1" IsFile
    move -4
    uint_flex "2" UnicodeName
    move -4
    uint_flex "7" HasClassIdentifier
    move -3
    uint8 "Unknown"                          // observed 0
    uint32 "File size"                       // 0 for directories
    DOSDateTime "Last modification (UTC)"    // FAT date and time, 2 s granularity
    hexadecimal uint16 "File attribute flags" // low 16 bits of the attributes
    IfEqual UnicodeName 1
        zstring16 "Primary name"
    Else
        zstring "Primary name"               // usually the 8.3 short name; 16-bit
                                             // aligned, so may be followed by a
                                             // zero byte before the extension
    EndIf
endsection

goto (ItemSize-2)
uint16 FirstExtensionOffset                  // from the start of the item
goto FirstExtensionOffset

section "Extension block 0xbeef0004"
    uint16 ExtensionSize                     // includes these two bytes
    uint16 ExtensionVersion                  // 3 XP/2003, 7 Vista, 8 2008/7/8.0, 9 8.1/10/11
    hexadecimal uint32 "Extension signature" // 0xBEEF0004
    DOSDateTime "Creation (UTC)"
    DOSDateTime "Last access (UTC)"
    uint16 "Long name offset"                // from the start of the extension block
    IfGreater ExtensionVersion 6
        hex 2 "Unknown"
        uint48 "MFT entry index"             // NTFS file reference; not always set
        uint16 "MFT sequence number"
        hex 8 "Unknown"
    EndIf
    IfGreater ExtensionVersion 2
        uint16 "Localized name offset"       // from the start of the extension block
    EndIf
    IfGreater ExtensionVersion 8
        hex 4 "Unknown"
    EndIf
    IfGreater ExtensionVersion 7
        hex 4 "Unknown"
    EndIf
    zstring16 "Long name"                    // may contain unpaired surrogates
    // A localized name may follow the long name (ASCII, and from version 7 also
    // UTF-16), e.g. @shell32.dll,-21781. It is rare and sits between here and
    // the trailing offset below.
    goto (FirstExtensionOffset+ExtensionSize-2)
    uint16 "First extension block offset"    // copy; equals FirstExtensionOffset
endsection
multiple ItemSize
end
