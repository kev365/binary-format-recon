template "Jump List Custom Destinations"
description "customDestinations-ms file header and first category"

// Reference: libyal dtformats, Jump lists format, "Custom destinations files".
// Community documentation; Microsoft has not published this structure.
//
// The file is a 12-byte header followed by categories. Each category ends with
// the footer BABFFBAB. A custom (type 0) or user-tasks (type 2) category holds
// entries, each a 16-byte class identifier followed by the object; for the
// shell link CLSID 00021401-0000-0000-C000-000000000046 the object is a
// complete shell link, so apply "Shell Link (LNK, Unicode)" immediately after
// the CLSID. A shell link carries no overall length field, so this template
// stops at the first entry's class identifier; the next category begins
// after that link's terminal ExtraData block and the footer.

applies_to file
fixed_start 0
requires 0 "02000000"
read-only

begin
section "File header"
    uint32 "Format version"                  // 2
    uint32 CategoryCount
    uint32 "Unknown"                         // observed 0
endsection
IfEqual CategoryCount 0
    Exit
EndIf
section "First category"
    uint32 CategoryType                      // 0 custom, 1 known, 2 user tasks
    IfEqual CategoryType 0
        uint16 NameChars
        string16 NameChars "Category name"
        uint32 "Number of entries"
    EndIf
    IfEqual CategoryType 1
        uint32 "Category identifier"         // 1 KDC_FREQUENT, 2 KDC_RECENT
        hexadecimal uint32 "Footer"          // BABFFBAB; known categories have
                                             // no entries
    EndIf
    IfEqual CategoryType 2
        uint32 "Number of entries"
    EndIf
    IfGreater CategoryType 2
        Exit
    EndIf
    IfEqual CategoryType 1
        Exit
    EndIf
    hex 16 "Entry 1 class identifier"        // 01140200-0000-0000-C000-000000000046
                                             // in packet form = shell link; apply
                                             // the Shell Link template here
endsection
end
