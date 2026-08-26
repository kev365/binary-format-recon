template "Shell Link (LNK, Unicode)"
description "Windows Shell Link .lnk, Unicode StringData - MS-SHLLINK v20251121"

// Reference: [MS-SHLLINK] Shell Link (.LNK) Binary File Format, v20251121.
//   2.1 ShellLinkHeader      2.1.1 LinkFlags        2.1.2 FileAttributesFlags
//   2.1.3 HotKeyFlags        2.2 LinkTargetIDList   2.3 LinkInfo
//   2.4 StringData           2.5 ExtraData
//
// Use this variant when LinkFlags bit 7 (IsUnicode) is set. When it is clear,
// use "Shell Link (LNK, ANSI)": StringData is then system-code-page text at one
// byte per character.
//
// Interpretation begins at the cursor, so the template also applies to a shell
// link embedded in another container, such as a jump list stream.

applies_to file
requires 0 "4C000000"
requires 4 "0114020000000000C000000000000046"
read-only

begin
section "ShellLinkHeader (2.1)"
    hexadecimal uint32 "HeaderSize"          // MUST be 0x0000004C
    hex 16 "LinkCLSID"                       // MUST be 00021401-0000-0000-C000-000000000046
    hex 4 "LinkFlags"                        // raw value; bits decoded below (2.1.1)
    move -4
    uint_flex "0" "  HasLinkTargetIDList"
    move -4
    uint_flex "1" "  HasLinkInfo"
    move -4
    uint_flex "2" "  HasName"
    move -4
    uint_flex "3" "  HasRelativePath"
    move -4
    uint_flex "4" "  HasWorkingDir"
    move -4
    uint_flex "5" "  HasArguments"
    move -4
    uint_flex "6" "  HasIconLocation"
    move -4
    uint_flex "7" "  IsUnicode"
    move -4
    uint_flex "8" "  ForceNoLinkInfo"
    move -4
    uint_flex "11" "  HasLogo3ID (pre-Vista)"
    move -4
    uint_flex "13" "  RunAsUser"
    move -4
    uint_flex "18" "  ForceNoLinkTrack"
    // Bit 11 is Unused1 in 2.1.1 but was SLDF_HAS_LOGO3ID in pre-Vista SDKs; it
    // changes the meaning of an A0000007 ExtraData block (see ExtraData below).
    // Bits 9-10, 12, 14-17 and 19-25 are named in 2.1.1. They govern resolution
    // behaviour rather than layout, and remain readable in the raw value above.
    hex 4 "FileAttributes"                   // raw value; bits decoded below (2.1.2)
    move -4
    uint_flex "0" "  FILE_ATTRIBUTE_READONLY"
    move -4
    uint_flex "1" "  FILE_ATTRIBUTE_HIDDEN"
    move -4
    uint_flex "2" "  FILE_ATTRIBUTE_SYSTEM"
    move -4
    uint_flex "4" "  FILE_ATTRIBUTE_DIRECTORY"
    move -4
    uint_flex "5" "  FILE_ATTRIBUTE_ARCHIVE"
    move -4
    uint_flex "7" "  FILE_ATTRIBUTE_NORMAL"
    move -4
    uint_flex "14" "  FILE_ATTRIBUTE_ENCRYPTED"
    // Timestamps are UTC and describe the link TARGET at the time the link was
    // written. Order is creation, access, write: the write (modified) time is
    // the third field, not the second.
    FileTime "CreationTime (UTC)"
    FileTime "AccessTime (UTC)"
    FileTime "WriteTime (UTC)"
    uint32 "FileSize"                        // low 32 bits of the target size
    int32 "IconIndex"
    uint32 "ShowCommand"                     // 1=NORMAL, 3=MAXIMIZED, 7=MINNOACTIVE
    uint8 "HotKey LowByte"                   // virtual key code (2.1.3)
    uint8 "HotKey HighByte"                  // 1=SHIFT, 2=CTRL, 4=ALT
    uint16 "Reserved1"                       // MUST be zero
    uint32 "Reserved2"                       // MUST be zero
    uint32 "Reserved3"                       // MUST be zero
endsection

// LinkTargetIDList (2.2) - present only when HasLinkTargetIDList is set.
IfEqual HasLinkTargetIDList 1
section "LinkTargetIDList (2.2)"
    uint16 IDListSize                        // byte length of the IDList that follows
    hex IDListSize "IDList (ItemID chain)"   // ItemID payloads are defined by the shell
                                             // data source and are outside MS-SHLLINK
endsection
EndIf

// LinkInfo (2.3) - present only when HasLinkInfo is set.
IfEqual HasLinkInfo 1
section "LinkInfo (2.3)"
    uint32 LinkInfoSize                      // total size of this structure
    uint32 "LinkInfoHeaderSize"              // 0x1C, or 0x24 and above when the
                                             // optional Unicode offsets are present
    hex 4 "LinkInfoFlags"
    move -4
    uint_flex "0" "  VolumeIDAndLocalBasePath"
    move -4
    uint_flex "1" "  CommonNetworkRelativeLinkAndPathSuffix"
    uint32 "VolumeIDOffset"                  // every offset in this structure is
    uint32 "LocalBasePathOffset"             // measured from the start of LinkInfo,
    uint32 "CommonNetworkRelativeLinkOffset" // that is from the LinkInfoSize field
    uint32 "CommonPathSuffixOffset"
    // The remainder holds, in order: LocalBasePathOffsetUnicode and
    // CommonPathSuffixOffsetUnicode when LinkInfoHeaderSize is 0x24 or above,
    // then VolumeID (2.3.1), LocalBasePath, CommonNetworkRelativeLink (2.3.2)
    // and CommonPathSuffix. Add the offsets above to this structure's start to
    // locate each field; the local base path reads as text in the hex view.
    hex (LinkInfoSize-28) "LinkInfo body"
endsection
EndIf

// StringData (2.4). Order is fixed: NAME_STRING, RELATIVE_PATH, WORKING_DIR,
// COMMAND_LINE_ARGUMENTS, ICON_LOCATION, each present only when its LinkFlags
// bit is set. Every entry is a 16-bit character count followed by that many
// characters, with no terminator.
section "StringData (2.4)"
IfEqual HasName 1
    uint16 NameChars                         // characters, not bytes
    string16 NameChars "NAME_STRING (description)"
EndIf
IfEqual HasRelativePath 1
    uint16 RelPathChars
    string16 RelPathChars "RELATIVE_PATH"
EndIf
IfEqual HasWorkingDir 1
    uint16 WorkDirChars
    string16 WorkDirChars "WORKING_DIR"
EndIf
IfEqual HasArguments 1
    uint16 ArgsChars
    string16 ArgsChars "COMMAND_LINE_ARGUMENTS"
EndIf
IfEqual HasIconLocation 1
    uint16 IconChars
    string16 IconChars "ICON_LOCATION"
EndIf
endsection

// ExtraData (2.5). Zero or more blocks, each a 32-bit size followed by a 32-bit
// signature, terminated by a size below 4. Signatures (2.5.1 to 2.5.11):
//   A0000001 EnvironmentVariable   A0000002 Console        A0000003 Tracker
//   A0000004 ConsoleFE             A0000005 SpecialFolder  A0000006 Darwin
//   A0000007 IconEnvironment       A0000008 Shim           A0000009 PropertyStore
//   A000000B KnownFolder           A000000C VistaAndAboveIDList
// For A0000003, apply "Shell Link TrackerDataBlock" at the start of the block.
// A0000007 is IconEnvironmentDataBlock per 2.5.5 - unless LinkFlags bit 11
// (HasLogo3ID) is set, in which case it is a Logo3 product block written by
// pre-Vista SDKs as EXP_LOGO3_ID_SIG, the same value and the same 788-byte
// CHAR[260]+WCHAR[260] shape. The flag, not the signature, decides.
section "ExtraData (2.5)"
numbering 1
{
    uint32 BlockSize                         // below 4 marks the terminal block
    IfGreater 4 BlockSize
        ExitLoop
    EndIf
    hexadecimal uint32 "Signature ~"
    hex (BlockSize-8) "Block ~ payload"      // per-block layout is in 2.5.1 to 2.5.11
}[unlimited]
endsection
end
