template "Shell Link TrackerDataBlock"
description "LNK ExtraData TrackerDataBlock - MS-SHLLINK v20251121 section 2.5.10"

// Reference: [MS-SHLLINK] section 2.5.10. Apply at the start of the ExtraData
// block whose signature is 0xA0000003.
//
// The block is written by the Distributed Link Tracking service and records the
// origin of the shortcut independently of any path string. MachineID is the
// NetBIOS name of the machine where the target last resided. DroidBirth holds
// the volume and object identity assigned when the target was first seen, and
// survives copying and renaming, so two links sharing a DroidBirth file
// identifier refer to the same original object.
//
// The file identifiers are version-1 UUIDs, whose final six bytes carry the MAC
// address of the adapter that generated them. That adapter is not necessarily
// the machine's primary or active one, and the value can be stale or forged, so
// it identifies a machine as a lead rather than establishing a network path.

applies_to file
requires 0 "60000000"
requires 4 "030000A0"
read-only
multiple 96

begin
section "TrackerDataBlock (2.5.10)"
    uint32 "BlockSize"                       // MUST be 0x00000060
    hexadecimal uint32 "BlockSignature"      // MUST be 0xA0000003
    uint32 "Length"                          // MUST be 0x00000058
    uint32 "Version"                         // MUST be zero
    char[16] "MachineID"                     // NetBIOS name, system code page,
                                             // null-terminated; trailing bytes
                                             // are undefined per 2 and may hold
                                             // remnants of previous content
    hex 16 "Droid VolumeIdentifier"          // GUID packet representation
    hex 16 "Droid FileIdentifier"
    hex 16 "DroidBirth VolumeIdentifier"     // identity assigned at first sight
    hex 16 "DroidBirth FileIdentifier"
endsection
end
