template "Compound File Directory Entry (OLE2 / CFB)"
description "128-byte OLE2 directory entry for a storage or stream - MS-CFB 2.6.1"

// Reference: [MS-CFB] v20200701, sections 2.6.1 to 2.6.3. Apply at the start
// of the directory sector, whose location is in the header; entries are 128
// bytes and navigation moves entry by entry. Stream ID 0 is the root entry,
// named "Root Entry", whose start sector and size describe the mini stream.
//
// A stream smaller than the mini stream cutoff (4096 bytes) is stored in the
// mini stream and its starting sector is a MINI sector number: offset within
// the mini stream is sector * 64. A larger stream's starting sector is a
// regular sector: file offset (sector + 1) * sector size. The reserved values
// FFFFFFFE (end of chain) and FFFFFFFF (no stream / free) apply to both.

applies_to file
read-only
multiple 128

begin
section "Directory entry (2.6.1)"
    string16 32 "Name"                       // UTF-16, null-terminated, 64 bytes
    uint16 "Name length"                     // bytes including the terminator
    uint8 "Object type"                      // 0 unallocated, 1 storage, 2 stream,
                                             // 5 root storage
    uint8 "Color"                            // 0 red, 1 black (red-black tree)
    hexadecimal uint32 "Left sibling ID"     // FFFFFFFF = none
    hexadecimal uint32 "Right sibling ID"
    hexadecimal uint32 "Child ID"            // storages only; streams FFFFFFFF
    hex 16 "CLSID"                           // storages only; zero for streams
    hex 4 "State bits"                       // user-defined; zero for streams
    FileTime "Creation time"                 // storages only; zero for streams
    FileTime "Modified time"                 // and for the root entry
    hexadecimal uint32 "Starting sector"     // stream: first sector (mini or
                                             // regular, by size); root: mini stream
    int64 "Stream size"                      // bytes; version 3 files: use the
                                             // low 32 bits, high bits may be junk
endsection
end
