# Encodings Reference

Contents:
1. Timestamp encodings
2. Textual timestamps
3. String encodings
4. Integers, floats, and packing
5. Checksums and hashes
6. Compression and container signatures
7. GUIDs, SIDs, and other fixed structures

---

## 1. Timestamp encodings

`tsscan.py` tests all of these. The **chance rate** column is the share of the
raw value space that falls inside a 1995–2035 window — that is, how often
random bytes produce a plausible date. It is the reason a 64-bit FILETIME hit
is meaningful and a 32-bit epoch hit usually is not.

| Encoding | Width | Epoch | Unit | Chance rate | Seen in |
|---|---|---|---|---|---|
| Windows FILETIME | u64 | 1601-01-01 | 100 ns | ~0.07% | Windows everywhere: NTFS, registry, EVTX, LNK, WMI |
| Chrome / WebKit | u64 | 1601-01-01 | 1 µs | ~0.01% | Chromium history, cookies, cache |
| Unix epoch (32-bit) | u32 | 1970-01-01 | 1 s | ~29% | Unix filesystems, tar, zip extras, syslog |
| Unix epoch (64-bit) | u64 | 1970-01-01 | 1 s | ~0.0000001% | Modern Linux, ext4 |
| Java / JS milliseconds | u64 | 1970-01-01 | 1 ms | ~0.00007% | Java, JavaScript, Android |
| HFS+ / classic Mac | u32 | 1904-01-01 | 1 s | ~29% | HFS+, some Apple metadata |
| Cocoa / Core Data | u32 or f64 | 2001-01-01 | 1 s | ~25% (u32) | macOS/iOS plists, SQLite from Apple apps |
| OLE automation date | f64 | 1899-12-30 | 1 day | n/a | VARIANT `VT_DATE`, Office, VB, some COM |
| FAT / DOS packed | u32 | 1980-01-01 | 2 s | ~48% of range | FAT, ZIP local headers, some installers |
| GPS time | u32 | 1980-01-06 | 1 s | ~29% | GNSS logs, some telematics |

**Gotchas.**

- FILETIME split across two dwords is extremely common. If you see one dword
  that looks like a plausible high half (values around `0x01D6`–`0x01DC` for
  the 2020s) next to a high-entropy dword, that is a FILETIME, not two fields.
- A u64 that increments by an exact multiple of 2^32 is two u32 fields.
- Some formats store FILETIME as a *string* of the decimal integer, notably
  parts of the WMI/`SWbemDateTime` surface. Check textual patterns too.
- Interval or duration fields use the same units with a zero epoch. A
  "timestamp" that decodes to 1601 or 1970 plus a few hours is a duration.
- Local time vs UTC is not recoverable from the bytes alone. Calibrate against
  a lab event whose true wall-clock time you know.
- Sub-second precision is often padded: FILETIMEs ending in many zero
  100-ns units indicate a second- or millisecond-resolution source upconverted.

---

## 2. Textual timestamps

| Format | Shape | Notes |
|---|---|---|
| CIM_DATETIME (DMTF) | `yyyymmddHHMMSS.mmmmmmsUUU` | 6-digit microseconds; sign `+`/`-`/`*`; `UUU` = UTC offset in **minutes**. Locale-independent. Used by WMI. |
| CIM interval | `ddddddddHHMMSS.mmmmmm:000` | Always ends `:000`; the colon distinguishes interval from datetime |
| ISO 8601 | `YYYY-MM-DDTHH:MM:SS` | Optional fractional seconds and zone |
| Compact 14 | `YYYYMMDDHHMMSS` | Common in logs and filenames |
| RFC 2822 / HTTP | `Wed, 21 Oct 2015 07:28:00 GMT` | Headers, MIME |

All of these also appear UTF-16LE encoded in Windows artefacts. `tsscan.py`
tests both widths.

---

## 3. String encodings

**Detection signals**

| Signal | Meaning |
|---|---|
| Alternating zero at odd offsets | UTF-16LE holding Latin text |
| Alternating zero at even offsets | UTF-16BE |
| `FF FE` / `FE FF` prefix | UTF-16 BOM, LE / BE |
| `EF BB BF` prefix | UTF-8 BOM |
| Bytes ≥ 0x80 in valid UTF-8 sequences | UTF-8 |
| Bytes ≥ 0x80 not valid UTF-8 | A legacy codepage — determine which from the producer's locale, not from the bytes |

`profile.py` reports the odd-offset NUL rate for exactly this reason: a rate
near 50% over the whole file means large UTF-16LE regions.

**Storage conventions**, in rough order of frequency:

- Length-prefixed, prefix counts **bytes** — most common in binary formats
- Length-prefixed, prefix counts **characters** — differs from bytes only for
  wide or multi-byte encodings, which is what makes it worth distinguishing
- Length-prefixed including the terminator (`len+1`)
- NUL-terminated (one byte, or two for UTF-16)
- Fixed-width padded field, padded with NUL or space
- Offset into a separate string table or heap — the field in the record is a
  pointer, and all strings live in one region. Common in index structures.

`strscan.py` tests prefix widths u8/u16/u32 in both endiannesses against both
byte-count and character-count readings, and reports termination separately.
A format that shows neither a prefix nor a terminator is using a string table
or an out-of-band length in the record header.

**Hashed names.** Index structures frequently store a hash of a name rather
than the name. If you see fixed-width hex-looking strings of 32, 40, or 64
characters, they are likely MD5, SHA-1, or SHA-256 digests rendered as text.
Confirm by hashing a known name — including its exact case treatment and
encoding, which is usually uppercased and UTF-16LE on Windows.

---

## 4. Integers, floats, and packing

- **Endianness** is normally uniform per format but not always. `fieldmap.py`
  infers it from where the zero padding of small values sits. Network-derived
  substructures embedded in host-order files are the usual exception.
- **Alignment.** Fields are typically aligned to their own width. A struct
  that only parses correctly with unaligned reads is probably packed
  deliberately, or your boundary is off by a few bytes.
- **Padding.** Compilers pad structs to the alignment of their widest member.
  Unexplained zero gaps of 1–7 bytes in a layout are usually padding, not
  reserved fields — though you cannot tell the difference from bytes alone, so
  record it as `unknown` rather than asserting either.
- **Signedness** is not recoverable from a single value. A dword of
  `0xFFFFFFFE` is either 4294967294 or −2. Decide from behaviour across the
  corpus: if the field is ever near 2^31 with no discontinuity, it is
  unsigned; if values cluster near 0 and 0xFFFFFFFF with nothing between, it
  is signed.
- **Floats.** IEEE 754 binary32/binary64. A float column mis-read as an
  integer shows a characteristic pattern: the high byte clusters in a narrow
  range (the exponent) while lower bytes look random.
- **Bitfields.** A column that `fieldmap.py` labels `enum_flags` with values
  that are powers of two, or ORs of them, is a bitfield. Decompose by checking
  which bits vary independently across the corpus.
- **VARINTs.** Continuation-bit encodings (high bit set = more bytes) appear
  in protobuf-derived formats, SQLite, and LEB128 in DWARF/WASM. Symptom:
  no consistent stride, many bytes in the 0x80–0xFF range, and length fields
  that never quite line up.

---

## 5. Checksums and hashes

`cksum_id.py` covers CRC-8/16/32/64 across 18 parameterisations plus simple
accumulators. Validate it with `--selftest` before trusting a result; the
catalogue is checked against the standard `123456789` check values.

**Choosing candidate coverage ranges.** Formats vary in what the checksum
covers. Test, in order:

1. Record start up to the checksum field
2. Checksum field end to record end
3. Whole record with the checksum field zeroed
4. Whole record as stored (rare, only when the algorithm is order-dependent
   in a way that makes it self-consistent)
5. A payload region identified separately — pass with `--range`

**Common families**

| Family | Widths | Notes |
|---|---|---|
| CRC-32/ISO-HDLC | 32 | The zlib/PNG/Ethernet one. By far the most common. Poly 0x04C11DB7, reflected (0xEDB88320 in reflected form) |
| CRC-32C (Castagnoli) | 32 | iSCSI, ext4, SSE4.2 hardware instruction |
| CRC-16 variants | 16 | Modbus, XMODEM, CCITT — embedded and serial lineage |
| CRC-64/XZ | 64 | xz, some archive formats |
| Adler-32 | 32 | zlib streams; weak, fast |
| Fletcher-16/32 | 16/32 | Older network protocols |
| Sum / XOR of bytes or words | any | Simple formats, firmware |
| MD5 / SHA-1 / SHA-256 | 128/160/256 | Not checksums — name hashes or integrity digests |

**If nothing matches**, the field may be a truncated hash, may include a seed
or salt, may cover bytes outside the record, or may not be a checksum at all.
A high-entropy near-unique column is equally consistent with a random
identifier or an encrypted value.

---

## 6. Compression and container signatures

`profile.py` scans for these. Presence *inside* a file usually means an
embedded stream, not the file's own type.

| Signature | Format |
|---|---|
| `78 01` / `78 9C` / `78 DA` | zlib (low / default / best) |
| `1F 8B 08` | gzip |
| `42 5A 68` (`BZh`) | bzip2 |
| `FD 37 7A 58 5A 00` | xz |
| `04 22 4D 18` | LZ4 frame |
| `28 B5 2F FD` | Zstandard |
| `50 4B 03 04` (`PK..`) | ZIP, and everything built on it (OOXML, JAR, APK) |
| `37 7A BC AF 27 1C` | 7-Zip |
| `4D 5A` (`MZ`) | DOS/PE executable |
| `7F 45 4C 46` | ELF |
| `D0 CF 11 E0 A1 B1 1A E1` | OLE compound file (legacy Office, MSI, jump lists) |
| `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite 3 |
| `72 65 67 66` (`regf`) | Windows registry hive |
| `45 6C 66 46 69 6C 65 00` (`ElfFile`) | Windows EVTX |
| `EF CD AB 89` | ESE / JET database (EDB) |
| `46 49 4C 45 30` (`FILE0`) | NTFS $MFT record |
| `49 4E 44 58` (`INDX`) | NTFS index record |
| `SCCA` / `MAM\x04` | Windows Prefetch, uncompressed / MAM-compressed |

Windows also uses **LZNT1**, **XPRESS**, and **XPRESS HUFF** internally with
no magic at all — hibernation files, prefetch, registry differencing, and
various caches. Suspect these when a region shows entropy around 6–7 with no
recognisable signature and no parseable structure.

---

## 7. GUIDs, SIDs, and other fixed structures

| Structure | Size | Recognition |
|---|---|---|
| GUID / UUID | 16 bytes | Mixed-endian on Windows: first three fields LE, last two BE. A "random-looking" 16-byte field at a fixed offset is usually a GUID |
| Windows SID | variable | Starts `01`, then subauthority count, then `00 00 00 00 00 05` for the NT authority. Highly recognisable |
| IPv4 / IPv6 | 4 / 16 | Look for private ranges (`10.`, `192.168.`, `172.16–31.`) in the corpus |
| MAC address | 6 | OUI in the first three bytes; check against a vendor list |
| FILETIME pair | 16 | Created/modified adjacent is a very common idiom |
| Length + offset pair | 8 | Two dwords where one is bounded by the record and the other by the file |

A 16-byte field that `fieldmap.py` calls `hash_or_crc` at u64 granularity but
that never repeats is usually a GUID. Check for version nibble `4` in the
right position to confirm a v4 UUID.
