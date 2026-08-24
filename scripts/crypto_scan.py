#!/usr/bin/env python3
"""Find obfuscation and compression that a checksum search will not.

cksum_id.py resolves integrity fields. This handles the rest of the reasons a
region refuses to make sense: it is encrypted, compressed, XOR-masked, or
encoded. Getting this wrong wastes days -- you cannot infer a struct from
ciphertext, and high entropy plus no structure usually means stop looking for
fields and start looking for a transform.

Covers crypto constant tables, single- and multi-byte XOR recovery, textual
encodings, and compression signatures including the Windows families that have
no magic at all.

Usage:
  crypto_scan.py sample.bin
  crypto_scan.py sample.bin --xor --plaintext "Microsoft" --max-keylen 16
  crypto_scan.py sample.bin --region 0x2000:0x4000
"""
import argparse
import collections
import math
import os
import re
import struct
import sys

# Constant tables that identify an algorithm outright. Each entry is a short
# prefix distinctive enough to be worth a memmem.
CRYPTO_CONSTANTS = [
    ("AES S-box", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                         0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])),
    ("AES inverse S-box", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
                                 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3])),
    ("MD5 initial state", struct.pack("<4I", 0x67452301, 0xEFCDAB89,
                                      0x98BADCFE, 0x10325476)),
    ("SHA-1 initial state", struct.pack(">5I", 0x67452301, 0xEFCDAB89,
                                        0x98BADCFE, 0x10325476, 0xC3D2E1F0)),
    ("SHA-256 initial state", struct.pack(">8I", 0x6A09E667, 0xBB67AE85,
                                          0x3C6EF372, 0xA54FF53A, 0x510E527F,
                                          0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)),
    ("SHA-256 K constants", struct.pack(">4I", 0x428A2F98, 0x71374491,
                                        0xB5C0FBCF, 0xE9B5DBA5)),
    ("SHA-512 initial state", struct.pack(">2Q", 0x6A09E667F3BCC908,
                                          0xBB67AE8584CAA73B)),
    ("MD5 T-table", struct.pack("<4I", 0xD76AA478, 0xE8C7B756, 0x242070DB,
                                0xC1BDCEEE)),
    ("Blowfish P-array (pi digits)", struct.pack(">4I", 0x243F6A88, 0x85A308D3,
                                                 0x13198A2E, 0x03707344)),
    ("ChaCha/Salsa 'expand 32-byte k'", b"expand 32-byte k"),
    ("ChaCha/Salsa 'expand 16-byte k'", b"expand 16-byte k"),
    ("Tiny Encryption Algorithm delta", struct.pack("<I", 0x9E3779B9)),
    ("CRC-32 reflected table head", struct.pack("<2I", 0x00000000, 0x77073096)),
    ("CRC-32C reflected table head", struct.pack("<2I", 0x00000000, 0xF26B8303)),
    ("zlib fixed Huffman / DEFLATE hint", b"\x78\x9c"),
]

COMPRESSION_MAGICS = [
    (b"\x78\x01", "zlib (no/low compression)"),
    (b"\x78\x5e", "zlib (fast)"),
    (b"\x78\x9c", "zlib (default)"),
    (b"\x78\xda", "zlib (best)"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "LZ4 frame"),
    (b"\x28\xb5\x2f\xfd", "Zstandard"),
    (b"\x5d\x00\x00", "LZMA alone"),
    (b"\x50\x4b\x03\x04", "ZIP/deflate container"),
]

# Windows compression families that carry no magic at all -- named so the
# absence of a signature does not get read as absence of compression.
SILENT_COMPRESSION = [
    "LZNT1 (RtlDecompressBuffer, COMPRESSION_FORMAT_LZNT1) -- registry "
    "differencing, hibernation, some caches",
    "Xpress (COMPRESSION_FORMAT_XPRESS) -- prefetch, WIM, various services",
    "Xpress Huffman (COMPRESSION_FORMAT_XPRESS_HUFF) -- MAM prefetch, "
    "Windows Update, memory compression",
    "LZ77+Huffman via the Compression API (ntdll RtlCompressBuffer)",
]

ENGLISH_FREQ = b" etaoinshrdlucmfwypvbgkjqxz"


def shannon(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7F or x in (9, 10, 13)) / len(b)


def score_plaintext(b):
    """Crude English/structure plausibility, for ranking XOR key candidates."""
    if not b:
        return 0.0
    pr = printable_ratio(b)
    ent = shannon(b)
    common = sum(1 for x in b if x in ENGLISH_FREQ) / len(b)
    nulls = b.count(0) / len(b)
    return pr * 2.0 + common * 1.5 + max(0.0, 4.0 - ent) * 0.4 + nulls * 0.5


def xor_bytes(data, key):
    k = len(key)
    return bytes(d ^ key[i % k] for i, d in enumerate(data))


def recover_xor_known_plaintext(data, plaintext, max_keylen):
    """Slide known plaintext; the XOR difference repeats at the key length."""
    hits = []
    pt = plaintext.encode() if isinstance(plaintext, str) else plaintext
    n = len(pt)
    if n < 2:
        return hits
    for off in range(0, len(data) - n):
        diff = bytes(data[off + i] ^ pt[i] for i in range(n))
        for klen in range(1, min(max_keylen, n) + 1):
            cand = diff[:klen]
            if all(diff[i] == cand[i % klen] for i in range(n)):
                if set(cand) == {0}:
                    continue          # plaintext already present, not XORed
                hits.append((off, klen, cand))
                break
    return hits


def recover_xor_statistical(data, max_keylen, sample=1 << 16):
    """Per-position frequency attack, assuming the most common byte is 0x00."""
    buf = data[:sample]
    out = []
    for klen in range(1, max_keylen + 1):
        key = bytearray()
        for pos in range(klen):
            col = buf[pos::klen]
            if not col:
                key.append(0)
                continue
            common = collections.Counter(col).most_common(1)[0][0]
            key.append(common)          # assume it decrypts to 0x00
        if set(key) == {0}:
            continue
        dec = xor_bytes(buf[:4096], bytes(key))
        out.append((bytes(key), score_plaintext(dec), dec[:48]))
    out.sort(key=lambda r: -r[1])
    return out


def detect_encodings(data, sample=1 << 20):
    buf = data[:sample]
    findings = []
    b64 = re.findall(rb"[A-Za-z0-9+/]{40,}={0,2}", buf)
    if b64:
        findings.append(("base64", len(b64), b64[0][:40]))
    b64u = re.findall(rb"[A-Za-z0-9_\-]{40,}", buf)
    if len(b64u) > len(b64):
        findings.append(("base64url or token-like", len(b64u), b64u[0][:40]))
    hexr = re.findall(rb"[0-9a-fA-F]{32,}", buf)
    if hexr:
        findings.append(("hex-encoded", len(hexr), hexr[0][:40]))
    b32 = re.findall(rb"[A-Z2-7]{32,}={0,6}", buf)
    if b32:
        findings.append(("base32", len(b32), b32[0][:40]))
    return findings


def parse_region(spec, size):
    a, _, b = spec.partition(":")
    return int(a or 0, 0), int(b or size, 0)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--region", help="limit to START:END, e.g. 0x2000:0x4000")
    ap.add_argument("--xor", action="store_true",
                    help="attempt XOR key recovery")
    ap.add_argument("--plaintext", action="append", default=[],
                    help="known plaintext for XOR recovery (repeatable)")
    ap.add_argument("--max-keylen", type=int, default=16)
    ap.add_argument("--top", type=int, default=6)
    ap.add_argument("--max-bytes", type=int, default=64 << 20)
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read(args.max_bytes)
    base = 0
    if args.region:
        a, b = parse_region(args.region, len(data))
        data, base = data[a:b], a
        print(f"region    0x{a:x}..0x{b:x} ({len(data)} bytes)")

    ent = shannon(data)
    print(f"file      {args.file}")
    print(f"entropy   {ent:.4f} bits/byte, printable {printable_ratio(data):.1%}")

    hits = []
    for name, needle in CRYPTO_CONSTANTS:
        i = data.find(needle)
        if i >= 0:
            hits.append((base + i, name))
    if hits:
        print(f"\ncrypto/algorithm constants: {len(hits)}")
        for off, name in sorted(hits):
            print(f"  0x{off:08x}  {name}")
        print("  In a data file these are usually embedded key material or a\n"
              "  bundled implementation. In a producer binary they identify the\n"
              "  algorithm outright -- feed the offset to constant_hunt.py to\n"
              "  place it in a section, then xref it.")
    else:
        print("\ncrypto/algorithm constants: none")

    comp = []
    for needle, name in COMPRESSION_MAGICS:
        start = 0
        n = 0
        while n < 32:
            i = data.find(needle, start)
            if i < 0:
                break
            comp.append((base + i, name))
            start = i + 1
            n += 1
    if comp:
        by = collections.Counter(n for _, n in comp)
        print(f"\ncompression signatures: {len(comp)} hit(s)")
        for name, count in by.most_common():
            first = next(o for o, n in comp if n == name)
            print(f"  {count:>4}x  {name}  first at 0x{first:08x}")
        print("  A compression magic inside a file usually marks an embedded\n"
              "  stream, not the file's own type. Decompress it and re-run the\n"
              "  whole recon loop on the output.")
    else:
        print("\ncompression signatures: none")

    if ent > 7.2 and not comp:
        print("\n  High entropy with no compression magic. Before concluding\n"
              "  encryption, consider that Windows uses several compression\n"
              "  formats with no header at all:")
        for s in SILENT_COMPRESSION:
            print(f"    - {s}")
        print("  If the producer calls RtlDecompressBuffer, the format argument\n"
              "  tells you which -- that is a producer-side question, see\n"
              "  references/producer-side.md.")

    enc = detect_encodings(data)
    if enc:
        print(f"\ntextual encodings:")
        for name, count, sample in enc:
            print(f"  {count:>5} run(s)  {name}  e.g. {sample.decode('ascii','replace')}")

    if args.xor:
        print("\nXOR key recovery")
        any_hit = False
        for pt in args.plaintext:
            found = recover_xor_known_plaintext(data, pt, args.max_keylen)
            if found:
                any_hit = True
                print(f"  known plaintext {pt!r}: {len(found)} candidate(s)")
                for off, klen, key in found[:args.top]:
                    print(f"    0x{base+off:08x}  keylen {klen}  "
                          f"key {key.hex()}  ({key!r})")
                print("    Known-plaintext recovery is exact, not statistical --\n"
                      "    if the difference repeats at a fixed period, that is\n"
                      "    the key.")
            else:
                print(f"  known plaintext {pt!r}: no repeating-difference match")
        if not args.plaintext:
            print("  no --plaintext given; falling back to frequency analysis")
        stats = recover_xor_statistical(data, args.max_keylen)
        if stats:
            print(f"  statistical candidates (assumes most common byte is 0x00):")
            for key, score, preview in stats[:args.top]:
                txt = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in preview)
                print(f"    keylen {len(key):>2}  score {score:5.2f}  "
                      f"key {key.hex()}")
                print(f"       -> {txt}")
            print("    Score ranks plausibility of the decrypted preview; it is a\n"
                  "    heuristic, so read the preview rather than trusting the\n"
                  "    ranking. A correct key makes structure appear immediately.")
        if not any_hit and not stats:
            print("  nothing recovered")

    print("\nIf a region resists all of the above and entropy stays near 8.0, "
          "stop trying\nto infer fields from it. Either find the transform "
          "(producer-side analysis is\nusually the fastest route) or record it "
          "as opaque and move on -- an inferred\nstruct over ciphertext is "
          "worse than an honest gap.")


def _quiet_pipe():
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass


if __name__ == "__main__":
    _quiet_pipe()
    try:
        main()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        raise SystemExit(130)
