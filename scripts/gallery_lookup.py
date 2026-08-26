#!/usr/bin/env python3
"""Generate a prior-art lookup plan before reverse engineering anything.

The cheapest phase of format work is finding out somebody already did it, and
the reason it gets skipped is friction: knowing which of two dozen galleries
to check, in what order, with what search terms. This removes the friction.

Given a sample (or just a name), it identifies what it can offline, guesses
the domain, and prints an ordered checklist of galleries with working URLs and
pre-built search strings. It does not fetch anything -- no network is assumed.

Usage:
  gallery_lookup.py FILE
  gallery_lookup.py --name OBJECTS.DATA
  gallery_lookup.py FILE --domain windows --terms "wmi,cim,repository"
"""
import argparse
import collections
import os
import re
import sys
import urllib.parse

# ---------------------------------------------------------------- signatures

# (offset, signature, label, domain, search terms)
# offset None means "anywhere in the first block".
SIGNATURES = [
    (0, b"regf", "Windows registry hive", "windows", ["registry hive", "regf"]),
    (0, b"ElfFile\x00", "Windows EVTX", "windows", ["evtx", "windows event log"]),
    (0, b"ElfChnk\x00", "EVTX chunk", "windows", ["evtx chunk"]),
    (0, b"\x0cLfLe", "Windows EVT (legacy)", "windows", ["windows evt"]),
    (0, b"\xef\xcd\xab\x89", "ESE / JET database", "windows", ["ese", "edb", "jet database"]),
    (0, b"FILE0", "NTFS MFT record", "filesystem", ["mft", "ntfs"]),
    (0, b"INDX", "NTFS index record", "filesystem", ["ntfs indx"]),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", "windows",
     ["compound file", "ole cfb", "MS-CFB"]),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows LNK shortcut", "windows",
     ["lnk shell link", "MS-SHLLINK"]),
    (0, b"SCCA", "Windows Prefetch", "windows", ["prefetch"]),
    (0, b"MAM\x04", "Prefetch (MAM compressed)", "windows",
     ["prefetch mam", "xpress huffman"]),
    (0, b"SQLite format 3\x00", "SQLite 3", "generic", ["sqlite file format"]),
    (0, b"\x7fELF", "ELF executable", "executable", ["elf"]),
    (0, b"MZ", "DOS/PE executable", "executable", ["pe portable executable"]),
    (0, b"\xca\xfe\xba\xbe", "Java class / Mach-O fat", "executable",
     ["java class", "mach-o fat"]),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit", "executable", ["mach-o"]),
    (0, b"bplist00", "Apple binary plist", "apple", ["binary plist", "bplist"]),
    (0, b"PK\x03\x04", "ZIP / OOXML / JAR", "archive", ["zip", "ooxml"]),
    (0, b"\x1f\x8b\x08", "gzip", "archive", ["gzip"]),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", "archive", ["7z"]),
    (0, b"Rar!\x1a\x07", "RAR", "archive", ["rar"]),
    (0, b"\xfd7zXZ\x00", "xz", "archive", ["xz"]),
    (0, b"BZh", "bzip2", "archive", ["bzip2"]),
    (0, b"\x28\xb5\x2f\xfd", "Zstandard", "archive", ["zstd"]),
    (0, b"\x04\x22\x4d\x18", "LZ4 frame", "archive", ["lz4"]),
    (0, b"%PDF-", "PDF", "document", ["pdf"]),
    (0, b"\x89PNG\r\n\x1a\n", "PNG", "multimedia", ["png"]),
    (0, b"\xff\xd8\xff", "JPEG", "multimedia", ["jpeg", "jfif", "exif"]),
    (0, b"GIF8", "GIF", "multimedia", ["gif"]),
    (0, b"RIFF", "RIFF container", "multimedia", ["riff", "wav", "avi"]),
    (0, b"\x1a\x45\xdf\xa3", "Matroska / WebM", "multimedia", ["matroska", "ebml"]),
    (0, b"OggS", "Ogg", "multimedia", ["ogg"]),
    (4, b"ftyp", "ISO BMFF (MP4/MOV/HEIF)", "multimedia", ["isobmff", "mp4"]),
    (0, b"CD001", "ISO 9660", "filesystem", ["iso9660"]),
    (0, b"\xd4\xc3\xb2\xa1", "pcap", "network", ["pcap"]),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng", "network", ["pcapng"]),
    (0, b"\x53\xef", "ext2/3/4 superblock magic", "filesystem", ["ext4"]),
    (0, b"NXSB", "APFS container", "apple", ["apfs"]),
    (0, b"H+\x00\x04", "HFS+", "apple", ["hfs+"]),
]

# Filename patterns for artefacts with no magic worth the name. These are the
# ones that most often send people down a needless reversing path.
NAME_HINTS = [
    (r"^objects\.data$", "WMI CIM repository objects", "windows",
     ["wmi cim repository", "objects.data"]),
    (r"^index\.btr$", "WMI CIM index B-tree", "windows", ["wmi index.btr"]),
    (r"^mapping[0-9]*\.map$", "WMI CIM mapping file", "windows",
     ["wmi mapping.map"]),
    (r"^(ntuser|usrclass)\.dat$", "Registry hive (user)", "windows",
     ["ntuser.dat", "registry hive"]),
    (r"^(system|software|security|sam|default)$", "Registry hive (system)",
     "windows", ["registry hive"]),
    (r"^\$mft$", "NTFS master file table", "filesystem", ["mft"]),
    (r"^\$usnjrnl", "NTFS USN journal", "filesystem", ["usn journal"]),
    (r"^\$logfile$", "NTFS log file", "filesystem", ["ntfs logfile"]),
    (r"^pagefile\.sys$", "Windows page file", "windows", ["pagefile"]),
    (r"^hiberfil\.sys$", "Windows hibernation file", "windows",
     ["hiberfil", "hibernation"]),
    (r"^srudb\.dat$", "SRUM database (ESE)", "windows", ["srum", "srudb"]),
    (r"^webcachev[0-9]*\.dat$", "IE/Edge WebCache (ESE)", "windows",
     ["webcache ese"]),
    (r"^amcache\.hve$", "Amcache hive", "windows", ["amcache"]),
    (r"\.evtx$", "Windows event log", "windows", ["evtx"]),
    (r"\.pf$", "Windows prefetch", "windows", ["prefetch"]),
    (r"\.lnk$", "Windows shortcut", "windows", ["lnk", "MS-SHLLINK"]),
    (r"\.pst$|\.ost$", "Outlook mail store", "windows", ["pst", "MS-PST"]),
    (r"\.edb$", "ESE database", "windows", ["ese", "edb"]),
    (r"\.e01$|\.ex01$", "EnCase evidence image", "forensic-container",
     ["ewf", "encase e01"]),
    (r"\.aff4$", "AFF4 evidence container", "forensic-container", ["aff4"]),
    (r"\.vmdk$|\.vhdx?$|\.qcow2?$", "Virtual disk image", "filesystem",
     ["vmdk", "vhdx", "qcow2"]),
    (r"\.plist$", "Apple property list", "apple", ["plist"]),
    (r"\.dex$", "Android Dalvik executable", "mobile", ["dex"]),
    (r"\.pak$|\.dat$|\.bin$|\.res$|\.arc$", "Generic container (ambiguous)",
     "unknown", []),
]

# ------------------------------------------------------------------ galleries

def q(s):
    return urllib.parse.quote_plus(s)


def gh_search(repo, term):
    return f"https://github.com/search?q=repo%3A{repo}+{q(term)}&type=code"


def gallery_targets(domain, terms, sample="sample.bin"):
    """Ordered (rank, name, kind, url, why) for a domain."""
    t = terms[0] if terms else ""
    out = []

    forensic = domain in ("windows", "filesystem", "apple", "mobile",
                          "forensic-container")

    # --- identification, always first
    out.append((1, "Siegfried / fido (PRONOM)", "identify",
                "https://github.com/richardlehane/siegfried",
                "Run against the sample first. A confident PUID short-circuits "
                "everything below."))
    out.append((1, "PRONOM registry", "signature",
                f"https://www.nationalarchives.gov.uk/PRONOM/{q(t)}"
                if t else "https://www.nationalarchives.gov.uk/PRONOM/",
                "Authoritative signature registry; per-PUID XML is "
                "machine-readable."))
    out.append((1, "file / libmagic", "identify", "man file(1)",
                "`file -k` shows all matching magic rules, not just the first."))

    # --- executable specs
    out.append((2, "Kaitai Struct gallery", "executable",
                f"https://formats.kaitai.io/?q={q(t)}" if t
                else "https://formats.kaitai.io/",
                "A hit gives you a compilable parser in a dozen languages."))
    out.append((2, "fq decoders", "executable",
                "https://github.com/wader/fq/blob/master/doc/formats.md",
                f"~150 decoders in one binary. Confirm in one command: "
                f"fq -d <format> d {sample}"))
    out.append((2, "ImHex-Patterns", "executable",
                gh_search("WerWolv/ImHex-Patterns", t) if t
                else "https://github.com/WerWolv/ImHex-Patterns",
                "Community .hexpat gallery, and ships custom libmagic files "
                "so it doubles as a signature source."))
    out.append((3, "010 Editor templates", "executable",
                "https://www.sweetscape.com/010editor/repository/templates/",
                "Largest curated .bt corpus. Plaintext and readable even "
                "without the editor."))

    # --- forensic prose
    if forensic:
        out.append((2, "libyal (whole org)", "prose",
                    f"https://github.com/search?q=org%3Alibyal+{q(t)}&type=repositories"
                    if t else "https://github.com/libyal",
                    "Deepest forensic-artefact documentation. Check dtformats, "
                    "winreg-kb, esedb-kb, and the per-format lib*."))
        out.append((2, "Microsoft Open Specifications", "prose",
                    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/",
                    "Authoritative for Windows and Office structures "
                    "(MS-CFB, MS-SHLLINK, MS-PST, MS-XCA). The [MS-XXXX] "
                    "top page is only an INDEX (revision table, PDF link, "
                    "GitHub source path) -- the structure tables are in the "
                    "section pages beneath it or in the PDF. Fetch the "
                    "section or download the PDF; an index page retrieved "
                    "is a spec not read."))
        out.append((3, "Forensics Wiki", "prose",
                    f"https://forensics.wiki/?s={q(t)}" if t
                    else "https://forensics.wiki/",
                    "Orientation and tooling. Note: forensicswiki.org and .xyz "
                    "are dead or frozen."))
        out.append((3, "plaso parsers", "code",
                    gh_search("log2timeline/plaso", t) if t
                    else "https://github.com/log2timeline/plaso/tree/main/plaso/parsers",
                    "Format knowledge encoded as code where no prose spec "
                    "exists."))
        out.append((4, "Velociraptor artifact exchange", "code",
                    "https://docs.velociraptor.app/exchange/",
                    "Collection-side knowledge; useful for acquiring more "
                    "corpus samples at scale."))

    # --- domain-specific community wikis
    if domain == "multimedia":
        out.append((2, "MultimediaWiki (FFmpeg)", "prose",
                    f"https://wiki.multimedia.cx/index.php?search={q(t)}"
                    if t else "https://wiki.multimedia.cx/",
                    "Deepest free codec and container reference, often with C "
                    "struct definitions."))
        out.append((3, "FFmpeg demuxer source", "code",
                    gh_search("FFmpeg/FFmpeg", t) if t
                    else "https://github.com/FFmpeg/FFmpeg/tree/master/libavformat",
                    "The de facto specification for many containers."))
    if domain in ("game", "unknown", "archive"):
        out.append((3, "ModdingWiki", "prose",
                    f"https://moddingwiki.shikadi.net/w/index.php?search={q(t)}"
                    if t else "https://moddingwiki.shikadi.net/",
                    "427 formats, heavily DOS and early-PC games, real "
                    "byte-level detail."))
        out.append((4, "XentaX via Internet Archive", "archived",
                    "https://web.archive.org/web/*/wiki.xentax.com/*",
                    "The live wiki shut down in 2023. Snapshots only."))
    if domain in ("executable", "windows"):
        out.append((4, "GNU poke pickles", "executable",
                    "https://pokology.org/pickles.html",
                    "Strongest coverage of object and debug formats "
                    "(ELF, DWARF, CTF, BTF)."))
    if domain == "network":
        out.append((2, "Wireshark dissectors", "code",
                    gh_search("wireshark/wireshark", t) if t
                    else "https://github.com/wireshark/wireshark/tree/master/epan/dissectors",
                    "Largest executable corpus of protocol knowledge. "
                    "tshark -T json gives structured output to diff against."))
    if domain == "apple":
        out.append((3, "Apple platform documentation + mac4n6", "prose",
                    "https://github.com/mac4n6",
                    "Community macOS/iOS artefact documentation."))

    # --- breadth and context, always worth a look
    out.append((4, "Just Solve the File Format Problem", "prose",
                f"http://fileformats.archiveteam.org/index.php?search={q(t)}"
                if t else "http://fileformats.archiveteam.org/",
                "~6,680 articles. Uneven depth, excellent breadth; usually "
                "links onward to primary sources."))
    out.append((4, "Library of Congress FDDs", "prose",
                f"https://www.loc.gov/search/?q={q(t)}&fa=partof:sustainability+of+digital+formats"
                if t else "https://www.loc.gov/preservation/digital/formats/",
                "470+ curated descriptions. Best for provenance and "
                "obsolescence context."))
    out.append((5, "TrID / Kessler signature table", "signature",
                "https://mark0.net/soft-trid-e.html",
                "Fallback identification for obscure formats."))

    return out


# ------------------------------------------------------------------- analysis

def detect(data, name):
    hits, domains, terms = [], collections.Counter(), []
    head = data[:4096] if data else b""

    for off, sig, label, domain, tt in SIGNATURES:
        if not head:
            break
        if off is None:
            if sig in head:
                hits.append((label, "anywhere", domain))
                domains[domain] += 2
                terms += tt
        elif head[off:off + len(sig)] == sig:
            hits.append((label, f"+{off}", domain))
            domains[domain] += 3
            terms += tt

    base = os.path.basename(name or "").lower()
    for pat, label, domain, tt in NAME_HINTS:
        if re.search(pat, base):
            hits.append((label, "filename", domain))
            domains[domain] += 2
            terms += tt
            break

    return hits, domains, terms


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="sample to inspect")
    ap.add_argument("--name", help="filename to reason about when the sample "
                                   "is unavailable or was renamed")
    ap.add_argument("--domain", help="override the inferred domain",
                    choices=["windows", "filesystem", "apple", "mobile",
                             "multimedia", "archive", "executable", "network",
                             "document", "game", "forensic-container",
                             "generic", "unknown"])
    ap.add_argument("--terms", help="comma-separated extra search terms")
    ap.add_argument("--all", action="store_true",
                    help="show every target, not just the top tiers")
    args = ap.parse_args()

    if not args.file and not args.name:
        ap.error("give a FILE or --name")

    data = b""
    if args.file:
        with open(args.file, "rb") as fh:
            data = fh.read(1 << 20)

    name = args.name or (args.file or "")
    hits, domains, terms = detect(data, name)
    if args.terms:
        terms = [t.strip() for t in args.terms.split(",") if t.strip()] + terms

    domain = args.domain or (domains.most_common(1)[0][0] if domains else "unknown")
    # de-duplicate, preserve order
    seen, uterms = set(), []
    for t in terms:
        if t.lower() not in seen:
            seen.add(t.lower())
            uterms.append(t)

    print(f"sample    {args.file or '(none)'}")
    if name:
        print(f"name      {os.path.basename(name)}")
    print(f"domain    {domain}" + ("" if args.domain else "  (inferred)"))

    if hits:
        print(f"\nidentification hits")
        for label, where, dom in hits:
            print(f"  {where:<10} {label}   [{dom}]")
    elif data:
        print("\nno known signature or filename match -- treat the domain as "
              "unknown and\ncast a wide net. If profile.py found a repeating "
              "magic, pass it as --terms.")

    if uterms:
        print(f"\nsearch terms  {', '.join(uterms[:6])}")
    else:
        print("\nsearch terms  none derived -- supply --terms with anything you "
              "know about\n              the producing application or subsystem")

    targets = gallery_targets(domain, uterms, args.file or "sample.bin")
    cutoff = 9 if args.all else 4
    print(f"\nlookup plan  (kind: executable = runnable spec, prose = "
          f"hand-implement,\n              code = read the parser, signature/"
          f"identify = what is it)")
    print("=" * 100)
    last = None
    for rank, label, kind, url, why in sorted(targets, key=lambda r: r[0]):
        if rank > cutoff:
            continue
        if rank != last:
            print(f"\n--- tier {rank} " + "-" * 84)
            last = rank
        print(f"  [{kind:<10}] {label}")
        print(f"    {url}")
        print(f"    {why}")

    if not args.all:
        print(f"\n  (--all shows lower-priority targets)")

    print("\nIf any tier-2 source has a spec, the job is verification, not "
          "discovery:\nrun the spec against your whole corpus and record where "
          "it disagrees. Specs\nare usually written from a handful of samples "
          "on a handful of producer versions.\nSee references/format-galleries.md "
          "for what each source is good and bad at.")



def _quiet_pipe():
    """Exit cleanly when output is piped into head/grep and the pipe closes."""
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError, ValueError):
        pass       # Windows has no SIGPIPE; the except in __main__ covers it


if __name__ == "__main__":
    _quiet_pipe()
    try:
        main()
    except BrokenPipeError:
        import os, sys
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        raise SystemExit(130)
