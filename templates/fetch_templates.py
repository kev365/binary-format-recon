#!/usr/bin/env python3
"""Fetch and sort the imported X-Ways template collection into imported/.

The template files themselves are not redistributed with this project: the
kacos2000 set is GPL-3.0 (fine to mirror), but the x-ways.net contributions
carry no stated licence, so what ships publicly is only the master index
(INDEX.md), the curation judgements, and PROVENANCE.json pointing at the
originals. This script rebuilds the local working copy from those originals.

Lives under templates/ rather than scripts/ deliberately: everything in
scripts/ is offline by contract, and this is the one network step.

Sources:
  https://github.com/kacos2000/WinHex_Templates       (GPL-3.0)
  https://www.x-ways.net/winhex/templates/            (Dalet *.txt only;
      the rest of that page is mirrored in the repo's WinHex_additional/)

Usage:
  python templates/fetch_templates.py            # populate imported/
  python templates/fetch_templates.py --check    # verify against PROVENANCE

Afterwards:
  python scripts/tplgen.py --check "templates/imported/**/*.tpl"
  python scripts/tpl_index.py                    # confirm INDEX.md current
"""
import argparse
import datetime as dt
import io
import json
import os
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

TDIR = os.path.dirname(os.path.abspath(__file__))
DEST = os.path.join(TDIR, "imported")

ZIP_URL = ("https://github.com/kacos2000/WinHex_Templates/"
           "archive/refs/heads/master.zip")
GH = "https://github.com/kacos2000/WinHex_Templates"
XW = "https://www.x-ways.net/winhex/templates/"
DALET = ["Dalet SND file header.txt", "Dalet VOL file header.txt",
         "Dalet BWF file header.txt"]

# Contributors per the x-ways.net templates page (applies equally to the
# mirrored copies in WinHex_additional/).
CONTRIB = {
    "OLYMPUS_WMA_v03.tpl": "Catalin Grigoras",
    "SQLite Header.tpl": "Terrance Maguire",
    "PCAP.tpl": "Frank Weiss",
    "DOS_exe.tpl": "Chris S",
    "exFAT Boot Sector 2.tpl": "Christopher Taylor / Robert Shullich",
    "exFAT Boot Sector.tpl": "Christopher Taylor / Robert Shullich",
    "Dalet SND file header.txt": "Steven Scholte",
    "Dalet VOL file header.txt": "Steven Scholte",
    "Dalet BWF file header.txt": "Steven Scholte",
    "JFS Superblock.tpl": "Jens Kirschner",
    "Reiser Superblock.tpl": "Jens Kirschner",
    "NTFS FILE Record.tpl": "Jens Kirschner",
    "NTFS Data Runs.tpl": "Jens Kirschner",
    "Non-Unicode LNK FILE Record.tpl": "Steve Guty",
    "LNK FILE Record.tpl": "Steve Guty",
    "EVT_Cursor.tpl": "Andreas Schuster",
    "EVT_Event.tpl": "Andreas Schuster",
    "EVT_Header.tpl": "Andreas Schuster",
    "POS_File_Format_1.1.tpl": "Stefan Fleischmann",
    "POS_File_Format_2.0.tpl": "Stefan Fleischmann",
    "WAVPCM.tpl": "Khomenko Volodymyr",
    "BMP.tpl": "Khomenko Volodymyr",
    "AFP_Structured_Fields.tpl": "Bob Carlyle",
    "SFF_File_Format.tpl": "Ulf Zibis",
    "TIFF File Format.tpl": "Ulf Zibis",
    "TIFF File IFD.tpl": "Ulf Zibis",
    "Palm PDB.tpl": "Ulf Zibis",
    "Palm PDB 6 records.tpl": "Ulf Zibis",
    "ZIP.tpl": "Alex Sidorov",
    "ZIP_Local_File_Header_Structure.tpl": "Trenton D. Adams",
    "ZIP_Data_Descriptor_Structure.tpl": "Trenton D. Adams",
    "ZIP_Central_Directory_Structure.tpl": "Trenton D. Adams",
    "ZIP_End_of_Central_Dir_Structure.tpl": "Trenton D. Adams",
    "FSINFO_Sector.tpl": "Stefan Fleischmann",
    "FAT16_Entry.tpl": "Paul Mullen",
    "FAT32_Entry.tpl": "Stefan Fleischmann",
    "dbf field.tpl": "Paul Mullen",
    "dbf header.tpl": "Paul Mullen",
    "dbf sample records.tpl": "Paul Mullen",
}
for _p in ("UFS1", "UFS2"):
    for _w in ("Superblock", "Cylinder Group Descriptor", "Inode"):
        for _e in ("BE", "LE"):
            CONTRIB[f"{_p} {_w} {_e}.tpl"] = "Michele Larese"
for _n in ("UFS directory entry BE.tpl", "UFS directory entry LE.tpl"):
    CONTRIB[_n] = "Michele Larese"
for _n in ("CDFS Volume Descriptor.tpl", "CDFS Path Tables Ascii.tpl",
           "CDFS Path Tables Unicode.tpl", "CDFS Directory Entry Ascii.tpl",
           "CDFS Directory Entry Unicode.tpl"):
    CONTRIB[_n] = "Chris Taylor"
for _n in ("Reiser4 Superblock.tpl", "Reiser4 Node Header.tpl",
           "Reiser4 Item Header Large.tpl", "Reiser4 Item Header Small.tpl",
           "Reiser4 Stat Data.tpl", "Reiser4 Directory Entries.tpl"):
    CONTRIB[_n] = "Jens Kirschner"
for _n in ("HFSPlus_Volume_Header.tpl", "HFSPlus_Catalog_Key.tpl",
           "HFSPlus_B-Tree_Header.tpl", "HFSPlus_Index_Node.tpl"):
    CONTRIB[_n] = "Jens Kirschner / Stefan Fleischmann"
for _n in ("exFAT Regular File.tpl", "exFAT type code 81.tpl",
           "exFAT type code 82.tpl", "exFAT type code 83.tpl",
           "exFAT type code 85.tpl", "exFAT type code A0.tpl",
           "exFAT type code C0.tpl", "exFAT type code C1.tpl"):
    CONTRIB[_n] = "Scott Pancoast"

# filename -> destination subdirectory (relative to imported/)
PLACEMENT = {}


def _place(subdir, names):
    for n in names:
        PLACEMENT[n] = subdir


_place("disk-partition", [
    "MBR.tpl", "GPT.tpl", "MBR-GPT.tpl",
    "Master Boot Record.tpl", "GUID Partition Table.tpl",
])
_place("filesystem/ntfs", [
    "NTFS_VBR.tpl", "Boot Sector NTFS.tpl",
    "NTFS - $AttrDef Structure.tpl", "NTFS - $EFS Stream.tpl",
    "NTFS - $R INDX Structure.tpl", "NTFS - MFT Attribute List.tpl",
    "NTFS - MFT FILE Record.tpl", "NTFS MFT FILE Record.tpl",
    "NTFS FILE Record.tpl", "NTFS Data Runs.tpl",
])
_place("filesystem/fat-exfat", [
    "FAT_VBR.tpl", "ExFAT_VBR.tpl", "ExFAT Directory Entries.tpl",
    "exFAT Boot Sector.tpl", "exFAT Boot Sector 2.tpl",
    "exFAT Regular File.tpl",
    "exFAT type code 81.tpl", "exFAT type code 82.tpl",
    "exFAT type code 83.tpl", "exFAT type code 85.tpl",
    "exFAT type code A0.tpl", "exFAT type code C0.tpl",
    "exFAT type code C1.tpl",
    "FAT16_Entry.tpl", "FAT32_Entry.tpl", "FSINFO_Sector.tpl",
    "Boot Sector FAT.tpl", "Boot Sector FAT32.tpl",
    "FAT Directory Entry.tpl", "FAT LFN Entry.tpl",
])
_place("filesystem/refs", [
    "REFS - $AttrDef Structure.tpl", "ReFS CheckPoint.tpl",
    "ReFS SuperBlock.tpl", "ReFS_FSRS.tpl",
])
_place("filesystem/ext", [
    "Ext Directory Entry.tpl", "Ext Group Descriptor.tpl",
    "Ext Inode.tpl", "Ext Superblock.tpl",
])
_place("filesystem/hfsplus", [
    "HFSPlus_Volume_Header.tpl", "HFSPlus_Catalog_Key.tpl",
    "HFSPlus_B-Tree_Header.tpl", "HFSPlus_Index_Node.tpl",
    "HFS+ Volume Header.tpl",
])
_place("filesystem/ufs",
       [f"{p} {w} {e}.tpl"
        for p in ("UFS1", "UFS2")
        for w in ("Superblock", "Cylinder Group Descriptor", "Inode")
        for e in ("BE", "LE")]
       + ["UFS directory entry BE.tpl", "UFS directory entry LE.tpl"])
_place("filesystem/reiser", [
    "Reiser Superblock.tpl", "Reiser4 Superblock.tpl",
    "Reiser4 Node Header.tpl", "Reiser4 Item Header Large.tpl",
    "Reiser4 Item Header Small.tpl", "Reiser4 Stat Data.tpl",
    "Reiser4 Directory Entries.tpl",
])
_place("filesystem/other", [
    "JFS Superblock.tpl",
    "CDFS Volume Descriptor.tpl", "CDFS Path Tables Ascii.tpl",
    "CDFS Path Tables Unicode.tpl", "CDFS Directory Entry Ascii.tpl",
    "CDFS Directory Entry Unicode.tpl",
])
_place("windows-artefacts", [
    "$I File Structure.tpl", "INFO2 Structure.tpl",
    "EVTX File Header.tpl", "EVTX Chunk Header.tpl",
    "EVTX Record Structure.tpl",
    "EVT_Header.tpl", "EVT_Event.tpl", "EVT_Cursor.tpl",
    "ETL_Header_x64.tpl",
    "LNK FILE Record.tpl", "Non-Unicode LNK FILE Record.tpl",
    "SHD spool shadow file.tpl",
])
_place("disk-images", [
    "VHD Header.tpl", "VHDX Header.tpl", "VMDK Header.tpl",
    "Acronis - TIB File Header.tpl",
])
_place("file-formats", [
    "ZIP.tpl", "ZIP_Local_File_Header_Structure.tpl",
    "ZIP_Data_Descriptor_Structure.tpl",
    "ZIP_Central_Directory_Structure.tpl",
    "ZIP_End_of_Central_Dir_Structure.tpl",
    "SQLite Header.tpl", "PCAP.tpl", "DOS_exe.tpl",
    "TIFF File Format.tpl", "TIFF File IFD.tpl", "BMP.tpl", "WAVPCM.tpl",
    "SFF_File_Format.tpl", "AFP_Structured_Fields.tpl",
    "Palm PDB.tpl", "Palm PDB 6 records.tpl",
    "OLYMPUS_WMA_v03.tpl",
    "POS_File_Format_1.1.tpl", "POS_File_Format_2.0.tpl",
    "dbf header.tpl", "dbf field.tpl", "dbf sample records.tpl",
    "Dalet SND file header.txt", "Dalet VOL file header.txt",
    "Dalet BWF file header.txt",
])

XW_LICENCE = ("contributed to x-ways.net, no explicit license; "
              "contributor credited")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent":
                                               "binary-format-recon-fetch"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def main():
    ap = argparse.ArgumentParser(
        description="Populate templates/imported/ from the original sources")
    ap.add_argument("--check", action="store_true",
                    help="verify local files against PROVENANCE.json "
                         "instead of downloading")
    args = ap.parse_args()

    prov_path = os.path.join(DEST, "PROVENANCE.json")
    if args.check:
        if not os.path.exists(prov_path):
            print("no PROVENANCE.json; run without --check first")
            sys.exit(1)
        with open(prov_path, encoding="utf-8") as f:
            prov = json.load(f)
        missing = [k for k in prov
                   if not os.path.exists(os.path.join(DEST,
                                                      *k.split("/")))]
        extra = []
        for dirpath, _, files in os.walk(DEST):
            for n in files:
                rel = os.path.relpath(os.path.join(dirpath, n),
                                      DEST).replace("\\", "/")
                if rel not in prov and rel not in (
                        "PROVENANCE.json", "LICENSE-kacos2000"):
                    extra.append(rel)
        for m in missing:
            print(f"missing: {m}")
        for e in extra:
            print(f"untracked: {e}")
        print(f"{len(prov)} tracked, {len(missing)} missing, "
              f"{len(extra)} untracked")
        sys.exit(1 if missing else 0)

    retrieved = dt.date.today().isoformat()
    prov = {}
    copied = 0
    unplaced = []

    print(f"downloading {ZIP_URL} ...")
    zdata = fetch(ZIP_URL)
    with tempfile.TemporaryDirectory() as td:
        zipfile.ZipFile(io.BytesIO(zdata)).extractall(td)
        repo = os.path.join(td, os.listdir(td)[0])
        sources = [
            (repo, "kacos2000", "GPL-3.0", GH,
             "Costas Katsavounidis (kacos2000)"),
            (os.path.join(repo, "WinHex_default"), "winhex-default",
             "shipped with WinHex/X-Ways, no explicit license", GH,
             "X-Ways Software Technology AG"),
            (os.path.join(repo, "WinHex_additional"), "x-ways.net-contrib",
             XW_LICENCE, XW, None),
        ]
        for srcdir, tag, lic, url, default_contrib in sources:
            for name in sorted(os.listdir(srcdir)):
                if not name.lower().endswith(".tpl"):
                    continue
                sub = PLACEMENT.get(name)
                if sub is None:
                    # new upstream template we have no placement for --
                    # never silently drop it
                    sub = "_unsorted"
                    unplaced.append(f"{tag}/{name}")
                destdir = os.path.join(DEST, *sub.split("/"))
                os.makedirs(destdir, exist_ok=True)
                base, ext = os.path.splitext(name)
                dest, key = os.path.join(destdir, name), f"{sub}/{name}"
                if key in prov:  # same filename from an earlier source
                    dest = os.path.join(destdir, f"{base} ({tag}){ext}")
                    key = f"{sub}/{base} ({tag}){ext}"
                shutil.copy2(os.path.join(srcdir, name), dest)
                entry = {"source": tag, "url": url, "retrieved": retrieved,
                         "license": lic,
                         "original_path": os.path.relpath(
                             os.path.join(srcdir, name),
                             repo).replace("\\", "/")}
                contrib = (CONTRIB.get(name)
                           if tag == "x-ways.net-contrib"
                           else default_contrib)
                if contrib:
                    entry["contributor"] = contrib
                prov[key] = entry
                copied += 1
        shutil.copy2(os.path.join(repo, "LICENSE"),
                     os.path.join(DEST, "LICENSE-kacos2000"))
    for name in DALET:
        sub = PLACEMENT[name]
        print(f"downloading {XW}{name} ...")
        data = fetch(XW + urllib.parse.quote(name))
        destdir = os.path.join(DEST, *sub.split("/"))
        os.makedirs(destdir, exist_ok=True)
        with open(os.path.join(destdir, name), "wb") as f:
            f.write(data)
        prov[f"{sub}/{name}"] = {
            "source": "x-ways.net-contrib", "url": XW,
            "retrieved": retrieved, "license": XW_LICENCE,
            "original_path": name, "contributor": CONTRIB[name]}
        copied += 1

    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(prov, f, indent=1, sort_keys=True)
    print(f"copied {copied} templates")
    for u in unplaced:
        print(f"NEW UPSTREAM (placed in _unsorted/, assign in PLACEMENT "
              f"and re-run): {u}")
    print("next: python scripts/tplgen.py --check "
          "\"templates/imported/**/*.tpl\"")
    print("      python scripts/tpl_index.py")


if __name__ == "__main__":
    main()
