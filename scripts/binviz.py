#!/usr/bin/env python3
"""Render a binary as an image, because the eye catches what statistics miss.

profile.py measures periodicity; a picture shows it. Region boundaries, record
alignment, embedded compressed blobs, string tables, padding, and repeating
structure are often obvious at a glance and invisible in a summary statistic.
This is the cheapest high-yield step on a genuinely unknown file.

Four views:
  bytemap   file laid out in rows, coloured by byte class -- shows regions,
            alignment, and where structure gives way to noise
  digraph   256x256 heatmap of consecutive byte pairs -- an encoding
            fingerprint; text, UTF-16, code, and compressed data look nothing
            alike
  hilbert   space-filling curve, so nearby pixels are nearby offsets at every
            scale -- best for locating region boundaries in a large file
  entropy   windowed entropy strip -- compression and encryption stand out

PNG is written directly with zlib, so there are no dependencies.

Usage:
  binviz.py sample.bin -o out/            # all views
  binviz.py sample.bin --view bytemap --width 8192 -o out/
  binviz.py sample.bin --view digraph -o out/
"""
import argparse
import collections
import math
import os
import struct
import sys
import zlib

# Byte-class palette, in the tradition of binvis-style tools: structure and
# text should be distinguishable from noise at a glance.
#   0x00        near-black blue    padding, zero fill
#   printable   green              text, identifiers
#   whitespace  teal               formatted text
#   low control orange             packed binary, small integers
#   high        red                high-entropy or non-ASCII
#   0xFF        white              fill, unallocated markers
def byte_color(b):
    if b == 0x00:
        return (16, 16, 48)
    if b == 0xFF:
        return (245, 245, 245)
    if b in (9, 10, 13):
        return (64, 190, 190)
    if 0x20 <= b < 0x7F:
        return (70, 200, 110)
    if b < 0x20:
        return (230, 150, 60)
    return (215, 70, 70)


def png_write(path, width, height, rgb_rows):
    """Minimal PNG encoder: 8-bit RGB, filter type 0."""
    raw = bytearray()
    for row in rgb_rows:
        raw.append(0)
        raw.extend(row)
    comp = zlib.compress(bytes(raw), 9)

    def chunk(tag, payload):
        return (struct.pack(">I", len(payload)) + tag + payload +
                struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", ihdr))
        fh.write(chunk(b"IDAT", comp))
        fh.write(chunk(b"IEND", b""))


def view_bytemap(data, width, scale):
    height = (len(data) + width - 1) // width
    rows = []
    for y in range(height):
        row = bytearray()
        chunk = data[y * width:(y + 1) * width]
        for x in range(width):
            if x < len(chunk):
                r, g, b = byte_color(chunk[x])
            else:
                r, g, b = (0, 0, 0)
            row += bytes((r, g, b))
        rows.append(row)
    if scale > 1:
        rows = [r for row in rows for r in [row] * scale]
        rows = [bytes(b for i in range(0, len(row), 3)
                      for b in row[i:i + 3] * scale) for row in rows]
        width *= scale
    return width, len(rows), rows


def view_digraph(data, sample=1 << 22):
    """256x256 log-scaled heatmap of (byte[i], byte[i+1])."""
    grid = [[0] * 256 for _ in range(256)]
    buf = data[:sample]
    for i in range(len(buf) - 1):
        grid[buf[i]][buf[i + 1]] += 1
    peak = max(max(r) for r in grid) or 1
    lp = math.log1p(peak)
    rows = []
    for y in range(256):
        row = bytearray()
        for x in range(256):
            v = grid[y][x]
            t = math.log1p(v) / lp if v else 0.0
            # dark blue -> cyan -> yellow -> white
            if t == 0:
                r = g = b = 12
            elif t < 0.4:
                k = t / 0.4
                r, g, b = int(20 * k), int(80 + 120 * k), int(120 + 100 * k)
            elif t < 0.75:
                k = (t - 0.4) / 0.35
                r, g, b = int(20 + 215 * k), int(200 + 40 * k), int(220 - 160 * k)
            else:
                k = (t - 0.75) / 0.25
                r, g, b = 235 + int(20 * k), 240 + int(15 * k), int(60 + 195 * k)
            row += bytes((min(r, 255), min(g, 255), min(b, 255)))
        rows.append(row)
    return 256, 256, rows


def hilbert_d2xy(order, d):
    x = y = 0
    t = d
    s = 1
    while s < order:
        rx = 1 & (t // 2)
        ry = 1 & (t ^ rx)
        if ry == 0:
            if rx == 1:
                x, y = s - 1 - x, s - 1 - y
            x, y = y, x
        x += s * rx
        y += s * ry
        t //= 4
        s *= 2
    return x, y


def view_hilbert(data, order):
    cells = order * order
    per = max(1, len(data) // cells)
    grid = [[(0, 0, 0)] * order for _ in range(order)]
    for d in range(min(cells, (len(data) + per - 1) // per)):
        chunk = data[d * per:(d + 1) * per]
        if not chunk:
            break
        if len(chunk) == 1:
            col = byte_color(chunk[0])
        else:
            acc = [0, 0, 0]
            step = max(1, len(chunk) // 16)
            n = 0
            for i in range(0, len(chunk), step):
                c = byte_color(chunk[i])
                acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]
                n += 1
            col = (acc[0] // n, acc[1] // n, acc[2] // n)
        x, y = hilbert_d2xy(order, d)
        grid[y][x] = col
    rows = [bytearray(b for px in row for b in px) for row in grid]
    return order, order, rows


def view_entropy(data, window, height):
    cols = []
    for off in range(0, len(data), window):
        chunk = data[off:off + window]
        if len(chunk) < 16:
            break
        c = collections.Counter(chunk)
        n = len(chunk)
        e = -sum((v / n) * math.log2(v / n) for v in c.values())
        cols.append(e / 8.0)
    if not cols:
        raise SystemExit("file too small for an entropy strip; lower --window")
    rows = []
    for y in range(height):
        row = bytearray()
        for t in cols:
            # blue (low) -> green -> yellow -> red (high)
            if t < 0.5:
                k = t / 0.5
                r, g, b = int(30 * k), int(60 + 160 * k), int(200 - 80 * k)
            else:
                k = (t - 0.5) / 0.5
                r, g, b = int(30 + 210 * k), int(220 - 140 * k), int(120 - 100 * k)
            row += bytes((min(r, 255), min(g, 255), max(b, 0)))
        rows.append(row)
    return len(cols), height, rows


READINGS = {
    "bytemap": [
        "Horizontal banding at a constant pitch is your record or page stride;"
        " measure it and check against profile.py.",
        "A green block is a string table. Orange is packed binary. Solid dark"
        " blue is zero padding or slack.",
        "A red region with no visible texture is compressed or encrypted --"
        " run crypto_scan.py on it.",
        "A vertical edge partway across every row means a fixed-size header"
        " followed by variable data.",
    ],
    "digraph": [
        "A tight cluster in the printable range means text; a checkerboard with"
        " a strong column at 0x00 means UTF-16LE.",
        "A diffuse uniform square means compression or encryption -- there is"
        " no structure left to find.",
        "Sharp lines and repeated points mean fixed opcodes or repeated"
        " delimiters.",
        "Compare two files' digraphs to spot an encoding change without"
        " parsing either.",
    ],
    "hilbert": [
        "Region boundaries stay compact at every scale, which is what the curve"
        " is for -- a blob of one colour is one contiguous region.",
        "Use it on large files where a bytemap would be too tall to read.",
        "Note the offset of a boundary by counting cells, then confirm exactly"
        " with profile.py or a hex editor.",
    ],
    "entropy": [
        "Flat high (red) regions are compressed or encrypted payloads.",
        "Periodic dips are headers interrupting payload at regular intervals --"
        " the period is the stride.",
        "A sharp step marks a container boundary worth carving at.",
    ],
}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("-o", "--outdir", default=".", help="where to write PNGs")
    ap.add_argument("--view", action="append", default=[],
                    choices=["bytemap", "digraph", "hilbert", "entropy"],
                    help="repeatable; default is all four")
    ap.add_argument("--width", type=int,
                    help="bytemap row width; defaults to the detected stride "
                         "or 512")
    ap.add_argument("--stride", type=int,
                    help="known record/page size -- sets bytemap width so each "
                         "row is one record and fields line up in columns")
    ap.add_argument("--scale", type=int, default=1, help="bytemap pixel scale")
    ap.add_argument("--order", type=int, default=512,
                    help="hilbert edge length, power of two")
    ap.add_argument("--window", type=int, default=256,
                    help="entropy window in bytes")
    ap.add_argument("--height", type=int, default=64, help="entropy strip height")
    ap.add_argument("--max-bytes", type=int, default=64 << 20)
    args = ap.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read(args.max_bytes)
    if not data:
        raise SystemExit("empty file")
    os.makedirs(args.outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(args.file))[0]
    views = args.view or ["bytemap", "digraph", "hilbert", "entropy"]

    width = args.width or args.stride or 512
    if args.stride:
        print(f"bytemap width set to stride {args.stride}: each row is one "
              f"record, so\nconstant fields appear as vertical stripes and "
              f"variable ones as noise columns.\n")

    made = []
    for v in views:
        if v == "bytemap":
            w, h, rows = view_bytemap(data, width, max(1, args.scale))
        elif v == "digraph":
            w, h, rows = view_digraph(data)
        elif v == "hilbert":
            order = 1 << (args.order.bit_length() - 1)
            w, h, rows = view_hilbert(data, order)
        else:
            w, h, rows = view_entropy(data, args.window, args.height)
        path = os.path.join(args.outdir, f"{base}_{v}.png")
        png_write(path, w, h, rows)
        made.append((v, path, w, h))

    for v, path, w, h in made:
        print(f"{path}  ({w}x{h})")
        for line in READINGS[v]:
            words, cur = line.split(), "    - "
            for word in words:
                if len(cur) + len(word) + 1 > 78:
                    print(cur)
                    cur = "      " + word
                else:
                    cur += ("" if cur.endswith("- ") else " ") + word
            print(cur)
        print()

    print("These are for orientation, not measurement. Anything you see here "
          "gets\nconfirmed numerically before it enters the ledger -- an eye "
          "for pattern is\nexcellent at generating hypotheses and unreliable at "
          "settling them.")


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
