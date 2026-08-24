#!/usr/bin/env python3
"""Find the conventions that govern an artefact before authoring it.

If a spec, pattern, or parser might ever be published -- upstreamed to a format
gallery, committed to a team repo, handed to a colleague -- the conventions
that govern it are an input to writing it, not a cleanup step afterwards.
Kaitai's KSY style guide mandates a key order and requires an `-orig-id` when
transcribing from existing software; discovering that after writing 400 lines
means rewriting them.

This looks in three places, in order of authority:

  1. The target repository's own contribution documents.
  2. The user's standing conventions, for their own repos or for repos that
     have none of their own.
  3. Known upstream conventions for the galleries this skill points at.

It reads nothing but the local filesystem and knows nothing about git remotes,
pull requests, or issue trackers -- submission mechanics are deliberately out
of scope. The question here is only what shape the artefact should be in.

Usage:
  house_style.py .                          # scan a repo for conventions
  house_style.py ~/src/myrepo --user-config ~/.config/format-conventions.md
  house_style.py --target kaitai            # upstream conventions for a gallery
  house_style.py --list-targets
"""
import argparse
import os
import sys

# Files that carry authoring conventions, and what each governs. Ordered by how
# strongly it binds.
CONVENTION_FILES = [
    ("CONTRIBUTING.md", "contribution requirements", 1),
    ("CONTRIBUTING.rst", "contribution requirements", 1),
    ("CONTRIBUTING", "contribution requirements", 1),
    (".github/CONTRIBUTING.md", "contribution requirements", 1),
    ("docs/CONTRIBUTING.md", "contribution requirements", 1),
    ("STYLE.md", "style guide", 1),
    ("STYLEGUIDE.md", "style guide", 1),
    ("docs/style.md", "style guide", 1),
    ("docs/STYLE.md", "style guide", 1),
    ("CONVENTIONS.md", "project conventions", 1),
    ("AGENTS.md", "instructions for automated contributors", 1),
    ("CLAUDE.md", "instructions for automated contributors", 1),
    (".github/copilot-instructions.md", "instructions for automated contributors", 2),
    ("docs/DEVELOPMENT.md", "development practices", 2),
    ("DEVELOPMENT.md", "development practices", 2),
    ("HACKING.md", "development practices", 2),
    (".github/PULL_REQUEST_TEMPLATE.md", "what a change must state", 2),
    (".github/pull_request_template.md", "what a change must state", 2),
    (".github/ISSUE_TEMPLATE", "how findings are reported", 3),
    ("CODE_OF_CONDUCT.md", "conduct expectations", 3),
    ("LICENSE", "licence the artefact must be compatible with", 2),
    ("LICENSE.md", "licence the artefact must be compatible with", 2),
    ("LICENSE.txt", "licence the artefact must be compatible with", 2),
    ("COPYING", "licence the artefact must be compatible with", 2),
    (".editorconfig", "whitespace and line endings", 3),
    (".markdownlint.json", "markdown linting rules", 3),
    (".markdownlint.yaml", "markdown linting rules", 3),
    (".markdownlintrc", "markdown linting rules", 3),
    (".pre-commit-config.yaml", "checks a change must pass", 2),
    (".yamllint", "YAML linting rules", 3),
    ("setup.cfg", "may carry lint/format config", 3),
    ("pyproject.toml", "may carry lint/format config", 3),
    ("docs/adr", "architecture decision records -- how decisions get recorded", 3),
    ("doc/adr", "architecture decision records -- how decisions get recorded", 3),
]

# Directories whose presence implies a house pattern worth matching.
PATTERN_DIRS = [
    ("documentation", "existing format documents -- match their structure"),
    ("docs", "existing documentation -- match its structure"),
    ("formats", "existing format specs -- match their layout"),
    ("patterns", "existing patterns -- match their layout"),
    ("specs", "existing specifications -- match their layout"),
    ("templates", "existing templates -- match their layout"),
]

# Known upstream conventions for the galleries this skill sends people to.
# These govern authoring, not submission.
TARGETS = {
    "kaitai": {
        "name": "Kaitai Struct format gallery",
        "repo": "https://github.com/kaitai-io/kaitai_struct_formats",
        "docs": [
            ("KSY Style Guide", "https://doc.kaitai.io/ksy_style_guide.html"),
            ("KSY user guide", "https://doc.kaitai.io/user_guide.html"),
        ],
        "notes": [
            "The style guide is normative and uses RFC 2119 keywords -- it says "
            "attribute keys MUST appear in a specified order, so key ordering is "
            "not a matter of taste.",
            "Integer and string types SHOULD carry an explicit be/le suffix "
            "rather than relying on a default, because a spec has to describe "
            "the byte layout unambiguously on its own.",
            "Use -orig-id to record the original identifier when transcribing a "
            "structure from existing software or an official spec. For "
            "reverse-engineered work this is the traceability link back to the "
            "producing code.",
            "doc SHOULD NOT restate the id. A doc string that adds nothing is "
            "noise; omit it.",
            "Populate meta/xref with registry identifiers (pronom, loc, "
            "wikidata, mime, rfc, iso) where they exist.",
            "Files are per-file licensed; gallery entries commonly use CC0-1.0.",
        ],
    },
    "imhex": {
        "name": "ImHex pattern database",
        "repo": "https://github.com/WerWolv/ImHex-Patterns",
        "docs": [
            ("Pattern language docs", "https://docs.werwolv.net/pattern-language"),
        ],
        "notes": [
            "Patterns, includes, and magic files live in separate trees -- put "
            "each artefact in the right one.",
            "Read several existing patterns in the same category before writing; "
            "the house layout is conveyed by example rather than by a style doc.",
            "If the work also produced signatures, the magic files are a "
            "separate and often more valuable contribution than the pattern.",
        ],
    },
    "libyal": {
        "name": "libyal / dtformats",
        "repo": "https://github.com/libyal/dtformats",
        "docs": [
            ("Existing format documents",
             "https://github.com/libyal/dtformats/tree/main/documentation"),
        ],
        "notes": [
            "Documents are asciidoc and follow a consistent skeleton: Summary, "
            "Document information, License, Revision history, Overview with a "
            "characteristics table, Test versions, numbered structure sections, "
            "Notes, then Appendix A references.",
            "Structure tables are Offset | Size | Value | Description, with "
            "byte.bit offsets for sub-byte fields and arithmetic shown for "
            "arrays (52 x 8 = 208).",
            "Bold marks inferred or unknown material, inline with the field.",
            "Documentation is GNU FDL 1.3 -- check compatibility before reusing "
            "text in a differently licensed deliverable.",
            "See references/documentation.md, which adopts this structure.",
        ],
    },
    "010": {
        "name": "010 Editor template repository",
        "repo": "https://www.sweetscape.com/010editor/repository/templates/",
        "docs": [],
        "notes": [
            "Templates are submitted through Sweetscape rather than a public VCS.",
            "Existing .bt files carry a standard header comment block with name, "
            "author, revision history, and purpose -- match it.",
        ],
    },
    "plaso": {
        "name": "plaso / log2timeline",
        "repo": "https://github.com/log2timeline/plaso",
        "docs": [
            ("Developer guide",
             "https://plaso.readthedocs.io/en/latest/sources/developer/"),
        ],
        "notes": [
            "Parsers are expected to come with test data and tests; the project "
            "has an explicit style guide and review process.",
            "A parser contribution is a much larger commitment than a format "
            "document -- consider contributing the format documentation "
            "upstream to libyal and the parser separately.",
        ],
    },
    "velociraptor": {
        "name": "Velociraptor artifact exchange",
        "repo": "https://github.com/Velocidex/velociraptor-docs",
        "docs": [
            ("Artifact exchange", "https://docs.velociraptor.app/exchange/"),
        ],
        "notes": [
            "Artefacts are YAML with required metadata fields; read several "
            "exchange artefacts in the same category first.",
        ],
    },
}


def find_conventions(root):
    found, missing = [], []
    for rel, governs, rank in CONVENTION_FILES:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            kind = "dir" if os.path.isdir(path) else "file"
            size = 0 if kind == "dir" else os.path.getsize(path)
            found.append((rank, rel, governs, kind, size))
        elif rank == 1:
            missing.append(rel)
    found.sort()
    return found, missing


def find_patterns(root):
    hits = []
    for rel, why in PATTERN_DIRS:
        path = os.path.join(root, rel)
        if os.path.isdir(path):
            try:
                n = sum(1 for _ in os.scandir(path))
            except OSError:
                n = 0
            if n:
                hits.append((rel, why, n))
    return hits


def show_target(key):
    t = TARGETS[key]
    print(f"{t['name']}")
    print(f"  {t['repo']}")
    for label, url in t["docs"]:
        print(f"  {label}: {url}")
    print()
    for note in t["notes"]:
        # wrap at ~76 for terminal readability
        words, line = note.split(), "  - "
        for w in words:
            if len(line) + len(w) + 1 > 78:
                print(line)
                line = "    " + w
            else:
                line += ("" if line.endswith("- ") else " ") + w
        print(line)
    print()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?",
                    help="repository or directory the artefact will land in")
    ap.add_argument("--user-config",
                    help="your own standing conventions file, used for your own "
                         "repos and for repos that have none")
    ap.add_argument("--target", choices=sorted(TARGETS),
                    help="show upstream authoring conventions for a gallery")
    ap.add_argument("--list-targets", action="store_true")
    args = ap.parse_args()

    if args.list_targets:
        print("known upstream targets\n")
        for k, t in sorted(TARGETS.items()):
            print(f"  {k:<14} {t['name']}")
        print("\nShow one with --target <key>.")
        return

    if args.target:
        show_target(args.target)
        if not args.path:
            return
        print("-" * 78 + "\n")

    if not args.path and not args.user_config:
        ap.error("give a path to scan, or --target, or --list-targets")

    if args.path:
        root = os.path.abspath(args.path)
        if not os.path.isdir(root):
            raise SystemExit(f"not a directory: {root}")
        print(f"scanning  {root}\n")

        found, missing = find_conventions(root)
        if found:
            print(f"conventions found ({len(found)})")
            for rank, rel, governs, kind, size in found:
                extra = "" if kind == "dir" else f"  ({size} bytes)"
                print(f"  [{rank}] {rel}{extra}")
                print(f"      governs: {governs}")
            print("\nRead the rank-1 documents before writing anything. They are "
                  "an input to\nauthoring, not a checklist for afterwards -- a "
                  "mandated key order or a\nrequired metadata field is far "
                  "cheaper to honour up front than to retrofit.")
        else:
            print("no contribution or style documents found")

        pats = find_patterns(root)
        if pats:
            print(f"\nexisting work to match ({len(pats)} location(s))")
            for rel, why, n in pats:
                print(f"  {rel}/  ({n} entries)")
                print(f"      {why}")
            print("\nWhere a repo has no written style guide, its existing "
                  "artefacts are the\nstyle guide. Read two or three in the same "
                  "category and match them.")

        if not found:
            print("\nWith nothing written down, fall back in this order:")
            print("  1. Match the shape of the artefacts already in the repo "
                  "(above).")
            print("  2. Apply your own standing conventions (--user-config).")
            print("  3. Apply the upstream convention for the artefact type "
                  "(--target).")
            print("  4. Failing all of those, use this skill's defaults: the "
                  "libyal\n     structure for prose specs and the KSY style "
                  "guide for .ksy files.")
            print("\nState in the deliverable which of these you followed, so a "
                  "maintainer\ncan tell a deliberate choice from an accident.")

    if args.user_config:
        print()
        if os.path.exists(args.user_config):
            size = os.path.getsize(args.user_config)
            print(f"your standing conventions: {args.user_config} ({size} bytes)")
            print("  Applies to your own repos, and to repos with no conventions "
                  "of their own.\n  A target repo's own documents outrank it.")
        else:
            print(f"your standing conventions: {args.user_config} -- NOT FOUND")
            print("  Worth writing one if you produce format documentation "
                  "regularly: preferred\n  spec structure, licence, how you mark "
                  "uncertainty, whether specs ship with\n  a .ksy. It makes your "
                  "output consistent across repos that have no rules\n  of their "
                  "own.")

    print("\nSubmission mechanics -- forking, pull requests, issue etiquette -- "
          "are out of\nscope here and are the repo's business, not this tool's. "
          "The only question\nthis answers is what shape the artefact should be "
          "in before anyone sees it.")


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
