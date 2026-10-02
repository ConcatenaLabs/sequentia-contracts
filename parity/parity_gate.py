#!/usr/bin/env python3
"""Parity gate: the pinned compiler's C library against the node's.

A Simplicity program is checked twice: by the Rust library when it is built,
pruned and costed, and by the node when it is mined. The Rust side runs the C
sources bundled in `simplicity-sys`; the node runs its own copy under
`src/simplicity`. If the two ever differ in a jet, a cost, the decoder or the
budget check, a program can pass every local test and still be refused on the
chain, or the reverse.

This script compares every file of the two trees after normalising the
versioned symbol prefix the Rust crate adds (`rustsimplicity_0_7_` and the
`rust_0_7_` allocator hooks). Any file that exists on one side only, or that
differs, fails the gate unless `allowlist.txt` lists it with the exact
content hashes of both sides and a reason. A listed file that changes on
either side fails again, so every difference is re-reviewed.

    parity/parity_gate.py --node /path/to/Sequentia/src/simplicity

The `simplicity-sys` sources are located through `cargo metadata`, so the
version compared is the one `Cargo.lock` resolves.
"""
import argparse
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Build artefacts a configured node checkout leaves beside its sources.
ARTEFACT = re.compile(r"(\.o|\.lo|\.la|\.a|\.so|\.dirstamp)$")
ARTEFACT_DIRS = {".deps", ".libs"}

PREFIXES = [
    (re.compile(rb"rustsimplicity_\d+_\d+_"), b"simplicity_"),
    (re.compile(rb"rust_\d+_\d+_(malloc|calloc|free)"), rb"rust_\1"),
]


def crate_sources():
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked"], cwd=ROOT))
    sys_pkgs = [p for p in meta["packages"] if p["name"] == "simplicity-sys"]
    if len(sys_pkgs) != 1:
        sys.exit("expected exactly one simplicity-sys in the lock file, found %s"
                 % [p["version"] for p in sys_pkgs])
    pkg = sys_pkgs[0]
    path = os.path.join(os.path.dirname(pkg["manifest_path"]), "depend", "simplicity")
    rev_file = os.path.join(os.path.dirname(path), "simplicity-HEAD-revision.txt")
    rev = open(rev_file).read().split()[-1] if os.path.exists(rev_file) else "unknown"
    return pkg["version"], rev, path


def files_under(top):
    out = set()
    for d, dirs, names in os.walk(top):
        dirs[:] = [x for x in dirs if x not in ARTEFACT_DIRS]
        for n in names:
            if ARTEFACT.search(n):
                continue
            out.add(os.path.relpath(os.path.join(d, n), top))
    return out


def normalise(data):
    for pat, rep in PREFIXES:
        data = pat.sub(rep, data)
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_allowlist(path):
    allowed = {}
    with open(path) as f:
        for ln in f:
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            rel, crate_hash, node_hash = ln.split()
            allowed[rel] = (crate_hash, node_hash)
    return allowed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", required=True,
                    help="the node's src/simplicity directory")
    ap.add_argument("--allowlist", default=os.path.join(HERE, "allowlist.txt"))
    ap.add_argument("--show-hashes", action="store_true",
                    help="print both hashes of every differing file (to review an allow-list entry)")
    a = ap.parse_args()

    version, rev, crate_dir = crate_sources()
    node_dir = os.path.abspath(a.node)
    if not os.path.isfile(os.path.join(node_dir, "elements", "primitiveJetNode.inc")):
        sys.exit("%s does not look like the node's src/simplicity" % node_dir)
    allowed = load_allowlist(a.allowlist)

    crate_files, node_files = files_under(crate_dir), files_under(node_dir)
    print("simplicity-sys %s (C revision %s)\n  %s\nnode\n  %s" % (version, rev, crate_dir, node_dir))

    failures, identical, allowed_hits = [], 0, []
    for rel in sorted(crate_files - node_files):
        failures.append("only in simplicity-sys: %s" % rel)
    for rel in sorted(node_files - crate_files):
        failures.append("only in the node: %s" % rel)
    for rel in sorted(crate_files & node_files):
        c = normalise(open(os.path.join(crate_dir, rel), "rb").read())
        n = open(os.path.join(node_dir, rel), "rb").read()
        if c == n:
            identical += 1
            continue
        hc, hn = sha(c), sha(n)
        if a.show_hashes:
            print("  %s %s %s" % (rel, hc, hn))
        if allowed.get(rel) == (hc, hn):
            allowed_hits.append(rel)
            continue
        diff = list(difflib.unified_diff(
            n.decode(errors="replace").splitlines(), c.decode(errors="replace").splitlines(),
            "node/" + rel, "simplicity-sys/" + rel, lineterm="", n=1))
        why = "listed, but its content changed" if rel in allowed else "differs"
        failures.append("%s %s (%d diff lines):\n    %s" % (
            rel, why, len(diff), "\n    ".join(diff[:24])))

    for rel in sorted(set(allowed) - set(allowed_hits)):
        if rel in crate_files and rel in node_files and rel not in [f.split()[0] for f in failures]:
            failures.append("allow-list entry no longer needed (files are identical): %s" % rel)

    total = len(crate_files | node_files)
    print("compared %d files: %d identical, %d allow-listed%s" % (
        total, identical, len(allowed_hits),
        "" if not allowed_hits else " (" + ", ".join(allowed_hits) + ")"))
    if failures:
        print("\nPARITY FAILED: %d difference(s)" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("PARITY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
