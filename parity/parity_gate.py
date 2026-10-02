#!/usr/bin/env python3
"""Parity gate: the Simplicity libraries a Rust project builds with, against
the node's.

A Simplicity program is checked twice: by the Rust libraries when it is built,
pruned, costed and padded, and by the node when it is mined. If the two ever
differ in a jet, a cost, the decoder or the budget check, a program can pass
every local test and still be refused on the chain, or the reverse. Two
things are compared:

1. The C library. `simplicity-sys` bundles the C sources the Rust side runs;
   the node runs its own copy under `src/simplicity`. Every file of the two
   trees is compared after normalising the versioned symbol prefix the Rust
   crate adds (`rustsimplicity_0_7_` and the `rust_0_7_` allocator hooks). Any
   file that exists on one side only, or that differs, fails the gate unless
   `allowlist.txt` lists it with the exact content hashes of both sides and a
   reason. A listed file that changes on either side fails again, so every
   difference is re-reviewed.
2. The Rust jet table. `simplicity-lang` carries its own table of every
   Elements jet: its name, its cost, which sizes a spend's budget and its
   padding, and its commitment root. It is compared with the node's C table
   (`elements/primitiveJetNode.inc`): the same jets, the same cost and the same
   root for each. Any difference fails, and none can be allow-listed.

    parity/parity_gate.py --node /path/to/Sequentia/src/simplicity
    parity/parity_gate.py --node ... --manifest-path /path/to/other/Cargo.toml

The crate sources are located through `cargo metadata --locked`, so the
versions compared are the ones the project's `Cargo.lock` resolves: this
repository's by default, or any other Rust project's with `--manifest-path`.
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


def locked_packages(manifest):
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", manifest],
        cwd=os.path.dirname(os.path.abspath(manifest))))
    return meta["packages"]


def one_package(packages, name):
    found = [p for p in packages if p["name"] == name]
    if len(found) != 1:
        sys.exit("expected exactly one %s in the lock file, found %s"
                 % (name, [p["version"] for p in found]))
    return found[0]


def crate_sources(packages):
    pkg = one_package(packages, "simplicity-sys")
    path = os.path.join(os.path.dirname(pkg["manifest_path"]), "depend", "simplicity")
    rev_file = os.path.join(os.path.dirname(path), "simplicity-HEAD-revision.txt")
    rev = open(rev_file).read().split()[-1] if os.path.exists(rev_file) else "unknown"
    return pkg["version"], rev, path


def rust_jet_table(text):
    """{name: (cost in milli weight units, commitment root hex)} from
    simplicity-lang's src/jet/init/elements.rs."""
    def block(start):
        b = text[text.index(start):]
        return b[:b.index("\n    }\n")]
    names = dict(re.findall(r'Elements::(\w+) => f\.write_str\("(\w+)"\)', block("impl fmt::Display for Elements")))
    costs = dict(re.findall(r"Elements::(\w+) => Cost::from_milliweight\((\d+)\)", block("fn cost(&self) -> Cost")))
    roots = {v: bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", b)).hex()
             for v, b in re.findall(r"Elements::(\w+) => \[([^\]]*)\]", block("fn cmr(&self) -> Cmr"))}
    table = {}
    for variant, name in names.items():
        table[name] = (int(costs[variant]) if variant in costs else None, roots.get(variant))
    return table


def node_jet_table(text):
    """{name: (cost in milli weight units, commitment root hex)} from the node's
    elements/primitiveJetNode.inc."""
    table = {}
    for body in re.findall(r"\[\w+\] =\s*\{(.*?)\n\}", text, re.S):
        name = re.search(r"\.jet = simplicity_(\w+)", body)
        if not name:
            continue
        cost = re.search(r"\.cost = (\d+)", body)
        words = re.search(r"\.cmr = \{\{([^}]*)\}\}", body)
        root = "".join("%08x" % int(w.strip().rstrip("u"), 16) for w in words.group(1).split(",")) if words else None
        table[name.group(1)] = (int(cost.group(1)) if cost else None, root)
    return table


def compare_jets(rust, node):
    """Every difference between the two jet tables, as text."""
    failures = []
    for name in sorted(set(rust) - set(node)):
        failures.append("jet only in simplicity-lang: %s" % name)
    for name in sorted(set(node) - set(rust)):
        failures.append("jet only in the node: %s" % name)
    for name in sorted(set(rust) & set(node)):
        (rc, rr), (nc, nr) = rust[name], node[name]
        if rc is None or nc is None or rc != nc:
            failures.append("jet %s: cost %s in simplicity-lang, %s in the node" % (name, rc, nc))
        if rr is None or nr is None or rr != nr:
            failures.append("jet %s: root %s in simplicity-lang, %s in the node" % (name, rr, nr))
    return failures


def jet_tables(packages, node_dir):
    pkg = one_package(packages, "simplicity-lang")
    path = os.path.join(os.path.dirname(pkg["manifest_path"]), "src", "jet", "init", "elements.rs")
    rust = rust_jet_table(open(path).read())
    node = node_jet_table(open(os.path.join(node_dir, "elements", "primitiveJetNode.inc")).read())
    return pkg["version"], rust, node


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
    ap.add_argument("--manifest-path", default=os.path.join(ROOT, "Cargo.toml"),
                    help="the Cargo.toml of the project whose Cargo.lock is gated (default: this repository's)")
    a = ap.parse_args()

    manifest = os.path.abspath(a.manifest_path)
    packages = locked_packages(manifest)
    version, rev, crate_dir = crate_sources(packages)
    node_dir = os.path.abspath(a.node)
    if not os.path.isfile(os.path.join(node_dir, "elements", "primitiveJetNode.inc")):
        sys.exit("%s does not look like the node's src/simplicity" % node_dir)
    allowed = load_allowlist(a.allowlist)

    crate_files, node_files = files_under(crate_dir), files_under(node_dir)
    print("project %s\nsimplicity-sys %s (C revision %s)\n  %s\nnode\n  %s" % (
        manifest, version, rev, crate_dir, node_dir))

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

    lang_version, rust, node = jet_tables(packages, node_dir)
    jet_failures = compare_jets(rust, node)
    if not rust or not node:
        jet_failures.append("a jet table is empty: %d jets in simplicity-lang, %d in the node"
                            % (len(rust), len(node)))
    print("simplicity-lang %s jet table: %d jets; node: %d jets; %s" % (
        lang_version, len(rust), len(node),
        "names, costs and roots identical" if not jet_failures else "%d difference(s)" % len(jet_failures)))
    failures += jet_failures
    if failures:
        print("\nPARITY FAILED: %d difference(s)" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("PARITY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
