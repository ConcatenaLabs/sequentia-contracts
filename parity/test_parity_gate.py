#!/usr/bin/env python3
"""The jet-table comparison of the parity gate fails on any difference.

    python3 parity/test_parity_gate.py /path/to/Sequentia/src/simplicity

Reads the simplicity-lang table this repository's Cargo.lock resolves and the
node's table, checks they agree, then changes one jet's cost, one jet's root,
removes one jet and renames one, and checks that each is reported."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parity_gate as g  # noqa: E402

NODE = None


def tables():
    packages = g.locked_packages(os.path.join(g.ROOT, "Cargo.toml"))
    pkg = g.one_package(packages, "simplicity-lang")
    path = os.path.join(os.path.dirname(pkg["manifest_path"]), "src", "jet", "init", "elements.rs")
    rust_text = open(path).read()
    node_text = open(os.path.join(NODE, "elements", "primitiveJetNode.inc")).read()
    return rust_text, node_text


class JetTables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rust_text, cls.node_text = tables()
        cls.rust = g.rust_jet_table(cls.rust_text)
        cls.node = g.node_jet_table(cls.node_text)

    def test_the_tables_agree_and_are_complete(self):
        self.assertGreater(len(self.rust), 400)
        self.assertEqual(g.compare_jets(self.rust, self.node), [])
        for name, (cost, root) in self.rust.items():
            self.assertIsNotNone(cost, name)
            self.assertEqual(len(root or ""), 64, name)

    def test_a_cost_difference_fails(self):
        text = re.sub(r"(simplicity_add_32\n, \.cmr = [^\n]*\n[^\n]*\n[^\n]*\n, \.cost = )(\d+)",
                      lambda m: m.group(1) + str(int(m.group(2)) + 1), self.node_text, count=1)
        f = g.compare_jets(self.rust, g.node_jet_table(text))
        self.assertEqual(len(f), 1, f)
        self.assertIn("jet add_32: cost", f[0])

    def test_a_root_difference_fails(self):
        text = self.node_text.replace("0x3d767446u", "0x3d767447u", 1)
        f = g.compare_jets(self.rust, g.node_jet_table(text))
        self.assertEqual(f, ["jet add_32: root %s in simplicity-lang, %s in the node"
                             % (self.rust["add_32"][1], "3d767447" + self.rust["add_32"][1][8:])])

    def test_a_missing_or_renamed_jet_fails(self):
        node = dict(self.node)
        del node["lbtc_asset"]
        self.assertEqual(g.compare_jets(self.rust, node), ["jet only in simplicity-lang: lbtc_asset"])
        rust = dict(self.rust)
        rust["check_lock_distance"] = rust.pop("broken_do_not_use_check_lock_distance")
        self.assertEqual(sorted(g.compare_jets(rust, self.node)),
                         ["jet only in simplicity-lang: check_lock_distance",
                          "jet only in the node: broken_do_not_use_check_lock_distance"])

    def test_a_cost_missing_from_the_rust_table_fails(self):
        text = self.rust_text.replace("Elements::Add32 => Cost::from_milliweight(", "Elements::Add32x => Cost::from_milliweight(", 1)
        f = g.compare_jets(g.rust_jet_table(text), self.node)
        self.assertEqual(f, ["jet add_32: cost None in simplicity-lang, %d in the node" % self.node["add_32"][0]])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    NODE = sys.argv.pop(1)
    unittest.main()
