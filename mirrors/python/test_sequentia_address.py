"""Checks the Python mirror against every template's golden vectors, and against
the refusals every reader must make (mirrors/fixtures/refusals.json)."""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sequentia_address as sa  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
FIXTURES = os.path.join(ROOT, "mirrors", "fixtures")


def descriptor_dirs():
    """Every template, and every fixture that is a descriptor."""
    paths = glob.glob(os.path.join(ROOT, "templates", "*", "descriptor.json"))
    paths += glob.glob(os.path.join(FIXTURES, "*", "descriptor.json"))
    return sorted(os.path.dirname(p) for p in paths)


def read(path):
    with open(path) as f:
        return f.read()


class Vectors(unittest.TestCase):
    def test_every_template_and_fixture(self):
        dirs = descriptor_dirs()
        self.assertTrue(any("one_key_exit" in d for d in dirs))
        for path in dirs:
            d = sa.loads(read(os.path.join(path, "descriptor.json")))
            v = json.loads(read(os.path.join(path, "vectors.json")))
            self.assertEqual(sa.template_hash(d["template"]), d["template_hash"], path)
            self.assertEqual(v["template_hash"], d["template_hash"], path)
            self.assertEqual(v["vectors"], d["descriptor"], path)
            if d["descriptor"] == 1:
                self.assertEqual(v["cmr"], d["template"]["program"]["cmr"], path)
            for case in v["addresses"]:
                got = sa.derive(d, case["params"], case.get("slots", {}))
                want = {k: case[k] for k in got}
                self.assertEqual(set(case) - set(got), {"name", "params"} | ({"slots"} if "slots" in case else set()))
                self.assertEqual(got, want, "%s: %s" % (path, case["name"]))

    def test_bech32m_matches_bip350(self):
        # BIP350's valid segwit v1 example.
        program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertEqual(sa.segwit_v1_address("bc", program),
                         "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")

    def test_a_version_1_template_is_its_version_2_tree(self):
        # The fixture is one_key written as version 2: the same addresses.
        v1 = json.loads(read(os.path.join(ROOT, "templates", "one_key", "vectors.json")))["addresses"]
        v2 = json.loads(read(os.path.join(FIXTURES, "one_key_as_v2", "vectors.json")))["addresses"]
        self.assertEqual(len(v1), len(v2))
        for a, b in zip(v1, v2):
            self.assertEqual(a["params"], b["params"])
            self.assertEqual(a["address"], b["address"])
            self.assertEqual(a["script_pubkey"], b["script_pubkey"])
            self.assertEqual(a["data_leaf"], b["leaves"]["params"]["hash"])
            self.assertEqual(a["program_leaf"], b["leaves"]["program"]["hash"])
            self.assertEqual(a["param_bytes"], b["leaves"]["params"]["data"])


def edit(doc, op):
    *path, last = op["at"]
    target = doc
    for k in path:
        target = target[k]
    if "set" in op:
        target[last] = op["set"]
    elif "delete" in op:
        del target[last]
    elif "append" in op:
        target[last].append(op["append"])
    elif "suffix" in op:
        target[last] = target[last] + op["suffix"]
    else:
        raise AssertionError("unknown edit %r" % op)


def refusal_text(case):
    """The descriptor text a refusal case reads."""
    text = read(os.path.join(ROOT, case["base"], "descriptor.json"))
    if "text" in case:
        for old, new in case["text"]:
            assert old in text, (case["name"], old)
            text = text.replace(old, new, 1)
        return text
    d = json.loads(text)
    for op in case["edit"]:
        edit(d, op)
    if case.get("reseal", True):
        d["template_hash"] = sa.template_hash(d["template"])
    return json.dumps(d, indent=2)


class Refusals(unittest.TestCase):
    def test_every_refusal(self):
        cases = json.loads(read(os.path.join(FIXTURES, "refusals.json")))["cases"]
        self.assertGreater(len(cases), 50)
        for case in cases:
            text = refusal_text(case)
            with self.subTest(case["name"]):
                if case.get("accept"):
                    sa.loads(text)
                    continue
                if "derive" in case:
                    d = sa.loads(text)
                    with self.assertRaises(ValueError) as e:
                        sa.derive(d, case["derive"]["params"], case["derive"]["slots"])
                else:
                    with self.assertRaises(ValueError) as e:
                        sa.loads(text)
                self.assertIn(case["expect"], str(e.exception), case["name"])

    def test_the_unedited_bases_are_read(self):
        for case in json.loads(read(os.path.join(FIXTURES, "refusals.json")))["cases"]:
            sa.loads(read(os.path.join(ROOT, case["base"], "descriptor.json")))


def one_key():
    return json.loads(read(os.path.join(ROOT, "templates", "one_key", "descriptor.json")))


def resealed(d, change):
    d = json.loads(json.dumps(d))
    change(d["template"])
    d["template_hash"] = sa.template_hash(d["template"])
    return d


X_OF_G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PK = {"PK": X_OF_G}


class VersionOne(unittest.TestCase):
    def refused(self, d, words):
        with self.assertRaises(ValueError) as e:
            sa.derive(d, PK)
        self.assertIn(words, str(e.exception))

    def test_a_key_path_must_be_declared(self):
        d = one_key()
        self.refused(resealed(d, lambda t: t.update(internal_key=X_OF_G)), "no key path")

        def declare(t):
            t.update(internal_key=X_OF_G, key_path="cooperative")
            t["paths"].append({"name": "cooperative", "who": "the holder of the internal key",
                               "effect": "Spends the output into any transaction that key signs."})
        sa.derive(resealed(d, declare), PK)
        self.refused(resealed(d, lambda t: t.update(internal_key=X_OF_G, key_path="cooperative")), "paths")
        self.refused(resealed(d, lambda t: t.update(key_path="spend")), "NUMS")

    def test_integers_of_2_pow_53_or_more_are_refused(self):
        d = one_key()
        sa.derive(resealed(d, lambda t: t.update(version=2**53 - 1)), PK)
        self.refused(resealed(d, lambda t: t.update(version=2**53)), "2^53")

    def test_hex_with_trailing_junk_is_refused(self):
        d = one_key()
        for bad in (X_OF_G + "zz", X_OF_G + "0", X_OF_G.upper(), X_OF_G[:-2]):
            with self.assertRaises(ValueError):
                sa.derive(d, {"PK": bad})


def unsorted_root(node, leaves):
    """The Merkle root a mirror that does not sort a branch's two hashes would get."""
    if node[0] == "branch":
        return sa.tagged("TapBranch/elements", unsorted_root(node[1], leaves) + unsorted_root(node[2], leaves))
    return bytes.fromhex(leaves[node[1]]["hash"])


class TheVectorsCatchMistakes(unittest.TestCase):
    def test_an_unsorted_branch(self):
        # A mirror that hashes a branch's children in tree order, without
        # sorting, gets some vectors wrong in every template.
        for path in descriptor_dirs():
            d = sa.loads(read(os.path.join(path, "descriptor.json")))
            if d["descriptor"] != 2:
                continue
            tree = sa.model(d)["tree"]
            cases = json.loads(read(os.path.join(path, "vectors.json")))["addresses"]
            wrong = sum(unsorted_root(tree, c["leaves"]).hex() != c["merkle_root"] for c in cases)
            self.assertGreaterEqual(wrong, 2, path)

    def test_a_dropped_parity(self):
        # A mirror that leaves the output key's parity out of a control block
        # gets every vector with an odd output key wrong.
        for path in descriptor_dirs():
            d = sa.loads(read(os.path.join(path, "descriptor.json")))
            if d["descriptor"] != 2:
                continue
            cases = json.loads(read(os.path.join(path, "vectors.json")))["addresses"]
            odd = [c for c in cases if c["output_key_parity"] == 1]
            self.assertTrue(odd, path)
            for c in odd:
                for leaf in c["leaves"].values():
                    if "control_block" in leaf:
                        self.assertEqual(int(leaf["control_block"][:2], 16) & 1, 1)

    def test_a_script_number_is_minimal(self):
        self.assertEqual(sa.script_num(0), b"\x00")
        self.assertEqual(sa.script_num(16), b"\x60")
        self.assertEqual(sa.script_num(17), b"\x01\x11")
        self.assertEqual(sa.script_num(0x80), b"\x02\x80\x00")
        self.assertEqual(sa.script_num(0x400002), b"\x03\x02\x00\x40")


if __name__ == "__main__":
    unittest.main()
