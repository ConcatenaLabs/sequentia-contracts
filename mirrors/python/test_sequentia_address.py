"""Checks the Python mirror against every template's golden vectors."""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sequentia_address as sa  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


class Vectors(unittest.TestCase):
    def test_every_template(self):
        dirs = sorted(glob.glob(os.path.join(ROOT, "templates", "*", "descriptor.json")))
        self.assertTrue(dirs)
        for path in dirs:
            with open(path) as f:
                d = sa.loads(f.read())
            with open(os.path.join(os.path.dirname(path), "vectors.json")) as f:
                v = json.load(f)
            self.assertEqual(sa.template_hash(d["template"]), d["template_hash"], path)
            self.assertEqual(v["template_hash"], d["template_hash"], path)
            self.assertEqual(v["cmr"], d["template"]["program"]["cmr"], path)
            for case in v["addresses"]:
                got = sa.derive(d, case["params"])
                want = {k: case[k] for k in got}
                self.assertEqual(got, want, "%s: %s" % (path, case["name"]))

    def test_bech32m_matches_bip350(self):
        # BIP350's valid segwit v1 example.
        program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertEqual(sa.segwit_v1_address("bc", program),
                         "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")


def one_key():
    with open(os.path.join(ROOT, "templates", "one_key", "descriptor.json")) as f:
        return json.load(f)


def resealed(d, edit):
    d = json.loads(json.dumps(d))
    edit(d["template"])
    d["template_hash"] = sa.template_hash(d["template"])
    return d


X_OF_G = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PK = {"PK": X_OF_G}


class Refusals(unittest.TestCase):
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

    def test_unknown_fields_are_refused(self):
        d = one_key()
        self.refused(resealed(d, lambda t: t.update(expiry=5)), "unknown field expiry")
        self.refused(resealed(d, lambda t: t["program"].update(note="x")), "unknown field note")
        d2 = json.loads(json.dumps(d))
        d2["extra"] = 1
        self.refused(d2, "unknown field extra")

    def test_integers_of_2_pow_53_or_more_are_refused(self):
        d = one_key()
        sa.derive(resealed(d, lambda t: t.update(version=2**53 - 1)), PK)
        self.refused(resealed(d, lambda t: t.update(version=2**53)), "2^53")
        with open(os.path.join(ROOT, "templates", "one_key", "descriptor.json")) as f:
            text = f.read()
        for bad in ('"descriptor": 9007199254740993', '"descriptor": 1.0', '"descriptor": -1'):
            with self.assertRaises(ValueError):
                sa.loads(text.replace('"descriptor": 1', bad, 1))

    def test_hex_with_trailing_junk_is_refused(self):
        d = one_key()
        for bad in (X_OF_G + "zz", X_OF_G + "0", X_OF_G.upper(), X_OF_G[:-2]):
            with self.assertRaises(ValueError):
                sa.derive(d, {"PK": bad})

    def test_the_vectors_catch_an_unsorted_branch(self):
        # A mirror that hashes the two leaves in a fixed order instead of
        # sorting them is wrong whenever the data leaf sorts above the program
        # leaf; the vectors hold such instances, so they refuse that mirror.
        d = one_key()
        with open(os.path.join(ROOT, "templates", "one_key", "vectors.json")) as f:
            v = json.load(f)
        wrong = 0
        for case in v["addresses"]:
            data = sa.param_bytes(d["template"], case["params"])
            leaf = sa.tagged("TapData", data).hex()
            unsorted = sa.tagged("TapBranch/elements", bytes.fromhex(leaf + case["program_leaf"])).hex()
            wrong += unsorted != case["merkle_root"]
        self.assertGreaterEqual(wrong, 2)


if __name__ == "__main__":
    unittest.main()
