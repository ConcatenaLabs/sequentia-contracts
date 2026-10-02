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
                d = json.load(f)
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


if __name__ == "__main__":
    unittest.main()
