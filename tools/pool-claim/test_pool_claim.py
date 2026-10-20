"""Offline checks of the claim tool: the pool record's rules, the address it
derives, the transaction encoding, and the tapscript twin's claim leaf as
twin_script.py writes it. The tool's claims on a chain are tested by the
harness (p1, p2).

    python3 tools/pool-claim/test_pool_claim.py
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import pool_claim as pc  # noqa: E402
import twin_script  # noqa: E402


def record(template="sequentia/pool-split", rows=None, denom=10000, cap=100):
    rows = rows or [("pool", "0014" + "11" * 20, 500), ("alice", "5120" + "22" * 32, 6000),
                    ("bob", "76a914" + "33" * 20 + "88ac", 3500)]
    return {"pool_record": 1, "template": template, "denom": denom, "withhold_cap_bp": cap,
            "rows": [{"label": l, "script": s, "numerator": n} for l, s, n in rows]}


class Records(unittest.TestCase):
    def test_a_good_record_derives_the_vectors_table(self):
        with open(os.path.join(ROOT, "templates", "pool_split", "tables.json")) as f:
            e = json.load(f)["entries"][0]
        rows = [(r["script"], r["numerator"]) for r in e["rows"]]
        rec = record(rows=[("row %d" % i, s, n) for i, (s, n) in enumerate(rows)],
                     denom=sum(n for _, n in rows))
        self.assertEqual(pc.Pool(rec).params["TABLE"], e["table"])

    def test_the_address_is_the_vectors(self):
        """A record holding a vector's rows gives that vector's script."""
        with open(os.path.join(ROOT, "templates", "pool_split", "tables.json")) as f:
            entries = {e["table"]: e for e in json.load(f)["entries"]}
        with open(os.path.join(ROOT, "templates", "pool_split", "vectors.json")) as f:
            vectors = json.load(f)["addresses"]
        checked = 0
        for v in vectors:
            e = entries[v["params"]["TABLE"]]
            rec = record(rows=[("row %d" % i, r["script"], r["numerator"]) for i, r in enumerate(e["rows"])],
                         denom=int(v["params"]["DENOM"], 16), cap=int(v["params"]["WITHHOLD_CAP_BP"], 16))
            rec["denom"] = sum(r["numerator"] for r in e["rows"])
            if rec["denom"] != int(v["params"]["DENOM"], 16):
                continue
            p = pc.Pool(rec)
            self.assertEqual(p.script_pubkey.hex(), v["script_pubkey"], v["name"])
            self.assertEqual(p.address("sequentia-testnet"), v["address"]["sequentia-testnet"])
            checked += 1
        self.assertEqual(checked, len(vectors))

    def test_refusals(self):
        bad = [
            (record(rows=[("a", "51", 1), ("b", "51", 2)], denom=4), "sum to 3"),
            (record(rows=[("a", "51", 0), ("b", "51", 4)], denom=4), "positive"),
            (record(denom=1 << 31, rows=[("a", "51", (1 << 31) - 1), ("b", "51", 1)]), "2\\^31"),
            (record(cap=10001), "10,000"),
            (record(template="sequentia/pool-split-tap3", rows=[("a", "51", 1), ("b", "51", 1)], denom=2), "exactly 3"),
            (record(rows=[("r%d" % i, "51", 1) for i in range(64)], denom=64), "1 to 63"),
            (record(rows=[("a", "5220" + "00" * 32, 1)], denom=1), "version 2"),
        ]
        for rec, why in bad:
            with self.assertRaisesRegex(ValueError, why):
                pc.Pool(rec)

    def test_withheld_over_the_cap_is_refused(self):
        p = pc.Pool(record())
        self.assertEqual(p.cap(1234567), 12345)
        p.payouts(1234567, 12345)
        with self.assertRaisesRegex(pc.Refused, "over the cap"):
            p.payouts(1234567, 12346)


class Transactions(unittest.TestCase):
    def test_round_trip(self):
        t = pc.Tx()
        t.vin = [["ab" * 32, 1, 0xffffffff], ["cd" * 32, 0, 0xfffffffe]]
        t.vout = [pc.TxOut.explicit(b"\x01" * 32, 12345, bytes.fromhex("0014" + "11" * 20)),
                  pc.TxOut.explicit(b"\x01" * 32, 7, b"")]
        t.wit = [[b"\x01" * 8, b"\x02" * 30, b"\xc4" + b"\x03" * 32], [b"x", b"y"]]
        u = pc.Tx.parse(t.hex())
        self.assertEqual(u.hex(), t.hex())
        self.assertEqual(u.txid(), t.txid())
        self.assertEqual([o.value for o in u.vout], [12345, 7])
        self.assertEqual(pc.Tx.parse(t.serialize(False)).wit, [[], []])


class Twin(unittest.TestCase):
    def test_the_descriptor_holds_what_twin_script_writes(self):
        with open(os.path.join(ROOT, "templates", "pool_split_tap3", "descriptor.json")) as f:
            tree = json.load(f)["template"]["tree"]
        claim = [n for n in tree["branch"] if n["leaf"] == "claim"][0]
        self.assertEqual(claim["tapscript"], twin_script.build().to_descriptor())


if __name__ == "__main__":
    unittest.main()
