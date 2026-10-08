"""O1: one format-2 price attestation, accepted by a Simplicity program and by
a tapscript leaf of the same output, and every wrong one refused in a block.

The output is P2TR(NUMS, {Simplicity leaf, tapscript leaf}); both leaves pin
the oracle's key, the pair, the precision and the (empty) beacon, take the
price and the time from the witness, require the time to be no earlier than
NOT_BEFORE and the price under STRIKE, and need the owner's signature over
the spend. Two coins at that output: one is spent through each leaf with the
same attestation.

The attestations come from the golden vectors of sequentia-oracle
(vectors/attestations.json, pinned in this repository), whose test key A signs
the extra ones the contract-level negatives need. With O1_SET=<file>, they come
from that file instead: a set a running signer produced (sequentia-oracle's
`doc/runbook.md` says how), and its key is the one the contract pins.

Negatives, each refused by the mempool and in a block forced with
generateblock, each with an accepted control on the same coin:
  wrong price   the witness price is not the signed one
  wrong time    the witness time is not the signed one
  early         a genuine attestation dated before NOT_BEFORE
  high          a genuine attestation at or above STRIKE
  wrong pair    the same oracle's genuine attestation of another pair
  wrong key     another key's attestation of the same fields
  format 1      the oracle's format-1 signature over the same observation
  version 1     a message laid out as format 2 but with version byte 1, signed
                by the oracle's key (golden vectors only: it needs the secret)
and, for the tapscript leaf only, the whole format-1 record (its 8-byte
timestamp and its signature), a price pushed as 9 bytes and a time pushed as
5, which must not be able to shift the fields of the message.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.script import OP_LESSTHAN64, OP_GREATERTHANOREQUAL64, OP_LE32TOLE64  # noqa: E402

VECTORS = os.path.join(REPO_ROOT, "vectors", "attestations.json")
TAG = "Sequentia/oracle/price"
FEE = 500
COIN_ATOMS = 1_000_000


# -- format 2, written out here so the harness checks the bytes itself ------
def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def message(f):
    return (b"\x02" + f["key"] + f["base"] + f["quote"] + f["price"].to_bytes(8, "little")
            + bytes([f["precision"]]) + f["time"].to_bytes(4, "little") + f["beacon"])


def decode(d):
    """A format-2 record: its fields from its message, the signature beside it."""
    m = bytes.fromhex(d["message"])
    assert len(m) == 142 and m[0] == 2, d
    f = {"key": m[1:33], "base": m[33:65], "quote": m[65:97],
         "price": int.from_bytes(m[97:105], "little"), "precision": m[105],
         "time": int.from_bytes(m[106:110], "little"), "beacon": m[110:142],
         "sig": bytes.fromhex(d["signature"])}
    assert message(f) == m
    return f


def sign2(sec, f):
    g = dict(f, key=compute_xonly_pubkey(sec)[0])
    g["sig"] = sign_schnorr(sec, tagged(TAG, message(g)))
    return g


def sign_version(sec, f, version):
    """The oracle's key over f's message with another version byte."""
    g = dict(f, key=compute_xonly_pubkey(sec)[0])
    g["sig"] = sign_schnorr(sec, tagged(TAG, bytes([version]) + message(g)[1:]))
    return g


def load_vectors():
    with open(VECTORS) as f:
        v = json.load(f)
    for c in v["v2"]:
        f2 = decode(c)
        assert tagged(TAG, message(f2)).hex() == c["digest"], c["name"]
        assert verify_schnorr(f2["key"], f2["sig"], bytes.fromhex(c["digest"])), c["name"]
    return v


def vector_set(v):
    """The set from the vectors: `ok` is the gold_usdx vector itself."""
    sec = bytes.fromhex(v["keys"]["A"]["secret"])
    ok = decode(v["v2"][0])
    early = sign2(sec, dict(ok, time=ok["time"] - 3600, price=ok["price"] - 1000))
    high = sign2(sec, dict(ok, time=ok["time"] + 60, price=ok["price"] + 1000))
    return {"source": "vectors", "ok": ok, "early": early, "high": high,
            "version_1": sign_version(sec, ok, 1),
            "other_pair": decode(v["v2"][1]),
            "v1_signature": bytes.fromhex(v["v1"][0]["signature"]),
            "v1_message": bytes.fromhex(v["v1"][0]["message"])}


def file_set(path):
    """A set a running signer wrote: ok, early, high and other_pair are its
    format-2 records, v1 its format-1 record of ok's observation."""
    with open(path) as f:
        s = json.load(f)
    out = {"source": path}
    for k in ("ok", "early", "high", "other_pair"):
        out[k] = decode(s[k])
    v1 = s["v1"]
    out["v1_signature"] = bytes.fromhex(v1["signature"])
    out["v1_message"] = bytes.fromhex(v1["feed_id"]) + int(v1["timestamp"]).to_bytes(8, "little") \
        + int(v1["price"]).to_bytes(8, "little")
    return out


def push_byte(b):
    """One byte as tapscript's minimal-push rule wants it: 1 to 16 as OP_1 ..
    OP_16 (which push exactly that byte), anything else as a one-byte push.
    Zero must be the byte 0x00, never OP_0, which pushes nothing."""
    return CScriptOp.encode_op_n(b) if 1 <= b <= 16 else bytes([b])


def tap_leaf(f, not_before, strike, owner_x):
    """The tapscript twin of attestation_check.simf.
    witness (bottom to top): owner_sig, oracle_sig, time (4 bytes LE), price (8 bytes LE)."""
    head = b"\x02" + f["key"] + f["base"] + f["quote"]
    t = sha256(TAG.encode())
    return CScript([
        OP_DUP, le8(strike), OP_LESSTHAN64, OP_VERIFY,                        # price < STRIKE (8 bytes or fail)
        OP_OVER, OP_LE32TOLE64, le8(not_before), OP_GREATERTHANOREQUAL64, OP_VERIFY,  # time >= NOT_BEFORE (4 bytes or fail)
        head, OP_SWAP, OP_CAT,                                                # .. || price
        push_byte(f["precision"]), OP_CAT,                                    # .. || precision
        OP_SWAP, OP_CAT,                                                      # .. || time
        f["beacon"], OP_CAT,                                                  # .. || beacon = message
        t + t, OP_SWAP, OP_CAT, OP_SHA256,                                    # the tagged hash
        f["key"], OP_CHECKSIGFROMSTACKVERIFY,                                 # (sig, digest, key)
        owner_x, OP_CHECKSIG,
    ])


class O1(SimBase, BitcoinTestFramework):
    NAME = "o1"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        v = load_vectors()
        path = os.environ.get("O1_SET")
        S = file_set(path) if path else vector_set(v)
        ok = S["ok"]
        self.rec("attestation", {"source": S["source"], "key": ok["key"].hex(),
                                 "message": message(ok).hex(), "digest": tagged(TAG, message(ok)).hex(),
                                 "signature": ok["sig"].hex(), "price": ok["price"], "time": ok["time"],
                                 "precision": ok["precision"]})
        if not path:
            assert message(ok).hex() == v["v2"][0]["message"] and ok["sig"].hex() == v["v2"][0]["signature"]
        NOT_BEFORE = ok["time"]
        STRIKE = ok["price"] + 1
        assert S["early"]["time"] < NOT_BEFORE and S["early"]["price"] < STRIKE
        assert S["high"]["time"] >= NOT_BEFORE and S["high"]["price"] >= STRIKE
        assert (S["other_pair"]["base"], S["other_pair"]["quote"]) != (ok["base"], ok["quote"])
        assert S["other_pair"]["key"] == ok["key"]
        o_sec = generate_privkey()
        owner_x = compute_xonly_pubkey(o_sec)[0]
        stranger = generate_privkey()
        wrong_key = sign2(stranger, ok)

        leaf = tap_leaf(ok, NOT_BEFORE, STRIKE, owner_x)
        self.rec_script("tapscript_leaf", leaf)
        args = {"ORACLE": vpub(ok["key"]), "BASE": v256(ok["base"]), "QUOTE": v256(ok["quote"]),
                "PRECISION": vu(ok["precision"], 8), "BEACON": v256(ok["beacon"]),
                "NOT_BEFORE": vu(NOT_BEFORE, 32), "STRIKE": vu(STRIKE), "OWNER": vpub(owner_x)}
        prog = SimProg(src("attestation_check.simf"), args, sibling=("tap", leaf))
        self.rec("program", prog.info())
        cb_tap = control_block(prog.tap, "tap")
        dest = self.wallet_spk()
        XO = self.X_OUT

        def build_sim(u, att, price=None, time=None, sig=None, ok_=False):
            tx = self.mktx([u], [self.out(COIN_ATOMS - FEE, dest, XO), self.fee(FEE, XO)])
            osig = att["sig"] if sig is None else sig
            W = {"PRICE": vu(att["price"] if price is None else price),
                 "TIME": vu(att["time"] if time is None else time, 32),
                 "ORACLE_SIG": vsig(osig),
                 "OWNER_SIG": vsig(sign_schnorr(o_sec, self.sim_sighash(prog, tx, 0)))}
            r = self.sim_satisfy(prog, tx, 0, W, prune=ok_, must_exec=ok_)
            return tx, r

        def build_tap(u, att, price=None, time=None, sig=None):
            tx = self.mktx([u], [self.out(COIN_ATOMS - FEE, dest, XO), self.fee(FEE, XO)])
            p = att["price"].to_bytes(8, "little") if price is None else price
            t = att["time"].to_bytes(4, "little") if time is None else time
            osig = att["sig"] if sig is None else sig
            self.setwit(tx, 0, [self.sign(o_sec, tx, 0, leaf), osig, t, p, leaf, cb_tap])
            return tx

        us = self.fund(prog.spk, COIN_ATOMS, self.X)
        ut = self.fund(prog.spk, COIN_ATOMS, self.X)
        J = "Assertion failed inside jet"
        BADSIG = "Invalid Schnorr signature"

        # -- Simplicity leaf ------------------------------------------------
        ctl, _ = build_sim(us, ok)
        cases = [
            ("sim_neg_wrong_price", dict(att=ok, price=ok["price"] - 1), J),
            ("sim_neg_wrong_time", dict(att=ok, time=ok["time"] + 1), J),
            ("sim_neg_early_attestation", dict(att=S["early"]), J),
            ("sim_neg_price_at_or_above_strike", dict(att=S["high"]), J),
            ("sim_neg_wrong_pair", dict(att=S["other_pair"]), J),
            ("sim_neg_wrong_key", dict(att=wrong_key), J),
            ("sim_neg_format_1_signature", dict(att=ok, sig=S["v1_signature"]), J),
        ]
        if "version_1" in S:
            cases.append(("sim_neg_version_byte_1", dict(att=S["version_1"]), J))
        for label, kw, why in cases:
            tx, _ = build_sim(us, **kw)
            self.reject(tx, label, why, control=ctl)
        tx, r = build_sim(us, ok, ok_=True)
        self.send(tx, "sim_accept", extra=self.sim_measure(tx, 0, r))

        # -- tapscript leaf ------------------------------------------------
        ctl = build_tap(ut, ok)
        cases = [
            ("tap_neg_wrong_price", dict(att=ok, price=(ok["price"] - 1).to_bytes(8, "little")), BADSIG),
            ("tap_neg_wrong_time", dict(att=ok, time=(ok["time"] + 1).to_bytes(4, "little")), BADSIG),
            ("tap_neg_early_attestation", dict(att=S["early"]), "Script failed an OP_VERIFY operation"),
            ("tap_neg_price_at_or_above_strike", dict(att=S["high"]), "Script failed an OP_VERIFY operation"),
            ("tap_neg_wrong_pair", dict(att=S["other_pair"]), BADSIG),
            ("tap_neg_wrong_key", dict(att=wrong_key), BADSIG),
            ("tap_neg_format_1_signature", dict(att=ok, sig=S["v1_signature"]), BADSIG),
            ("tap_neg_format_1_record", dict(att=ok, time=S["v1_message"][32:40],
                                             price=S["v1_message"][40:48], sig=S["v1_signature"]),
             "Arithmetic opcode error"),
            ("tap_neg_price_9_bytes", dict(att=ok, price=ok["price"].to_bytes(9, "little")),
             "Arithmetic opcodes expect 8 bytes operands"),
            ("tap_neg_time_5_bytes", dict(att=ok, time=ok["time"].to_bytes(5, "little")),
             "Arithmetic opcode error"),
        ]
        if "version_1" in S:
            cases.append(("tap_neg_version_byte_1", dict(att=S["version_1"]), BADSIG))
        for label, kw, why in cases:
            self.reject(build_tap(ut, **kw), label, why, control=ctl)
        tx = build_tap(ut, ok)
        self.send(tx, "tap_accept")

        if not path:
            self.both_leaves_accept(decode(v["v2"][3]), "btc_usd", dest)

        # The format-1 message really is that observation, signed by that key,
        # so the refusal above is the format's and not a bad signature.
        self.rec("format_1_check", {"message": S["v1_message"].hex(), "bytes": len(S["v1_message"]),
                                    "verifies_as_format_1": verify_schnorr_any(ok["key"], S["v1_signature"], S["v1_message"])})
        assert self.R["format_1_check"]["verifies_as_format_1"]


def _both_leaves_accept(self, att, name, dest):
    """Another vector through both leaves: native bitcoin priced in US
    dollars, two unit ids and precision 0, which the tapscript leaf must push
    as the byte 0x00 rather than as OP_0."""
    o_sec = generate_privkey()
    owner_x = compute_xonly_pubkey(o_sec)[0]
    leaf = tap_leaf(att, att["time"], att["price"] + 1, owner_x)
    args = {"ORACLE": vpub(att["key"]), "BASE": v256(att["base"]), "QUOTE": v256(att["quote"]),
            "PRECISION": vu(att["precision"], 8), "BEACON": v256(att["beacon"]),
            "NOT_BEFORE": vu(att["time"], 32), "STRIKE": vu(att["price"] + 1), "OWNER": vpub(owner_x)}
    prog = SimProg(src("attestation_check.simf"), args, sibling=("tap", leaf))
    XO = self.X_OUT
    us = self.fund(prog.spk, COIN_ATOMS, self.X)
    ut = self.fund(prog.spk, COIN_ATOMS, self.X)
    tx = self.mktx([us], [self.out(COIN_ATOMS - FEE, dest, XO), self.fee(FEE, XO)])
    W = {"PRICE": vu(att["price"]), "TIME": vu(att["time"], 32), "ORACLE_SIG": vsig(att["sig"]),
         "OWNER_SIG": vsig(sign_schnorr(o_sec, self.sim_sighash(prog, tx, 0)))}
    r = self.sim_satisfy(prog, tx, 0, W)
    self.send(tx, "sim_accept_" + name, extra=self.sim_measure(tx, 0, r))
    tx = self.mktx([ut], [self.out(COIN_ATOMS - FEE, dest, XO), self.fee(FEE, XO)])
    self.setwit(tx, 0, [self.sign(o_sec, tx, 0, leaf), att["sig"], att["time"].to_bytes(4, "little"),
                        att["price"].to_bytes(8, "little"), leaf, control_block(prog.tap, "tap")])
    self.send(tx, "tap_accept_" + name)


O1.both_leaves_accept = _both_leaves_accept


def verify_schnorr_any(key, sig, msg):
    """BIP340 over a message of any length (the framework's verifier asserts 32)."""
    from test_framework import key as K
    P = K.SECP256K1.lift_x(int.from_bytes(key, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if P is None or r >= K.SECP256K1_FIELD_SIZE or s >= K.SECP256K1_ORDER:
        return False
    e = int.from_bytes(K.TaggedHash("BIP0340/challenge", sig[:32] + key + msg), "big") % K.SECP256K1_ORDER
    R = K.SECP256K1.mul([(K.SECP256K1_G, s), (P, K.SECP256K1_ORDER - e)])
    return K.SECP256K1.has_even_y(R) and ((r * R[2] * R[2]) % K.SECP256K1_FIELD_SIZE) == R[0]


if __name__ == "__main__":
    O1().main()
