"""O2: fresh attestations through a beacon coin.

An oracle keeps coins of its beacon asset at a beacon script (sequentia-oracle
`doc/format.md`, "The beacon"), and every format-2 attestation names the
program of that script. A contract pins the oracle's key, the pair, the
precision and the BEACON ASSET, and requires its spending transaction to spend
a coin of that asset from the script the attestation names. The oracle
rotates by moving every beacon coin to a new script with a signature of its
own key; from then on an attestation naming the old script has no coin to
point at.

The run, on golden vectors (sequentia-oracle `vectors/attestations.json`, key
A's beacon in epochs 0 and 1) or, with O2_SET=<file>, on a beacon log and
attestations a running signer wrote (`tools/o2_set.py` in sequentia-oracle):

  1. Two beacon coins at B1; a contract output with a Simplicity leaf and a
     tapscript leaf, opened while the beacon is B1.
  2. An attestation naming B1 is accepted by both leaves, the beacon coin
     spent through its recreate leaf and left where it was.
  3. The beacon rotates to B2 with the oracle's rotation signature.
  4. The attestation naming B1 is refused by both leaves in a forced block,
     each against an accepted control that differs only in naming B2; it is
     refused too with the spent B1 coin, and with a foreign coin put at B1.
  5. The attestation naming B2 is accepted by both leaves.

And the beacon script itself: nothing but a correct rotation moves a coin,
nothing takes the asset out, and an old rotation signature cannot move the
coins again (forward or back). Every negative is refused by the mempool and
in a block forced with generateblock.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.script import OP_LESSTHAN64, OP_GREATERTHANOREQUAL64, OP_LE32TOLE64  # noqa: E402
from test_framework.script import OP_INSPECTINPUTSCRIPTPUBKEY  # noqa: E402

VECTORS = os.path.join(REPO_ROOT, "vectors", "attestations.json")
TAG = "Sequentia/oracle/price"
BEACON_TAG = "Sequentia/oracle/beacon"
FEE = 3000
COIN_ATOMS = 1_000_000
BEACON_ATOMS = 1


# -- the formats, written out here so the harness checks the bytes itself --
def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def message(f):
    return (b"\x02" + f["key"] + f["base"] + f["quote"] + f["price"].to_bytes(8, "little")
            + bytes([f["precision"]]) + f["time"].to_bytes(4, "little") + f["beacon"])


def decode(d):
    m = bytes.fromhex(d["message"])
    assert len(m) == 142 and m[0] == 2, d
    f = {"key": m[1:33], "base": m[33:65], "quote": m[65:97],
         "price": int.from_bytes(m[97:105], "little"), "precision": m[105],
         "time": int.from_bytes(m[106:110], "little"), "beacon": m[110:142],
         "sig": bytes.fromhex(d["signature"])}
    assert message(f) == m
    assert verify_schnorr(f["key"], f["sig"], tagged(TAG, m)), d
    return f


def same(inspect_in, inspect_out):
    """Input k's field equals output 2k's."""
    return [OP_PUSHCURRENTINPUTINDEX, inspect_in, OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_ADD,
            inspect_out, OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY]


KEEP = same(OP_INSPECTINPUTASSET, OP_INSPECTOUTPUTASSET) + same(OP_INSPECTINPUTVALUE, OP_INSPECTOUTPUTVALUE)


class Beacon:
    """One epoch's beacon script, built here from the format document with the
    node's framework and compared with the program the oracle published."""

    def __init__(self, key, nonce, program=None):
        self.key, self.nonce = key, nonce
        t = sha256(BEACON_TAG.encode())
        self.recreate = CScript(same(OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTOUTPUTSCRIPTPUBKEY) + KEEP + [OP_1])
        self.rotate = CScript(
            [nonce, OP_DROP,
             OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_ADD, OP_INSPECTOUTPUTSCRIPTPUBKEY,
             OP_1, OP_EQUALVERIFY, OP_OVER, OP_EQUALVERIFY] + KEEP
            + [OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTSCRIPTPUBKEY, OP_DROP, OP_SWAP, OP_CAT,
               t + t, OP_SWAP, OP_CAT, OP_SHA256, key, OP_CHECKSIGFROMSTACK])
        self.tap = taproot_construct(NUMS, [("recreate", self.recreate), ("rotate", self.rotate)])
        self.spk = bytes(self.tap.scriptPubKey)
        self.program = self.spk[2:]
        if program is not None:
            assert self.program == program, "the beacon program is not the one the oracle published"

    def wit_recreate(self):
        return [self.recreate, control_block(self.tap, "recreate")]

    def wit_rotate(self, sig, to):
        return [sig, to, self.rotate, control_block(self.tap, "rotate")]


def push_byte(b):
    return CScriptOp.encode_op_n(b) if 1 <= b <= 16 else bytes([b])


def tap_leaf(f, beacon_asset, not_before, strike, owner_x):
    """The tapscript twin of attestation_fresh.simf.
    witness (bottom to top): owner_sig, oracle_sig, time (4 LE), price (8 LE), beacon_at.
    The beacon is not in the witness: the leaf reads the program of the coin
    at input beacon_at and puts it into the message, after checking that the
    coin is explicit beacon asset at a witness-v1 output."""
    head = b"\x02" + f["key"] + f["base"] + f["quote"]
    t = sha256(TAG.encode())
    return CScript([
        OP_DUP, OP_INSPECTINPUTASSET, OP_1, OP_EQUALVERIFY, beacon_asset, OP_EQUALVERIFY,  # explicit beacon asset
        OP_INSPECTINPUTSCRIPTPUBKEY, OP_1, OP_EQUALVERIFY, OP_TOALTSTACK,               # its v1 program -> alt
        OP_DUP, le8(strike), OP_LESSTHAN64, OP_VERIFY,
        OP_OVER, OP_LE32TOLE64, le8(not_before), OP_GREATERTHANOREQUAL64, OP_VERIFY,
        head, OP_SWAP, OP_CAT,
        push_byte(f["precision"]), OP_CAT,
        OP_SWAP, OP_CAT,
        OP_FROMALTSTACK, OP_CAT,                                                       # .. || beacon
        t + t, OP_SWAP, OP_CAT, OP_SHA256,
        f["key"], OP_CHECKSIGFROMSTACKVERIFY,
        owner_x, OP_CHECKSIG,
    ])


def vector_set():
    with open(VECTORS) as fh:
        v = json.load(fh)
    by = {c["name"]: c for c in v["v2"]}
    b = v["beacon"]
    ep = b["epochs"]
    return {"source": "vectors", "key": bytes.fromhex(v["keys"]["A"]["key"]),
            "secret": bytes.fromhex(v["keys"]["A"]["secret"]),
            "epochs": [{"nonce": bytes.fromhex(e["nonce"]), "program": bytes.fromhex(e["program"]),
                        "signature": bytes.fromhex(e["signature"]) if e.get("signature") else None}
                       for e in ep],
            "b1": decode(by["gold_usdx_beacon"]), "b2": decode(by["gold_usdx_beacon_1"]),
            "zero": decode(by["gold_usdx"]),
            "vectors": {"leaves": ep}}


def file_set(path):
    """A set a running signer wrote: its key, two consecutive epochs of its
    beacon log, a record naming each, and optionally one with no beacon."""
    with open(path) as fh:
        s = json.load(fh)
    out = {"source": path, "key": bytes.fromhex(s["key"]), "secret": None,
           "epochs": [{"nonce": bytes.fromhex(e["nonce"]), "program": bytes.fromhex(e["program"]),
                       "signature": bytes.fromhex(e["signature"]) if e.get("signature") else None}
                      for e in s["epochs"]],
           "b1": decode(s["b1"]), "b2": decode(s["b2"])}
    if s.get("zero"):
        out["zero"] = decode(s["zero"])
    return out


class O2(SimBase, BitcoinTestFramework):
    NAME = "o2"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot(issue=("X", "BEACON"))
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        path = os.environ.get("O2_SET")
        S = file_set(path) if path else vector_set()
        K = S["key"]
        e1, e2 = S["epochs"][0], S["epochs"][1]
        B1 = Beacon(K, e1["nonce"], e1["program"])
        B2 = Beacon(K, e2["nonce"], e2["program"])
        if not path:
            for B, e in ((B1, S["vectors"]["leaves"][0]), (B2, S["vectors"]["leaves"][1])):
                assert bytes(B.recreate).hex() == e["recreate_leaf"]
                assert bytes(B.rotate).hex() == e["rotate_leaf"]
                assert control_block(B.tap, "rotate").hex() == e["rotate_control_block"]
                assert control_block(B.tap, "recreate").hex() == e["recreate_control_block"]
        rot12 = e2["signature"]
        assert verify_schnorr(K, rot12, tagged(BEACON_TAG, B1.program + B2.program))
        a1, a2 = S["b1"], S["b2"]
        assert a1["beacon"] == B1.program and a2["beacon"] == B2.program
        assert a1["key"] == a2["key"] == K
        assert (a1["base"], a1["quote"], a1["precision"]) == (a2["base"], a2["quote"], a2["precision"])
        self.rec("beacon", {"source": S["source"], "key": K.hex(), "asset": self.BEACON,
                            "b1": B1.program.hex(), "b2": B2.program.hex(),
                            "rotation_signature": rot12.hex(),
                            "recreate_leaf_bytes": len(B1.recreate), "rotate_leaf_bytes": len(B1.rotate)})
        self.rec_script("recreate_leaf", B1.recreate, B1.tap, "recreate")
        self.rec_script("rotate_leaf_b1", B1.rotate, B1.tap, "rotate")

        XO = self.X_OUT
        BO = self.BEACON_OUT
        BID = self.BEACON_ID
        dest = self.wallet_spk()

        # -- the beacon coins at B1, and a foreign coin there ---------------
        bc = [self.fund(B1.spk, BEACON_ATOMS, self.BEACON) for _ in range(2)]
        self.rec("beacon_coin", {"atoms": BEACON_ATOMS, "outpoints": [str(u) for u in bc]})

        # -- the contract, opened under B1 ----------------------------------
        o_sec = generate_privkey()
        owner_x = compute_xonly_pubkey(o_sec)[0]
        # Every record the run presents is inside the time and price bounds,
        # so a refusal is the beacon's and no other check's.
        used = [a1, a2] + ([S["zero"]] if "zero" in S else [])
        NOT_BEFORE = min(a["time"] for a in used)
        STRIKE = max(a["price"] for a in used) + 1
        leaf = tap_leaf(a1, BID, NOT_BEFORE, STRIKE, owner_x)
        self.rec_script("tapscript_leaf", leaf)
        args = {"ORACLE": vpub(K), "BASE": v256(a1["base"]), "QUOTE": v256(a1["quote"]),
                "PRECISION": vu(a1["precision"], 8), "BEACON_ASSET": v256(BID),
                "NOT_BEFORE": vu(NOT_BEFORE, 32), "STRIKE": vu(STRIKE), "OWNER": vpub(owner_x)}
        prog = SimProg(src("attestation_fresh.simf"), args, sibling=("tap", leaf))
        self.rec("program", prog.info())
        cb_tap = control_block(prog.tap, "tap")
        coins = {k: self.fund(prog.spk, COIN_ATOMS, self.X) for k in ("s1", "t1", "s2", "t2")}

        def spend(u, att, beacon_coin, beacon, leaf_kind, at=1, price=None, sig=None, beacon_field=None,
                  extra_out=None, ok_=False):
            """The contract coin at input 0, the beacon coin at input `at`
            (recreated at output 2*at), the payout at output 0."""
            outs = [self.out(COIN_ATOMS - FEE, dest, XO), self.fee(FEE, XO)]
            if beacon_coin is not None:
                bout = extra_out if extra_out is not None else \
                    self.out(beacon_coin.amount, beacon_coin.spk, bytes(beacon_coin.txout.nAsset.vchCommitment))
                outs.append(bout)
            ins = [u] + ([beacon_coin] if beacon_coin is not None else [])
            tx = self.mktx(ins, outs)
            if beacon_coin is not None and beacon is not None:
                self.setwit(tx, 1, beacon.wit_recreate())
            osig = att["sig"] if sig is None else sig
            p = att["price"] if price is None else price
            if leaf_kind == "sim":
                W = {"PRICE": vu(p), "TIME": vu(att["time"], 32), "ORACLE_SIG": vsig(osig),
                     "BEACON": v256(att["beacon"] if beacon_field is None else beacon_field),
                     "BEACON_AT": vu(at, 32),
                     "OWNER_SIG": vsig(sign_schnorr(o_sec, self.sim_sighash(prog, tx, 0)))}
                r = self.sim_satisfy(prog, tx, 0, W, prune=ok_, must_exec=ok_)
                return tx, r
            self.setwit(tx, 0, [self.sign(o_sec, tx, 0, leaf), osig, att["time"].to_bytes(4, "little"),
                                p.to_bytes(8, "little"), bytes([at]) if at else b"",
                                leaf, cb_tap])
            return tx, None

        J = "Assertion failed inside jet"
        BADSIG = "Invalid Schnorr signature"
        EQV = "Script failed an OP_EQUALVERIFY operation"

        def cur(u):
            """The beacon coin a mined spend left at output 2 of its txid."""
            return self.utxo_at(u, 2)

        # -- before the rotation: B1 accepted, wrong beacons refused -------
        foreign_b1 = self.fund(B1.spk, 10_000, self.X)
        for kind, coin in (("sim", coins["s1"]), ("tap", coins["t1"])):
            ctl, _ = spend(coin, a1, bc[0], B1, kind)
            bad = BADSIG if kind == "tap" else J
            self.reject(spend(coin, a1, foreign_b1, B1, kind)[0], f"{kind}_neg_foreign_coin_at_b1",
                        EQV if kind == "tap" else J, control=ctl)
            if "zero" in S:
                z = S["zero"]
                assert z["beacon"] == bytes(32) and z["key"] == K
                ctl_z, _ = spend(coin, a1, bc[0], B1, kind, price=a1["price"])
                self.reject(spend(coin, z, bc[0], B1, kind, beacon_field=bytes(32))[0],
                            f"{kind}_neg_zero_beacon", bad, control=ctl_z)
            # the beacon index pointing at the contract's own coin, not a beacon
            self.reject(spend(coin, a1, bc[0], B1, kind, at=0)[0], f"{kind}_neg_beacon_at_wrong_input",
                        EQV if kind == "tap" else J, control=ctl)
            tx, r = spend(coin, a1, bc[0], B1, kind, ok_=True)
            extra = self.sim_measure(tx, 0, r) if kind == "sim" else None
            txid = self.send(tx, f"{kind}_accept_b1", extra=extra)
            bc[0] = cur(txid)
            assert bc[0].spk == B1.spk

        # -- the beacon script: nothing but a correct rotation moves a coin -
        fee_u = self.wallet_utxo(100_000, self.X)
        thief = self.wallet_spk()

        def beacon_tx(ins, outs, wits):
            """`ins` beacon coins, then a wallet coin of X that pays the fee;
            any X in `outs` (a filler at an odd index) comes out of its change."""
            used = sum(o.nValue.getAmount() for o in outs if bytes(o.nAsset.vchCommitment) == XO)
            tx = self.mktx(ins + [fee_u], outs + [self.out(100_000 - FEE - used, dest, XO), self.fee(FEE, XO)])
            for i, w in enumerate(wits):
                self.setwit(tx, i, w)
            return self.wallet_sign(tx)

        keep = self.out(BEACON_ATOMS, B1.spk, BO)
        to_b2 = self.out(BEACON_ATOMS, B2.spk, BO)
        ctl_recreate = beacon_tx([bc[0]], [keep], [B1.wit_recreate()])
        self.reject(beacon_tx([bc[0]], [self.out(BEACON_ATOMS, thief, BO)], [B1.wit_recreate()]),
                    "beacon_neg_recreate_to_another_script", EQV, control=ctl_recreate)
        self.reject(beacon_tx([bc[0]], [self.out(10_000, B1.spk, XO), self.out(BEACON_ATOMS, thief, BO)], [B1.wit_recreate()]),
                    "beacon_neg_recreate_with_another_asset", EQV, control=ctl_recreate)
        # Two beacon coins, one recreated output: input 1 owns output 2, not 0.
        ctl2 = beacon_tx([bc[0], bc[1]], [keep, self.out(1000, thief, XO), keep], [B1.wit_recreate()] * 2)
        two = self.mktx([bc[0], bc[1], fee_u], [keep, self.out(BEACON_ATOMS, thief, BO),
                                                self.out(100_000 - FEE - 0, dest, XO), self.fee(FEE, XO)])
        self.setwit(two, 0, B1.wit_recreate())
        self.setwit(two, 1, B1.wit_recreate())
        two = self.wallet_sign(two)
        self.reject(two, "beacon_neg_one_output_for_two_coins", EQV, control=ctl2, index=1)
        ctl_rot = beacon_tx([bc[0]], [to_b2], [B1.wit_rotate(rot12, B2.program)])
        # the signed destination, but the coin paid elsewhere
        self.reject(beacon_tx([bc[0]], [self.out(BEACON_ATOMS, thief, BO)], [B1.wit_rotate(rot12, B2.program)]),
                    "beacon_neg_rotate_to_unsigned_script", EQV, control=ctl_rot)
        # another destination, claimed in the witness, with the signature for B2
        thief_prog = self.wallet_spk_v1()
        self.reject(beacon_tx([bc[0]], [self.out(BEACON_ATOMS, b"\x51\x20" + thief_prog, BO)],
                              [B1.wit_rotate(rot12, thief_prog)]),
                    "beacon_neg_rotate_signature_for_another_destination", BADSIG, control=ctl_rot)
        stranger = generate_privkey()
        forged = sign_schnorr(stranger, tagged(BEACON_TAG, B1.program + B2.program))
        self.reject(beacon_tx([bc[0]], [to_b2], [B1.wit_rotate(forged, B2.program)]),
                    "beacon_neg_rotate_by_another_key", BADSIG, control=ctl_rot)
        # an attestation digest is not a rotation: the price key's signature over a format-2 digest
        self.reject(beacon_tx([bc[0]], [to_b2], [B1.wit_rotate(a1["sig"], B2.program)]),
                    "beacon_neg_rotate_with_an_attestation_signature", BADSIG, control=ctl_rot)

        # -- the rotation B1 -> B2 ------------------------------------------
        rot = beacon_tx([bc[0], bc[1]], [to_b2, self.out(1000, dest, XO), to_b2],
                        [B1.wit_rotate(rot12, B2.program)] * 2)
        rot_txid = self.send(rot, "rotate_b1_to_b2")
        old = list(bc)
        bc = [self.utxo_at(rot_txid, 0), self.utxo_at(rot_txid, 2)]
        assert all(u.spk == B2.spk for u in bc)
        self.rec("rotate_b1_to_b2_witness_bytes", wit_bytes(rot.wit.vtxinwit[0].scriptWitness.stack))

        # -- after the rotation: B1 is dead, B2 is live ----------------------
        foreign_b1_late = self.fund(B1.spk, 10_000, self.X)
        fee_u = self.wallet_utxo(100_000, self.X)
        for kind, coin in (("sim", coins["s2"]), ("tap", coins["t2"])):
            ctl, _ = spend(coin, a2, bc[0], B2, kind)
            # the old attestation against the live beacon coin: the control is
            # the same transaction naming B2
            self.reject(spend(coin, a1, bc[0], B2, kind)[0], f"{kind}_neg_old_attestation_after_rotation",
                        BADSIG if kind == "tap" else J, control=ctl)
            # the old attestation with the B1 coin it named, which is spent
            self.reject(spend(coin, a1, old[0], B1, kind)[0], f"{kind}_neg_old_attestation_with_spent_b1_coin",
                        "bad-txns-inputs-missingorspent", mempool="missing-inputs")
            # the old attestation with a foreign coin put at B1 after the rotation
            self.reject(spend(coin, a1, foreign_b1_late, B1, kind)[0], f"{kind}_neg_old_attestation_foreign_coin_at_b1",
                        EQV if kind == "tap" else J, control=ctl)
            tx, r = spend(coin, a2, bc[0], B2, kind, ok_=True)
            extra = self.sim_measure(tx, 0, r) if kind == "sim" else None
            txid = self.send(tx, f"{kind}_accept_b2", extra=extra)
            bc[0] = cur(txid)

        # -- an old rotation signature cannot move the coins again ----------
        keep2 = self.out(BEACON_ATOMS, B2.spk, BO)
        ctl_r2 = beacon_tx([bc[0]], [keep2], [B2.wit_recreate()])
        self.reject(beacon_tx([bc[0]], [self.out(BEACON_ATOMS, B1.spk, BO)], [B2.wit_rotate(rot12, B1.program)]),
                    "beacon_neg_rotate_back_to_b1_with_the_old_signature", BADSIG, control=ctl_r2)
        if S["secret"] is not None:
            # A third epoch, signed here with test key A: the old signature does
            # not move B2's coins there, the new one does.
            e3 = sha256(b"o2 epoch 3 nonce")
            B3 = Beacon(K, e3)
            to_b3 = self.out(BEACON_ATOMS, B3.spk, BO)
            self.reject(beacon_tx([bc[0]], [to_b3], [B2.wit_rotate(rot12, B3.program)]),
                        "beacon_neg_replay_b1_b2_signature_to_b3", BADSIG, control=ctl_r2)
            rot23 = sign_schnorr(S["secret"], tagged(BEACON_TAG, B2.program + B3.program))
            tx = beacon_tx([bc[0], bc[1]], [to_b3, self.out(1000, dest, XO), to_b3],
                           [B2.wit_rotate(rot23, B3.program)] * 2)
            self.send(tx, "rotate_b2_to_b3")
        self.rec("result", "PASS")

    def wallet_spk_v1(self):
        """A 32-byte program nobody here signs for: what a thief would name."""
        return sha256(b"o2 thief program")


if __name__ == "__main__":
    O2().main()
