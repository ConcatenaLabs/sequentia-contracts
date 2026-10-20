"""E1: the subscription escrow, addressed and spent from its descriptor.

The template `subscription_escrow` holds one subscription's payment:

    P2TR(NUMS, {{release, cancel}, {refund, H_TapData(SUBSCRIPTION)}})

all three leaves tapscript. The issuer releases, with its key and once the
offering has closed, every subscription's coin into one transaction whose
output 0 pays the issuer at least the minimum; the issuer cancels a
subscription at any time, the coin going back to the subscriber; and after a
deadline anyone refunds a subscription to the subscriber, with no signature,
keeping back at most a capped fee.

Each instance is derived by the Python mirror from the descriptor alone.
A release of two subscriptions, a cancel, and a refund of two subscriptions
in one transaction after the deadline confirm. Every violation is refused by
the mempool and in a block forced with `generateblock`, each for its reason;
a refusal whose error does not name its check comes with a control. The
payment asset and the fee asset are issued assets; the policy asset pays
nothing."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

LOCKTIME = "Locktime requirement not satisfied"
NONFINAL, NONFINAL_MEMPOOL = "bad-txns-nonfinal", "non-final"
EQV, VFY = "Script failed an OP_EQUALVERIFY operation", "Script failed an OP_VERIFY operation"
BADSIG = "Invalid Schnorr signature"
MINIMUM = 1_000_000_000              # atoms of X
FEE_CAP = 10_000                     # atoms of the coin's asset a refund may keep back
FEE = 3000


class Escrow:
    """One subscription's instance."""

    def __init__(self, t, sub_id, refund_spk, amount):
        self.t, self.sub_id, self.refund_spk, self.amount = t, sub_id, refund_spk, amount
        p = {"PAY_ASSET": t.X_ID.hex(), "ISSUER_KEY": t.issuer_pk.hex(),
             "ISSUER_SCRIPT": sha256(t.issuer_spk).hex(), "MINIMUM": "%016x" % MINIMUM,
             "CLOSE": "%08x" % t.close, "REFUND_SCRIPT": sha256(refund_spk).hex(),
             "DEADLINE": "%08x" % t.deadline, "FEE_CAP": "%016x" % FEE_CAP,
             "SUBSCRIPTION": "%064x" % sub_id}
        self.params = p
        self.x = t.sa.derive(t.desc, p, {})
        info = t.node.getaddressinfo(self.x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == self.x["script_pubkey"], info
        self.spk = bytes.fromhex(self.x["script_pubkey"])

    def leaf(self, name):
        l = self.x["leaves"][name]
        return bytes.fromhex(l["script"]), bytes.fromhex(l["control_block"])


class E1(SimBase, BitcoinTestFramework):
    NAME = "e1"

    def set_test_params(self):
        self.chain_params()

    def coins(self, n, asset, atoms):
        node = self.node
        addrs = [node.getnewaddress("", "bech32") for _ in range(n)]
        txid = node.sendmany(dummy="", amounts={a: Decimal(atoms) / COIN for a in addrs},
                             output_assets={a: asset for a in addrs}, fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        tx = tx_from_hex(node.getrawtransaction(txid))
        out = []
        for a in addrs:
            spk = bytes.fromhex(node.getaddressinfo(a)["scriptPubKey"])
            for i, o in enumerate(tx.vout):
                if bytes(o.scriptPubKey) == spk:
                    out.append(Utxo(txid, i, o))
        node.lockunspent(False, [{"txid": u.txid, "vout": u.vout} for u in out])
        return out

    def leafsign(self, tx, spends, sk=None):
        """Sets each escrow input's witness: `spends` is [(index, escrow, leaf)],
        signed by `sk` (the issuer's, unless given) for the keyed leaves."""
        for idx, e, name in spends:
            script, cb = e.leaf(name)
            if name == "refund":
                self.setwit(tx, idx, [script, cb])
            else:
                self.setwit(tx, idx, [self.sign(sk or self.issuer_sk, tx, idx, script), script, cb])
        return self.wallet_sign(tx)

    def release_tx(self, coins, fee_coin, locktime, out0=None, out0_spk=None, out0_asset=None, extra=()):
        total = sum(c.amount for c in coins)
        out0 = total if out0 is None else out0
        outs = [self.out(out0, out0_spk or self.issuer_spk, out0_asset or self.X_OUT)]
        if total > out0 and out0_asset is None:
            outs.append(self.out(total - out0, self.wallet_spk(), self.X_OUT))
        outs += list(extra)
        outs += [self.out(fee_coin.amount - FEE, self.change_spk, self.Y_OUT), self.fee(FEE, self.Y_OUT)]
        ins = [(c, 0xfffffffe) for c in coins] + [(fee_coin, 0xffffffff)]
        return self.mktx(ins, outs, locktime=locktime)

    def refund_tx(self, pairs, locktime, kept=None, spk=None, fee_coin=None):
        """Each (coin, escrow) at input k back to its subscriber at output k;
        the fee from the coins, in their asset, unless a fee coin is given."""
        outs, fee = [], 0
        for k, (c, e) in enumerate(pairs):
            keep = (FEE if fee_coin is None else 0) if kept is None else kept
            fee += keep
            outs.append(self.out(c.amount - keep, spk or e.refund_spk, self.X_OUT))
        ins = [(c, 0xfffffffe) for c, _ in pairs]
        if fee_coin is not None:
            ins.append((fee_coin, 0xffffffff))
            outs += [self.out(fee_coin.amount - FEE, self.change_spk, self.Y_OUT), self.fee(FEE, self.Y_OUT)]
        else:
            outs.append(self.fee(fee, self.X_OUT))
        return self.mktx(ins, outs, locktime=locktime)

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.sa, self.desc, self.vectors, _ = load_template("subscription_escrow")
        self.issuer_sk = generate_privkey()
        self.issuer_pk = compute_xonly_pubkey(self.issuer_sk)[0]
        other_sk = generate_privkey()
        self.issuer_spk, self.change_spk = self.wallet_spk(), self.wallet_spk()
        h = node.getblockcount()
        self.close, self.deadline = h + 30, h + 50
        subs = {}
        for i, (name, amount) in enumerate([("A", 600_000_000), ("B", 500_000_000), ("C", 200_000_000),
                                             ("D", 300_000_000), ("E", 100_000_000)]):
            subs[name] = Escrow(self, 1000 + i, self.wallet_spk(), amount)
        # Each subscriber pays straight into the escrow's address.
        coin = {n: self.fund(e.spk, e.amount, self.X) for n, e in subs.items()}
        for n, c in coin.items():
            assert c.spk == subs[n].spk and c.amount == subs[n].amount
        self.rec("instance", {"template_hash": self.desc["template_hash"], "minimum": MINIMUM,
                              "close": self.close, "deadline": self.deadline,
                              "addresses": {n: e.x["address"]["elementsregtest"] for n, e in subs.items()},
                              "leaf_bytes": {l: len(subs["A"].leaf(l)[0]) for l in ("release", "cancel", "refund")}})
        fees = self.coins(30, self.Y, 100_000)
        F = fees.pop
        A, B, C, D, E = (subs[n] for n in "ABCDE")
        cA, cB, cC, cD, cE = (coin[n] for n in "ABCDE")

        # ---- before the close --------------------------------------------------
        assert node.getblockcount() < self.close
        fc = F()
        self.reject(self.leafsign(self.release_tx([cA, cB], fc, node.getblockcount()), [(0, A, "release"), (1, B, "release")]),
                    "release/neg_locktime_below_the_close", LOCKTIME)
        self.reject(self.leafsign(self.release_tx([cA, cB], fc, self.close), [(0, A, "release"), (1, B, "release")]),
                    "release/neg_before_the_close_is_mined", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.reject(self.leafsign(self.refund_tx([(cC, C)], node.getblockcount()), [(0, C, "refund")]),
                    "refund/neg_locktime_below_the_deadline", LOCKTIME)

        # The cancel, at any time: D goes back to its subscriber.
        fc = F()
        good = self.leafsign(self.refund_tx([(cD, D)], 0, kept=0, fee_coin=fc), [(0, D, "cancel")])
        self.reject(self.leafsign(self.refund_tx([(cD, D)], 0, kept=0, fee_coin=fc, spk=self.wallet_spk()), [(0, D, "cancel")]),
                    "cancel/neg_to_another_script", EQV)
        over = self.refund_tx([(cD, D)], 0, kept=FEE_CAP + 1, fee_coin=fc)
        over.vout.insert(1, self.out(FEE_CAP + 1, self.wallet_spk(), self.X_OUT))
        self.pad(over)
        self.reject(self.leafsign(over, [(0, D, "cancel")]), "cancel/neg_one_atom_over_the_fee_cap", VFY)
        self.reject(self.leafsign(self.refund_tx([(cD, D)], 0, kept=0, fee_coin=fc), [(0, D, "cancel")], sk=other_sk),
                    "cancel/neg_signed_by_another_key", BADSIG)
        at_cap = self.refund_tx([(cD, D)], 0, kept=FEE_CAP, fee_coin=fc)
        at_cap.vout.insert(1, self.out(FEE_CAP, self.wallet_spk(), self.X_OUT))
        self.pad(at_cap)
        assert self.accept(self.leafsign(at_cap, [(0, D, "cancel")]))["allowed"]
        self.rec("cancel/exactly_the_fee_cap_kept_accepted", {"testmempoolaccept": True, "kept": FEE_CAP})
        self.send(good, "cancel/subscription_d_returned")

        # ---- after the close: the release ---------------------------------------
        self.mine_to(self.close)
        fc = F()
        rel = self.leafsign(self.release_tx([cA, cB], fc, self.close), [(0, A, "release"), (1, B, "release")])
        assert self.accept(rel)["allowed"]
        # Output 0 one atom under the minimum, the same coins and the rest elsewhere.
        self.reject(self.leafsign(self.release_tx([cA, cB], fc, self.close, out0=MINIMUM - 1),
                                  [(0, A, "release"), (1, B, "release")]),
                    "release/neg_output_0_one_atom_under_the_minimum", VFY)
        exact = self.leafsign(self.release_tx([cA, cB], fc, self.close, out0=MINIMUM), [(0, A, "release"), (1, B, "release")])
        assert self.accept(exact)["allowed"]
        self.rec("release/output_0_exactly_the_minimum_accepted", {"testmempoolaccept": True, "out0": MINIMUM})
        # Subscriptions short of the minimum: A and C hold 800,000,000.
        self.reject(self.leafsign(self.release_tx([cA, cC], fc, self.close), [(0, A, "release"), (1, C, "release")]),
                    "release/neg_subscriptions_short_of_the_minimum", VFY)
        self.reject(self.leafsign(self.release_tx([cA, cB], fc, self.close, out0_spk=self.wallet_spk()),
                                  [(0, A, "release"), (1, B, "release")]),
                    "release/neg_output_0_to_another_script", EQV)
        nonce = self.release_tx([cA, cB], fc, self.close)
        nonce.vout[0].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        self.reject(self.leafsign(nonce, [(0, A, "release"), (1, B, "release")]), "release/neg_output_0_carries_a_nonce", EQV)
        self.reject(self.leafsign(self.release_tx([cA, cB], fc, self.close), [(0, A, "release"), (1, B, "release")], sk=other_sk),
                    "release/neg_signed_by_another_key", BADSIG)
        # A signature made for the release leaf, on a cancel of C.
        moved = self.refund_tx([(cC, C)], 0, kept=0, fee_coin=fc)
        rs, _ = C.leaf("release")
        cs, ccb = C.leaf("cancel")
        self.setwit(moved, 0, [self.sign(self.issuer_sk, moved, 0, rs), cs, ccb])
        self.reject(self.wallet_sign(moved), "cancel/neg_signature_made_for_the_release_leaf", BADSIG)
        # The payment asset: a Y coin of the issuer's at output 0 instead.
        big_y = self.coins(1, self.Y, 2 * MINIMUM)[0]
        wrong = self.mktx([(cA, 0xfffffffe), (cB, 0xfffffffe), (big_y, 0xffffffff), (fc, 0xffffffff)],
                          [self.out(2 * MINIMUM, self.issuer_spk, self.Y_OUT),
                           self.out(cA.amount + cB.amount, self.issuer_spk, self.X_OUT),
                           self.out(fc.amount - FEE, self.change_spk, self.Y_OUT), self.fee(FEE, self.Y_OUT)],
                          locktime=self.close)
        self.reject(self.leafsign(wrong, [(0, A, "release"), (1, B, "release")]), "release/neg_output_0_in_another_asset", EQV)
        self.send(rel, "release/subscriptions_a_and_b", extra={"escrow_inputs": 2, "out0": cA.amount + cB.amount})

        # ---- after the deadline: anyone refunds C and E in one transaction ------
        self.reject(self.leafsign(self.refund_tx([(cC, C), (cE, E)], self.deadline), [(0, C, "refund"), (1, E, "refund")]),
                    "refund/neg_before_the_deadline_is_mined", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.mine_to(self.deadline)
        refund = self.leafsign(self.refund_tx([(cC, C), (cE, E)], self.deadline), [(0, C, "refund"), (1, E, "refund")])
        assert self.accept(refund)["allowed"]
        self.reject(self.leafsign(self.refund_tx([(cC, C), (cE, E)], self.deadline, spk=self.wallet_spk()),
                                  [(0, C, "refund"), (1, E, "refund")]), "refund/neg_to_another_script", EQV)
        swapped = self.refund_tx([(cC, C), (cE, E)], self.deadline)
        swapped.vout[0].scriptPubKey, swapped.vout[1].scriptPubKey = E.refund_spk, C.refund_spk
        self.reject(self.leafsign(swapped, [(0, C, "refund"), (1, E, "refund")]), "refund/neg_subscribers_swapped", EQV)
        greedy = self.refund_tx([(cC, C), (cE, E)], self.deadline, kept=FEE_CAP + 1)
        self.reject(self.leafsign(greedy, [(0, C, "refund"), (1, E, "refund")]), "refund/neg_fee_one_atom_over_the_cap", VFY)
        self.send(refund, "refund/subscriptions_c_and_e_by_anyone", extra={"escrow_inputs": 2})


if __name__ == "__main__":
    E1().main()
