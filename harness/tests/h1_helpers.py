"""H1: the shared helpers, each in a program that uses it, accepted and refused.

Every helper is included as source (`// include <name>`). Each program here is
a keyless covenant, so a negative case reuses the valid spend's pruned program
and witness and changes only the transaction, or rewrites a witness value at
bit level where the branches taken stay the same. Every refusal is forced into
a block with `generateblock`, after the mempool's, and asserts the error. The
error of a failed assertion does not say which assertion failed, so each
negative names a control: the valid spend it differs from in the one property
it breaks, which the node accepts."""
import hashlib
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

FEE = 1000


def u(n, bits):
    return {"value": str(int(n)), "type": "u%d" % bits}


class H1(SimBase, BitcoinTestFramework):
    NAME = "h1"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.dest = self.wallet_spk()
        self.output_reader()
        self.wide_arith()
        self.state()
        self.relative_lock()
        self.merkle()
        self.fee_cap()

    # -- shared --------------------------------------------------------
    def keyless(self, prog, coin, outs, witness=None, ins=None, version=2, label=None):
        """A spend of `coin` by `prog` alone: satisfy, prune, execute, measure."""
        tx = self.mktx(ins or [coin], outs, version=version)
        r = self.sim_satisfy(prog, tx, 0, witness or {})
        return tx, r

    def reuse(self, prog, tx, r, program=None, witness=None):
        """Put the valid spend's program and witness (or rewritten ones) on `tx`."""
        self.set_sim_wit(tx, 0, prog, program or bytes.fromhex(r["program_hex"]),
                         witness if witness is not None else bytes.fromhex(r["witness_hex"]))
        return tx

    def ok_spend(self, tx, r, label, extra=None):
        """Broadcast and mine a valid spend, recording its size and cost."""
        m = self.sim_measure(tx, 0, r)
        if extra:
            m.update(extra)
        return self.send(tx, label, extra=m)

    # -- output reader -------------------------------------------------
    def output_reader(self):
        AMOUNT = 10_000_000
        spk_hash = sha256(self.dest)
        prog = SimProg(src("h_output_reader.simf"),
                       {"ASSET": v256(self.X_ID), "AMOUNT": u(AMOUNT, 64), "SPK_HASH": v256(spk_hash)})
        self.rec("output_reader/program", prog.info())
        coin = self.fund(prog.spk, AMOUNT + FEE, self.X)
        good = [self.out(AMOUNT, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)]
        tx, r = self.keyless(prog, coin, good)

        J = "Assertion failed inside jet"
        bad = self.mktx([coin], [self.out(AMOUNT - 1, self.dest, self.X_OUT), self.fee(FEE + 1, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "output_reader/neg_amount_one_short", J, control=tx)
        other = self.wallet_spk()
        bad = self.mktx([coin], [self.out(AMOUNT, other, self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "output_reader/neg_other_script", J, control=tx)
        ycoin = self.fund(prog.spk, AMOUNT + FEE, self.Y)
        bad = self.mktx([ycoin], [self.out(AMOUNT, self.dest, self.Y_OUT), self.fee(FEE, self.Y_OUT)])
        self.reject(self.reuse(prog, bad, r), "output_reader/neg_coin_of_another_asset", J,
                    control=tx, other_coin=True)
        # The right asset, amount and script, with a nonce (a blinding pubkey)
        # on the output: out_require refuses an output that is not plainly explicit.
        node = self.node
        ck = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        o0 = self.out(AMOUNT, self.dest, self.X_OUT)
        o0.nNonce = CTxOutNonce(ck)
        bad = self.mktx([coin], [o0, self.fee(FEE, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "output_reader/neg_output_carries_a_nonce", "Assertion failed",
                    control=tx)

        self.ok_spend(tx, r, "output_reader/spend")

    # -- wide arithmetic -----------------------------------------------
    def wide_arith(self):
        PRICE, SCALE, BONUS = 7_000_000_000, 10_000_000_000, 5
        X = 3_000_000_001
        product = X * PRICE                       # 21,000,000,007,000,000,000 > 2^64
        assert product >= 1 << 64
        CAP = product + BONUS
        pay = product // SCALE                    # 2,100,000,000 (floor of ...000.7)
        prog = SimProg(src("h_wide_arith.simf"),
                       {"PRICE": u(PRICE, 64), "SCALE": u(SCALE, 64), "BONUS": u(BONUS, 128), "CAP": u(CAP, 128)})
        self.rec("wide_arith/program", {**prog.info(), "x": X, "product": str(product), "pay": pay})
        coin = self.fund(prog.spk, pay + FEE, self.X)
        tx, r = self.keyless(prog, coin, [self.out(pay, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)],
                             {"X": u(X, 64), "Q": u(pay, 64)})
        wit = bytes.fromhex(r["witness_hex"])

        # The output pays one more than the quotient the witness proves.
        bad = self.mktx([coin], [self.out(pay + 1, self.dest, self.X_OUT), self.fee(FEE - 1, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "wide_arith/neg_pays_one_more_than_the_quotient",
                    "Assertion failed inside jet", control=tx)
        # A quotient one too small, paid as such: the remainder reaches the divisor.
        bad = self.mktx([coin], [self.out(pay - 1, self.dest, self.X_OUT), self.fee(FEE + 1, self.X_OUT)])
        w = bit_replace(wit, pay.to_bytes(8, "big"), (pay - 1).to_bytes(8, "big"))
        self.reject(self.reuse(prog, bad, r, witness=w), "wide_arith/neg_quotient_one_too_small",
                    "Assertion failed inside jet", control=tx)
        # A quotient one too large, paid as such: q * c passes the product.
        bad = self.mktx([coin], [self.out(pay + 1, self.dest, self.X_OUT), self.fee(FEE - 1, self.X_OUT)])
        w = bit_replace(wit, pay.to_bytes(8, "big"), (pay + 1).to_bytes(8, "big"))
        self.reject(self.reuse(prog, bad, r, witness=w), "wide_arith/neg_quotient_one_too_large",
                    "Assertion failed", control=tx)

        # X + 1: the product rises by PRICE and passes CAP; the output pays the
        # new quotient and the witness proves it, so only the 128-bit cap is broken.
        X2 = X + 1
        pay2 = X2 * PRICE // SCALE
        assert X2 * PRICE + BONUS > CAP and (X2 * PRICE + BONUS) >> 64 == CAP >> 64
        bad = self.mktx([coin], [self.out(pay2, self.dest, self.X_OUT), self.fee(pay + FEE - pay2, self.X_OUT)])
        w = bit_replace(wit, X.to_bytes(8, "big"), X2.to_bytes(8, "big"))
        w = bit_replace(w, pay.to_bytes(8, "big"), pay2.to_bytes(8, "big"))
        self.reject(self.reuse(prog, bad, r, witness=w), "wide_arith/neg_product_over_the_128_bit_cap",
                    "Assertion failed", control=tx)

        self.ok_spend(tx, r, "wide_arith/spend")

    # -- state skeleton ------------------------------------------------
    def state(self):
        AMT = 5_0000_0000
        hi = bytes.fromhex("a5" * 24)
        st = lambda n: hi + int(n).to_bytes(8, "big")
        base = SimProg(src("h_state.simf"), {}, data=st(0))
        at = lambda n: base.with_data(st(n))
        self.rec("state/program", {**base.info(), "scriptPubKey": None, "spk_state7": at(7).spk.hex()})
        coin = self.fund(at(7).spk, AMT, self.X)

        def hop(coin, n, out_state=None, out_amount=AMT, extra_outs=()):
            w = self.wallet_utxo(50_000)
            outs = [self.out(out_amount, at(n + 1 if out_state is None else out_state).spk, self.X_OUT)] \
                + list(extra_outs) + [self.out(49_000, self.wallet_spk(), self.POL_OUT), self.fee(1000, self.POL_OUT)]
            tx = self.mktx([coin, w], outs)
            return tx

        tx = hop(coin, 7)
        r = self.sim_satisfy(at(7), tx, 0, {"STATE": v256(st(7))})
        good = self.wallet_sign(tx)
        J = "Assertion failed inside jet"

        bad = self.wallet_sign(self.reuse(at(7), hop(coin, 7, out_state=9), r))
        self.reject(bad, "state/neg_successor_skips_a_state", J, control=good)
        bad = self.wallet_sign(self.reuse(at(7), hop(coin, 7, out_amount=AMT - 1,
                                                      extra_outs=[self.out(1, self.dest, self.X_OUT)]), r))
        self.reject(bad, "state/neg_successor_one_atom_short", J, control=good)
        # The witness claims state 6 against a data leaf holding 7, and pays the
        # successor of 6, which is 7: only the current-state check can refuse it.
        claim6 = bit_replace(bytes.fromhex(r["witness_hex"]), st(7), st(6))
        bad = self.wallet_sign(self.reuse(at(7), hop(coin, 7, out_state=7), r, witness=claim6))
        self.reject(bad, "state/neg_witness_names_another_state", J, control=good)

        txid = self.ok_spend(good, r, "state/spend_7_to_8")
        nxt = self.utxo_of(txid, at(8).spk)
        tx2 = hop(nxt, 8)
        r2 = self.sim_satisfy(at(8), tx2, 0, {"STATE": v256(st(8))})
        self.ok_spend(self.wallet_sign(tx2), r2, "state/spend_8_to_9")

    # -- relative lock -------------------------------------------------
    def relative_lock(self):
        BLOCKS = 5
        AMT = 1_0000_0000
        prog = SimProg(src("h_relative_lock.simf"), {"BLOCKS": u(BLOCKS, 16)})
        self.rec("relative_lock/program", prog.info())
        coin = self.fund(prog.spk, AMT, self.X)
        old = self.wallet_utxo(50_000)
        self.generate(self.node, BLOCKS)
        outs = [self.out(AMT - FEE, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)]
        tx, r = self.keyless(prog, coin, outs, ins=[(coin, BLOCKS)])

        bad = self.mktx([(coin, BLOCKS - 2)], outs)
        self.reject(self.reuse(prog, bad, r), "relative_lock/neg_own_sequence_below_the_lock",
                    "Assertion failed inside jet", control=tx)
        bad = self.mktx([(coin, BLOCKS)], outs, version=1)
        self.reject(self.reuse(prog, bad, r), "relative_lock/neg_version_1_turns_bip68_off",
                    "Assertion failed inside jet", control=tx)
        # The bypass that defeats the broken jets: this input's lock disabled,
        # an old coin of the spender's own carrying the sequence instead.
        outs2 = [self.out(AMT - FEE, self.dest, self.X_OUT), self.out(50_000, self.wallet_spk(), self.POL_OUT),
                 self.fee(FEE, self.X_OUT)]
        bad = self.mktx([(coin, 0xffffffff), (old, BLOCKS)], outs2)
        # The control: the same two inputs and outputs, the lock on the coin itself.
        ctl = self.wallet_sign(self.reuse(prog, self.mktx([(coin, BLOCKS), (old, 0xffffffff)], outs2), r))
        self.reject(self.wallet_sign(self.reuse(prog, bad, r)), "relative_lock/neg_lock_on_another_input",
                    "Assertion failed", control=ctl)

        self.ok_spend(tx, r, "relative_lock/spend")

    # -- Merkle fold ---------------------------------------------------
    def merkle(self):
        AMT = 1_0000_0000
        members = [hashlib.sha256(b"member %d" % i).digest() for i in range(256)]
        level = [sha256(b"\x00" + m) for m in members]
        tree = [level]
        while len(level) > 1:
            level = [sha256(b"\x01" + level[i] + level[i + 1]) for i in range(0, len(level), 2)]
            tree.append(level)
        root = level[0]
        index = 77
        proof, k = [], index
        for lvl in tree[:-1]:
            sib = lvl[k ^ 1]
            proof.append((sib, k & 1 == 1))       # the sibling is on the left when this node is a right child
            k >>= 1
        proof_v = "[" + ", ".join("(0x%s, %s)" % (s.hex(), "true" if left else "false") for s, left in proof) + "]"
        prog = SimProg(src("h_merkle.simf"), {"ROOT": v256(root)})
        self.rec("merkle/program", {**prog.info(), "members": 256, "index": index})
        coin = self.fund(prog.spk, AMT, self.X)
        outs = [self.out(AMT - FEE, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)]
        tx, r = self.keyless(prog, coin, outs, {"MEMBER": v256(members[index]),
                                                "PROOF": vraw(proof_v, "[(u256, bool); 8]")})
        wit = bytes.fromhex(r["witness_hex"])

        bad = self.mktx([coin], outs)
        w = bit_replace(wit, proof[3][0], hashlib.sha256(b"not a node").digest())
        self.reject(self.reuse(prog, bad, r, witness=w), "merkle/neg_wrong_sibling_at_level_3",
                    "Assertion failed inside jet", control=tx)
        bad = self.mktx([coin], outs)
        w = bit_replace(wit, members[index], hashlib.sha256(b"not a member").digest())
        self.reject(self.reuse(prog, bad, r, witness=w), "merkle/neg_not_a_member",
                    "Assertion failed inside jet", control=tx)

        self.ok_spend(tx, r, "merkle/spend_depth_8")

    # -- fee cap -------------------------------------------------------
    def fee_cap(self):
        CAP, FEE = 500, 300                       # a fee under the cap, above the relay floor
        AMT = 1_0000_0000
        prog = SimProg(src("h_fee_cap.simf"), {"ASSET": v256(self.X_ID), "CAP": u(CAP, 64)})
        self.rec("fee_cap/program", prog.info())
        coin = self.fund(prog.spk, AMT, self.X)
        tx, r = self.keyless(prog, coin, [self.out(AMT - FEE, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)])

        bad = self.mktx([coin], [self.out(AMT - 600, self.dest, self.X_OUT), self.fee(600, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "fee_cap/neg_fee_over_the_cap",
                    "Assertion failed inside jet", control=tx)
        bad = self.mktx([coin], [self.out(AMT - CAP - 1, self.dest, self.X_OUT), self.fee(CAP + 1, self.X_OUT)])
        self.reject(self.reuse(prog, bad, r), "fee_cap/neg_fee_one_over_the_cap",
                    "Assertion failed inside jet", control=tx)

        self.ok_spend(tx, r, "fee_cap/spend")

        # The cap is per asset: a fee paid in another asset is not counted. A
        # template that must bound every fee caps each asset it lets pay one.
        coin = self.fund(prog.spk, AMT, self.X)
        w = self.wallet_utxo(50_000)
        tx = self.mktx([coin, w], [self.out(AMT, self.dest, self.X_OUT), self.out(50_000 - 600, self.wallet_spk(),
                                   self.POL_OUT), self.fee(600, self.POL_OUT)])
        self.reuse(prog, tx, r)
        self.ok_spend(self.wallet_sign(tx), r, "fee_cap/fee_in_another_asset_is_not_capped")


if __name__ == "__main__":
    H1().main()
