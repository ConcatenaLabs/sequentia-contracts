"""S2: covenant tree node at radix 4 in Simplicity, against the tapscript
node (94-byte compact unroll leaf, 452 vB)."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

CHILD = 1_0000_0000
RESERVE = 1000


def plain_src(r):
    return src("node_plain.simf.in").replace(
        "%%CHECKS%%", "\n".join("    check(%d, param::V%d, param::S%d);" % (i, i, i) for i in range(r)))


def compact_src(r):
    return src("node_compact.simf.in").replace(
        "%%ADDS%%", "\n".join("    let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, unwrap(jet::output_hash(%d)));" % i
                              for i in range(r)))


def chain_src(r):
    return src("node_chain.simf.in").replace(
        "%%STEPS%%", "\n".join("    let h: u256 = jet::sha_256_block(h, unwrap(jet::output_hash(%d)), unwrap(jet::output_hash(%d)));"
                               % (i, i + 1) for i in range(0, r, 2)))


class S2(SimBase, BitcoinTestFramework):
    NAME = "s2"
    # The plain form checks the child's fields one by one with `assert!` on a
    # match or a bool; the compact and chain forms compare jet results.
    BLINDED = {"plain": "Assertion failed", "compact": "Assertion failed inside jet",
               "chain": "Assertion failed inside jet"}
    NONCE = {"plain": "Assertion failed", "compact": "Assertion failed inside jet",
             "chain": "Assertion failed inside jet"}

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X))
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        self.rec("source/plain_r4", plain_src(4))
        self.rec("source/compact_r4", compact_src(4))
        self.rec("source/chain_r4", chain_src(4))
        for r in (2, 4, 8):
            for form in ("plain", "compact", "chain"):
                for tree in ("with_sweep_leaf", "single_leaf"):
                    self.case(r, form, tree, negatives=(r == 4 and tree == "with_sweep_leaf"))

    def make(self, r, form, tree):
        spks = [self.p2tr()[0] for _ in range(r)]
        expiry = self.node.getblockcount() + 2000
        if form == "plain":
            args = {"ASSET": v256(self.X_ID)}
            for i, spk in enumerate(spks):
                args["V%d" % i] = vu(CHILD)
                args["S%d" % i] = v256(sha256(spk))
            source = plain_src(r)
        elif form == "compact":
            h = sha256(b"".join(output_hash(self.X_ID, CHILD, spk) for spk in spks))
            args = {"H": v256(h)}
            source = compact_src(r)
        else:
            h = SHA256_IV
            for i in range(0, r, 2):
                h = sha256_block(h, output_hash(self.X_ID, CHILD, spks[i]) + output_hash(self.X_ID, CHILD, spks[i + 1]))
            args = {"H": v256(h)}
            source = chain_src(r)
        sib = ("sweep", sweep_leaf(expiry, self.s_x)) if tree == "with_sweep_leaf" else None
        return spks, SimProg(source, args, sibling=sib)

    def case(self, r, form, tree, negatives):
        node = self.node
        tag = "r%d_%s_%s" % (r, form, tree)
        self.log.info("=== S2 %s ===", tag)
        spks, prog = self.make(r, form, tree)
        self.rec(tag + "/program", prog.info())
        total = r * CHILD + RESERVE
        good = [self.out(CHILD, spk, self.X_OUT) for spk in spks]
        u = self.fund(prog.spk, total, self.X)

        # the valid spend: gives the (pruned) program + witness bytes, which do not
        # depend on the transaction (no signature), so negatives reuse them.
        tx = self.mktx([u], good + [self.fee(RESERVE, self.X_OUT)])
        rr = self.sim_satisfy(prog, tx, 0, {})
        P, W = tx.wit.vtxinwit[0].scriptWitness.stack[1], tx.wit.vtxinwit[0].scriptWitness.stack[0]

        def unroll(outs, extra_in=()):
            t = self.mktx([u] + list(extra_in), outs)
            self.set_sim_wit(t, 0, prog, P, W)
            return self.wallet_sign(t) if extra_in else t

        if negatives:
            # Each refusal names its control: the valid unroll it differs from
            # in the one property it breaks, accepted by the node.
            J = "Assertion failed inside jet"
            ok = unroll(good + [self.fee(RESERVE, self.X_OUT)])
            y = self.wallet_utxo(CHILD, self.Y)
            outs = [self.out(CHILD, spks[0], self.Y_OUT)] + good[1:] + \
                   [self.out(CHILD, self.wallet_spk(), self.X_OUT), self.fee(RESERVE, self.X_OUT)]
            ctl = good + [self.out(CHILD, self.wallet_spk(), self.Y_OUT), self.fee(RESERVE, self.X_OUT)]
            self.reject(unroll(outs, [y]), tag + "/neg_wrong_asset", J, control=unroll(ctl, [y]))
            outs = [self.out(CHILD - 1, spks[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE + 1, self.X_OUT)]
            self.reject(unroll(outs), tag + "/neg_wrong_value_minus1", J, control=ok)
            x1 = self.wallet_utxo(1000, self.X)
            outs = [self.out(CHILD + 1, spks[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE + 999, self.X_OUT)]
            ctl = good + [self.fee(RESERVE + 1000, self.X_OUT)]
            self.reject(unroll(outs, [x1]), tag + "/neg_wrong_value_plus1", J, control=unroll(ctl, [x1]))
            outs = [self.out(CHILD, self.p2tr()[0], self.X_OUT)] + good[1:] + [self.fee(RESERVE, self.X_OUT)]
            self.reject(unroll(outs), tag + "/neg_wrong_script", J, control=ok)
            outs = [good[1], good[0]] + good[2:] + [self.fee(RESERVE, self.X_OUT)]
            self.reject(unroll(outs), tag + "/neg_wrong_index_swap", J, control=ok)
            outs = [self.fee(RESERVE, self.X_OUT)] + good
            self.reject(unroll(outs), tag + "/neg_wrong_index_shift", J, control=ok)
            blinded, explicit = self.blinded_tx(u, prog, P, W, spks, good)
            self.reject(blinded, tag + "/neg_blinded_child", self.BLINDED[form], control=explicit)
            outs = good[:-1] + [self.fee(RESERVE + CHILD, self.X_OUT)]
            self.reject(unroll(outs), tag + "/neg_missing_child", J, control=ok)
            # the T1c substitution: child 0 as witness v0 with the 33-byte program P||0x01.
            # Relay policy refuses the output script first; the block refuses the covenant.
            bad = bytes([0x00, 0x21]) + spks[0][2:] + b"\x01"
            outs = [self.out(CHILD, bad, self.X_OUT)] + good[1:] + [self.fee(RESERVE, self.X_OUT)]
            self.reject(unroll(outs), tag + "/neg_v0_33byte_program_substitution", J,
                        mempool="scriptpubkey", control=ok)
            # an unpruned program (plain form only: it still holds its FAIL nodes)
            if form == "plain":
                t = self.mktx([u], good + [self.fee(RESERVE, self.X_OUT)])
                self.sim_satisfy(prog, t, 0, {}, prune=False)
                self.reject(t, tag + "/neg_unpruned_program", "Program has FAIL node")
            # child 0 explicit but carrying a nonce (an ECDH pubkey): same asset, value, script
            ck = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
            o0 = self.out(CHILD, spks[0], self.X_OUT)
            o0.nNonce = CTxOutNonce(ck)
            t = unroll([o0] + good[1:] + [self.fee(RESERVE, self.X_OUT)])
            self.reject(t, tag + "/neg_explicit_child_with_nonce", self.NONCE[form], control=ok)

        # positive A: fee from the in-node reserve
        tx = unroll(good + [self.fee(RESERVE, self.X_OUT)])
        m = self.sim_measure(tx, 0, rr)
        txid = self.send(tx, tag + "/unroll_reserve_fee", extra=m)
        for i in range(r):
            o = node.gettxout(txid, i)
            assert o["scriptPubKey"]["hex"] == spks[i].hex() and o["asset"] == self.X

        # positive B: broadcaster adds a fee input and three more outputs
        if tree == "with_sweep_leaf":
            spks, prog = self.make(r, form, tree)
            good = [self.out(CHILD, spk, self.X_OUT) for spk in spks]
            u = self.fund(prog.spk, total, self.X)
            w = self.wallet_utxo(100000)
            FEE = 2000
            outs = good + [self.out(RESERVE, self.wallet_spk(), self.X_OUT),
                           self.out(100000 - FEE, self.wallet_spk(), self.POL_OUT),
                           self.fee(FEE, self.POL_OUT)]
            tx = self.mktx([u, w], outs)
            rr = self.sim_satisfy(prog, tx, 0, {})
            tx = self.wallet_sign(tx)
            self.send(tx, tag + "/unroll_external_fee", extra=self.sim_measure(tx, 0, rr))

    def blinded_tx(self, u, prog, P, W, spks, good):
        node = self.node
        ck0 = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        chg_addr = node.getnewaddress("", "blech32")
        chg_info = node.getaddressinfo(chg_addr)
        chg_spk = bytes.fromhex(node.getaddressinfo(chg_info["unconfidential"])["scriptPubKey"])
        x = self.wallet_utxo(25000, self.X)
        o0 = self.out(CHILD, spks[0], self.X_OUT)
        o0.nNonce = CTxOutNonce(ck0)
        oc = self.out(5000, chg_spk, self.X_OUT)
        oc.nNonce = CTxOutNonce(bytes.fromhex(chg_info["confidential_key"]))
        outs = [o0] + good[1:] + [oc, self.fee(RESERVE + 20000, self.X_OUT)]
        tx = self.mktx([u, x], outs)
        z = "00" * 32
        blinded = node.rawblindrawtransaction(
            tx.serialize().hex(), [z, z],
            [Decimal(u.amount) / COIN, Decimal(25000) / COIN],
            [self.X, self.X], [z, z], "", False)
        t2 = Tx.from_hex(blinded)
        assert t2.vout[0].nAsset.vchCommitment[0] in (0x0a, 0x0b)
        assert bytes(t2.vout[0].scriptPubKey) == spks[0]
        t2.prev = tx.prev
        self.pad(t2)
        self.set_sim_wit(t2, 0, prog, P, W)
        # The control: the same inputs and outputs, nothing blinded.
        explicit = self.mktx([u, x], good + [self.out(5000, chg_spk, self.X_OUT),
                                             self.fee(RESERVE + 20000, self.X_OUT)])
        self.set_sim_wit(explicit, 0, prog, P, W)
        return self.wallet_sign(t2), self.wallet_sign(explicit)


if __name__ == "__main__":
    S2().main()
