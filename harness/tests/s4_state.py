"""S4: a covenant output that commits to a 64-bit state (an expiry) in a
taproot data leaf, and can only be re-created with a LARGER state, same
program, same asset, same amount, on one key's signature."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

AMT = 16_0000_0000
HI = 0xA5C3F00D << 32          # distinctive high half; the low 32 bits are the expiry height


def be8(n):
    return int(n).to_bytes(8, "big")


class S4(SimBase, BitcoinTestFramework):
    NAME = "s4"

    def set_test_params(self):
        self.chain_params()

    def cov(self, state):
        return self.base.with_data(be8(state))

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.s_sec = generate_privkey()
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        source = src("state_extend.simf")
        self.rec("source", source)
        self.base = SimProg(source, {"S": vpub(self.s_x)}, data=be8(0))
        h0 = node.getblockcount()
        st0, st1, st2 = HI | (h0 + 40), HI | (h0 + 60), HI | (h0 + 75)
        c0, c1, c2 = self.cov(st0), self.cov(st1), self.cov(st2)
        self.rec("program", {**self.base.info(), "scriptPubKey": None, "state0": hex(st0), "spk_state0": c0.spk.hex(),
                             "state1": hex(st1), "spk_state1": c1.spk.hex(),
                             "data_leaf_state0": tapdata_hash(be8(st0)).hex()})
        assert c0.spk != c1.spk and c0.cmr == c1.cmr

        u = self.fund(c0.spk, AMT, self.X)

        def extend_tx(u, cin, old, new, out0=None, extra_outs=(), extra_in=(), signer=None, wit_old=None, wit_new=None,
                      cov_index=0, valid=True, change=True):
            """inputs: covenant (+ wallet fee input [+extra]); outputs: covenant' , policy change, fee."""
            w = self.wallet_utxo(50_000)
            o = out0 if out0 is not None else self.out(u.amount, self.cov(new).spk, self.X_OUT)
            ins = [u, w] + list(extra_in)
            outs = [o] + list(extra_outs) + ([self.out(49_000, self.wallet_spk(), self.POL_OUT)] if change else []) \
                + [self.fee(1000, self.POL_OUT)]
            if cov_index == 1:
                ins = [w, u] + list(extra_in)
                outs = [outs[1], o] + outs[2:] if valid else outs
            tx = self.mktx(ins, outs)
            msg = self.sim_sighash(cin, tx, cov_index)
            sig = sign_schnorr(signer or self.s_sec, msg)
            W = {"OLD": vu(wit_old if wit_old is not None else old), "SIG": vsig(sig),
                 "PATH": vraw("Left(%d)" % (wit_new if wit_new is not None else new), "Either<u64, ()>")}
            return tx, W, sig

        # ---- the valid extension st0 -> st1 (gives the pruned EXTEND program)
        tx, W, sig = extend_tx(u, c0, st0, st1)
        r = self.sim_satisfy(c0, tx, 0, W)
        PB = tx.wit.vtxinwit[0].scriptWitness.stack[1]
        WB = tx.wit.vtxinwit[0].scriptWitness.stack[0]
        meas = self.sim_measure(tx, 0, r)
        self.rec("extend/witness_layout", {"order": "OLD(64 bits) SIG(512 bits) PATH tag(1 bit) NEW(64 bits), bit-packed",
                                           "witness_bytes": len(WB)})
        valid_tx = self.wallet_sign(tx)

        def neg(label, **kw):
            """Build a refused extension: the EXTEND program as pruned for the valid
            spend, with OLD / NEW / SIG re-written in the witness bit stream."""
            wo, wn = kw.get("wit_old", st0), kw.get("wit_new", kw.get("new", st1))
            t, _, s = extend_tx(u, c0, st0, kw.pop("new", st1), **kw)
            wb = bit_replace(WB, sig, s)
            if wo != st0:
                wb = bit_replace(wb, be8(st0), be8(wo))
            if wn != st1:
                wb = bit_replace(wb, be8(st1), be8(wn))
            ci = kw.get("cov_index", 0)
            self.set_sim_wit(t, ci, c0, PB, wb)
            self.reject(self.wallet_sign(t), "extend/" + label)

        neg("neg_state_lowered", new=st0 - 1)
        neg("neg_state_equal", new=st0)
        neg("neg_witness_claims_higher_new_than_output_commits", new=st0 - 1, wit_new=st1)
        neg("neg_witness_claims_lower_old", wit_old=st0 - 30)
        neg("neg_amount_reduced_by_1", out0=self.out(AMT - 1, c1.spk, self.X_OUT),
            extra_outs=[self.out(1, self.wallet_spk(), self.X_OUT)])
        x1 = self.wallet_utxo(1, self.X)
        neg("neg_amount_increased_by_1", out0=self.out(AMT + 1, c1.spk, self.X_OUT), extra_in=[x1])
        y = self.wallet_utxo(AMT, self.Y)
        neg("neg_other_asset_same_amount", out0=self.out(AMT, c1.spk, self.Y_OUT),
            extra_outs=[self.out(AMT, self.wallet_spk(), self.X_OUT)], extra_in=[y])
        other = SimProg(src("p2pk.simf"), {"PK": vpub(self.s_x)}, data=be8(st1))
        neg("neg_different_program_same_data_leaf", out0=self.out(AMT, other.spk, self.X_OUT))
        neg("neg_plain_p2tr_of_S", out0=self.out(AMT, bytes(taproot_construct(self.s_x).scriptPubKey), self.X_OUT))
        neg("neg_wrong_signer", signer=generate_privkey())
        # covenant output at the wrong index (input 0, successor at output 1)
        w2 = self.wallet_spk()
        neg("neg_successor_at_other_index", out0=self.out(49_000, w2, self.POL_OUT),
            extra_outs=[self.out(AMT, c1.spk, self.X_OUT)], change=False)
        # SWEEP before expiry, lock time = current height (below the committed expiry)
        def sweep_tx(u, cin, state, locktime, signer=None):
            tx = self.mktx([(u, 0xfffffffe)], [self.out(u.amount - 400, self.wallet_spk(), self.X_OUT),
                                               self.fee(400, self.X_OUT)], locktime)
            msg = self.sim_sighash(cin, tx, 0)
            sig = sign_schnorr(signer or self.s_sec, msg)
            return tx, {"OLD": vu(state), "SIG": vsig(sig), "PATH": vraw("Right(())", "Either<u64, ()>")}, sig

        # ---- positive: st0 -> st1, then st1 -> st2 with the covenant at index 1
        txid = self.send(valid_tx, "extend/st0_to_st1", extra=meas)
        u1 = self.utxo_at(txid, 0)
        assert u1.spk == c1.spk and u1.amount == AMT
        tx, W, sig = extend_tx(u1, c1, st1, st2, cov_index=1)
        r = self.sim_satisfy(c1, tx, 1, W)
        tx = self.wallet_sign(tx)
        st = tx.wit.vtxinwit[1].scriptWitness.stack
        txid = self.send(tx, "extend/st1_to_st2_at_index1",
                         extra={"program_bytes": len(st[1]), "witness_bytes": len(st[0]),
                                "same_program_bytes_as_first_extension": st[1] == PB,
                                "cost_bound_wu": (r["cost_milli"] + 999) // 1000})
        u2 = self.utxo_at(txid, 1)
        assert u2.spk == c2.spk and u2.amount == AMT

        # ---- SWEEP: refused before the (twice extended) expiry, allowed at it
        exp2 = st2 & 0xffffffff
        exp0 = st0 & 0xffffffff
        self.mine_to(exp0 + 1)                      # the ORIGINAL expiry has passed
        h = node.getblockcount()
        assert exp0 < h < exp2
        # (i) lock time = the old expiry: final now, but below the committed state
        tx, W, sig = sweep_tx(u2, c2, st2, exp0)
        # get a pruned SWEEP program from a valid sweep built for the real expiry
        txv, Wv, sigv = sweep_tx(u2, c2, st2, exp2)
        rv = self.sim_satisfy(c2, txv, 0, Wv)
        PS, WS = txv.wit.vtxinwit[0].scriptWitness.stack[1], txv.wit.vtxinwit[0].scriptWitness.stack[0]
        self.set_sim_wit(tx, 0, c2, PS, bit_replace(WS, sigv, sig))
        self.reject(tx, "sweep/neg_locktime_at_original_expiry_after_extension")
        # (ii) lock time = the committed expiry, but the chain is not there yet
        self.reject(txv, "sweep/neg_before_expiry_nonfinal")
        # (iii) claiming the old state in the witness
        tx, W, sig = sweep_tx(u2, c2, st0, exp0)
        self.set_sim_wit(tx, 0, c2, PS, bit_replace(bit_replace(WS, sigv, sig), be8(st2), be8(st0)))
        self.reject(tx, "sweep/neg_witness_claims_original_state")
        self.mine_to(exp2)
        tx, W, sig = sweep_tx(u2, c2, st2, exp2, signer=generate_privkey())
        self.set_sim_wit(tx, 0, c2, PS, bit_replace(WS, sigv, sig))
        self.reject(tx, "sweep/neg_wrong_signer")
        self.send(txv, "sweep/after_expiry", extra=self.sim_measure(txv, 0, rv))


if __name__ == "__main__":
    S4().main()
