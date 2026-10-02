"""S3: custom signature hash. Two keys sign a hash of outputs 0..m-1 plus a
salt and nothing about the input, so one signature pair spends any coin that
carries the program. Variant `bind`: the message also covers the spent coin's
asset and amount. Tapscript reference (T10): 215-byte script, 280 vB (m = 1)
and 358 vB (m = 2)."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

TAG = b"ArcaRbd1"
LEAF = 1_0000_0000
FEE = 600
BIND_SRC = ("    let (a, v): (Asset1, Amount1) = jet::current_amount();\n"
            "    let ctx: Ctx8 = jet::asset_amount_hash(ctx, a, v);")


def loop_src(bind):
    return (src("rebind_loop.simf.in").replace("%%BIND%%", BIND_SRC if bind else "")
            .replace("%%BINDDOC%%", "|| 0x01 || asset || 0x01 || amount_be8 of the spent coin " if bind else ""))


def fixed_src(m, bind):
    outs = "\n".join("    let ctx: Ctx8 = add_out(ctx, %d);" % j for j in range(m))
    return (src("rebind_fixed.simf.in").replace("%%M%%", str(m)).replace("%%OUTS%%", outs)
            .replace("%%BIND%%", BIND_SRC if bind else "")
            .replace("%%BINDDOC%%", "|| 0x01 || asset || 0x01 || amount_be8 of the spent coin " if bind else ""))


def message(salt, outs, bind=None):
    """outs = [(asset32, value, spk)]; bind = (asset32, amount) of the spent coin or None."""
    acc = TAG + salt + bytes([len(outs)])
    for a, v, s in outs:
        acc += output_hash(a, v, s)
    if bind:
        acc += b"\x01" + bind[0] + b"\x01" + int(bind[1]).to_bytes(8, "big")
    return sha256(acc)


class S3(SimBase, BitcoinTestFramework):
    NAME = "s3"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.a_sec, self.s_sec = generate_privkey(), generate_privkey()
        self.a_x = compute_xonly_pubkey(self.a_sec)[0]
        self.s_x = compute_xonly_pubkey(self.s_sec)[0]
        # the sibling leaves of the tapscript leaf, so the control block is 65 bytes as in T10
        self.sib = ("exit", bytes(CScript([6, OP_CHECKSEQUENCEVERIFY, OP_DROP, self.a_x, OP_CHECKSIG])))
        self.rec("source/loop", loop_src(False))
        self.rec("source/loop_bind", loop_src(True))
        self.rec("source/fixed_m2", fixed_src(2, False))
        self.rec("source/fixed_m2_bind", fixed_src(2, True))
        for form in ("loop", "fixed"):
            for bind in (False, True):
                for m in (1, 2):
                    self.case(form, bind, m)
        for m in (3, 4):
            self.case("loop", False, m, negatives=False)
            self.case("fixed", False, m, negatives=False)

    def prog(self, form, bind, m, salt):
        args = {"A": vpub(self.a_x), "S": vpub(self.s_x), "SALT": v256(salt),
                "TAG": {"value": "0x" + TAG.hex(), "type": "u64"}}
        source = loop_src(bind) if form == "loop" else fixed_src(m, bind)
        return SimProg(source, args, sibling=self.sib)

    def wit(self, form, m, sig_a, sig_s):
        w = {"SIG_A": vsig(sig_a), "SIG_S": vsig(sig_s)}
        if form == "loop":
            w["M"] = vu(m, 8)
        return w

    def case(self, form, bind, m, negatives=True):
        node = self.node
        tag = "%s%s_m%d" % (form, "_bind" if bind else "", m)
        self.log.info("=== S3 %s ===", tag)
        salt = os.urandom(32)
        prog = self.prog(form, bind, m, salt)
        self.rec(tag + "/program", prog.info())
        # committed outputs: m new leaves (plain P2TR stand-ins), total LEAF - FEE
        spks = [self.p2tr()[0] for _ in range(m)]
        vals = [(LEAF - FEE) // m] * m
        vals[0] += (LEAF - FEE) - sum(vals)
        couts = [(self.X_ID, v, s) for v, s in zip(vals, spks)]
        good = [self.out(v, s, self.X_OUT) for v, s in zip(vals, spks)]
        # signed BEFORE any coin exists
        msg = message(salt, couts, (self.X_ID, LEAF) if bind else None)
        sig_a, sig_s = sign_schnorr(self.a_sec, msg), sign_schnorr(self.s_sec, msg)
        W = self.wit(form, m, sig_a, sig_s)

        # coin 1: one input, uncommitted remainder is the fee
        u1 = self.fund(prog.spk, LEAF, self.X)
        tx = self.mktx([u1], good + [self.fee(FEE, self.X_OUT)])
        r = self.sim_satisfy(prog, tx, 0, W)
        PB, WB = tx.wit.vtxinwit[0].scriptWitness.stack[1], tx.wit.vtxinwit[0].scriptWitness.stack[0]
        meas = self.sim_measure(tx, 0, r)

        def raw(u, outs, extra_in=(), wb=WB):
            t = self.mktx([u] + list(extra_in), outs)
            self.set_sim_wit(t, 0, prog, PB, wb)
            return self.wallet_sign(t) if extra_in else t

        if negatives:
            self.reject(raw(u1, [self.out(vals[0] - 1, spks[0], self.X_OUT)] + good[1:] + [self.fee(FEE + 1, self.X_OUT)]),
                        tag + "/neg_output0_value_minus1")
            self.reject(raw(u1, [self.out(vals[0], self.p2tr()[0], self.X_OUT)] + good[1:] + [self.fee(FEE, self.X_OUT)]),
                        tag + "/neg_output0_other_script")
            y = self.wallet_utxo(vals[0], self.Y)
            self.reject(raw(u1, [self.out(vals[0], spks[0], self.Y_OUT)] + good[1:] +
                            [self.out(vals[0], self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)], [y]),
                        tag + "/neg_output0_other_asset")
            if m == 2:
                self.reject(raw(u1, [good[1], good[0], self.fee(FEE, self.X_OUT)]), tag + "/neg_outputs_swapped")
            # signatures made for another salt
            msg2 = message(os.urandom(32), couts, (self.X_ID, LEAF) if bind else None)
            wb = bit_replace(bit_replace(WB, sig_a, sign_schnorr(self.a_sec, msg2)), sig_s, sign_schnorr(self.s_sec, msg2))
            self.reject(raw(u1, good + [self.fee(FEE, self.X_OUT)], wb=wb), tag + "/neg_sigs_for_other_salt")
            wb = bit_replace(WB, sig_a, sign_schnorr(generate_privkey(), msg))
            self.reject(raw(u1, good + [self.fee(FEE, self.X_OUT)], wb=wb), tag + "/neg_sig_A_by_stranger")
            wb = bit_replace(WB, sig_s, sign_schnorr(generate_privkey(), msg))
            self.reject(raw(u1, good + [self.fee(FEE, self.X_OUT)], wb=wb), tag + "/neg_sig_S_by_stranger")
            tmp = os.urandom(64)      # a random placeholder: an all-zero one can match at a shifted bit offset
            wb = bit_replace(bit_replace(bit_replace(WB, sig_a, tmp), sig_s, sig_a), tmp, sig_s)
            self.reject(raw(u1, good + [self.fee(FEE, self.X_OUT)], wb=wb), tag + "/neg_sigs_swapped")
            # a signature made over Simplicity's ordinary sig_all_hash does not satisfy it
            sh = self.sim_sighash(prog, tx, 0)
            wb = bit_replace(bit_replace(WB, sig_a, sign_schnorr(self.a_sec, sh)), sig_s, sign_schnorr(self.s_sec, sh))
            self.reject(raw(u1, good + [self.fee(FEE, self.X_OUT)], wb=wb), tag + "/neg_sig_all_hash_signatures")

        txid1 = self.send(tx, tag + "/spend_coin1", extra=meas)

        # coin 2: a different outpoint, same program; broadcaster adds a fee input
        # and extra outputs after index m-1. SAME witness bytes.
        u2 = self.fund(prog.spk, LEAF, self.X)
        assert (u2.txid, u2.vout) != (u1.txid, u1.vout)
        w = self.wallet_utxo(50_000)
        outs = good + [self.out(FEE, self.wallet_spk(), self.X_OUT),
                       self.out(50_000 - 1000, self.wallet_spk(), self.POL_OUT), self.fee(1000, self.POL_OUT)]
        tx2 = raw(u2, outs, [w])
        st1 = tx.wit.vtxinwit[0].scriptWitness.stack
        st2 = tx2.wit.vtxinwit[0].scriptWitness.stack
        self.send(tx2, tag + "/spend_coin2_same_witness",
                  extra={"same_witness_bytes_as_coin1": st1[0] == st2[0], "same_program_bytes": st1[1] == st2[1],
                         "coin1": "%s:%d" % (u1.txid, u1.vout), "coin2": "%s:%d" % (u2.txid, u2.vout)})

        if not negatives:
            return
        # coin 3: same program, DIFFERENT amount (LEAF + 5000). Same signatures.
        u3 = self.fund(prog.spk, LEAF + 5000, self.X)
        tx3 = raw(u3, good + [self.fee(FEE + 5000, self.X_OUT)])
        # coin 4: same program, different ASSET (Y), same numeric amount; outputs are
        # still the signed X outputs, funded by a wallet X input.
        u4 = self.fund(prog.spk, LEAF, self.Y)
        wx = self.wallet_utxo(LEAF, self.X)
        tx4 = raw(u4, good + [self.out(LEAF, self.wallet_spk(), self.Y_OUT), self.fee(FEE, self.X_OUT)], [wx])
        if bind:
            self.reject(tx3, tag + "/neg_coin_with_other_amount")
            self.reject(tx4, tag + "/neg_coin_with_other_asset")
        else:
            self.send(tx3, tag + "/spend_coin3_other_amount_ACCEPTED")
            self.send(tx4, tag + "/spend_coin4_other_asset_ACCEPTED")


if __name__ == "__main__":
    S3().main()
