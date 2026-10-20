"""V1: the verifier token, addressed and spent from its descriptor.

The template `verifier_token` holds the reissuance token of an OpenDAMP
asset's verifier asset V:

    P2TR(NUMS, TapBranch(TapLeaf_0xbe(token), H_TapData(params || state)))

with VERIFIER_ASSET, TOKEN, AMOUNT and ISSUER_KEY fixed and VERIFIER, the
SHA-256 of the scriptPubKey a resume mints into, as its state. The issuer key
records the script of input 0 when that coin holds exactly AMOUNT of V, and
resumes by reissuing exactly AMOUNT of V into the recorded script.

Two stand-ins play the asset's verifier covenant under two policies, A and B:
the same one-key program, which is what OpenDAMP's issuer path G(I) is, beside
two different data leaves, so they are two scripts the issuer key spends. The
token moves in recording A, as an issuance records its genesis verifier. The
issuer moves V from A to B (an update), then halts: V is burned from B and the
same transaction records B. The resume mints V back into B. Every violation is
refused by the mempool and in a block forced with `generateblock`, each for
its reason, against a control the node accepts that differs only in the
property it breaks. Every spend pays its fee in an issued asset from a wallet
coin, never in the policy asset."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.messages import CAssetIssuance  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
Q = 1000                              # the verifier amount, in atoms of V
TOKEN_ATOMS = 10**8                   # issueasset tokenamount=1
FEE = 3000                            # atoms of X, the fee asset
PATH_T = "Either<(), ()>"
PATHS = {"resume": "Left(())", "record": "Right(())"}
SIG_OF = {"resume": "RESUME_SIG", "record": "RECORD_SIG"}
BURN = bytes([0x6a])


class Token:
    """The instance: its parameters, and per recorded script its coin's script and leaf."""

    def __init__(self, t, v, token, entropy, issuer_pk, amount=Q):
        self.t, self.v, self.token, self.entropy = t, v, token, entropy
        self.issuer_pk, self.amount = issuer_pk, amount
        self.V_ID, self.TOKEN_ID = bytes.fromhex(v)[::-1], bytes.fromhex(token)[::-1]
        self.V_OUT, self.TOKEN_OUT = t.asset_out(v), t.asset_out(token)
        self._cache = {}

    def params(self):
        return {"VERIFIER_ASSET": self.V_ID.hex(), "TOKEN": self.TOKEN_ID.hex(), "AMOUNT": "%016x" % self.amount,
                "ISSUER_KEY": self.issuer_pk.hex()}

    def at(self, recorded_spk):
        """(script_pubkey, leaf, derivation) of the coin recording `recorded_spk`."""
        key = bytes(recorded_spk)
        if key not in self._cache:
            t = self.t
            x = t.sa.derive(t.desc, self.params(), {"VERIFIER": sha256(key).hex()})
            info = t.node.getaddressinfo(x["address"]["elementsregtest"])
            assert info["scriptPubKey"] == x["script_pubkey"], info
            leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["token"]["control_block"]))
            self._cache[key] = (bytes.fromhex(x["script_pubkey"]), leaf, x)
        return self._cache[key]

    def spk(self, recorded_spk):
        return self.at(recorded_spk)[0]


class V1(SimBase, BitcoinTestFramework):
    NAME = "v1"

    def set_test_params(self):
        self.chain_params()

    # -- helpers ---------------------------------------------------------------
    def witness(self, tok, recorded_spk, path, sig):
        w = {"VERIFIER_ASSET": v256(tok.V_ID), "TOKEN": v256(tok.TOKEN_ID), "AMOUNT": vu(tok.amount, 64),
             "ISSUER_KEY": vpub(tok.issuer_pk), "VERIFIER": v256(sha256(bytes(recorded_spk))),
             "PATH": vraw(PATHS[path], PATH_T)}
        for p, name in SIG_OF.items():
            w[name] = vsig(sig if p == path else bytes(64))
        return w

    def fee_coins(self, n, atoms=50_000):
        node = self.node
        addrs = [node.getnewaddress("", "bech32") for _ in range(n)]
        txid = node.sendmany(dummy="", amounts={a: Decimal(atoms) / COIN for a in addrs},
                             output_assets={a: self.X for a in addrs}, fee_asset=BITCOIN_ASSET)
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

    def pay(self, spk, atoms, asset):
        ver = 0 if spk[0] == 0 else spk[0] - 0x50
        txid = self.node.sendtoaddress(address=program_to_witness(ver, spk[2:]), amount=Decimal(atoms) / COIN,
                                       assetlabel=asset, fee_asset_label=BITCOIN_ASSET)
        return txid

    def wallet_sign_keep(self, tx):
        keep = {k: getattr(tx, k) for k in ("sig", "r", "leaf", "index") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in keep.items():
            setattr(t2, k, v)
        return t2

    def satisfy(self, tok, tx, recorded_spk, path, sk, index):
        leaf = tok.at(recorded_spk)[1]
        sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, index))
        r = self.sim_satisfy(leaf, tx, index, self.witness(tok, recorded_spk, path, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, r, leaf, index

    def verifier_sign(self, prog, tx, index=0):
        """The stand-in verifier's issuer path: one signature over sig_all_hash."""
        sig = sign_schnorr(self.issuer_sk, self.sim_sighash(prog, tx, index))
        self.sim_satisfy(prog, tx, index, {"SIG": vsig(sig)})

    def reuse(self, control, tx, sk=None, sig=None, msg=None, verifier=None):
        """`tx` with the control's pruned program and witness at the covenant's
        input, its signature made again by `sk` for `tx`; the stand-in
        verifier, if `tx` spends one at input 0, signs again too."""
        idx = control.index
        if verifier is not None:
            self.verifier_sign(verifier, tx, 0)
        if sig is None:
            m = msg if msg is not None else self.sim_sighash(control.leaf, tx, idx)
            sig = sign_schnorr(sk, m)
        w = bytes.fromhex(control.r["witness_hex"])
        self.set_sim_wit(tx, idx, control.leaf, bytes.fromhex(control.r["program_hex"]), bit_replace(w, control.sig, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, control.leaf, idx
        return self.wallet_sign_keep(tx)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, tx.index, tx.r)
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def reject_moved(self, tx, label, expect, control, neg_index, control_index):
        """A negative whose covenant coin sits at another input than its
        control's, which spends the same coin. Refused by the mempool and in a
        block forced with generateblock, each for `expect`."""
        a, b = tx.vin[neg_index].prevout, control.vin[control_index].prevout
        assert (a.hash, a.n) == (b.hash, b.n), label
        pos = self._logpos()
        d = {"rejected": True, "expect": expect}
        control.rehash()
        assert self.accept(control)["allowed"], "%s: the control is refused" % label
        d["control"] = {"txid": control.hash, "same_coin": True, "control_input": control_index,
                        "negative_input": neg_index, "testmempoolaccept": True}
        res = self.accept(tx)
        assert not res["allowed"], "%s unexpectedly ACCEPTED" % label
        d["reject-reason"] = res.get("reject-reason", "")
        assert reason_matches(expect, d["reject-reason"]), (label, d)
        h0 = self.node.getblockcount()
        try:
            self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
            raise AssertionError("%s: MINED" % label)
        except JSONRPCException as e:
            d["block-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
        assert self.node.getblockcount() == h0
        assert reason_matches(expect, d["block-error"]), (label, d)
        d["block-log"] = [l for l in self._logsince(pos) if "ConnectBlock" in l or "CheckInputScripts" in l][:2]
        self.log.info("REJECT %-42s block: %s (control accepted)", label, d["block-error"])
        self.rec(label, d)

    # -- transactions ------------------------------------------------------------
    def record_tx(self, tok, verifier_coin, coin, recorded_next, fee_coin, burn_to=BURN, burn_atoms=None,
                  succ_spk=None, issue=None, outs=(), token_at=1, front=()):
        """The halt: the verifier coin at input 0, burned (or sent to
        `burn_to`); the token covenant at input `token_at`, re-created at the
        output of that index recording `recorded_next`; a fee coin."""
        ins = [(verifier_coin, 0xffffffff)] + list(front)
        ins.insert(token_at, (coin, 0xffffffff))
        ins.append((fee_coin, 0xffffffff))
        o = [self.out(verifier_coin.amount if burn_atoms is None else burn_atoms, burn_to, tok.V_OUT)]
        filler = [self.out(f.amount, self.wallet_spk(), self.X_OUT) for f, _ in front]
        succ = self.out(coin.amount, succ_spk or tok.spk(recorded_next), tok.TOKEN_OUT)
        o += filler
        o.insert(token_at, succ)
        o += list(outs)
        o += [self.out(fee_coin.amount - FEE, self.change_spk, self.X_OUT), self.fee(FEE, self.X_OUT)]
        tx = self.mktx(ins, o)
        if issue is not None:
            iss = CAssetIssuance()
            iss.assetBlindingNonce = 1
            iss.assetEntropy = int(tok.entropy, 16)
            iss.nAmount = CTxOutValue(issue)
            tx.vin[token_at].assetIssuance = iss
        return tx

    def resume_tx(self, tok, coin, recorded, fee_coin, amount=None, to=None, to_amount=None, succ_spk=None,
                  issue=True, outs=(), ins=(), front=(), fee_asset_out=None, fee_atoms=FEE, change_atoms=None):
        """The resume: the token covenant at input 0 (after `front`), reissuing
        `amount` of V; the successor at output 0, `to_amount` of V to `to` at
        output 1, then `outs`, the change and the fee."""
        amount = tok.amount if amount is None else amount
        o = [self.out(coin.amount, succ_spk or tok.spk(recorded), tok.TOKEN_OUT),
             self.out(amount if to_amount is None else to_amount, recorded if to is None else to, tok.V_OUT)]
        o += list(outs)
        fee_out = fee_asset_out or self.X_OUT
        o.append(self.out(fee_coin.amount - FEE if change_atoms is None else change_atoms, self.change_spk, self.X_OUT))
        o.append(self.fee(fee_atoms, fee_out))
        tx = self.mktx(list(front) + [(coin, 0xffffffff), (fee_coin, 0xffffffff)] + list(ins), o)
        if issue:
            iss = CAssetIssuance()
            iss.assetBlindingNonce = 1
            iss.assetEntropy = int(tok.entropy, 16)
            iss.nAmount = CTxOutValue(amount)
            tx.vin[len(front)].assetIssuance = iss
        return tx

    def run_test(self):
        self.boot()
        node = self.node
        self.change_spk = self.wallet_spk()
        self.sa, self.desc, self.vectors, self.sources = load_template("verifier_token")
        self.text, self.body = self.sources["token"]
        self.issuer_sk, self.other_sk = generate_privkey(), generate_privkey()
        issuer_pk = compute_xonly_pubkey(self.issuer_sk)[0]
        self.fees = self.fee_coins(60)
        fee_coin = lambda: self.fees.pop()

        # V, with ten times the verifier amount: AMOUNT for the verifier and the
        # rest as stray V, which exists here only so that the negatives can try
        # to place it where the covenant must refuse it.
        r = node.issueasset(assetamount=Decimal(10 * Q) / COIN, tokenamount=Decimal(TOKEN_ATOMS) / COIN, blind=False,
                            fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        T = Token(self, r["asset"], r["token"], r["entropy"], issuer_pk)
        # V is whitelisted as a fee asset too, so that relay reaches the
        # covenant when a negative pays its fee in V.
        self.rec("whitelist", self.whitelist(self.X, self.Y, T.v))

        # The two stand-in verifiers, under policies A and B.
        VA = SimProg(src("p2pk.simf"), {"PK": vpub(issuer_pk)}, data=b"policy A")
        VB = VA.with_data(b"policy B")
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"], "params": T.params(),
                              "verifier_A": VA.spk.hex(), "verifier_B": VB.spk.hex(),
                              "address_recording_A": T.at(VA.spk)[2]["address"]["elementsregtest"]})

        # Issuance's end: AMOUNT of V into verifier A, the token into the
        # covenant recording A. Stray V coins for the negatives.
        t_va = self.pay(VA.spk, Q, T.v)
        t_tok = self.pay(T.spk(VA.spk), TOKEN_ATOMS, T.token)
        stray_spk = self.wallet_spk()
        t_less = self.pay(VB.spk, Q - 1, T.v)            # one atom short, at B's script
        t_stray = self.pay(stray_spk, 5 * Q, T.v)
        t_x_at_b = self.pay(VB.spk, Q, self.X)            # B's script, holding another asset
        self.generate(node, 1)
        va = self.utxo_of(t_va, VA.spk)
        c0 = self.utxo_of(t_tok, T.spk(VA.spk))
        less = self.utxo_of(t_less, VB.spk)
        stray = self.utxo_of(t_stray, stray_spk)
        node.lockunspent(False, [{"txid": stray.txid, "vout": stray.vout}])
        x_at_b = self.utxo_of(t_x_at_b, VB.spk)
        self.rec("token_moved_in", {"txid": t_tok, "recording": "A", "covenant_atoms": c0.amount})

        # ---- an update: the issuer path moves V from A to B -----------------------
        fc = fee_coin()
        up = self.mktx([(va, 0xffffffff), (fc, 0xffffffff)],
                       [self.out(Q, VB.spk, T.V_OUT), self.out(fc.amount - FEE, self.change_spk, self.X_OUT),
                        self.fee(FEE, self.X_OUT)])
        self.verifier_sign(VA, up)
        up = self.wallet_sign(up)
        t_vb = node.sendrawtransaction(up.serialize().hex())
        self.generate(node, 1)
        vb = self.utxo_at(t_vb, 0)
        self.rec("update/verifier_moved_from_A_to_B", {"txid": t_vb})

        # ---- the halt: V burned from B, and B recorded in the same transaction ----
        fc = fee_coin()
        halt = self.record_tx(T, vb, c0, VB.spk, fc)
        self.verifier_sign(VB, halt, 0)
        self.satisfy(T, halt, VA.spk, "record", self.issuer_sk, 1)
        halt = self.wallet_sign_keep(halt)
        assert self.accept(halt)["allowed"], self.accept(halt)
        rec_neg = lambda **kw: self.record_tx(T, kw.pop("vcoin", vb), c0, kw.pop("rec", VB.spk), fc, **kw)
        self.reject(self.reuse(halt, rec_neg(), self.other_sk, verifier=VB),
                    "record/neg_signed_by_another_key", J, control=halt, index=1)
        self.reject(self.reuse(halt, rec_neg(vcoin=less, burn_atoms=Q - 1), self.issuer_sk, verifier=VB),
                    "record/neg_input_0_holds_one_atom_less", J, control=halt, index=1)
        xb = self.record_tx(T, x_at_b, c0, VB.spk, fc)
        xb.vout[0] = self.out(Q, BURN, self.X_OUT)
        self.reject(self.reuse(halt, xb, self.issuer_sk, verifier=VB),
                    "record/neg_input_0_holds_another_asset", J, control=halt, index=1)
        self.reject(self.reuse(halt, rec_neg(rec=VA.spk), self.issuer_sk, verifier=VB),
                    "record/neg_successor_keeps_the_old_record", J, control=halt, index=1)
        self.reject(self.reuse(halt, rec_neg(rec=self.wallet_spk()), self.issuer_sk, verifier=VB),
                    "record/neg_successor_records_another_script", J, control=halt, index=1)
        self.reject(self.reuse(halt, rec_neg(succ_spk=self.wallet_spk()), self.issuer_sk, verifier=VB),
                    "record/neg_token_to_another_script", J, control=halt, index=1)
        self.reject(self.reuse(halt, rec_neg(issue=Q, outs=[self.out(Q, self.wallet_spk(), T.V_OUT)]),
                               self.issuer_sk, verifier=VB),
                    "record/neg_record_and_mint_at_once", A, control=halt, index=1)
        # The covenant at input 2, its successor at output 2: against the same coin at input 1.
        f2 = fee_coin()
        moved = self.record_tx(T, vb, c0, VB.spk, fc, token_at=2, front=[(f2, 0xffffffff)])
        self.verifier_sign(VB, moved, 0)
        msg2 = self.sim_sighash(halt.leaf, moved, 2)
        self.set_sim_wit(moved, 2, halt.leaf, bytes.fromhex(halt.r["program_hex"]),
                         bit_replace(bytes.fromhex(halt.r["witness_hex"]), halt.sig, sign_schnorr(self.issuer_sk, msg2)))
        self.reject_moved(self.wallet_sign(moved), "record/neg_coin_at_input_2", J, halt, 2, 1)
        self.fees.append(f2)
        txh = self.ok(halt, "halt/burned_and_recorded", extra={"recorded": "B", "burned_atoms": Q})
        assert node.gettxout(txh, 0) is None, "the burn is spendable"
        c1 = self.utxo_at(txh, 1)
        assert c1.spk == T.spk(VB.spk) and c1.amount == TOKEN_ATOMS
        # Nothing holds AMOUNT of V at a verifier now: the asset is halted.
        self.rec("halt/no_verifier_left", {"verifier_B_coin_spent": node.gettxout(t_vb, 0) is None})

        # ---- the resume: AMOUNT of V reissued into B ---------------------------
        fc = fee_coin()
        res = self.resume_tx(T, c1, VB.spk, fc)
        self.satisfy(T, res, VB.spk, "resume", self.issuer_sk, 0)
        res = self.wallet_sign_keep(res)
        assert self.accept(res)["allowed"], self.accept(res)
        neg = lambda **kw: self.resume_tx(T, c1, VB.spk, fc, **kw)
        # V minted to any other script.
        self.reject(self.reuse(res, neg(to=VA.spk), self.issuer_sk),
                    "resume/neg_to_the_old_verifier", J, control=res)
        self.reject(self.reuse(res, neg(to=self.wallet_spk()), self.issuer_sk),
                    "resume/neg_to_an_ordinary_address", J, control=res)
        # In another amount.
        self.reject(self.reuse(res, neg(amount=Q + 1), self.issuer_sk),
                    "resume/neg_one_atom_more", J, control=res)
        self.reject(self.reuse(res, neg(amount=Q - 1), self.issuer_sk),
                    "resume/neg_one_atom_less", J, control=res)
        self.reject(self.reuse(res, neg(amount=2 * Q, to_amount=Q,
                                        outs=[self.out(Q, self.wallet_spk(), T.V_OUT)]), self.issuer_sk),
                    "resume/neg_twice_the_amount_half_elsewhere", J, control=res)
        # Beside another output that takes V.
        self.reject(self.reuse(res, neg(ins=[(stray, 0xffffffff)],
                                        outs=[self.out(5 * Q, self.wallet_spk(), T.V_OUT)]), self.issuer_sk),
                    "resume/neg_beside_another_output_of_V", A, control=res)
        self.reject(self.reuse(res, neg(ins=[(stray, 0xffffffff)], outs=[self.out(5 * Q - FEE, self.wallet_spk(), T.V_OUT)],
                                        fee_asset_out=T.V_OUT, change_atoms=fc.amount), self.issuer_sk),
                    "resume/neg_beside_a_fee_paid_in_V", A, control=res)
        # By another key.
        self.reject(self.reuse(res, neg(), self.other_sk), "resume/neg_signed_by_another_key", J, control=res)
        # The rest of the shape.
        self.reject(self.reuse(res, neg(outs=[self.out(1000, self.wallet_spk(), self.X_OUT) for _ in range(3)],
                                        change_atoms=fc.amount - FEE - 3000), self.issuer_sk),
                    "resume/neg_seven_outputs", J, control=res)
        self.reject(self.reuse(res, neg(succ_spk=T.spk(VA.spk)), self.issuer_sk),
                    "resume/neg_successor_changes_the_record", J, control=res)
        self.reject(self.reuse(res, neg(succ_spk=self.wallet_spk()), self.issuer_sk),
                    "resume/neg_token_to_another_script", J, control=res)
        none = neg(issue=False)
        none.vout = [none.vout[0]] + none.vout[2:]
        self.pad(none)
        self.reject(self.reuse(res, none, self.issuer_sk), "resume/neg_no_reissuance", A, control=res)
        nonce = neg()
        nonce.vout[1].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        self.reject(self.reuse(res, nonce, self.issuer_sk), "resume/neg_verifier_output_carries_a_nonce", A,
                    control=res)
        # A confidential output: the change blinded by the node.
        chg = node.getnewaddress("", "blech32")
        chg_info = node.getaddressinfo(chg)
        bl = neg(outs=[self.out(1000, self.wallet_spk(), self.X_OUT)], change_atoms=fc.amount - FEE - 1000)
        bl.vout[2].nNonce = CTxOutNonce(bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"]))
        bl.vout[3].nNonce = CTxOutNonce(bytes.fromhex(chg_info["confidential_key"]))
        bl.vout[3].scriptPubKey = bytes.fromhex(node.getaddressinfo(chg_info["unconfidential"])["scriptPubKey"])
        z = "00" * 32
        blinded = Tx.from_hex(node.rawblindrawtransaction(
            bl.serialize().hex(), [z, z], [Decimal(c1.amount) / COIN, Decimal(fc.amount) / COIN],
            [T.token, self.X], [z, z], "", False))
        assert blinded.vout[2].nAsset.vchCommitment[0] in (0x0a, 0x0b), "output 2 is not blinded"
        blinded.prev = bl.prev
        self.pad(blinded)
        self.reject(self.reuse(res, blinded, self.issuer_sk), "resume/neg_a_confidential_output", A, control=res,
                    mempool="min relay fee not met")
        # The covenant at input 1: against the same coin at input 0.
        f0 = fee_coin()
        moved = self.resume_tx(T, c1, VB.spk, fc, front=[(f0, 0xffffffff)],
                               outs=[self.out(f0.amount, self.wallet_spk(), self.X_OUT)])
        msg1 = self.sim_sighash(res.leaf, moved, 1)
        self.set_sim_wit(moved, 1, res.leaf, bytes.fromhex(res.r["program_hex"]),
                         bit_replace(bytes.fromhex(res.r["witness_hex"]), res.sig, sign_schnorr(self.issuer_sk, msg1)))
        self.reject_moved(self.wallet_sign(moved), "resume/neg_coin_at_input_1", J, res, 1, 0)
        self.fees.append(f0)
        txr = self.ok(res, "resume/reissued_into_the_recorded_verifier", extra={"to": "B", "atoms": Q})
        vb2 = self.utxo_at(txr, 1)
        assert vb2.spk == VB.spk and vb2.amount == Q
        c2 = self.utxo_at(txr, 0)
        assert c2.spk == T.spk(VB.spk)

        # ---- the verifier lives again: the issuer path can move it, and a record follows it
        fc = fee_coin()
        again = self.record_tx(T, vb2, c2, VB.spk, fc, burn_to=VA.spk)
        self.verifier_sign(VB, again, 0)
        self.satisfy(T, again, VB.spk, "record", self.issuer_sk, 1)
        again = self.wallet_sign_keep(again)
        self.ok(again, "update/back_to_A_recording_B", extra={"note": "an update may record the verifier it leaves"})


if __name__ == "__main__":
    V1().main()
