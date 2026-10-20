"""U1: the supply cap, addressed and spent from its descriptor.

The template `supply_cap` holds an asset's reissuance token:

    P2TR(NUMS, TapBranch(TapLeaf_0xbe(cap), H_TapData(params || state)))

with the parameters ASSET, TOKEN, OPERATOR_KEY, COLD_KEY and CAP and the state
MINTED in the data leaf. The operator mints by reissuing on input 0; MINTED
grows by the amount and may never pass CAP. The cold key moves the coin to new
keys with MINTED and CAP unchanged, and nothing takes the token out.

Each instance is derived by the Python mirror from the descriptor alone. Two
mints reach the cap exactly, one each side of a rekey, and the instance is
retired by a rekey to keys nobody holds. Every violation is refused by the
mempool and in a block forced with `generateblock`, each for its reason; a
refusal whose error is a failed assertion names a control, a transaction that
differs from it only in the property it breaks and that the node accepts. A
negative reuses its control's pruned program, re-signed for its own
transaction, so it takes the control's branches up to the check it breaks.
Every spend pays its fee in an issued asset from a wallet coin, never in the
policy asset."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.messages import CAssetIssuance  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
CAP = 10**9                          # atoms of the minted asset
TOKEN_ATOMS = 10**8                  # issueasset tokenamount=1
FEE = 3000                           # atoms of X, the fee asset
PATH_T = "Either<(), ()>"
PATHS = {"mint": "Left(())", "rekey": "Right(())"}
SIG_OF = {"mint": "OPERATOR_SIG", "rekey": "COLD_SIG"}


class Cap:
    """One instance: its parameters, and per MINTED its script and leaf."""

    def __init__(self, t, asset, token, entropy, op_pk, cold_pk, cap=CAP):
        self.t, self.asset, self.token, self.entropy = t, asset, token, entropy
        self.op_pk, self.cold_pk, self.cap = op_pk, cold_pk, cap
        self.ASSET_ID, self.TOKEN_ID = bytes.fromhex(asset)[::-1], bytes.fromhex(token)[::-1]
        self.TOKEN_OUT = t.asset_out(token)
        self.ASSET_OUT = t.asset_out(asset)
        self._cache = {}

    def rekeyed(self, op_pk, cold_pk):
        return Cap(self.t, self.asset, self.token, self.entropy, op_pk, cold_pk, self.cap)

    def with_cap(self, cap):
        return Cap(self.t, self.asset, self.token, self.entropy, self.op_pk, self.cold_pk, cap)

    def params(self):
        return {"ASSET": self.ASSET_ID.hex(), "TOKEN": self.TOKEN_ID.hex(), "OPERATOR_KEY": self.op_pk.hex(),
                "COLD_KEY": self.cold_pk.hex(), "CAP": "%016x" % self.cap}

    @staticmethod
    def slots(minted):
        return {"MINTED": "%016x" % minted}

    def at(self, minted):
        """(script_pubkey, leaf, derivation) of the instance holding `minted`."""
        if minted not in self._cache:
            t = self.t
            x = t.sa.derive(t.desc, self.params(), self.slots(minted))
            info = t.node.getaddressinfo(x["address"]["elementsregtest"])
            assert info["scriptPubKey"] == x["script_pubkey"], info
            leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["cap"]["control_block"]))
            self._cache[minted] = (bytes.fromhex(x["script_pubkey"]), leaf, x)
        return self._cache[minted]

    def spk(self, minted):
        return self.at(minted)[0]


class U1(SimBase, BitcoinTestFramework):
    NAME = "u1"

    def set_test_params(self):
        self.chain_params()

    # -- witnesses and transactions -----------------------------------------
    def witness(self, cap, minted, path, sig, new_keys=None):
        new_op, new_cold = new_keys if new_keys is not None else (NUMS, NUMS)
        w = {"ASSET": v256(cap.ASSET_ID), "TOKEN": v256(cap.TOKEN_ID), "OPERATOR_KEY": vpub(cap.op_pk),
             "COLD_KEY": vpub(cap.cold_pk), "CAP": vu(cap.cap, 64), "MINTED": vu(minted, 64),
             "PATH": vraw(PATHS[path], PATH_T), "NEW_OPERATOR_KEY": vpub(new_op), "NEW_COLD_KEY": vpub(new_cold)}
        for p, name in SIG_OF.items():
            w[name] = vsig(sig if p == path else bytes(64))
        return w

    def fee_coins(self, n, atoms=50_000):
        """n wallet coins of the fee asset X, made in one transaction and one
        block, and locked so the wallet's own coin selection leaves them."""
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

    def fee_coin(self):
        return self.fees.pop()

    def spend_tx(self, coin, fee_coin, succ_spk, succ_amount=None, succ_asset=None, issue=None, entropy=None,
                 outs=(), ins=(), front_ins=(), no_successor=False):
        """The covenant coin at input 0 (after `front_ins`), a fee coin of X,
        the successor at output 0, then `outs`, the change and the fee.
        `issue` is the reissued amount on the covenant's input, or None."""
        o = [] if no_successor else [self.out(coin.amount if succ_amount is None else succ_amount,
                                              succ_spk, succ_asset or self.L.TOKEN_OUT)]
        o += list(outs)
        o += [self.out(fee_coin.amount - FEE, self.change_spk, self.X_OUT), self.fee(FEE, self.X_OUT)]
        ins_ = list(front_ins) + [(coin, 0xffffffff), (fee_coin, 0xffffffff)] + list(ins)
        tx = self.mktx(ins_, o)
        if issue is not None:
            k = len(front_ins)
            iss = CAssetIssuance()
            iss.assetBlindingNonce = 1
            iss.assetEntropy = int(entropy, 16)
            iss.nAmount = CTxOutValue(issue)
            tx.vin[k].assetIssuance = iss
        return tx

    def mint_tx(self, cap, coin, minted, x, fee_coin, **kw):
        """A mint of `x` from `coin` holding `minted`; the successor holds the
        total the program computes, unless `claim` says otherwise."""
        nxt = kw.pop("claim", minted + x)
        succ = kw.pop("succ_cap", cap)
        outs = [self.out(x, self.dest, cap.ASSET_OUT)] + list(kw.pop("outs", ()))
        kw.setdefault("succ_asset", cap.TOKEN_OUT)
        tx = self.spend_tx(coin, fee_coin, kw.pop("succ_spk", None) or succ.spk(nxt), issue=kw.pop("issue", x),
                           entropy=cap.entropy, outs=outs, **kw)
        tx.next_minted = nxt
        return tx

    def signed(self, cap, tx, minted, path, sk, new_keys=None, index=0):
        """Satisfies and prunes the program against `tx` for `path`, the
        signature by `sk` over sig_all_hash; the wallet signs its fee coin."""
        leaf = cap.at(minted)[1]
        sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, index))
        r = self.sim_satisfy(leaf, tx, index, self.witness(cap, minted, path, sig, new_keys))
        tx.sig, tx.r, tx.leaf, tx.index = sig, r, leaf, index
        return self.wallet_sign_keep(tx)

    def wallet_sign_keep(self, tx):
        keep = {k: getattr(tx, k) for k in ("sig", "r", "leaf", "index", "next_minted") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in keep.items():
            setattr(t2, k, v)
        return t2

    def reuse(self, control, tx, sk=None, sig=None, msg=None):
        """`tx` with the control's pruned program and witness, its signature
        made again by `sk` for `tx` (or over `msg`, or `sig` as given)."""
        idx = control.index
        if sig is None:
            m = msg if msg is not None else self.sim_sighash(control.leaf, tx, idx)
            sig = sign_schnorr(sk, m)
        w = bytes.fromhex(control.r["witness_hex"])
        self.set_sim_wit(tx, idx, control.leaf, bytes.fromhex(control.r["program_hex"]), bit_replace(w, control.sig, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, control.leaf, idx
        return self.wallet_sign_keep(tx)

    def reuse_into(self, control, tx, cap, minted_from, minted_to, sk):
        """`tx` spends a coin of the same instance holding another count: the
        control's pruned program and witness with the count replaced, the new
        coin's control block, and the signature made again by `sk` for `tx`."""
        idx = control.index
        leaf = cap.at(minted_to)[1]
        w = bit_replace(bytes.fromhex(control.r["witness_hex"]), minted_from.to_bytes(8, "big"),
                        minted_to.to_bytes(8, "big"))
        sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, idx))
        w = bit_replace(w, control.sig, sig)
        self.set_sim_wit(tx, idx, leaf, bytes.fromhex(control.r["program_hex"]), w)
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, leaf, idx
        return self.wallet_sign_keep(tx)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, tx.index, tx.r)
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def reject_at(self, tx, label, expect, control):
        """A negative whose covenant coin sits at input 1, where its control
        spends the same coin at input 0. Refused by the mempool and in a block
        forced with generateblock, each for `expect`."""
        a, b = tx.vin[1].prevout, control.vin[0].prevout
        assert (a.hash, a.n) == (b.hash, b.n), label
        pos = self._logpos()
        d = {"rejected": True, "expect": expect}
        control.rehash()
        assert self.accept(control)["allowed"], "%s: the control is refused" % label
        d["control"] = {"txid": control.hash, "same_coin_at_input_0": True, "testmempoolaccept": True}
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

    def issue(self, token_atoms):
        node = self.node
        r = node.issueasset(assetamount=Decimal(1) / COIN, tokenamount=Decimal(token_atoms) / COIN, blind=False,
                            fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        return r

    def pay(self, spk, atoms, asset, blinding_key=None):
        node = self.node
        addr = program_to_witness(1, spk[2:])
        if blinding_key is not None:
            addr = node.createblindedaddress(addr, blinding_key.hex())
        return node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel=asset,
                                  fee_asset_label=BITCOIN_ASSET)

    def blinded_successor(self, cap, coin, minted, x, fee_coin):
        """The mint with its successor blinded by the node: the successor and
        the change carry blinding keys and `rawblindrawtransaction` replaces
        their amounts and assets by commitments."""
        node = self.node
        ck = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        chg = node.getnewaddress("", "blech32")
        chg_info = node.getaddressinfo(chg)
        chg_spk = bytes.fromhex(node.getaddressinfo(chg_info["unconfidential"])["scriptPubKey"])
        tx = self.mint_tx(cap, coin, minted, x, fee_coin)
        tx.vout[0].nNonce = CTxOutNonce(ck)
        tx.vout[2] = self.out(fee_coin.amount - FEE, chg_spk, self.X_OUT)
        tx.vout[2].nNonce = CTxOutNonce(bytes.fromhex(chg_info["confidential_key"]))
        z = "00" * 32
        blinded = node.rawblindrawtransaction(
            tx.serialize().hex(), [z, z], [Decimal(coin.amount) / COIN, Decimal(fee_coin.amount) / COIN],
            [cap.token, self.X], [z, z], "", False)
        t2 = Tx.from_hex(blinded)
        assert t2.vout[0].nAsset.vchCommitment[0] in (0x0a, 0x0b), "the successor's asset is not blinded"
        assert t2.vout[0].nValue.vchCommitment[0] in (0x08, 0x09), "the successor's amount is not blinded"
        assert bytes(t2.vout[0].scriptPubKey) == cap.spk(minted + x)
        t2.prev = tx.prev
        self.pad(t2)
        return t2

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.dest = self.wallet_spk()
        self.change_spk = self.wallet_spk()
        self.sa, self.desc, self.vectors, self.sources = load_template("supply_cap")
        self.text, self.body = self.sources["cap"]
        self.op_sk, self.cold_sk, self.op2_sk, self.other_sk = (generate_privkey() for _ in range(4))
        op_pk, cold_pk, op2_pk = (compute_xonly_pubkey(k)[0] for k in (self.op_sk, self.cold_sk, self.op2_sk))
        self.fees = self.fee_coins(70)

        # The main instance, L, holds its asset's whole token in one coin.
        z = self.issue(TOKEN_ATOMS)
        L = self.L = Cap(self, z["asset"], z["token"], z["entropy"], op_pk, cold_pk)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"], "params": L.params(), "slots": L.slots(0),
                              "address": L.at(0)[2]["address"]["elementsregtest"],
                              "script_pubkey": L.at(0)[2]["script_pubkey"], "token": z["token"], "asset": z["asset"],
                              "cap": CAP})
        # A twin instance, T, whose three token coins sit in chosen states: for
        # the negatives that need a second coin or a coin at the cap.
        w = self.issue(3 * TOKEN_ATOMS)
        T = Cap(self, w["asset"], w["token"], w["entropy"], op_pk, cold_pk)
        # An instance whose cap is the largest count, for the overflow.
        v = self.issue(TOKEN_ATOMS)
        BIG = (1 << 64) - 1
        V = Cap(self, v["asset"], v["token"], v["entropy"], op_pk, cold_pk, cap=BIG)
        NEAR = BIG - 9

        t_in = self.pay(L.spk(0), TOKEN_ATOMS, L.token)
        t_w1, t_w2 = self.pay(T.spk(CAP - 1), TOKEN_ATOMS, T.token), self.pay(T.spk(CAP - 1), TOKEN_ATOMS, T.token)
        t_full = self.pay(T.spk(CAP), TOKEN_ATOMS, T.token)
        t_v = self.pay(V.spk(NEAR), TOKEN_ATOMS, V.token)
        self.generate(node, 1)
        c0 = self.utxo_of(t_in, L.spk(0))
        w1, w2 = self.utxo_of(t_w1, T.spk(CAP - 1)), self.utxo_of(t_w2, T.spk(CAP - 1))
        wfull = self.utxo_of(t_full, T.spk(CAP))
        cv = self.utxo_of(t_v, V.spk(NEAR))
        self.rec("token_moved_in", {"txid": t_in, "issuance_token_atoms": TOKEN_ATOMS, "covenant_atoms": c0.amount})
        H = CAP // 2

        # ---- the first mint: half the cap ---------------------------------------
        fc = self.fee_coin()
        m1 = self.signed(L, self.mint_tx(L, c0, 0, H, fc), 0, "mint", self.op_sk)
        assert self.accept(m1)["allowed"]
        # The cap: exactly it is accepted, one atom over refused.
        at_cap = self.signed(L, self.mint_tx(L, c0, 0, CAP, fc), 0, "mint", self.op_sk)
        self.reject(self.reuse(at_cap, self.mint_tx(L, c0, 0, CAP + 1, fc), self.op_sk),
                    "mint/neg_one_atom_over_the_cap", J, control=at_cap)
        # The operator's signature.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc), self.other_sk),
                    "mint/neg_signed_by_another_key", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc), self.cold_sk),
                    "mint/neg_signed_by_the_cold_key", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc), self.op_sk,
                               msg=self.sim_sighash(m1.leaf, self.mint_tx(L, c0, 0, H - 1, fc), 0)),
                    "mint/neg_signature_over_another_mint", J, control=m1)
        # The issuance on the coin's input.
        none = self.mint_tx(L, c0, 0, H, fc, issue=None, claim=0)
        none.vout = [none.vout[0]] + none.vout[2:]
        self.pad(none)
        self.reject(self.reuse(m1, none, self.op_sk), "mint/neg_no_reissuance", A, control=m1)
        # A new issuance on the coin's input instead, which the node itself
        # places and pays out: an asset of its own, not ASSET.
        bare = self.mint_tx(L, c0, 0, H, fc, issue=None, claim=0)
        bare.vout = [bare.vout[0]] + bare.vout[2:]
        dest_addr = program_to_witness(0, self.dest[2:])
        r = node.rawissueasset(bare.serialize().hex(), [{"asset_amount": H / COIN, "asset_address": dest_addr,
                                                          "blind": False}])[0]
        assert r["vin"] == 0, r
        fresh = Tx.from_hex(r["hex"])
        fresh.prev = bare.prev
        self.pad(fresh)
        self.reject(self.reuse(m1, fresh, self.op_sk), "mint/neg_new_issuance_not_a_reissuance", J, control=m1)
        # The successor.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, claim=H - 1), self.op_sk),
                    "mint/neg_successor_counts_one_atom_less", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, claim=0), self.op_sk),
                    "mint/neg_successor_counts_nothing_minted", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, succ_cap=L.with_cap(CAP + H)), self.op_sk),
                    "mint/neg_successor_raises_the_cap", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, succ_cap=L.rekeyed(op2_pk, cold_pk)), self.op_sk),
                    "mint/neg_successor_changes_the_operator_key", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, succ_spk=self.wallet_spk()), self.op_sk),
                    "mint/neg_token_to_another_script", J, control=m1)
        split = self.mint_tx(L, c0, 0, H, fc, succ_amount=TOKEN_ATOMS - 1,
                             outs=[self.out(1, self.wallet_spk(), L.TOKEN_OUT)])
        self.reject(self.reuse(m1, split, self.op_sk), "mint/neg_one_token_atom_split_off", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, 0, H, fc, no_successor=True,
                                                outs=[self.out(TOKEN_ATOMS, self.wallet_spk(), L.TOKEN_OUT)]),
                               self.op_sk), "mint/neg_no_successor", J, control=m1)
        nonce = self.mint_tx(L, c0, 0, H, fc)
        nonce.vout[0].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        self.reject(self.reuse(m1, nonce, self.op_sk), "mint/neg_successor_carries_a_nonce", A, control=m1)
        blinded = self.blinded_successor(L, c0, 0, H, fc)
        # Its range proofs make it heavier than the control's fee pays for, so
        # relay refuses it on the fee first; the block refuses it for the covenant.
        self.reject(self.reuse(m1, blinded, self.op_sk), "mint/neg_successor_confidential", A, control=m1,
                    mempool="min relay fee not met")
        # The coin at input 1: the control spends it at input 0.
        front = self.fee_coin()
        moved = self.mint_tx(L, c0, 0, H, fc, front_ins=[(front, 0xffffffff)],
                             outs=[self.out(front.amount, self.wallet_spk(), self.X_OUT)])
        msg1 = self.sim_sighash(m1.leaf, moved, 1)
        self.set_sim_wit(moved, 1, m1.leaf, bytes.fromhex(m1.r["program_hex"]),
                         bit_replace(bytes.fromhex(m1.r["witness_hex"]), m1.sig, sign_schnorr(self.op_sk, msg1)))
        self.reject_at(self.wallet_sign(moved), "mint/neg_coin_at_input_1", J, m1)
        self.fees.append(front)

        txid1 = self.ok(m1, "mint/first_half_of_the_cap", extra={"minted": H, "next_minted": m1.next_minted})
        c1 = self.utxo_at(txid1, 0)
        assert c1.spk == L.spk(H) and c1.amount == TOKEN_ATOMS

        # ---- the rekey: a new operator key, the count and the cap kept ------------
        L2 = L.rekeyed(op2_pk, cold_pk)
        NEW = (op2_pk, cold_pk)
        fc = self.fee_coin()
        rk = self.signed(L, self.spend_tx(c1, fc, L2.spk(H)), H, "rekey", self.cold_sk, new_keys=NEW)
        assert self.accept(rk)["allowed"]
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L2.spk(H)), self.op_sk),
                    "rekey/neg_signed_by_the_operator", J, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L2.spk(H)), self.other_sk),
                    "rekey/neg_signed_by_another_key", J, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L2.spk(H), issue=5, entropy=L.entropy,
                                                 outs=[self.out(5, self.dest, L.ASSET_OUT)]), self.cold_sk),
                    "rekey/neg_rekey_and_mint_at_once", A, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L2.spk(0)), self.cold_sk),
                    "rekey/neg_successor_forgets_the_count", J, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L2.with_cap(2 * CAP).spk(H)), self.cold_sk),
                    "rekey/neg_successor_raises_the_cap", J, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, L.rekeyed(op2_pk, op2_pk).spk(H)), self.cold_sk),
                    "rekey/neg_successor_keys_not_the_ones_named", J, control=rk)
        self.reject(self.reuse(rk, self.spend_tx(c1, fc, self.wallet_spk()), self.cold_sk),
                    "rekey/neg_token_to_another_script", J, control=rk)
        txr = self.ok(rk, "rekey/to_a_new_operator_key", extra={"minted": H, "new_operator_key": op2_pk.hex()})
        c2 = self.utxo_at(txr, 0)
        assert c2.spk == L2.spk(H)

        # ---- the second mint, by the new key: exactly the room left ---------------
        fc = self.fee_coin()
        room = CAP - H
        m2 = self.signed(L2, self.mint_tx(L2, c2, H, room, fc), H, "mint", self.op2_sk)
        self.reject(self.reuse(m2, self.mint_tx(L2, c2, H, room, fc), self.op_sk),
                    "mint/neg_old_operator_key_after_the_rekey", J, control=m2)
        self.reject(self.reuse(m2, self.mint_tx(L2, c2, H, room + 1, fc), self.op2_sk),
                    "mint/neg_after_the_rekey_one_atom_over_the_cap", J, control=m2)
        txm2 = self.ok(m2, "mint/the_room_left_reaches_the_cap", extra={"minted": room, "next_minted": CAP})
        c3 = self.utxo_at(txm2, 0)
        assert c3.spk == L2.spk(CAP)
        # Minted through the covenant, read back from the chain: exactly the cap.
        total = 0
        for txid in (txid1, txm2):
            d = node.getrawtransaction(txid, True)
            total += int(Decimal(str(d["vin"][0]["issuance"]["assetamount"])) * COIN)
        assert total == CAP, total
        self.rec("cap/reached", {"minted_on_chain": total, "cap": CAP, "coin": "%s:0" % txm2})

        # ---- at the cap, one atom: against the same mint from a coin with room ----
        fc = self.fee_coin()
        room1 = self.signed(T, self.mint_tx(T, w1, CAP - 1, 1, fc), CAP - 1, "mint", self.op_sk)
        full = self.reuse_into(room1, self.mint_tx(T, wfull, CAP, 1, fc), T, CAP - 1, CAP, self.op_sk)
        self.reject(full, "cap/neg_one_atom_from_a_coin_at_the_cap", J, control=room1, other_state=True)
        # Two coins of one state, one successor: the second at input 2.
        both = self.mint_tx(T, w1, CAP - 1, 1, fc, ins=[(w2, 0xffffffff)],
                            outs=[self.out(TOKEN_ATOMS, self.dest, T.TOKEN_OUT)])
        self.reuse(room1, both, self.op_sk)
        msg2 = self.sim_sighash(room1.leaf, both, 2)
        st = both.wit.vtxinwit[0].scriptWitness.stack
        both.wit.vtxinwit[2].scriptWitness.stack = [bit_replace(bytes.fromhex(room1.r["witness_hex"]), room1.sig,
                                                               sign_schnorr(self.op_sk, msg2)), st[1], st[2], st[3]]
        self.reject(self.wallet_sign(both), "twin/neg_second_coin_shares_the_successor", J, control=room1)
        self.fees.append(fc)

        # ---- a count that would overflow 64 bits: against the largest that does not
        fc = self.fee_coin()
        fits = self.signed(V, self.mint_tx(V, cv, NEAR, 9, fc), NEAR, "mint", self.op_sk)
        self.reject(self.reuse(fits, self.mint_tx(V, cv, NEAR, 10, fc, claim=0), self.op_sk),
                    "mint/neg_count_overflows", J, control=fits)
        self.fees.append(fc)

        # ---- retired: both keys moved to the NUMS point, which nobody holds -----
        fc = self.fee_coin()
        L3 = L2.rekeyed(NUMS, NUMS)
        ret = self.signed(L2, self.spend_tx(c3, fc, L3.spk(CAP)), CAP, "rekey", self.cold_sk, new_keys=(NUMS, NUMS))
        txret = self.ok(ret, "rekey/retired_to_keys_nobody_holds", extra={"minted": CAP})
        assert self.utxo_at(txret, 0).spk == L3.spk(CAP)


if __name__ == "__main__":
    U1().main()
