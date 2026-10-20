"""M1: the mint limiter, addressed and spent from its descriptor.

The template `mint_limiter` holds an asset's reissuance token:

    P2TR(NUMS, TapBranch(TapLeaf_0xbe(limiter), H_TapData(params || state)))

with the state MINTED, ELAPSED and ARMED in the data leaf. The operator mints
by reissuing on input 0, in a coin at least two blocks old; the coin's age, a
relative lock in blocks on its own input, is added to ELAPSED, a window ends
once ELAPSED reaches WINDOW, and MINTED may not pass ALLOWANCE within one. A
cold key's signature over a message that names no coin applies a brake that
stops every mint; the cold key lifts it, or takes the token once the brake has
held RECOVERY_DELAY units of 512 seconds.

Each instance is derived by the Python mirror from the descriptor alone. The
mints, the window's reset, the brake, its release and the recovery confirm.
Every violation is refused by the mempool and in a block forced with
`generateblock`, each for its reason; a refusal whose error is a failed
assertion names a control, a transaction that differs from it only in the
property it breaks and that the node accepts. A negative reuses its control's
pruned program, re-signed for its own transaction, so it takes the control's
branches up to the check it breaks. Every spend pays its fee in an issued
asset from a wallet coin, never in the policy asset."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.messages import CAssetIssuance  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
NONFINAL, NONFINAL_MEMPOOL = "bad-txns-nonfinal", "non-BIP68-final"
TIME = 1 << 22
WINDOW = 20                          # blocks
ALLOWANCE = 10**9                    # atoms of the minted asset
RECOVERY_UNITS = 2                   # units of 512 seconds
TOKEN_ATOMS = 10**8                  # issueasset tokenamount=1
FEE = 3000                           # atoms of X, the fee asset
PATH_T = "Either<(), Either<(), Either<(), ()>>>"
PATHS = {"mint": "Left(())", "arm": "Right(Left(()))", "disarm": "Right(Right(Left(())))",
         "recover": "Right(Right(Right(())))"}
SIG_OF = {"mint": "OPERATOR_SIG", "arm": "ARM_SIG", "disarm": "COLD_SIG", "recover": "RECOVER_SIG"}
ARM_TAG = sha256(b"sequentia/mint-limiter/arm")


class Limiter:
    """One instance: its parameters, and per state its script and leaf."""

    def __init__(self, t, asset, token, entropy, op_pk, cold_pk, window=WINDOW, allowance=ALLOWANCE,
                 delay=RECOVERY_UNITS):
        self.t, self.asset, self.token, self.entropy = t, asset, token, entropy
        self.op_pk, self.cold_pk = op_pk, cold_pk
        self.window, self.allowance, self.delay = window, allowance, delay
        self.ASSET_ID, self.TOKEN_ID = bytes.fromhex(asset)[::-1], bytes.fromhex(token)[::-1]
        self.TOKEN_OUT = t.asset_out(token)
        self.ASSET_OUT = t.asset_out(asset)
        self._cache = {}

    def params(self):
        return {"ASSET": self.ASSET_ID.hex(), "TOKEN": self.TOKEN_ID.hex(), "OPERATOR_KEY": self.op_pk.hex(),
                "COLD_KEY": self.cold_pk.hex(), "WINDOW": "%04x" % self.window,
                "ALLOWANCE": "%016x" % self.allowance, "RECOVERY_DELAY": "%04x" % self.delay}

    @staticmethod
    def slots(state):
        minted, elapsed, armed = state
        return {"MINTED": "%016x" % minted, "ELAPSED": "%04x" % elapsed, "ARMED": "%02x" % armed}

    def at(self, state):
        """(script_pubkey, leaf, derivation) of the instance holding `state`."""
        if state not in self._cache:
            t = self.t
            x = t.sa.derive(t.desc, self.params(), self.slots(state))
            info = t.node.getaddressinfo(x["address"]["elementsregtest"])
            assert info["scriptPubKey"] == x["script_pubkey"], info
            leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["limiter"]["control_block"]))
            self._cache[state] = (bytes.fromhex(x["script_pubkey"]), leaf, x)
        return self._cache[state]

    def spk(self, state):
        return self.at(state)[0]

    def arm_message(self, genesis=None, allowance=None):
        g = genesis if genesis is not None else bytes.fromhex(self.t.node.getblockhash(0))[::-1]
        leaf_hash = bytes.fromhex(self.at((0, 0, 0))[2]["leaves"]["limiter"]["hash"])
        return sha256(ARM_TAG + ARM_TAG + g + leaf_hash + self.ASSET_ID + self.TOKEN_ID + self.op_pk + self.cold_pk
                      + self.window.to_bytes(2, "big")
                      + (self.allowance if allowance is None else allowance).to_bytes(8, "big")
                      + self.delay.to_bytes(2, "big"))


class M1(SimBase, BitcoinTestFramework):
    NAME = "m1"

    def set_test_params(self):
        self.chain_params()

    # -- witnesses and transactions -----------------------------------------
    def witness(self, lim, state, path, sig):
        minted, elapsed, armed = state
        w = {"ASSET": v256(lim.ASSET_ID), "TOKEN": v256(lim.TOKEN_ID), "OPERATOR_KEY": vpub(lim.op_pk),
             "COLD_KEY": vpub(lim.cold_pk), "WINDOW": vu(lim.window, 16), "ALLOWANCE": vu(lim.allowance, 64),
             "RECOVERY_DELAY": vu(lim.delay, 16), "MINTED": vu(minted, 64), "ELAPSED": vu(elapsed, 16),
             "ARMED": vu(armed, 8), "PATH": vraw(PATHS[path], PATH_T)}
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

    def spend_tx(self, lim, coin, state_next, seq, fee_coin, issue=None, succ_spk=None, succ_amount=None,
                 succ_asset=None, outs=(), ins=(), version=2, no_successor=False, front_ins=()):
        """The covenant coin at input 0 (after `front_ins`), a fee coin of X,
        the successor in `state_next` at output 0, then `outs`, the change and
        the fee. `issue` is the reissued amount on input 0, or None."""
        o = [] if no_successor else [self.out(coin.amount if succ_amount is None else succ_amount,
                                              succ_spk or lim.spk(state_next), succ_asset or lim.TOKEN_OUT)]
        o += list(outs)
        o += [self.out(fee_coin.amount - FEE, self.change_spk, self.X_OUT), self.fee(FEE, self.X_OUT)]
        ins_ = list(front_ins) + [(coin, seq), (fee_coin, 0xffffffff)] + list(ins)
        tx = self.mktx(ins_, o, version=version)
        if issue is not None:
            k = len(front_ins)
            iss = CAssetIssuance()
            iss.assetBlindingNonce = 1
            iss.assetEntropy = int(lim.entropy, 16)
            iss.nAmount = CTxOutValue(issue)
            tx.vin[k].assetIssuance = iss
        return tx

    def mint_tx(self, lim, coin, state, x, d, fee_coin, **kw):
        """A mint of `x` from `coin` in `state`, its sequence a lock of `d`
        blocks; the successor holds the state the program computes, unless a
        keyword says otherwise."""
        minted, elapsed, _ = state
        nxt = (x, 0, 0) if elapsed + d >= lim.window else (minted + x, elapsed + d, 0)
        nxt = kw.pop("claim", nxt)
        seq = kw.pop("seq", d)
        outs = [self.out(x, self.dest, lim.ASSET_OUT)] + list(kw.pop("outs", ()))
        tx = self.spend_tx(lim, coin, nxt, seq, fee_coin, issue=kw.pop("issue", x), outs=outs, **kw)
        tx.next_state = nxt
        return tx

    def signed(self, lim, tx, state, path, sk, index=0, msg=None):
        """Satisfies and prunes the program against `tx` for `path`, the
        signature by `sk` over sig_all_hash (or over `msg`); the wallet signs
        its fee coin."""
        leaf = lim.at(state)[1]
        m = msg if msg is not None else self.sim_sighash(leaf, tx, index)
        sig = sign_schnorr(sk, m)
        r = self.sim_satisfy(leaf, tx, index, self.witness(lim, state, path, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, r, leaf, index
        return self.wallet_sign_keep(tx)

    def wallet_sign_keep(self, tx):
        keep = {k: getattr(tx, k) for k in ("sig", "r", "leaf", "index", "next_state") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in keep.items():
            setattr(t2, k, v)
        return t2

    def reuse(self, control, tx, sk=None, sig=None, msg=None, witness=None):
        """`tx` with the control's pruned program and witness, its signature
        made again by `sk` for `tx` (or over `msg`, or `sig` as given)."""
        idx = control.index
        if sig is None:
            m = msg if msg is not None else self.sim_sighash(control.leaf, tx, idx)
            sig = sign_schnorr(sk, m)
        w = bytes.fromhex(control.r["witness_hex"]) if witness is None else witness
        self.set_sim_wit(tx, idx, control.leaf, bytes.fromhex(control.r["program_hex"]), bit_replace(w, control.sig, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, control.leaf, idx
        return self.wallet_sign_keep(tx)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, tx.index, tx.r)
        m.update(extra or {})
        txid = self.send(tx, label, extra=m)
        return txid

    def coin_at(self, txid, vout=0):
        return self.utxo_at(txid, vout)

    # -- time ------------------------------------------------------------------
    def tip_mtp(self):
        return self.node.getblockheader(self.node.getbestblockhash())["mediantime"]

    def mtp_to(self, target):
        """Mines eleven blocks one second apart, centred on `target`, so that
        the tip's median time past is exactly `target`."""
        node = self.node
        assert target - 5 > self.tip_mtp(), (target, self.tip_mtp())
        for i in range(11):
            node.setmocktime(target - 5 + i)
            self.generate(node, 1)
        assert self.tip_mtp() == target, (self.tip_mtp(), target)

    def mtp_step(self):
        """One more block one second after the tip: the median time past moves by one."""
        node = self.node
        t = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(t + 1)
        self.generate(node, 1)

    def coin_time(self, txid):
        """The median time past BIP68 counts a coin's time lock from: that of
        the block before the coin's."""
        node = self.node
        h = node.getblockheader(node.getrawtransaction(txid, True)["blockhash"])["height"]
        return node.getblockheader(node.getblockhash(h - 1))["mediantime"]

    def coin_height(self, txid):
        node = self.node
        return node.getblockheader(node.getrawtransaction(txid, True)["blockhash"])["height"]

    def to_age(self, txid, age):
        """Mines until a spend in the next block finds the coin `age` blocks old."""
        self.mine_to(self.coin_height(txid) + age - 1)

    # -- setup -----------------------------------------------------------------
    def issue(self, token_atoms):
        node = self.node
        r = node.issueasset(assetamount=Decimal(1) / COIN, tokenamount=Decimal(token_atoms) / COIN, blind=False,
                            fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        return r

    @staticmethod
    def state_bytes(state):
        m, e, a = state
        return m.to_bytes(8, "big") + e.to_bytes(2, "big") + a.to_bytes(1, "big")

    def with_sig(self, lim, tx, state, path, sig, index=0):
        """Satisfies and prunes the program against `tx` for `path` with a
        signature given as is (the arm signature, made in advance)."""
        leaf = lim.at(state)[1]
        r = self.sim_satisfy(leaf, tx, index, self.witness(lim, state, path, sig))
        tx.sig, tx.r, tx.leaf, tx.index = sig, r, leaf, index
        return self.wallet_sign_keep(tx)

    def reuse_into(self, control, tx, lim, state_from, state_to, sk):
        """`tx` spends a coin of the same program in another state: the
        control's pruned program and witness with the state values replaced
        by the new coin's, the new coin's control block, and the signature
        made again by `sk` for `tx`."""
        idx = control.index
        leaf = lim.at(state_to)[1]
        w = bit_replace(bytes.fromhex(control.r["witness_hex"]), self.state_bytes(state_from), self.state_bytes(state_to))
        sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, idx))
        w = bit_replace(w, control.sig, sig)
        self.set_sim_wit(tx, idx, leaf, bytes.fromhex(control.r["program_hex"]), w)
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, leaf, idx
        return self.wallet_sign_keep(tx)

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

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.dest = self.wallet_spk()
        self.change_spk = self.wallet_spk()
        self.sa, self.desc, self.vectors, self.sources = load_template("mint_limiter")
        self.text, self.body = self.sources["limiter"]
        self.op_sk, self.cold_sk, self.other_sk = generate_privkey(), generate_privkey(), generate_privkey()
        op_pk = compute_xonly_pubkey(self.op_sk)[0]
        cold_pk = compute_xonly_pubkey(self.cold_sk)[0]
        self.fees = self.fee_coins(80)

        # The main instance, Z, holds its asset's whole token in one coin.
        z = self.issue(TOKEN_ATOMS)
        L = Limiter(self, z["asset"], z["token"], z["entropy"], op_pk, cold_pk)
        S0 = (0, 0, 0)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"], "params": L.params(), "slots": L.slots(S0),
                              "address": L.at(S0)[2]["address"]["elementsregtest"],
                              "script_pubkey": L.at(S0)[2]["script_pubkey"], "token": z["token"], "asset": z["asset"]})
        # The brake's signature, made once and before any coin of the instance exists.
        arm_sig = sign_schnorr(self.cold_sk, L.arm_message())
        self.rec("arm/signature_made_in_advance", {"message": L.arm_message().hex(), "signature": arm_sig.hex()})

        # A twin instance, W, whose two token coins share one state: for the
        # negatives that need a second coin, or a coin in another state.
        w = self.issue(3 * TOKEN_ATOMS)
        T = Limiter(self, w["asset"], w["token"], w["entropy"], op_pk, cold_pk)
        ST = (123456789, 7, 0)
        ST_ARMED = (123456789, 7, 1)
        ST2 = (123456789, 8, 0)               # a third coin, one block further into its window

        pay = lambda spk, atoms, asset: node.sendtoaddress(
            address=program_to_witness(1, spk[2:]), amount=Decimal(atoms) / COIN, assetlabel=asset,
            fee_asset_label=BITCOIN_ASSET)
        t_in = pay(L.spk(S0), TOKEN_ATOMS, L.token)
        t_w1, t_w2 = pay(T.spk(ST), TOKEN_ATOMS, T.token), pay(T.spk(ST), TOKEN_ATOMS, T.token)
        t_w3 = pay(T.spk(ST2), TOKEN_ATOMS, T.token)
        self.generate(node, 1)
        w3 = self.utxo_of(t_w3, T.spk(ST2))
        c0 = self.utxo_of(t_in, L.spk(S0))
        w1, w2 = self.utxo_of(t_w1, T.spk(ST)), self.utxo_of(t_w2, T.spk(ST))
        self.rec("token_moved_in", {"txid": t_in, "height": self.coin_height(t_in),
                                    "issuance_token_atoms": TOKEN_ATOMS, "covenant_atoms": c0.amount})
        H = ALLOWANCE // 2

        # ---- the first mint: half the allowance, from a coin two blocks old ------
        self.to_age(t_in, 2)
        fc = self.fee_coin()
        m1 = self.signed(L, self.mint_tx(L, c0, S0, H, 2, fc), S0, "mint", self.op_sk)
        assert self.accept(m1)["allowed"]
        # The coin's age, by its own sequence.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 1, fc), self.op_sk),
                    "mint/neg_coin_one_block_old", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 0, fc), self.op_sk),
                    "mint/neg_coin_age_zero", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, seq=0xffffffff), self.op_sk),
                    "mint/neg_lock_disabled", A, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, seq=TIME | 0), self.op_sk),
                    "mint/neg_lock_in_time", A, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, version=1), self.op_sk),
                    "mint/neg_version_1", J, control=m1)
        # Declaring the window's length as the coin's age: the chain refuses it.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, WINDOW, fc), self.op_sk),
                    "mint/neg_age_declared_beyond_the_coins", NONFINAL, mempool=NONFINAL_MEMPOOL)
        # The allowance, from a fresh window: exactly it is accepted, one atom over refused.
        at_cap = self.signed(L, self.mint_tx(L, c0, S0, ALLOWANCE, 2, fc), S0, "mint", self.op_sk)
        self.reject(self.reuse(at_cap, self.mint_tx(L, c0, S0, ALLOWANCE + 1, 2, fc), self.op_sk),
                    "mint/neg_one_atom_over_the_allowance", J, control=at_cap)
        # The operator's signature.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc), self.other_sk),
                    "mint/neg_signed_by_another_key", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc), self.cold_sk),
                    "mint/neg_signed_by_the_cold_key", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc), self.op_sk,
                               msg=self.sim_sighash(m1.leaf, self.mint_tx(L, c0, S0, H - 1, 2, fc), 0)),
                    "mint/neg_signature_over_another_mint", J, control=m1)
        # No reissuance on the coin's input.
        none = self.mint_tx(L, c0, S0, H, 2, fc, issue=None)
        none.vout = [none.vout[0]] + none.vout[2:]
        self.pad(none)
        self.reject(self.reuse(m1, none, self.op_sk), "mint/neg_no_reissuance", A, control=m1)
        # The successor.
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, claim=(0, 2, 0)), self.op_sk),
                    "mint/neg_successor_counts_nothing_minted", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, claim=(H, 0, 0)), self.op_sk),
                    "mint/neg_successor_restarts_the_window", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, claim=(H, 2, 1)), self.op_sk),
                    "mint/neg_successor_braked", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, succ_spk=self.wallet_spk()), self.op_sk),
                    "mint/neg_token_to_another_script", J, control=m1)
        split = self.mint_tx(L, c0, S0, H, 2, fc, succ_amount=TOKEN_ATOMS - 1,
                             outs=[self.out(1, self.wallet_spk(), L.TOKEN_OUT)])
        self.reject(self.reuse(m1, split, self.op_sk), "mint/neg_one_token_atom_split_off", J, control=m1)
        self.reject(self.reuse(m1, self.mint_tx(L, c0, S0, H, 2, fc, no_successor=True,
                                                outs=[self.out(TOKEN_ATOMS, self.wallet_spk(), L.TOKEN_OUT)]),
                               self.op_sk), "mint/neg_no_successor", J, control=m1)
        nonce = self.mint_tx(L, c0, S0, H, 2, fc)
        nonce.vout[0].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        self.reject(self.reuse(m1, nonce, self.op_sk), "mint/neg_successor_carries_a_nonce", A, control=m1)
        # The coin at input 1: the control spends it at input 0.
        front = self.fee_coin()
        moved = self.mint_tx(L, c0, S0, H, 2, fc, front_ins=[(front, 0xffffffff)],
                             outs=[self.out(front.amount, self.wallet_spk(), self.X_OUT)])
        msg1 = self.sim_sighash(m1.leaf, moved, 1)
        self.set_sim_wit(moved, 1, m1.leaf, bytes.fromhex(m1.r["program_hex"]),
                         bit_replace(bytes.fromhex(m1.r["witness_hex"]), m1.sig, sign_schnorr(self.op_sk, msg1)))
        self.reject_at(self.wallet_sign(moved), "mint/neg_coin_at_input_1", J, m1)
        self.fees.append(front)

        txid1 = self.ok(m1, "mint/first_half_of_the_allowance",
                        extra={"declared_age": 2, "minted": H, "state": m1.next_state})
        S1 = m1.next_state
        assert S1 == (H, 2, 0), S1
        c1 = self.coin_at(txid1)
        assert c1.spk == L.spk(S1) and c1.amount == TOKEN_ATOMS

        # ---- the second mint: exactly the allowance is accepted, one more atom refused
        self.to_age(txid1, 2)
        fc = self.fee_coin()
        m2 = self.signed(L, self.mint_tx(L, c1, S1, H, 2, fc), S1, "mint", self.op_sk)
        self.reject(self.reuse(m2, self.mint_tx(L, c1, S1, H + 1, 2, fc), self.op_sk),
                    "mint/neg_second_mint_one_atom_over_the_allowance", J, control=m2)
        self.reject(self.reuse(m2, self.mint_tx(L, c1, S1, H, 2, fc, claim=(H, 0, 0)), self.op_sk),
                    "mint/neg_second_mint_claims_a_new_window", J, control=m2)
        self.reject(self.reuse(m2, self.mint_tx(L, c1, S1, H, WINDOW - S1[1], fc), self.op_sk),
                    "mint/neg_second_mint_declares_the_windows_end", NONFINAL, mempool=NONFINAL_MEMPOOL)
        # Mine a quarter instead, so the window has room left for the test at its end.
        Q = ALLOWANCE // 4
        fc2 = self.fee_coin()
        m2q = self.signed(L, self.mint_tx(L, c1, S1, Q, 2, fc2), S1, "mint", self.op_sk)
        self.fees.append(fc)
        txid2 = self.ok(m2q, "mint/second_a_quarter", extra={"declared_age": 2, "state": m2q.next_state})
        S2 = m2q.next_state
        assert S2 == (H + Q, 4, 0), S2
        c2 = self.coin_at(txid2)

        # ---- the window: one block before its end the allowance still binds; at it, it restarts
        need = WINDOW - S2[1]                          # the age at which c2's window ends
        self.to_age(txid2, need - 1)
        fc = self.fee_coin()
        room = ALLOWANCE - S2[0]
        last = self.signed(L, self.mint_tx(L, c2, S2, room, need - 1, fc), S2, "mint", self.op_sk)
        assert last.next_state == (ALLOWANCE, WINDOW - 1, 0), last.next_state
        self.reject(self.reuse(last, self.mint_tx(L, c2, S2, room + 1, need - 1, fc), self.op_sk),
                    "window/neg_one_block_before_its_end_one_atom_over", J, control=last)
        early = self.signed(L, self.mint_tx(L, c2, S2, ALLOWANCE, need, fc), S2, "mint", self.op_sk)
        assert early.next_state == (ALLOWANCE, 0, 0)
        self.reject(early, "window/neg_new_window_one_block_early", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.rec("window/one_block_before_its_end", {"coin_age_next_block": need - 1, "elapsed": S2[1],
                                                     "window": WINDOW, "control_mints_the_room_left": room})
        self.mine_to(node.getblockcount() + 1)         # now the next block finds c2 `need` blocks old
        whole = self.signed(L, self.mint_tx(L, c2, S2, ALLOWANCE, need, fc), S2, "mint", self.op_sk)
        assert whole.next_state == (ALLOWANCE, 0, 0)
        self.reject(self.reuse(whole, self.mint_tx(L, c2, S2, ALLOWANCE + 1, need, fc), self.op_sk),
                    "window/neg_new_window_one_atom_over", J, control=whole)
        self.reject(self.reuse(whole, self.mint_tx(L, c2, S2, ALLOWANCE, need, fc,
                                                   claim=(ALLOWANCE, WINDOW, 0)), self.op_sk),
                    "window/neg_new_window_keeps_counting_blocks", J, control=whole)
        # Mine ten atoms short of a whole allowance, so later tests have ten atoms of room.
        fc_r = self.fee_coin()
        reset = self.signed(L, self.mint_tx(L, c2, S2, ALLOWANCE - 10, need, fc_r), S2, "mint", self.op_sk)
        self.fees.append(fc)
        txid3 = self.ok(reset, "window/new_window_restarts_the_allowance",
                        extra={"declared_age": need, "state_before": S2, "state": reset.next_state})
        S3 = reset.next_state
        assert S3 == (ALLOWANCE - 10, 0, 0), S3
        c3 = self.coin_at(txid3)

        # ---- burns are unaffected: minted units burn from the wallet, the count stays
        burn = node.destroyamount(L.asset, Decimal(H) / COIN)
        self.generate(node, 1)
        assert node.gettxout(c3.txid, c3.vout) is not None
        self.rec("burn/minted_units_burned_from_the_wallet", {"txid": burn, "atoms": H, "confirmed": True,
                                                              "covenant_coin_unspent": True})

        # ---- the brake, applied by a third party with the signature made in advance
        fc = self.fee_coin()
        SA = (S3[0], S3[1], 1)
        arm = self.with_sig(L, self.spend_tx(L, c3, SA, 0, fc), S3, "arm", arm_sig)
        assert self.accept(arm)["allowed"]
        self.reject(self.reuse(arm, self.spend_tx(L, c3, SA, 0, fc), self.op_sk, msg=L.arm_message()),
                    "arm/neg_signed_by_the_operator", J, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, SA, 0, fc), self.cold_sk,
                               msg=L.arm_message(allowance=ALLOWANCE + 1)),
                    "arm/neg_signature_for_another_allowance", J, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, SA, 0, fc), self.cold_sk,
                               msg=L.arm_message(genesis=bytes(32))),
                    "arm/neg_signature_for_another_chain", J, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, SA, 0, fc), self.cold_sk,
                               msg=self.sim_sighash(arm.leaf, self.spend_tx(L, c3, SA, 0, fc), 0)),
                    "arm/neg_cold_signature_over_the_transaction", J, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, SA, 0, fc, issue=5,
                                                  outs=[self.out(5, self.dest, L.ASSET_OUT)]), sig=arm_sig),
                    "arm/neg_arm_and_mint_at_once", A, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, (0, 0, 1), 0, fc), sig=arm_sig),
                    "arm/neg_successor_forgets_the_count", J, control=arm)
        self.reject(self.reuse(arm, self.spend_tx(L, c3, S3, 0, fc), sig=arm_sig),
                    "arm/neg_successor_not_braked", J, control=arm)
        txa = self.ok(arm, "arm/brake_applied_by_a_third_party", extra={"state": SA})
        ca = self.coin_at(txa)

        # ---- the twin: two coins of one state ---------------------------------------
        self.to_age(t_w1, 2)
        fc = self.fee_coin()
        tw = self.signed(T, self.mint_tx(T, w1, ST, H, 2, fc), ST, "mint", self.op_sk)
        assert self.accept(tw)["allowed"]
        both = self.mint_tx(T, w1, ST, H, 2, fc, ins=[(w2, 2)], outs=[self.out(TOKEN_ATOMS, self.dest, T.TOKEN_OUT)])
        self.reuse(tw, both, self.op_sk)
        msg2 = self.sim_sighash(tw.leaf, both, 2)
        st = both.wit.vtxinwit[0].scriptWitness.stack
        both.wit.vtxinwit[2].scriptWitness.stack = [bit_replace(bytes.fromhex(tw.r["witness_hex"]), tw.sig,
                                                               sign_schnorr(self.op_sk, msg2)), st[1], st[2], st[3]]
        self.reject(self.wallet_sign(both), "twin/neg_second_coin_shares_the_successor", J, control=tw)
        self.fees.append(fc)
        # One coin braked, with the twin's own arm signature.
        fc_a = self.fee_coin()
        tarm = self.with_sig(T, self.spend_tx(T, w1, ST_ARMED, 0, fc_a), ST, "arm", sign_schnorr(self.cold_sk, T.arm_message()))
        txta = self.ok(tarm, "twin/brake_on_one_coin")
        wa = self.coin_at(txta)
        self.to_age(txta, 2)
        # A braked coin cannot mint: against the same mint from the coin with the brake off.
        fc = self.fee_coin()
        tw2 = self.signed(T, self.mint_tx(T, w2, ST, H, 2, fc), ST, "mint", self.op_sk)
        # The method first, on a spend the program accepts: the same pruned
        # program moved to the third coin, in another state with the brake off,
        # its state values and signature replaced, is accepted.
        moved_ok = self.reuse_into(tw2, self.mint_tx(T, w3, ST2, H, 2, fc), T, ST, ST2, self.op_sk)
        assert self.accept(moved_ok)["allowed"], self.accept(moved_ok)
        self.rec("brake/state_swap_method_accepted_on_an_unbraked_coin",
                 {"testmempoolaccept": True, "from_state": ST, "to_state": ST2})
        braked_mint = self.reuse_into(tw2, self.mint_tx(T, wa, ST_ARMED, H, 2, fc), T, ST, ST_ARMED, self.op_sk)
        self.reject(braked_mint, "brake/neg_mint_from_a_braked_coin", J, control=tw2, other_state=True)
        # Lifting a brake that is not on: against lifting the one that is.
        tdis = self.signed(T, self.spend_tx(T, wa, ST, 0, fc), ST_ARMED, "disarm", self.cold_sk)
        lift = self.reuse_into(tdis, self.spend_tx(T, w2, ST, 0, fc), T, ST_ARMED, ST, self.cold_sk)
        self.reject(lift, "brake/neg_disarm_a_coin_not_braked", J, control=tdis, other_state=True)
        self.fees.append(fc)

        # ---- while braked the operator cannot lift the brake; the cold key does --------
        self.to_age(txa, 2)
        fc = self.fee_coin()
        dis = self.signed(L, self.spend_tx(L, ca, S3, 0, fc), SA, "disarm", self.cold_sk)
        assert self.accept(dis)["allowed"]
        self.reject(self.reuse(dis, self.spend_tx(L, ca, S3, 0, fc), self.op_sk),
                    "disarm/neg_signed_by_the_operator", J, control=dis)
        self.reject(self.reuse(dis, self.spend_tx(L, ca, (0, 0, 0), 0, fc), self.cold_sk),
                    "disarm/neg_successor_forgets_the_count", J, control=dis)
        self.reject(self.reuse(dis, self.spend_tx(L, ca, S3, 0, fc, issue=5,
                                                  outs=[self.out(5, self.dest, L.ASSET_OUT)]), self.cold_sk),
                    "disarm/neg_disarm_and_mint_at_once", A, control=dis)
        txd = self.ok(dis, "disarm/brake_lifted_by_the_cold_key", extra={"state": S3})
        cd = self.coin_at(txd)
        # The operator mints again, from where the count stood: ten atoms of room.
        self.to_age(txd, 2)
        fc = self.fee_coin()
        again = self.signed(L, self.mint_tx(L, cd, S3, 10, 2, fc), S3, "mint", self.op_sk)
        self.reject(self.reuse(again, self.mint_tx(L, cd, S3, 11, 2, fc), self.op_sk),
                    "disarm/neg_count_survives_the_brake_one_atom_over", J, control=again)
        txg = self.ok(again, "disarm/mint_resumes_from_the_count", extra={"state": again.next_state})
        SG = again.next_state
        assert SG == (ALLOWANCE, 2, 0), SG
        cg = self.coin_at(txg)
        # The same arm signature, made once, brakes this new coin in the very
        # next block, where no mint can spend it (a mint needs two blocks).
        fc = self.fee_coin()
        SGA = (SG[0], SG[1], 1)
        age = node.getblockcount() + 1 - self.coin_height(txg)
        assert age == 1, age
        rearm = self.with_sig(L, self.spend_tx(L, cg, SGA, 0, fc), SG, "arm", arm_sig)
        txr = self.ok(rearm, "arm/the_same_signature_brakes_the_next_coin",
                      extra={"state": SGA, "coin_age_blocks": age})
        cr = self.coin_at(txr)

        # ---- recovery: refused one second before the delay, accepted at it --------
        base = self.coin_time(txr)
        due = base + RECOVERY_UNITS * 512
        self.mtp_to(due - 1)
        fc = self.fee_coin()
        rec_out = [self.out(TOKEN_ATOMS, self.wallet_spk(), L.TOKEN_OUT)]
        rtx = lambda seq=TIME | RECOVERY_UNITS, version=2: self.spend_tx(
            L, cr, None, seq, fc, no_successor=True, outs=rec_out, version=version)
        early = self.signed(L, rtx(), SGA, "recover", self.cold_sk)
        self.reject(early, "recover/neg_one_second_before_the_delay", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.rec("recover/clock", {"coin_time": base, "due": due, "tip_mtp_at_refusal": self.tip_mtp()})
        self.mtp_step()
        assert self.tip_mtp() == due, (self.tip_mtp(), due)
        rec = self.signed(L, rtx(), SGA, "recover", self.cold_sk)
        assert self.accept(rec)["allowed"]
        self.reject(self.reuse(rec, rtx(seq=TIME | (RECOVERY_UNITS - 1)), self.cold_sk),
                    "recover/neg_sequence_below_the_delay", J, control=rec)
        self.reject(self.reuse(rec, rtx(seq=RECOVERY_UNITS), self.cold_sk),
                    "recover/neg_lock_in_blocks", A, control=rec)
        self.reject(self.reuse(rec, rtx(seq=0xffffffff), self.cold_sk),
                    "recover/neg_lock_disabled", A, control=rec)
        self.reject(self.reuse(rec, rtx(version=1), self.cold_sk),
                    "recover/neg_version_1", J, control=rec)
        self.reject(self.reuse(rec, rtx(), self.op_sk), "recover/neg_signed_by_the_operator", J, control=rec)
        # Recovery of a coin whose brake is off: against the twin's braked coin, past its delay too.
        fc_t = self.fee_coin()
        trec_out = [self.out(TOKEN_ATOMS, self.wallet_spk(), T.TOKEN_OUT)]
        trec = self.signed(T, self.spend_tx(T, wa, None, TIME | RECOVERY_UNITS, fc_t, no_successor=True,
                                            outs=trec_out), ST_ARMED, "recover", self.cold_sk)
        unbraked = self.reuse_into(trec, self.spend_tx(T, w2, None, TIME | RECOVERY_UNITS, fc_t, no_successor=True,
                                                       outs=trec_out), T, ST_ARMED, ST, self.cold_sk)
        self.reject(unbraked, "recover/neg_coin_not_braked", J, control=trec, other_state=True)
        self.ok(rec, "recover/at_the_delay", extra={"coin_time": base, "due": due, "tip_mtp": self.tip_mtp()})


if __name__ == "__main__":
    M1().main()
