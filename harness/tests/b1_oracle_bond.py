"""B1: the oracle bond, from its descriptor.

`templates/oracle_bond` holds coins an oracle puts behind its format-2
attestations. Its key gives notice on a coin and withdraws it once the coin
has waited the notice by its own sequence; anyone who shows two of its
attestations of one pair, precision and time at different prices slashes it,
burning at least half and keeping the rest.

The run, on one regtest chain with Simplicity active from genesis:

  1. The oracle bonds three coins of the bond asset (one of them a top-up at
     the same address). It signs two attestations of one pair and time with
     different prices, as a liar who hands one price to a contract and
     publishes another would.
  2. A slash of a bonded coin with that pair: half burned, half to the
     presenter, mined. A slash during notice; a slash of two coins in one
     transaction, each burning at its own output 2k.
  3. Notice on a coin, the wait, the withdrawal to the key's chosen script.
  4. Every negative is refused by the mempool and in a block forced with
     `generateblock`, against an accepted control that differs from it only in
     the property it breaks: two attestations of different times, the same
     price twice, another pair, another precision, another key, one of each
     key; a burn one atom short, to another script, in another asset, or
     missing; a second coin's burn missing; a notice to another script or
     keeping the bonded state, signed for another coin, by another key, or
     with a price signature; a withdrawal too early (by BIP68 and by the
     program), with a sequence in blocks or disabled, at version 1, to another
     destination, under a signature for another coin or a notice signature,
     from the bonded state, or one atom short.

A negative's program is the control's pruned program, with the witness bits
swapped where the two differ, so the node runs the control's path on the
negative's transaction to the first check that fails.
"""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)
from simplicity import *  # noqa: E402,F401,F403

J, A = "Assertion failed inside jet", "Assertion failed"
TAG = "Sequentia/oracle/price"
BOND_TAG = "Sequentia/oracle/bond"
PATH_T = ("Either<Either<Signature, (u256, Signature)>, "
          "(u256, u256, u8, u32, (u64, u256, Signature), (u64, u256, Signature))>")
UNIT = 10 ** 8
FEE = 5000
NOTICE_UNITS = 2                       # 1,024 seconds: a test's notice; a real bond's is weeks
NOTICE = (1 << 22) | NOTICE_UNITS      # the nSequence form the template takes
BOND = 1_000 * UNIT
PRECISION = 5
OP_RETURN_SPK = b"\x6a"


def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


class B1(SimBase, BitcoinTestFramework):
    NAME = "b1"

    def set_test_params(self):
        self.chain_params()

    # -- chain time ------------------------------------------------------------
    def mtp(self):
        return self.node.getblockheader(self.node.getbestblockhash())["mediantime"]

    def advance(self, seconds):
        node = self.node
        tip = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(tip + seconds)
        self.generate(node, 12)

    # -- the oracle --------------------------------------------------------------
    def attest(self, price, time, sec=None, key=None, base=None, quote=None, precision=PRECISION, beacon=None):
        k = key or self.oracle_pk
        msg = (b"\x02" + k + (base or self.GOLD) + (quote or self.USDX) + price.to_bytes(8, "little")
               + bytes([precision]) + time.to_bytes(4, "little") + (beacon if beacon is not None else bytes(32)))
        assert len(msg) == 142
        return {"price": price, "time": time, "beacon": beacon if beacon is not None else bytes(32), "msg": msg,
                "base": base or self.GOLD, "quote": quote or self.USDX, "precision": precision,
                "sig": sign_schnorr(sec or self.oracle_sk, tagged(TAG, msg))}

    def bond_digest(self, kind, coin, dest=None):
        txid = bytes.fromhex(coin.txid)[::-1]
        m = bytes([kind]) + self.genesis_id + txid + coin.vout.to_bytes(4, "big")
        if dest is not None:
            m += dest
        return tagged(BOND_TAG, m)

    def sign_notice(self, coin, sec=None):
        return sign_schnorr(sec or self.oracle_sk, self.bond_digest(1, coin))

    def sign_withdraw(self, coin, dest_spk, sec=None):
        return sign_schnorr(sec or self.oracle_sk, self.bond_digest(2, coin, sha256(dest_spk)))

    # -- the template ----------------------------------------------------------
    def bond(self, state, key=None):
        params = {"ORACLE": (key or self.oracle_pk).hex(), "BOND_ASSET": self.BOND_ID.hex(),
                  "NOTICE": "%08x" % NOTICE}
        slots = {"STATE": "%02x" % state}
        x = self.sa.derive(self.desc, params, slots)
        info = self.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        b = type("Bond", (), {})()
        b.params, b.state, b.key = params, state, key or self.oracle_pk
        b.spk = bytes.fromhex(x["script_pubkey"])
        b.leaf = TreeLeaf(self.text, self.cmr, bytes.fromhex(x["leaves"]["bond"]["control_block"]))
        return b

    def witness(self, b, path):
        return {"ORACLE": vpub(b.key), "BOND_ASSET": v256(self.BOND_ID),
                "NOTICE": vu(NOTICE, 32), "STATE": vu(b.state, 8), "PATH": vraw(path, PATH_T)}

    @staticmethod
    def slash_path(a1, a2, time=None, base=None, quote=None, precision=None):
        t = a1["time"] if time is None else time
        return "Right((0x%s, 0x%s, %d, %d, (%d, 0x%s, 0x%s), (%d, 0x%s, 0x%s)))" % (
            (base or a1["base"]).hex(), (quote or a1["quote"]).hex(),
            a1["precision"] if precision is None else precision, t,
            a1["price"], a1["beacon"].hex(), a1["sig"].hex(),
            a2["price"], a2["beacon"].hex(), a2["sig"].hex())

    def agree(self, label, x, y, accepted):
        """The Python mirror's ruling on the pair agrees with the node's."""
        ruling = self.sa.oracle_bond_conflict(self.oracle_pk, x["msg"], x["sig"], y["msg"], y["sig"])
        assert (ruling is None) == accepted, (label, ruling)
        self.rec(label + "/mirror", {"conflict": ruling is None, "reason": ruling})

    @staticmethod
    def att_bits(a):
        return format(a["price"], "064b") + bits_of(a["beacon"]) + bits_of(a["sig"])

    # -- satisfying --------------------------------------------------------------
    def satisfy(self, b, tx, idx, path, ok, bits=None):
        """A control or a spend is satisfied, pruned and run here (it must
        execute). A negative is left pending: reject() gives it its control's
        pruned program and witness, with `bits` (old, new) swapped where the two
        differ, so the node runs the control's path to the first failing check."""
        if ok:
            return self.sim_satisfy(b.leaf, tx, idx, self.witness(b, path))
        tx.pending = dict(getattr(tx, "pending", {}), **{str(idx): (b.leaf, bits)})
        return None

    def finish(self, tx):
        kept = {k: getattr(tx, k) for k in ("r", "pending") if hasattr(tx, k)}
        tx2 = self.wallet_sign(tx)
        for k, v in kept.items():
            setattr(tx2, k, v)
        return tx2

    @staticmethod
    def swap_bits(blob, old, new):
        bits = bits_of(blob)
        assert len(old) == len(new) and bits.count(old) == 1, "the swapped bits occur %d times" % bits.count(old)
        bits = bits.replace(old, new)
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

    def reject(self, tx, label, expect, mempool=None, control=None, like=None, **kw):
        self.apply_pending(tx, like or control, label)
        return SimBase.reject(self, tx, label, expect, mempool=mempool, control=control, **kw)

    def apply_pending(self, tx, src, label=""):
        for k, (leaf, swaps) in getattr(tx, "pending", {}).items():
            idx = int(k)
            assert src is not None, "%s: a negative needs a control to take its program from" % label
            st = src.wit.vtxinwit[idx].scriptWitness.stack
            w = st[0]
            for old, new in (swaps or []):
                if old != new:
                    w = self.swap_bits(w, old, new)
            self.set_sim_wit(tx, idx, leaf, st[1], w)
        tx.pending = {}

    def ok(self, tx, label, extra=None, idx=0):
        m = self.sim_measure(tx, idx, tx.r) if getattr(tx, "r", None) else {}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    # -- the transactions --------------------------------------------------------
    def slash_tx(self, b, coin, a1, a2, ok=False, burn=None, burn_spk=None, burn_out=None, swaps=None, path=None):
        """The bond coin at input 0. Outputs: 0 the burn, 1 the presenter's half
        less the fee, 2 the fee, all in the bond asset."""
        c = coin.amount
        burned = c - c // 2 if burn is None else burn
        if burn_out is not None:
            # The burn in another asset, from the presenter's own coin; the
            # bond goes whole to the presenter, less the fee.
            fee_coin = self.coin(burned + 1000, self.POL)
            outs = [self.out(burned, OP_RETURN_SPK, burn_out),
                    self.out(c - FEE, self.presenter_spk, self.BOND_OUT),
                    self.out(fee_coin.amount - burned, self.presenter_spk, self.POL_OUT),
                    self.fee(FEE, self.BOND_OUT)]
            tx = self.mktx([coin, fee_coin], outs)
            tx = self._sat(b, tx, 0, path or self.slash_path(a1, a2), ok, swaps)
            return self.finish(tx)
        outs = [self.out(burned, burn_spk or OP_RETURN_SPK, self.BOND_OUT)]
        outs += [self.out(c - burned - FEE, self.presenter_spk, self.BOND_OUT), self.fee(FEE, self.BOND_OUT)]
        tx = self.mktx([coin], outs)
        return self._sat(b, tx, 0, path or self.slash_path(a1, a2), ok, swaps)

    def _sat(self, b, tx, idx, path, ok, swaps):
        tx.r = self.satisfy(b, tx, idx, path, ok, swaps)
        return tx

    def notice_tx(self, b, coin, sig, ok=False, to_spk=None, amount=None, swaps=None):
        """The bond coin at input 0, a wallet fee coin at input 1. Outputs: 0
        the bond with notice given, 1 the fee coin's change, 2 the fee."""
        fee_coin = self.fee_coin
        short = 0 if amount is None else coin.amount - amount     # what a short successor leaves goes to the fee
        outs = [self.out(coin.amount - short, to_spk or self.bond(1).spk, self.BOND_OUT),
                self.out(fee_coin.amount - FEE, self.oracle_wallet, self.BOND_OUT), self.fee(FEE + short, self.BOND_OUT)]
        tx = self.mktx([coin, fee_coin], outs)
        tx = self._sat(b, tx, 0, "Left(Left(0x%s))" % sig.hex(), ok, swaps)
        return self.finish(tx)

    def withdraw_tx(self, b, coin, dest_spk, sig, ok=False, seq=NOTICE, version=2, pay_spk=None, amount=None,
                    swaps=None, witness_dest=None):
        """The bond coin at input 0 with sequence `seq`, a wallet fee coin at
        input 1. Outputs: 0 the withdrawal, 1 the fee coin's change, 2 the fee."""
        fee_coin = self.fee_coin
        short = 0 if amount is None else coin.amount - amount
        outs = [self.out(coin.amount - short, pay_spk or dest_spk, self.BOND_OUT),
                self.out(fee_coin.amount - FEE, self.oracle_wallet, self.BOND_OUT), self.fee(FEE + short, self.BOND_OUT)]
        tx = self.mktx([(coin, seq), (fee_coin, 0xfffffffe)], outs, version=version)
        path = "Left(Right((0x%s, 0x%s)))" % ((witness_dest or sha256(dest_spk)).hex(), sig.hex())
        tx = self._sat(b, tx, 0, path, ok, swaps)
        return self.finish(tx)

    def coin(self, atoms, asset):
        return self.wallet_utxo(atoms, asset)

    # -- the run -----------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.boot(issue=("BOND", "GOLDA", "USDXA", "OTHER"))
        self.GOLD, self.USDX, self.OTHERQ = self.GOLDA_ID, self.USDXA_ID, self.OTHER_ID
        self.rec("whitelist", self.whitelist(self.BOND))
        self.genesis_id = bytes.fromhex(node.getblockhash(0))[::-1]
        self.advance(60)

        self.sa, self.desc, vectors, sources = load_template("oracle_bond")
        self.text, body = sources["bond"]
        self.cmr = bytes.fromhex(body["cmr"])

        self.oracle_sk = generate_privkey()
        self.oracle_pk = compute_xonly_pubkey(self.oracle_sk)[0]
        self.other_sk = generate_privkey()
        self.other_pk = compute_xonly_pubkey(self.other_sk)[0]
        self.presenter_spk, self.oracle_wallet = self.wallet_spk(), self.wallet_spk()
        self.dest_spk = self.wallet_spk()
        bonded, noticed = self.bond(0), self.bond(1)
        self.rec("template", {"template_hash": self.desc["template_hash"], "cmr": body["cmr"],
                              "max_cost_wu": body["max_cost_wu"], "params": bonded.params,
                              "bonded_spk": bonded.spk.hex(), "noticed_spk": noticed.spk.hex(),
                              "notice_sequence": "%08x" % NOTICE})

        # -- 1. the bond: two coins, then a top-up at the same address -------------
        K = [self.fund(bonded.spk, BOND, self.BOND) for _ in range(3)]
        K.append(self.fund(bonded.spk, BOND // 2 + 1, self.BOND))        # a top-up, odd
        self.rec("bond/posted", {"coins": ["%s:%d" % (k.txid, k.vout) for k in K], "atoms": [k.amount for k in K]})

        # Two attestations of one pair and time at different prices: the
        # conflict. The second names a beacon the first does not; a conflict
        # does not compare beacons.
        t = self.mtp() - 10
        a1 = self.attest(300_000_000, t)
        a2 = self.attest(240_000_000, t, beacon=sha256(b"some beacon"))

        # -- 2. the slash, against which every slash negative is judged ------------
        good = self.slash_tx(bonded, K[0], a1, a2, ok=True)
        self.agree("slash/bonded_coin", a1, a2, True)
        ab = lambda a: self.att_bits(a)
        # Two attestations of different times: the second signed at t+1 cannot
        # be put beside the first, which has one time field.
        a2_t = self.attest(240_000_000, t + 1, beacon=a2["beacon"])
        self.agree("slash/neg_two_times", a1, a2_t, False)
        self.reject(self.slash_tx(bonded, K[0], a1, a2_t, swaps=[(ab(a2), ab(a2_t))]),
                    "slash/neg_two_times", J, control=good)
        # The same price twice, under two signatures.
        a1b = self.attest(300_000_000, t, beacon=a2["beacon"])
        assert a1b["sig"] != a1["sig"]
        self.agree("slash/neg_same_price_twice", a1, a1b, False)
        self.reject(self.slash_tx(bonded, K[0], a1, a1b, swaps=[(ab(a2), ab(a1b))]),
                    "slash/neg_same_price_twice", J, control=good)
        # Another pair: the second prices GOLD in another asset.
        a2_q = self.attest(240_000_000, t, beacon=a2["beacon"], quote=self.OTHERQ)
        self.agree("slash/neg_another_pair", a1, a2_q, False)
        self.reject(self.slash_tx(bonded, K[0], a1, a2_q, swaps=[(ab(a2), ab(a2_q))]),
                    "slash/neg_another_pair", J, control=good)
        # Another precision: 2.4 at precision 6 is not a conflict with 3.0 at 5.
        a2_p = self.attest(2_400_000_000, t, beacon=a2["beacon"], precision=PRECISION + 1)
        self.agree("slash/neg_another_precision", a1, a2_p, False)
        self.reject(self.slash_tx(bonded, K[0], a1, a2_p, swaps=[(ab(a2), ab(a2_p))]),
                    "slash/neg_another_precision", J, control=good)
        # Another key: a conflict signed by a key the bond does not stand behind.
        b1o = self.attest(300_000_000, t, sec=self.other_sk, key=self.other_pk)
        b2o = self.attest(240_000_000, t, sec=self.other_sk, key=self.other_pk, beacon=a2["beacon"])
        self.agree("slash/neg_another_key", b1o, b2o, False)
        self.reject(self.slash_tx(bonded, K[0], b1o, b2o, swaps=[(ab(a1), ab(b1o)), (ab(a2), ab(b2o))]),
                    "slash/neg_another_key", J, control=good)
        # One attestation by the bonded key, the other by another.
        self.agree("slash/neg_one_by_another_key", a1, b2o, False)
        self.reject(self.slash_tx(bonded, K[0], a1, b2o, swaps=[(ab(a2), ab(b2o))]),
                    "slash/neg_one_by_another_key", J, control=good)
        # The burn: one atom short of half, to another script, in another asset, none.
        c0 = K[0].amount
        assert self.sa.oracle_bond_burn_min(c0) == c0 - c0 // 2
        self.reject(self.slash_tx(bonded, K[0], a1, a2, burn=c0 - c0 // 2 - 1),
                    "slash/neg_burns_one_atom_short_of_half", J, control=good)
        self.reject(self.slash_tx(bonded, K[0], a1, a2, burn_spk=self.presenter_spk),
                    "slash/neg_burn_paid_to_the_presenter", J, control=good)
        self.reject(self.slash_tx(bonded, K[0], a1, a2, burn_out=self.POL_OUT),
                    "slash/neg_burn_in_another_asset", J, control=good)
        whole = self.mktx([K[0]], [self.out(c0 - FEE, self.presenter_spk, self.BOND_OUT), self.fee(FEE, self.BOND_OUT)])
        whole.pending = {"0": (bonded.leaf, [])}
        self.reject(whole, "slash/neg_nothing_burned_all_to_the_presenter", J, control=good)

        presenter_before = sum(u["amount"] for u in node.listunspent() if u["scriptPubKey"] == self.presenter_spk.hex()
                               and u["asset"] == self.BOND)
        ts = self.ok(good, "slash/bonded_coin", extra={"bond": c0, "burned": c0 - c0 // 2,
                                                       "to_presenter_before_fee": c0 // 2})
        stx = node.getrawtransaction(ts, True)
        assert stx["vout"][0]["scriptPubKey"]["hex"] == "6a" and stx["vout"][0]["value"] * COIN == c0 - c0 // 2
        got = self.utxo_of(ts, self.presenter_spk)
        assert got.amount == c0 // 2 - FEE
        self.rec("slash/bonded_coin/outputs", {"burned": int(stx["vout"][0]["value"] * COIN),
                                               "presenter": got.amount, "fee": FEE,
                                               "presenter_before": str(presenter_before)})

        # -- two coins in one slash, each burning at its own output 2k --------------
        k1, k3 = K[1], K[3]
        outs = [self.out(k1.amount - k1.amount // 2, OP_RETURN_SPK, self.BOND_OUT),
                self.out(k1.amount // 2, self.presenter_spk, self.BOND_OUT),
                self.out(k3.amount - k3.amount // 2, OP_RETURN_SPK, self.BOND_OUT),
                self.out(k3.amount // 2 - FEE, self.presenter_spk, self.BOND_OUT), self.fee(FEE, self.BOND_OUT)]
        two = self.mktx([k1, k3], outs)
        self.sim_satisfy(bonded.leaf, two, 0, self.witness(bonded, self.slash_path(a1, a2)))
        two.r = self.sim_satisfy(bonded.leaf, two, 1, self.witness(bonded, self.slash_path(a1, a2)))
        # The second coin's burn missing: its output 2 pays the presenter.
        bad = self.mktx([k1, k3], outs[:2] + [self.out(k3.amount - k3.amount // 2, self.presenter_spk, self.BOND_OUT)]
                        + outs[3:])
        st0, st1 = two.wit.vtxinwit[0].scriptWitness.stack, two.wit.vtxinwit[1].scriptWitness.stack
        self.set_sim_wit(bad, 0, bonded.leaf, st0[1], st0[0])
        self.set_sim_wit(bad, 1, bonded.leaf, st1[1], st1[0])
        self.reject(bad, "slash/neg_second_coin_burn_missing", J, control=two, index=1)
        # Both coins pointing at one burn: the second coin's own output 2 pays the
        # presenter and output 0 burns enough for both.
        both = self.mktx([k1, k3], [self.out(k1.amount - k1.amount // 2 + k3.amount - k3.amount // 2, OP_RETURN_SPK,
                                             self.BOND_OUT),
                                    self.out(k1.amount // 2, self.presenter_spk, self.BOND_OUT),
                                    self.out(k3.amount // 2 - FEE, self.presenter_spk, self.BOND_OUT),
                                    self.fee(FEE, self.BOND_OUT)])
        self.set_sim_wit(both, 0, bonded.leaf, st0[1], st0[0])
        self.set_sim_wit(both, 1, bonded.leaf, st1[1], st1[0])
        self.reject(both, "slash/neg_two_coins_share_one_burn", J, control=two, index=1)
        self.ok(two, "slash/two_coins_one_transaction", idx=1,
                extra={"burned": [k1.amount - k1.amount // 2, k3.amount - k3.amount // 2]})

        # -- 3. notice on K[2], the wait, the withdrawal ------------------------------
        k2 = K[2]
        self.fee_coin = self.coin(100_000, self.BOND)
        n_sig = self.sign_notice(k2)
        nb = lambda s: bits_of(s)
        good_n = self.notice_tx(bonded, k2, n_sig, ok=True)
        self.reject(self.notice_tx(bonded, k2, n_sig, to_spk=self.oracle_wallet),
                    "notice/neg_to_another_script", J, control=good_n)
        self.reject(self.notice_tx(bonded, k2, n_sig, to_spk=bonded.spk),
                    "notice/neg_successor_still_bonded", J, control=good_n)
        self.reject(self.notice_tx(bonded, k2, n_sig, amount=k2.amount - 1),
                    "notice/neg_successor_one_atom_short", J, control=good_n)
        other_coin_sig = self.sign_notice(K[0])
        self.reject(self.notice_tx(bonded, k2, other_coin_sig, swaps=[(nb(n_sig), nb(other_coin_sig))]),
                    "notice/neg_signature_for_another_coin", J, control=good_n)
        other_key_sig = self.sign_notice(k2, sec=self.other_sk)
        self.reject(self.notice_tx(bonded, k2, other_key_sig, swaps=[(nb(n_sig), nb(other_key_sig))]),
                    "notice/neg_signature_by_another_key", J, control=good_n)
        self.reject(self.notice_tx(bonded, k2, a1["sig"], swaps=[(nb(n_sig), nb(a1["sig"]))]),
                    "notice/neg_a_price_signature", J, control=good_n)
        w_as_n = self.sign_withdraw(k2, self.dest_spk)
        self.reject(self.notice_tx(bonded, k2, w_as_n, swaps=[(nb(n_sig), nb(w_as_n))]),
                    "notice/neg_a_withdrawal_signature", J, control=good_n)
        tn = self.ok(good_n, "notice/given")
        U = self.utxo_at(tn, 0)
        assert U.spk == noticed.spk and U.amount == k2.amount

        # A notice on a coin already in notice: refused, against the notice on a
        # bonded coin (the same program at the other state).
        self.fee_coin = self.coin(100_000, self.BOND)
        u_sig = self.sign_notice(U)
        kb = self.fund(bonded.spk, BOND, self.BOND)
        kb_sig = self.sign_notice(kb)
        ctl_state = self.notice_tx(bonded, kb, kb_sig, ok=True)
        self.reject(self.notice_tx(noticed, U, u_sig, swaps=[self.state_swap(0, 1), (nb(kb_sig), nb(u_sig))]),
                    "notice/neg_from_notice_given", J, control=ctl_state, other_state=True)

        # -- the withdrawal: too early, then every refusal against the control -------
        self.fee_coin = self.coin(100_000, self.BOND)
        w_sig = self.sign_withdraw(U, self.dest_spk)
        self.advance(NOTICE_UNITS * 512 + 600)
        good_w = self.withdraw_tx(noticed, U, self.dest_spk, w_sig, ok=True)
        # BIP68 itself refuses a coin younger than its sequence: a fresh coin in
        # notice, its withdrawal signed and its program the control's.
        self.fee_coin = self.coin(100_000, self.BOND)
        young = self.fund(noticed.spk, BOND, self.BOND)
        y_sig = self.sign_withdraw(young, self.dest_spk)
        self.reject(self.withdraw_tx(noticed, young, self.dest_spk, y_sig, swaps=[(nb(w_sig), nb(y_sig))]),
                    "withdraw/neg_before_the_notice_has_run", "bad-txns-nonfinal", mempool="non-BIP68-final",
                    like=good_w)
        self.fee_coin = self.coin(100_000, self.BOND)
        good_w = self.withdraw_tx(noticed, U, self.dest_spk, w_sig, ok=True)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, seq=(1 << 22) | (NOTICE_UNITS - 1)),
                    "withdraw/neg_sequence_below_the_notice", J, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, seq=NOTICE_UNITS),
                    "withdraw/neg_sequence_in_blocks", A, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, seq=0xfffffffe),
                    "withdraw/neg_sequence_disabled", A, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, version=1),
                    "withdraw/neg_transaction_version_1", J, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, pay_spk=self.presenter_spk),
                    "withdraw/neg_paid_to_another_script", J, control=good_w)
        thief = self.presenter_spk
        self.reject(self.withdraw_tx(noticed, U, thief, w_sig,
                                     swaps=[(bits_of(sha256(self.dest_spk)), bits_of(sha256(thief)))]),
                    "withdraw/neg_signed_destination_replaced", J, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, w_sig, amount=U.amount - 1),
                    "withdraw/neg_one_atom_short", J, control=good_w)
        wo = self.sign_withdraw(K[0], self.dest_spk)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, wo, swaps=[(nb(w_sig), nb(wo))]),
                    "withdraw/neg_signature_for_another_coin", J, control=good_w)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, u_sig, swaps=[(nb(w_sig), nb(u_sig))]),
                    "withdraw/neg_a_notice_signature", J, control=good_w)
        wk = self.sign_withdraw(U, self.dest_spk, sec=self.other_sk)
        self.reject(self.withdraw_tx(noticed, U, self.dest_spk, wk, swaps=[(nb(w_sig), nb(wk))]),
                    "withdraw/neg_signature_by_another_key", J, control=good_w)
        # From the bonded state: a withdrawal signed for a bonded coin, refused
        # against the withdrawal of the coin in notice (the same program).
        kb2 = self.fund(bonded.spk, BOND, self.BOND)
        self.advance(NOTICE_UNITS * 512 + 600)
        self.fee_coin = self.coin(100_000, self.BOND)
        good_w = self.withdraw_tx(noticed, U, self.dest_spk, w_sig, ok=True)
        kb2_sig = self.sign_withdraw(kb2, self.dest_spk)
        self.reject(self.withdraw_tx(bonded, kb2, self.dest_spk, kb2_sig,
                                     swaps=[self.state_swap(1, 0), (nb(w_sig), nb(kb2_sig))]),
                    "withdraw/neg_without_notice", J, control=good_w, other_state=True)
        tw = self.ok(good_w, "withdraw/after_the_notice", extra={"notice_sequence": "%08x" % NOTICE})
        got = self.utxo_of(tw, self.dest_spk)
        assert got.amount == U.amount

        # -- a slash during notice ---------------------------------------------------
        self.fee_coin = self.coin(100_000, self.BOND)
        n2 = self.ok(self.notice_tx(bonded, kb, kb_sig, ok=True), "notice/second")
        U2 = self.utxo_at(n2, 0)
        assert U2.spk == noticed.spk
        # The method first: the bonded slash's pruned program, its state bits
        # swapped, on the coin in notice, is accepted.
        moved = self.slash_tx(noticed, U2, a1, a2, swaps=[self.state_swap(0, 1)])
        self.apply_pending(moved, good)
        assert self.accept(moved)["allowed"], self.accept(moved)
        self.rec("slash/state_swap_method_accepted", {"testmempoolaccept": True, "from_state": 0, "to_state": 1})
        tsn = self.ok(self.slash_tx(noticed, U2, a2, a1, ok=True), "slash/coin_in_notice",
                      extra={"bond": U2.amount, "burned": U2.amount - U2.amount // 2})
        assert node.getrawtransaction(tsn, True)["vout"][0]["scriptPubKey"]["hex"] == "6a"

        # -- the bond's measured limits ----------------------------------------------
        self.rec("measured", {k: {f: self.R[k].get(f) for f in ("vsize", "weight", "program_bytes", "witness_bytes",
                                                             "cost_bound_wu", "budget_wu")}
                              for k in ("slash/bonded_coin", "slash/coin_in_notice", "slash/two_coins_one_transaction",
                                        "notice/given", "withdraw/after_the_notice")})

    def state_swap(self, s_from, s_to):
        """The witness bits of BOND_ASSET, NOTICE and STATE, which the program
        reads in that order: STATE alone is one byte, too short to find."""
        return (bits_of(self.BOND_ID) + format(NOTICE, "032b") + format(s_from, "08b"),
                bits_of(self.BOND_ID) + format(NOTICE, "032b") + format(s_to, "08b"))


if __name__ == "__main__":
    B1().main()
