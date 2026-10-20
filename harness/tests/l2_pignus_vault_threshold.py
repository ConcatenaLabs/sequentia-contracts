"""L2: the Pignus vault and offer under several oracles, from their descriptors.

`templates/pignus_vault_threshold` is the version 2 vault with one change: a
liquidation takes a price record that at least THRESHOLD of three oracle keys
attest, each under its own live beacon. `templates/pignus_offer_threshold`
opens such vaults.

The run, on one regtest chain with Simplicity active from genesis:

  1. Three oracles, each with its own key, beacon asset and beacon. An offer of
     a 2-of-3 loan, taken: a vault opens. Vaults of the same program at
     thresholds 0, 1, 2 and 3, and one whose first two keys are one key, are
     paid at their addresses directly, so each differs from the 2-of-3 one in
     that alone.
  2. The 2-of-3 vault liquidated in part with two signatures (oracles 1 and 2),
     both beacons spent and recreated; its successor liquidated again with
     oracles 2 and 3; a 1-of-3 vault with one signature; a 3-of-3 with three.
  3. Refused in blocks, each against an accepted control that differs only in
     the property: the 2-of-3 vault with one signature; the second signature
     by a key outside the set, by the first oracle again, over another price,
     over another time, or naming a beacon spent at another input; a 3-of-3
     vault with two; a threshold of 0 with one; one oracle filling two slots
     of a set that lists its key twice; the offer opening a vault under another
     key set or another threshold.

A negative's program is its control's pruned program, with the witness bits
swapped where the two differ (a slot's signature, a term), so the node runs
the control's path to the first check that fails. A negative that needs
another vault takes the control's program to that vault's coin with the
differing terms swapped, as it would be spent; the method itself is shown
accepted on a vault where the swap changes nothing the program refuses.
"""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)
from simplicity import *  # noqa: E402,F401,F403
from o2_beacon import Beacon, tagged, TAG  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
SLOT_T = "Option<(Signature, u256, u32)>"
PATH_T = "Either<Either<(), ()>, Either<(u64, u32, [%s; 3], bool), ()>>" % SLOT_T
OFFER_PATH_T = "Either<u256, ()>"
UNIT = 10 ** 8
FEE = 5000
PRECISION = 8
LIQ, TARGET, BONUS = 12500, 15000, 10500
LOT, DEBT, COLLATERAL = 2_000_000 * UNIT, 2_100_000 * UNIT, 3_000_000 * UNIT
ISSUE = 40_000_000


def price_of(x):
    return int(round(x * 10 ** PRECISION))


class L2(SimBase, BitcoinTestFramework):
    NAME = "l2"

    def set_test_params(self):
        self.chain_params()

    # -- chain time ------------------------------------------------------------
    def mtp(self):
        return self.node.getblockheader(self.node.getbestblockhash())["mediantime"]

    def advance_to(self, t):
        node = self.node
        tip = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(max(t, tip) + 60)
        self.generate(node, 12)
        assert self.mtp() >= t, (self.mtp(), t)

    def tick(self):
        self.advance_to(self.mtp() + 120)

    # -- the oracles -------------------------------------------------------------
    def attest(self, i, price, time, beacon=None, sec=None, key=None):
        """Oracle i's format-2 attestation of the record (X in Y at PRECISION)."""
        k = key or self.pk[i]
        b = self.B[i].program if beacon is None else beacon
        msg = (b"\x02" + k + self.X_ID + self.Y_ID + price.to_bytes(8, "little") + bytes([PRECISION])
               + time.to_bytes(4, "little") + b)
        return {"price": price, "time": time, "beacon": b, "sig": sign_schnorr(sec or self.sk[i], tagged(TAG, msg))}

    # -- the templates ---------------------------------------------------------
    def terms(self, keys=None, threshold=2, borrower=True, beacons=None):
        keys = keys or self.pk
        beacons = beacons or self.BEACON_ID
        p = {"COLL": self.X_ID.hex(), "DEBT_ASSET": self.Y_ID.hex(),
             "ORACLE_1": keys[0].hex(), "ORACLE_2": keys[1].hex(), "ORACLE_3": keys[2].hex(),
             "BEACON_ASSET_1": beacons[0].hex(), "BEACON_ASSET_2": beacons[1].hex(),
             "BEACON_ASSET_3": beacons[2].hex(), "THRESHOLD": "%02x" % threshold,
             "PRECISION": "%02x" % PRECISION, "LIQ_BP": "%08x" % LIQ, "TARGET_BP": "%08x" % TARGET,
             "BONUS_BP": "%08x" % BONUS, "MATURITY": "%08x" % self.MATURITY,
             "RECOVER_AFTER": "%08x" % self.RECOVER_AFTER, "LENDER": sha256(self.lender_spk).hex()}
        if borrower:
            p["BORROWER"] = sha256(self.borrower_spk).hex()
        return p

    def vault(self, debt, last, params=None):
        params = params or self.terms()
        slots = {"DEBT_OUT": "%016x" % debt, "LAST_TIME": "%08x" % last}
        x = self.vsa.derive(self.vdesc, params, slots)
        info = self.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        v = type("Vault", (), {})()
        v.params, v.debt, v.last = params, debt, last
        v.spk = bytes.fromhex(x["script_pubkey"])
        v.leaf = TreeLeaf(self.vtext, self.vcmr, bytes.fromhex(x["leaves"]["vault"]["control_block"]))
        return v

    def vault_witness(self, v, path):
        p = v.params
        n = lambda k: int(p[k], 16)
        w = {k: v256(bytes.fromhex(p[k])) for k in ("COLL", "DEBT_ASSET", "BEACON_ASSET_1", "BEACON_ASSET_2",
                                                    "BEACON_ASSET_3", "LENDER", "BORROWER")}
        w.update({k: vpub(bytes.fromhex(p[k])) for k in ("ORACLE_1", "ORACLE_2", "ORACLE_3")})
        w.update({"THRESHOLD": vu(n("THRESHOLD"), 8), "PRECISION": vu(n("PRECISION"), 8),
                  "LIQ_BP": vu(n("LIQ_BP"), 32), "TARGET_BP": vu(n("TARGET_BP"), 32),
                  "BONUS_BP": vu(n("BONUS_BP"), 32), "MATURITY": vu(n("MATURITY"), 32),
                  "RECOVER_AFTER": vu(n("RECOVER_AFTER"), 32),
                  "DEBT_OUT": vu(v.debt, 64), "LAST_TIME": vu(v.last, 32), "PATH": vraw(path, PATH_T)})
        return w

    @staticmethod
    def slot(a, at):
        return "None" if a is None else "Some((0x%s, 0x%s, %d))" % (a["sig"].hex(), a["beacon"].hex(), at)

    def liq_path(self, price, time, slots, matured=False):
        return "Right(Left((%d, %d, [%s], %s)))" % (price, time, ", ".join(self.slot(a, at) for a, at in slots),
                                                     "true" if matured else "false")

    def offer(self, params_from=None, lots=2):
        params = self.terms(borrower=False)
        params.update({"LOT": "%016x" % LOT, "DEBT": "%016x" % DEBT, "COLLATERAL": "%016x" % COLLATERAL,
                       "EXPIRY": "%08x" % self.EXPIRY})
        x = self.osa.derive(self.odesc, params, {})
        o = type("Offer", (), {})()
        o.params = params
        o.spk = bytes.fromhex(x["script_pubkey"])
        o.leaf = TreeLeaf(self.otext, self.ocmr, bytes.fromhex(x["leaves"]["offer"]["control_block"]))
        return o

    def offer_witness(self, o, path):
        p = o.params
        n = lambda k: int(p[k], 16)
        w = {k: v256(bytes.fromhex(p[k])) for k in ("COLL", "DEBT_ASSET", "BEACON_ASSET_1", "BEACON_ASSET_2",
                                                    "BEACON_ASSET_3", "LENDER")}
        w.update({k: vpub(bytes.fromhex(p[k])) for k in ("ORACLE_1", "ORACLE_2", "ORACLE_3")})
        w.update({"THRESHOLD": vu(n("THRESHOLD"), 8), "PRECISION": vu(PRECISION, 8), "LIQ_BP": vu(LIQ, 32),
                  "TARGET_BP": vu(TARGET, 32), "BONUS_BP": vu(BONUS, 32), "MATURITY": vu(self.MATURITY, 32),
                  "RECOVER_AFTER": vu(self.RECOVER_AFTER, 32), "LOT": vu(LOT, 64), "DEBT": vu(DEBT, 64),
                  "COLLATERAL": vu(COLLATERAL, 64), "EXPIRY": vu(self.EXPIRY, 32), "PATH": vraw(path, OFFER_PATH_T)})
        return w

    # -- satisfying ------------------------------------------------------------
    def satisfy(self, leaf, tx, idx, witness, ok, swaps=None):
        if ok:
            return self.sim_satisfy(leaf, tx, idx, witness)
        tx.pending = dict(getattr(tx, "pending", {}), **{str(idx): (leaf, swaps)})
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

    def apply_pending(self, tx, src):
        for k, (leaf, swaps) in getattr(tx, "pending", {}).items():
            idx = int(k)
            assert src is not None, "a negative needs a control to take its program from"
            st = src.wit.vtxinwit[idx].scriptWitness.stack
            w = st[0]
            for old, new in (swaps or []):
                if old != new:
                    w = self.swap_bits(w, old, new)
            self.set_sim_wit(tx, idx, leaf, st[1], w)
        tx.pending = {}

    def reject(self, tx, label, expect, mempool=None, control=None, like=None, **kw):
        self.apply_pending(tx, like or control)
        return SimBase.reject(self, tx, label, expect, mempool=mempool, control=control, **kw)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, 0, tx.r) if getattr(tx, "r", None) else {}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def coin(self, atoms, asset):
        return self.wallet_utxo(atoms, asset)

    # -- swaps -------------------------------------------------------------------
    def term_swap(self, v_from, v_to):
        """The witness bits of the keys, beacon assets and threshold, which the
        program reads in that order, from one vault's terms to another's."""
        def bits(p):
            return "".join(bits_of(bytes.fromhex(p[k])) for k in
                           ("ORACLE_1", "ORACLE_2", "ORACLE_3", "BEACON_ASSET_1", "BEACON_ASSET_2",
                            "BEACON_ASSET_3")) + format(int(p["THRESHOLD"], 16), "08b")
        return (bits(v_from.params), bits(v_to.params))

    @staticmethod
    def sig_swap(a, b):
        return (bits_of(a["sig"]), bits_of(b["sig"]))

    # -- the transactions ------------------------------------------------------
    def liq_tx(self, v, vcoin, price, time, slots, paid, kept, ok=False, swaps=None, succ=None):
        """The vault at input 0, then one beacon coin per presented slot, then
        the liquidator's coin. Outputs: 0 the successor, 1 the lender, then each
        beacon recreated at output 2k, the seizure and the change between."""
        c = vcoin.amount
        seized = c - kept
        succ = succ or self.vault(v.debt - paid, time, params=v.params)
        ins, beacon_ins = [], []
        slot_list = []
        for i, a in enumerate(slots):
            if a is None:
                slot_list.append((None, 0))
                continue
            at = 1 + len(beacon_ins)
            bc = self.bcoins[a["oracle"]].pop(0)
            beacon_ins.append((bc, a["oracle"]))
            slot_list.append((a, at))
        lc = self.liquidator_coin
        ins = [b for b, _ in beacon_ins] + [lc]
        outs = [self.out(kept, succ.spk, self.X_OUT), self.out(paid, self.lender_spk, self.Y_OUT)]
        extra = [self.out(seized, self.liquidator_spk, self.X_OUT),
                 self.out(lc.amount - paid - FEE, self.liquidator_spk, self.Y_OUT)]
        for n, (bc, i) in enumerate(beacon_ins):
            outs.append(self.out(bc.amount, bc.spk, self.BEACON_OUT[i]))
            if n + 1 < len(beacon_ins):
                outs.append(extra.pop(0))
        outs += extra + [self.fee(FEE, self.Y_OUT)]
        tx = self.mktx([(vcoin, 0xfffffffe)] + [(x, 0xfffffffe) for x in ins], outs, locktime=time)
        for n, (bc, i) in enumerate(beacon_ins):
            self.setwit(tx, 1 + n, self.B[i].wit_recreate())
        # the beacon coins go back to the pool for the next transaction
        for bc, i in reversed(beacon_ins):
            self.bcoins[i].insert(0, bc)
        tx.r = self.satisfy(v.leaf, tx, 0, self.vault_witness(v, self.liq_path(price, time, slot_list)), ok, swaps)
        return self.finish(tx), succ

    # -- the run -----------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.boot(issue=("BEACON1", "BEACON2", "BEACON3"))
        self.BEACON_ID = [self.BEACON1_ID, self.BEACON2_ID, self.BEACON3_ID]
        self.BEACON_OUT = [self.BEACON1_OUT, self.BEACON2_OUT, self.BEACON3_OUT]
        beacon_labels = [self.BEACON1, self.BEACON2, self.BEACON3]
        for name in ("X", "Y"):
            a = node.issueasset(assetamount=ISSUE, tokenamount=0, blind=False, fee_asset=BITCOIN_ASSET)["asset"]
            self.generate(node, 1)
            setattr(self, name, a)
            setattr(self, name + "_OUT", self.asset_out(a))
            setattr(self, name + "_ID", bytes.fromhex(a)[::-1])
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 60)
        self.generate(node, 12)

        self.vsa, self.vdesc, _, vsrc = load_template("pignus_vault_threshold")
        self.osa, self.odesc, _, osrc = load_template("pignus_offer_threshold")
        self.vtext, vbody = vsrc["vault"]
        self.otext, obody = osrc["offer"]
        self.vcmr, self.ocmr = bytes.fromhex(vbody["cmr"]), bytes.fromhex(obody["cmr"])
        assert "0x" + vbody["cmr"] in self.otext, "the offer does not name the vault's program"

        # -- the oracles and the parties ---------------------------------------
        self.sk = [generate_privkey() for _ in range(3)]
        self.pk = [compute_xonly_pubkey(s)[0] for s in self.sk]
        self.B = [Beacon(self.pk[i], sha256(b"l2 beacon %d" % i)) for i in range(3)]
        self.bcoins = [[self.fund(self.B[i].spk, 1, beacon_labels[i]) for _ in range(3)] for i in range(3)]
        self.stranger_sk = generate_privkey()
        self.lender_spk, self.borrower_spk = self.wallet_spk(), self.wallet_spk()
        self.borrower_wallet, self.liquidator_spk = self.wallet_spk(), self.wallet_spk()
        now = self.mtp()
        self.MATURITY, self.RECOVER_AFTER, self.EXPIRY = now + 4 * 3600, now + 8 * 3600, now + 2 * 3600
        self.rec("terms", {"vault_template": self.vdesc["template_hash"], "offer_template": self.odesc["template_hash"],
                           "vault_cmr": vbody["cmr"], "offer_cmr": obody["cmr"],
                           "vault_max_cost_wu": vbody["max_cost_wu"], "offer_max_cost_wu": obody["max_cost_wu"],
                           "params": self.terms()})

        # -- 1. an offer of a 2-of-3 loan, taken ---------------------------------
        o = self.offer()
        ocoin = self.fund(o.spk, 2 * LOT, self.Y)
        lock = self.mtp() - 1

        def take(vault_params=None, ok=False):
            bc = self.take_coin
            v = self.vault(DEBT, lock, params=vault_params)
            outs = [self.out(COLLATERAL, v.spk, self.X_OUT), self.out(ocoin.amount - LOT, o.spk, self.Y_OUT),
                    self.out(LOT - FEE, self.borrower_wallet, self.Y_OUT), self.fee(FEE, self.Y_OUT)]
            tx = self.mktx([(ocoin, 0xfffffffe), (bc, 0xfffffffe)], outs, locktime=lock)
            tx.r = self.satisfy(o.leaf, tx, 0, self.offer_witness(o, "Left(0x%s)" % sha256(self.borrower_spk).hex()), ok)
            return self.finish(tx), v
        self.take_coin = self.coin(COLLATERAL, self.X)
        good_take, V = take(ok=True)
        stranger_set = [self.pk[0], self.pk[1], compute_xonly_pubkey(self.stranger_sk)[0]]
        self.reject(take(self.terms(keys=stranger_set))[0], "take/neg_vault_under_another_key_set", J, control=good_take)
        self.reject(take(self.terms(threshold=1))[0], "take/neg_vault_at_another_threshold", J, control=good_take)
        t1 = self.ok(good_take, "take/two_of_three")
        cV = self.utxo_at(t1, 0)
        assert cV.spk == V.spk

        # Vaults of the same program differing in one term, paid directly.
        last = lock
        V1 = self.vault(DEBT, last, params=self.terms(threshold=1))
        V0 = self.vault(DEBT, last, params=self.terms(threshold=0))
        V3 = self.vault(DEBT, last, params=self.terms(threshold=3))
        dup = [self.pk[0], self.pk[0], self.pk[2]]
        VD = self.vault(DEBT, last, params=self.terms(keys=dup, beacons=[self.BEACON_ID[0], self.BEACON_ID[0],
                                                                         self.BEACON_ID[2]]))
        c1, c0, c3, cD = (self.fund(v.spk, COLLATERAL, self.X) for v in (V1, V0, V3, VD))
        self.liquidator_coin = self.coin(3_000_000 * UNIT, self.Y)
        self.tick()

        # -- 2. the 2-of-3 liquidation and its refusals ------------------------------
        low = price_of(0.80)
        ta = self.mtp() - 2
        assert not self.vsa.pignus_vault_healthy(COLLATERAL, DEBT, low, PRECISION, LIQ)
        r_max = self.vsa.pignus_vault_max_repay(COLLATERAL, DEBT, low, PRECISION, TARGET, BONUS)
        kept = COLLATERAL - self.vsa.pignus_vault_max_seizure(r_max, low, PRECISION, BONUS)
        assert 0 < r_max < DEBT and 0 < kept < COLLATERAL, (r_max, kept)
        att = [dict(self.attest(i, low, ta), oracle=i) for i in range(3)]
        liq, succ = self.liq_tx(V, cV, low, ta, [att[0], att[1], None], r_max, kept, ok=True)

        # The method: the 2-of-3 control's program on the 1-of-3 vault, its
        # threshold swapped, two signatures still presented: accepted.
        moved, _ = self.liq_tx(V1, c1, low, ta, [att[0], att[1], None], r_max, kept, swaps=[self.term_swap(V, V1)])
        self.apply_pending(moved, liq)
        assert self.accept(moved)["allowed"], self.accept(moved)
        self.rec("method/threshold_swap_accepted", {"testmempoolaccept": True, "from": 2, "to": 1})

        # One signature for a 2-of-3: against the 1-of-3 vault liquidated with that one.
        one, _ = self.liq_tx(V1, c1, low, ta, [att[0], None, None], r_max, kept, ok=True)
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], None, None], r_max, kept, swaps=[self.term_swap(V1, V)])[0],
                    "threshold/neg_two_of_three_with_one_signature", J, control=one, other_state=True)
        # A 3-of-3 vault with two signatures: against the 2-of-3 with the same two.
        self.reject(self.liq_tx(V3, c3, low, ta, [att[0], att[1], None], r_max, kept, swaps=[self.term_swap(V, V3)])[0],
                    "threshold/neg_three_of_three_with_two_signatures", J, control=liq, other_state=True)
        # A threshold of 0 with one signature: against the 1-of-3 with it.
        self.reject(self.liq_tx(V0, c0, low, ta, [att[0], None, None], r_max, kept, swaps=[self.term_swap(V1, V0)])[0],
                    "threshold/neg_threshold_zero", J, control=one, other_state=True)
        # One oracle in two slots of a set that lists its key and its beacon
        # asset twice: each slot verifies under its own key with a beacon coin
        # of its own, so only the distinct-key rule refuses it. A block cannot
        # be handed this spend: a pruned program comes only from a run that
        # succeeds, and the control's program with the second key swapped for
        # the first holds two witness nodes of one value, which the node
        # refuses as "Subexpression not properly shared" before it runs
        # anything. So the rule is shown on the abstract machine, with the
        # unpruned program: refused at the duplicate, and the same spend with
        # three distinct keys runs.
        a0b = dict(self.attest(0, low, ta), oracle=0)
        neg = self.liq_tx(VD, cD, low, ta, [att[0], a0b, None], r_max, kept,
                          swaps=[self.term_swap(V, VD), (bits_of(att[1]["sig"]) + bits_of(att[1]["beacon"]),
                                                         bits_of(a0b["sig"]) + bits_of(a0b["beacon"]))])[0]
        self.apply_pending(neg, liq)
        res = self.accept(neg)
        assert not res["allowed"] and "Subexpression not properly shared" in res["reject-reason"], res
        self.rec("threshold/swapped_duplicate_key_is_not_a_shared_program", {"reject-reason": res["reject-reason"]})
        dup_ran = self.machine(VD, neg, [att[0], a0b, None], [1, 2], low, ta)
        ok_ran = self.machine(V, liq, [att[0], att[1], None], [1, 2], low, ta)
        assert dup_ran["executed"] is False and "jet" in dup_ran["exec_error"].lower(), dup_ran
        assert ok_ran["executed"] is True, ok_ran
        self.rec("machine/threshold/neg_one_oracle_in_two_slots", {"duplicate": dup_ran, "distinct": ok_ran})
        # The second slot's signature by a key outside the set.
        a_str = dict(self.attest(1, low, ta, sec=self.stranger_sk), oracle=1)
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], a_str, None], r_max, kept, swaps=[self.sig_swap(att[1], a_str)])[0],
                    "threshold/neg_second_signature_by_a_stranger", J, control=liq)
        # The second slot holding the first oracle's own signature.
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], dict(att[0], oracle=1), None], r_max, kept,
                                swaps=[self.sig_swap(att[1], att[0])])[0],
                    "threshold/neg_second_slot_the_first_oracle_again", J, control=liq)
        # The second oracle attesting another price, or another time.
        a_p = dict(self.attest(1, low + 1, ta), oracle=1)
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], a_p, None], r_max, kept, swaps=[self.sig_swap(att[1], a_p)])[0],
                    "threshold/neg_second_signature_over_another_price", J, control=liq)
        a_t = dict(self.attest(1, low, ta - 1), oracle=1)
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], a_t, None], r_max, kept, swaps=[self.sig_swap(att[1], a_t)])[0],
                    "threshold/neg_second_signature_over_another_time", J, control=liq)
        # The second slot's beacon named at the first oracle's beacon input.
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], att[1], None], r_max, kept,
                                swaps=[(bits_of(att[1]["beacon"]) + format(2, "032b"),
                                        bits_of(att[1]["beacon"]) + format(1, "032b"))])[0],
                    "threshold/neg_second_beacon_at_another_input", J, control=liq)
        # The second oracle's attestation under its beacon rotated away: a
        # program its coin is not at.
        a_old = dict(self.attest(1, low, ta, beacon=sha256(b"an old beacon program")), oracle=1)
        self.reject(self.liq_tx(V, cV, low, ta, [att[0], a_old, None], r_max, kept,
                                swaps=[(bits_of(att[1]["sig"]) + bits_of(att[1]["beacon"]),
                                        bits_of(a_old["sig"]) + bits_of(a_old["beacon"]))])[0],
                    "threshold/neg_second_beacon_not_live", J, control=liq)
        self.agree_health("liquidation/two_of_three", COLLATERAL, DEBT, low, r_max, kept)
        tl = self.ok(liq, "liquidation/two_of_three_oracles_1_2", extra={"repaid": r_max, "price": low, "signatures": 2})
        cS = self.utxo_at(tl, 0)
        assert cS.spk == succ.spk and cS.amount == kept
        self.bcoins[0][0], self.bcoins[1][0] = self.utxo_at(tl, 2), self.utxo_at(tl, 4)

        # The 1-of-3 and 3-of-3 liquidations, mined, for their sizes.
        self.liquidator_coin = self.coin(3_000_000 * UNIT, self.Y)
        one, _ = self.liq_tx(V1, c1, low, ta, [att[0], None, None], r_max, kept, ok=True)
        t1b = self.ok(one, "liquidation/one_of_three", extra={"signatures": 1})
        self.bcoins[0][0] = self.utxo_at(t1b, 2)
        self.liquidator_coin = self.coin(3_000_000 * UNIT, self.Y)
        three, _ = self.liq_tx(V3, c3, low, ta, att, r_max, kept, ok=True)
        t3 = self.ok(three, "liquidation/three_of_three", extra={"signatures": 3})
        self.bcoins[0][0], self.bcoins[1][0], self.bcoins[2][0] = (self.utxo_at(t3, 2), self.utxo_at(t3, 4),
                                                                    self.utxo_at(t3, 6))

        # -- the successor, liquidated again by oracles 2 and 3 ----------------------
        self.liquidator_coin = self.coin(3_000_000 * UNIT, self.Y)
        self.tick()
        lower = price_of(0.60)
        tb = self.mtp() - 1
        S = succ
        r2 = self.vsa.pignus_vault_max_repay(cS.amount, S.debt, lower, PRECISION, TARGET, BONUS)
        k2 = cS.amount - self.vsa.pignus_vault_max_seizure(r2, lower, PRECISION, BONUS)
        assert not self.vsa.pignus_vault_healthy(cS.amount, S.debt, lower, PRECISION, LIQ)
        assert 0 < r2 < S.debt and 0 < k2 < cS.amount, (r2, k2)
        att2 = [dict(self.attest(i, lower, tb), oracle=i) for i in range(3)]
        liq2, _ = self.liq_tx(S, cS, lower, tb, [None, att2[1], att2[2]], r2, k2, ok=True)
        self.agree_health("liquidation/two_of_three_again", cS.amount, S.debt, lower, r2, k2)
        self.ok(liq2, "liquidation/two_of_three_oracles_2_3", extra={"repaid": r2, "price": lower, "signatures": 2})

        # -- sizes beside the single-oracle vault ------------------------------------
        self.rec("measured", {k: {f: self.R[k].get(f) for f in ("vsize", "weight", "program_bytes", "witness_bytes",
                                                             "cost_bound_wu", "budget_wu")}
                              for k in ("take/two_of_three", "liquidation/one_of_three",
                                        "liquidation/two_of_three_oracles_1_2", "liquidation/two_of_three_oracles_2_3",
                                        "liquidation/three_of_three")})
        self.rec("result", "PASS")

    def machine(self, v, tx, slots, ats, price, time):
        """The vault's program, unpruned, run by seqc on the abstract machine
        against `tx`: whether it executed, and the error if not."""
        slot_list = [(a, at) for a, at in zip(slots, ats + [0] * (3 - len(ats)))]
        req = self.req(v.leaf, tx, 0, self.vault_witness(v, self.liq_path(price, time, slot_list)), False)
        r = seqc(req)
        return {"executed": r.get("executed"), "exec_error": r.get("exec_error"), "pruned": r.get("pruned")}

    def agree_health(self, label, c, debt, price, paid, kept):
        r = self.vsa.pignus_vault_liquidation(c, debt, 0, 1, price, PRECISION, LIQ, TARGET, BONUS, paid, kept, False)
        self.rec(label + "/mirror", r)


if __name__ == "__main__":
    L2().main()
