"""L1: the Pignus loan vault and offer, version 2, from their descriptors.

`templates/pignus_offer` holds a lender's principal; anyone takes a lot of it
by opening a `templates/pignus_vault` vault on the offer's terms. The vault
keeps its terms and its state (the debt outstanding and the time of the last
attestation it used) in the data leaf beside its program, and reads the
collateral from the coin itself.

The run, on one regtest chain with Simplicity active from genesis:

  1. An oracle key and its beacon (an issued asset with no token, three
     one-atom coins at epoch B1). An offer of three lots of 2,000,000 units
     of the debt asset, at 8 decimal places: a loan the version 1 vault cannot
     be built for (its builder is asked, and refuses).
  2. Three takes open three vaults. A top-up in place; a partial repay; a
     partial liquidation under a fresh attestation, its beacon spent and
     recreated beside it; the beacon rotated to B2; a second partial
     liquidation under a B2 attestation; the loan called at maturity, the
     surplus returned to the borrower; a full repay; a recovery after its
     time; an offer refunded after its expiry.
  3. Every negative is refused by the mempool and in a block forced with
     `generateblock`, against an accepted control that differs from it only
     in the property it breaks: a liquidation of a healthy vault, an
     attestation whose beacon has rotated (and the spent beacon coin), an
     attestation no newer than the vault's last, a seizure above what the
     price allows, a repayment beyond the target, a liquidation that leaves
     the vault unhealthy, a surplus not returned, and successors whose state
     does not follow the spend; and the offer's own refusals.

A negative's program is satisfied without pruning, so the node runs it up to
the first check that fails; the control, which differs only in the property,
is pruned and accepted, so the refusal is that property's and no other's.
Every decision is also checked against the Python mirror's rule
(`pignus_vault_liquidation`), so the mirror and the node agree.
"""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)
from simplicity import *  # noqa: E402,F401,F403
from o2_beacon import Beacon, tagged, TAG, BEACON_TAG  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
PATH_T = "Either<Either<(), ()>, Either<(u64, u32, u256, Signature, u32, bool), ()>>"
OFFER_PATH_T = "Either<u256, ()>"
UNIT = 10 ** 8
FEE = 5000
PRECISION = 8
LIQ, TARGET, BONUS = 12500, 15000, 10500
LOT, DEBT, COLLATERAL = 2_000_000 * UNIT, 2_100_000 * UNIT, 3_000_000 * UNIT
LOTS = 3
ISSUE = 20_000_000          # units of each loan asset


def price_of(x):
    """A price in debt atoms per collateral atom, at PRECISION."""
    return int(round(x * 10 ** PRECISION))


class L1(SimBase, BitcoinTestFramework):
    NAME = "l1"

    def set_test_params(self):
        self.chain_params()

    # -- chain time ------------------------------------------------------------
    def mtp(self):
        return self.node.getblockheader(self.node.getbestblockhash())["mediantime"]

    def advance_to(self, t):
        """Moves the median time past to at least t."""
        node = self.node
        tip = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(max(t, tip) + 60)
        self.generate(node, 12)
        assert self.mtp() >= t, (self.mtp(), t)

    def tick(self):
        """Moves the clock on, so the next attestation is newer than any lock
        time used so far."""
        self.advance_to(self.mtp() + 120)

    # -- the oracle ------------------------------------------------------------
    def attest(self, price, time, beacon, base=None, quote=None, sec=None, precision=PRECISION):
        k = self.oracle_pk
        msg = (b"\x02" + k + (base or self.X_ID) + (quote or self.Y_ID) + price.to_bytes(8, "little")
               + bytes([precision]) + time.to_bytes(4, "little") + beacon)
        assert len(msg) == 142
        return {"price": price, "time": time, "beacon": beacon,
                "sig": sign_schnorr(sec or self.oracle_sk, tagged(TAG, msg))}

    # -- the templates ---------------------------------------------------------
    def terms(self, lender_spk, borrower_spk=None):
        p = {"COLL": self.X_ID.hex(), "DEBT_ASSET": self.Y_ID.hex(), "ORACLE": self.oracle_pk.hex(),
             "BEACON_ASSET": self.BEACON_ID.hex(), "PRECISION": "%02x" % PRECISION,
             "LIQ_BP": "%08x" % LIQ, "TARGET_BP": "%08x" % TARGET, "BONUS_BP": "%08x" % BONUS,
             "MATURITY": "%08x" % self.MATURITY, "RECOVER_AFTER": "%08x" % self.RECOVER_AFTER,
             "LENDER": sha256(lender_spk).hex()}
        if borrower_spk is not None:
            p["BORROWER"] = sha256(borrower_spk).hex()
        return p

    def vault(self, debt, last, borrower_spk=None, params=None):
        """The vault of this loan's terms (or `params`) in this state: its script and its leaf."""
        params = params or self.terms(self.lender_spk, borrower_spk or self.borrower_spk)
        slots = {"DEBT_OUT": "%016x" % debt, "LAST_TIME": "%08x" % last}
        x = self.vsa.derive(self.vdesc, params, slots)
        info = self.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        v = type("Vault", (), {})()
        v.params, v.slots, v.debt, v.last = params, slots, debt, last
        v.spk = bytes.fromhex(x["script_pubkey"])
        v.address = x["address"]["elementsregtest"]
        v.leaf = TreeLeaf(self.vtext, self.vcmr, bytes.fromhex(x["leaves"]["vault"]["control_block"]))
        return v

    def vault_witness(self, v, path):
        p = v.params
        n = lambda k: int(p[k], 16)
        w = {"COLL": v256(bytes.fromhex(p["COLL"])), "DEBT_ASSET": v256(bytes.fromhex(p["DEBT_ASSET"])),
             "ORACLE": vpub(bytes.fromhex(p["ORACLE"])), "BEACON_ASSET": v256(bytes.fromhex(p["BEACON_ASSET"])),
             "PRECISION": vu(n("PRECISION"), 8), "LIQ_BP": vu(n("LIQ_BP"), 32), "TARGET_BP": vu(n("TARGET_BP"), 32),
             "BONUS_BP": vu(n("BONUS_BP"), 32), "MATURITY": vu(n("MATURITY"), 32),
             "RECOVER_AFTER": vu(n("RECOVER_AFTER"), 32),
             "LENDER": v256(bytes.fromhex(p["LENDER"])), "BORROWER": v256(bytes.fromhex(p["BORROWER"])),
             "DEBT_OUT": vu(v.debt, 64), "LAST_TIME": vu(v.last, 32), "PATH": vraw(path, PATH_T)}
        return w

    @staticmethod
    def liq_path(att, beacon_at, matured=False):
        return "Right(Left((%d, %d, 0x%s, 0x%s, %d, %s)))" % (
            att["price"], att["time"], att["beacon"].hex(), att["sig"].hex(), beacon_at,
            "true" if matured else "false")

    def offer(self, lots=LOTS, expiry=None, lot=LOT, debt=DEBT, collateral=COLLATERAL):
        params = self.terms(self.lender_spk)
        params.update({"LOT": "%016x" % lot, "DEBT": "%016x" % debt, "COLLATERAL": "%016x" % collateral,
                       "EXPIRY": "%08x" % (expiry or self.EXPIRY)})
        x = self.osa.derive(self.odesc, params, {})
        o = type("Offer", (), {})()
        o.params, o.lot, o.debt, o.collateral = params, lot, debt, collateral
        o.expiry = expiry or self.EXPIRY
        o.spk = bytes.fromhex(x["script_pubkey"])
        o.leaf = TreeLeaf(self.otext, self.ocmr, bytes.fromhex(x["leaves"]["offer"]["control_block"]))
        return o

    def offer_witness(self, o, path):
        p = o.params
        w = {k: v256(bytes.fromhex(p[k])) for k in ("COLL", "DEBT_ASSET", "BEACON_ASSET", "LENDER")}
        w.update({"ORACLE": vpub(bytes.fromhex(p["ORACLE"])), "PRECISION": vu(PRECISION, 8),
                  "LIQ_BP": vu(LIQ, 32), "TARGET_BP": vu(TARGET, 32), "BONUS_BP": vu(BONUS, 32),
                  "MATURITY": vu(self.MATURITY, 32), "RECOVER_AFTER": vu(self.RECOVER_AFTER, 32),
                  "LOT": vu(o.lot, 64), "DEBT": vu(o.debt, 64), "COLLATERAL": vu(o.collateral, 64),
                  "EXPIRY": vu(o.expiry, 32), "PATH": vraw(path, OFFER_PATH_T)})
        return w

    # -- satisfying ------------------------------------------------------------
    def satisfy(self, leaf, tx, idx, witness, ok, att=None):
        """A control or a spend is satisfied, pruned and run here (it must
        execute). A negative is left pending: reject() gives it its control's
        pruned program and witness, with the attestation's bits swapped where
        the two differ, so the node runs the control's path on the negative's
        transaction to the first check that fails. (An unpruned program is
        refused before it runs: it holds the FAIL nodes of its panics.)"""
        if ok:
            r = self.sim_satisfy(leaf, tx, idx, witness)
            tx.atts = dict(getattr(tx, "atts", {}), **{str(idx): att})
            return r
        tx.pending = dict(getattr(tx, "pending", {}), **{str(idx): (leaf, att)})
        return None

    KEEP = ("r", "atts", "pending")

    def finish(self, tx):
        """The wallet signs its own inputs; covenant witnesses stay."""
        kept = {k: getattr(tx, k) for k in self.KEEP if hasattr(tx, k)}
        tx2 = self.wallet_sign(tx)
        for k, v in kept.items():
            setattr(tx2, k, v)
        return tx2

    @staticmethod
    def swap_bits(blob, old, new):
        bits = bits_of(blob)
        assert len(old) == len(new) and bits.count(old) == 1, "the attestation occurs %d times" % bits.count(old)
        bits = bits.replace(old, new)
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

    def reject(self, tx, label, expect, mempool=None, control=None, like=None, **kw):
        src = like or control
        for k, (leaf, att) in getattr(tx, "pending", {}).items():
            idx = int(k)
            assert src is not None, "%s: a negative needs a control to take its program from" % label
            st = src.wit.vtxinwit[idx].scriptWitness.stack
            w, old = st[0], src.atts.get(k)
            if att is not None and old is not None and att != old:
                w = self.swap_bits(w, old, att)
            self.set_sim_wit(tx, idx, leaf, st[1], w)
        return SimBase.reject(self, tx, label, expect, mempool=mempool, control=control, **kw)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, 0, tx.r) if getattr(tx, "r", None) else {}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def coin(self, atoms, asset):
        return self.wallet_utxo(atoms, asset)

    # -- the transactions ------------------------------------------------------
    def take_tx(self, o, ocoin, borrower_coin, lock, vault_state=None, vault_amount=None, rest=None,
                borrower_spk=None, ok=False, extra_outs=(), vault_spk=None):
        """The offer at input 0, the borrower's collateral at input 1; outputs:
        0 the vault, 1 the offer's rest (when it holds more than a lot), the
        principal less the fee to the borrower, the fee."""
        bspk = borrower_spk or self.borrower_spk
        debt, last = vault_state or (o.debt, lock)
        v = self.vault(debt, last, bspk)
        amount = borrower_coin.amount if vault_amount is None else vault_amount
        left = ocoin.amount - o.lot if rest is None else rest
        outs = [self.out(amount, vault_spk or v.spk, self.X_OUT)]
        if left:
            outs.append(self.out(left, o.spk, self.Y_OUT))
        principal = ocoin.amount - left - FEE
        outs += [self.out(principal, self.borrower_wallet, self.Y_OUT)]
        if amount < borrower_coin.amount:
            outs.append(self.out(borrower_coin.amount - amount, self.borrower_wallet, self.X_OUT))
        outs += list(extra_outs) + [self.fee(FEE, self.Y_OUT)]
        tx = self.mktx([(ocoin, 0xfffffffe), (borrower_coin, 0xfffffffe)], outs, locktime=lock)
        tx.r = self.satisfy(o.leaf, tx, 0, self.offer_witness(o, "Left(0x%s)" % sha256(bspk).hex()), ok)
        return self.finish(tx), v

    def spend_tx(self, v, vcoin, ins, outs, path, lock=0, ok=False, beacon=None, att=None):
        """The vault at input 0, then `ins`; the beacon coin, when given, is
        one of them and is spent through its recreate leaf."""
        seq = 0xfffffffe if lock else 0xffffffff
        tx = self.mktx([(vcoin, seq)] + [(c, seq) for c in ins], outs, locktime=lock)
        if beacon is not None:
            at, b = beacon
            self.setwit(tx, at, b.wit_recreate())
        tx.r = self.satisfy(v.leaf, tx, 0, self.vault_witness(v, path), ok, att)
        return self.finish(tx)

    def liq_tx(self, v, vcoin, att, bcoin, b, paid, kept, closes=False, succ=None, matured=False,
               lock=None, lender_spk=None, borrower_out=None, beacon_at=1, ok=False, liq_coin=None):
        """A liquidation: the vault at input 0, the beacon coin at input 1 (recreated
        at output 2), the liquidator's debt-asset coin at input 2. Outputs:
        0 the successor (or the borrower's return), 1 the lender, 2 the beacon,
        3 the seized collateral to the liquidator, then the liquidator's
        change and the fee."""
        c = vcoin.amount
        seized = c - kept
        lc = liq_coin or self.liquidator_coin
        if succ is None and not closes:
            succ = self.vault(v.debt - paid, att["time"])
        first = (borrower_out if borrower_out is not None
                 else self.out(kept, self.borrower_spk, self.X_OUT) if closes
                 else self.out(kept, succ.spk, self.X_OUT))
        outs = [first, self.out(paid, lender_spk or self.lender_spk, self.Y_OUT),
                self.out(bcoin.amount, bcoin.spk, self.BEACON_OUT)]
        if seized:
            outs.append(self.out(seized, self.liquidator_spk, self.X_OUT))
        if lc.amount - paid - FEE:
            outs.append(self.out(lc.amount - paid - FEE, self.liquidator_spk, self.Y_OUT))
        outs.append(self.fee(FEE, self.Y_OUT))
        bits = "".join(format(x, "0%db" % n) for x, n in ((att["price"], 64), (att["time"], 32)))
        bits += bits_of(att["beacon"]) + bits_of(att["sig"]) + format(beacon_at, "032b") + ("1" if matured else "0")
        tx = self.spend_tx(v, vcoin, [bcoin, lc], outs, self.liq_path(att, beacon_at, matured),
                           lock=att["time"] if lock is None else lock, ok=ok, beacon=(1, b), att=bits)
        return tx, succ

    def mirror(self, v, c, att, paid, kept, matured=False):
        """The Python mirror's ruling on a liquidation, for comparison."""
        try:
            return self.vsa.pignus_vault_liquidation(c, v.debt, v.last, att["time"], att["price"], PRECISION,
                                                     LIQ, TARGET, BONUS, paid, kept, matured)
        except ValueError as e:
            return str(e)

    def agree(self, label, ruling, accepted):
        ok = not isinstance(ruling, str)
        assert ok == accepted, (label, ruling)
        self.rec(label + "/mirror", ruling if ok else {"refused": ruling})

    # -- the run ---------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.boot(issue=("BEACON",))
        for name in ("X", "Y"):
            a = node.issueasset(assetamount=ISSUE, tokenamount=0, blind=False, fee_asset=BITCOIN_ASSET)["asset"]
            self.generate(node, 1)
            setattr(self, name, a)
            setattr(self, name + "_OUT", self.asset_out(a))
            setattr(self, name + "_ID", bytes.fromhex(a)[::-1])
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 60)
        self.generate(node, 12)

        self.vsa, self.vdesc, _, vsrc = load_template("pignus_vault")
        self.osa, self.odesc, _, osrc = load_template("pignus_offer")
        self.vtext, vbody = vsrc["vault"]
        self.otext, obody = osrc["offer"]
        self.vcmr, self.ocmr = bytes.fromhex(vbody["cmr"]), bytes.fromhex(obody["cmr"])
        assert "0x" + vbody["cmr"] in self.otext, "the offer does not name the vault's program"

        # -- 1. the version 1 vault cannot be built for this loan --------------
        import pignus_covenant as v1
        v1_refusals = {}
        for scale in (10 ** 5, 10 ** PRECISION):
            try:
                v1.build_liquidate_leaf(b"\x01" * 32, b"\x02" * 32, DEBT, b"\x03" * 32, b"\x04" * 32, b"\x05" * 32,
                                        b"\x06" * 32, strike=price_of(1.0) * scale // 10 ** PRECISION,
                                        not_before=0, price_scale=scale)
                v1_refusals[scale] = "built"
            except AssertionError as e:
                v1_refusals[scale] = str(e)
        assert all(r.startswith("loan too large") for r in v1_refusals.values()), v1_refusals
        self.rec("v1_builder_refuses_this_loan", {"debt_atoms": DEBT, "refusals": v1_refusals})

        # -- the oracle, its beacon, the parties --------------------------------
        self.oracle_sk = generate_privkey()
        self.oracle_pk = compute_xonly_pubkey(self.oracle_sk)[0]
        B1 = Beacon(self.oracle_pk, sha256(b"l1 beacon epoch 0"))
        B2 = Beacon(self.oracle_pk, sha256(b"l1 beacon epoch 1"))
        bcoins = [self.fund(B1.spk, 1, self.BEACON) for _ in range(3)]
        self.lender_spk, self.borrower_spk = self.wallet_spk(), self.wallet_spk()
        self.borrower_wallet, self.liquidator_spk = self.wallet_spk(), self.wallet_spk()
        now = self.mtp()
        self.MATURITY, self.RECOVER_AFTER, self.EXPIRY = now + 4 * 3600, now + 8 * 3600, now + 2 * 3600
        self.rec("terms", {"vault_template": self.vdesc["template_hash"], "offer_template": self.odesc["template_hash"],
                           "vault_cmr": vbody["cmr"], "offer_cmr": obody["cmr"],
                           "params": self.terms(self.lender_spk, self.borrower_spk),
                           "lot": LOT, "debt": DEBT, "collateral": COLLATERAL})

        # -- 2. the offer, and three takes ----------------------------------------
        o = self.offer()
        ocoin = self.fund(o.spk, LOTS * LOT, self.Y)
        lock = self.mtp() - 1
        bcoin_x = self.coin(COLLATERAL, self.X)
        good, v = self.take_tx(o, ocoin, bcoin_x, lock, ok=True)
        # The offer's refusals, each against the take above.
        self.reject(self.take_tx(o, ocoin, bcoin_x, lock, vault_amount=COLLATERAL - 1)[0],
                    "take/neg_collateral_one_atom_short", J, control=good)
        self.reject(self.take_tx(o, ocoin, bcoin_x, lock, vault_state=(DEBT - 1, lock))[0],
                    "take/neg_vault_owes_less_than_the_debt", J, control=good)
        self.reject(self.take_tx(o, ocoin, bcoin_x, lock, vault_state=(DEBT, lock + 1))[0],
                    "take/neg_vault_last_time_not_the_lock_time", J, control=good)
        self.reject(self.take_tx(o, ocoin, bcoin_x, lock, rest=ocoin.amount - LOT - 1)[0],
                    "take/neg_draws_one_atom_more_than_a_lot", J, control=good)
        other = self.vault(DEBT, lock, self.borrower_spk)
        tx = self.take_tx(o, ocoin, bcoin_x, lock)[0]
        # A vault of another oracle: the same take, the vault output paid to
        # the vault the offer would build under a stranger's oracle key.
        stranger = compute_xonly_pubkey(generate_privkey())[0]
        xs = self.vsa.derive(self.vdesc, dict(other.params, ORACLE=stranger.hex()), other.slots)
        self.reject(self.take_tx(o, ocoin, bcoin_x, lock, vault_spk=bytes.fromhex(xs["script_pubkey"]))[0],
                    "take/neg_vault_under_another_oracle", J, control=good)
        # A take with no lock time: the vault's start time would be unbound.
        notime = self.mktx([ocoin, bcoin_x], tx.vout, locktime=0)
        self.satisfy(o.leaf, notime, 0, None, False)
        self.reject(self.finish(notime), "take/neg_no_lock_time", J, control=good)

        t1 = self.ok(good, "take/first", extra={"lot": LOT, "debt": DEBT, "collateral": COLLATERAL, "lock_time": lock})
        V1, c1 = v, self.utxo_at(t1, 0)
        assert c1.spk == V1.spk
        rest1 = self.utxo_at(t1, 1)
        lock = self.mtp() - 1
        good2, V2 = self.take_tx(o, rest1, self.coin(COLLATERAL, self.X), lock, ok=True)
        t2 = self.ok(good2, "take/second")
        c2, rest2 = self.utxo_at(t2, 0), self.utxo_at(t2, 1)
        lock = self.mtp() - 1
        good3, V3 = self.take_tx(o, rest2, self.coin(COLLATERAL, self.X), lock, ok=True)
        t3 = self.ok(good3, "take/third_whole_rest")
        c3 = self.utxo_at(t3, 0)
        assert len(node.getrawtransaction(t3, True)["vout"]) == 3, "the last take leaves no rest"

        # -- 3. top-up in place ---------------------------------------------------
        ADD = 500_000 * UNIT
        fx = self.coin(ADD + FEE, self.X)

        def topup(amount, spk=None, ok=False):
            outs = [self.out(c1.amount + amount, spk or V1.spk, self.X_OUT), self.fee(FEE, self.X_OUT)]
            if amount < ADD:
                outs.insert(1, self.out(ADD - amount, self.borrower_wallet, self.X_OUT))
            return self.spend_tx(V1, c1, [fx], outs, "Left(Right(()))", ok=ok)
        up = topup(ADD, ok=True)
        self.reject(topup(0), "top_up/neg_adds_nothing", J, control=up)
        self.reject(topup(ADD, spk=self.vault(DEBT - 1, V1.last).spk), "top_up/neg_state_changed", J, control=up)
        tu = self.ok(up, "top_up/in_place", extra={"added": ADD})
        c1 = self.utxo_at(tu, 0)
        assert c1.spk == V1.spk and c1.amount == COLLATERAL + ADD

        # -- 4. a partial repay -----------------------------------------------------
        P = 500_000 * UNIT
        fy = self.coin(P + FEE, self.Y)

        def repay(v, coin, paid, succ_debt=None, succ_amount=None, lender=None, asset_out=None, ok=False, payer=None):
            payer = payer or fy
            s = self.vault(v.debt - paid if succ_debt is None else succ_debt, v.last)
            amount = coin.amount if succ_amount is None else succ_amount
            outs = [self.out(amount, s.spk, self.X_OUT), self.out(paid, lender or self.lender_spk, asset_out or self.Y_OUT)]
            if amount < coin.amount:
                outs.append(self.out(coin.amount - amount, self.borrower_wallet, self.X_OUT))
            outs.append(self.fee(FEE, self.Y_OUT))
            return self.spend_tx(v, coin, [payer], outs, "Left(Left(()))", ok=ok), s
        rp, V1b = repay(V1, c1, P, ok=True)
        self.reject(repay(V1, c1, P, succ_debt=V1.debt)[0], "repay/neg_successor_keeps_the_old_debt", J, control=rp)
        self.reject(repay(V1, c1, P, succ_debt=V1.debt - P - 1)[0], "repay/neg_successor_owes_less_than_repaid", J, control=rp)
        self.reject(repay(V1, c1, P, succ_amount=c1.amount - 1)[0], "repay/neg_successor_one_atom_short", J, control=rp)
        self.reject(repay(V1, c1, P, lender=self.wallet_spk())[0], "repay/neg_paid_to_another_script", J, control=rp)
        tr = self.ok(rp, "repay/partial", extra={"paid": P, "debt_after": V1.debt - P})
        V1, c1 = V1b, self.utxo_at(tr, 0)
        assert c1.spk == V1.spk

        # -- 5. a partial liquidation under a fresh attestation ---------------------
        self.liquidator_coin = self.coin(2_000_000 * UNIT, self.Y)
        self.tick()
        low = price_of(0.55)
        assert not self.vsa.pignus_vault_healthy(c1.amount, V1.debt, low, PRECISION, LIQ)
        assert self.vsa.pignus_vault_healthy(c1.amount, V1.debt, price_of(0.60), PRECISION, LIQ)
        ta = self.mtp() - 2            # so that ta + 1 is a lock time the chain has passed
        a1 = self.attest(low, ta, B1.program)
        r_max = self.vsa.pignus_vault_max_repay(c1.amount, V1.debt, low, PRECISION, TARGET, BONUS)
        s_max = self.vsa.pignus_vault_max_seizure(r_max, low, PRECISION, BONUS)
        assert 0 < r_max < V1.debt and s_max < c1.amount
        kept = c1.amount - s_max
        self.rec("liquidation/plan", {"collateral": c1.amount, "debt": V1.debt, "price": low, "repay_max": r_max,
                                      "seizure_max": s_max, "ratio_after_bp": kept * low * 10000 // ((V1.debt - r_max) * UNIT)})
        liq, _ = self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, ok=True)
        self.agree("liquidation/partial", self.mirror(V1, c1.amount, a1, r_max, kept), True)

        # A healthy vault: the same transaction under an attestation of a price
        # at which the vault is healthy.
        a_hi = self.attest(price_of(0.60), ta, B1.program)
        self.agree("liquidation/neg_healthy_vault", self.mirror(V1, c1.amount, a_hi, r_max, kept), False)
        self.reject(self.liq_tx(V1, c1, a_hi, bcoins[0], B1, r_max, kept)[0], "liquidation/neg_healthy_vault", J, control=liq)
        # A seizure one atom above what the price allows.
        self.agree("liquidation/neg_seizure_one_atom_over", self.mirror(V1, c1.amount, a1, r_max, kept - 1), False)
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept - 1)[0],
                    "liquidation/neg_seizure_one_atom_over", J, control=liq)
        # One atom beyond the target, at the same seizure.
        over = r_max + 1
        self.agree("liquidation/neg_repays_beyond_the_target", self.mirror(V1, c1.amount, a1, over, kept), False)
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, over, kept)[0],
                    "liquidation/neg_repays_beyond_the_target", J, control=liq)
        # A small repayment that, at its full seizure, leaves the vault unhealthy;
        # the control repays the same and seizes less.
        small = V1.debt // 10
        s_small = self.vsa.pignus_vault_max_seizure(small, low, PRECISION, BONUS)
        lo, hi = 0, s_small        # the largest seizure that keeps the vault healthy
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if (V1.debt - small) * LIQ * UNIT <= (c1.amount - mid) * low * 10000:
                lo = mid
            else:
                hi = mid - 1
        assert lo < s_small
        ctl_small, _ = self.liq_tx(V1, c1, a1, bcoins[0], B1, small, c1.amount - lo, ok=True)
        self.agree("liquidation/neg_leaves_the_vault_unhealthy",
                   self.mirror(V1, c1.amount, a1, small, c1.amount - lo - 1), False)
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, small, c1.amount - lo - 1)[0],
                    "liquidation/neg_leaves_the_vault_unhealthy", J, control=ctl_small)
        # Successors whose state does not follow the spend.
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, succ=self.vault(V1.debt - r_max + 1, ta))[0],
                    "liquidation/neg_successor_debt_not_reduced_by_the_repayment", J, control=liq)
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, succ=self.vault(V1.debt - r_max, V1.last))[0],
                    "liquidation/neg_successor_keeps_the_old_last_time", J, control=liq)
        # A lock time other than the attestation's time, before it and after it.
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, lock=ta - 1)[0],
                    "liquidation/neg_lock_time_before_the_attestation", J, control=liq)
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, lock=ta + 1)[0],
                    "liquidation/neg_lock_time_after_the_attestation", J, control=liq)
        # The beacon index naming the liquidator's coin, not the beacon.
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, beacon_at=2)[0],
                    "liquidation/neg_beacon_at_another_input", J, control=liq)
        # The lender paid at another script.
        self.reject(self.liq_tx(V1, c1, a1, bcoins[0], B1, r_max, kept, lender_spk=self.wallet_spk())[0],
                    "liquidation/neg_lender_paid_at_another_script", J, control=liq)
        # Another key's attestation of the same observation.
        a_forged = self.attest(low, ta, B1.program, sec=generate_privkey())
        self.reject(self.liq_tx(V1, c1, a_forged, bcoins[0], B1, r_max, kept)[0],
                    "liquidation/neg_attestation_by_another_key", J, control=liq)
        # The pair reversed: the oracle's price of the debt asset in the collateral.
        a_rev = self.attest(low, ta, B1.program, base=self.Y_ID, quote=self.X_ID)
        self.reject(self.liq_tx(V1, c1, a_rev, bcoins[0], B1, r_max, kept)[0],
                    "liquidation/neg_attestation_of_the_reversed_pair", J, control=liq)

        tl = self.ok(liq, "liquidation/partial_b1", extra={"repaid": r_max, "seized": s_max, "price": low})
        V1, c1 = self.vault(V1.debt - r_max, ta), self.utxo_at(tl, 0)
        bcoins[0] = self.utxo_at(tl, 2)
        assert c1.spk == V1.spk and c1.amount == kept and bcoins[0].spk == B1.spk
        assert self.vsa.pignus_vault_healthy(c1.amount, V1.debt, low, PRECISION, LIQ)
        self.liquidator_coin = self.coin(2_000_000 * UNIT, self.Y)
        self.tick()

        # The same attestation again, now no newer than the vault's last: refused
        # against a control with a newer one at a price under the target.
        lower = price_of(0.45)
        tb = self.mtp() - 1
        assert tb > ta
        a_again = self.attest(lower, ta, B1.program)
        a_new = self.attest(lower, tb, B1.program)
        r2 = self.vsa.pignus_vault_max_repay(c1.amount, V1.debt, lower, PRECISION, TARGET, BONUS)
        k2 = c1.amount - self.vsa.pignus_vault_max_seizure(r2, lower, PRECISION, BONUS)
        ctl_new, _ = self.liq_tx(V1, c1, a_new, bcoins[0], B1, r2, k2, ok=True)
        self.agree("liquidation/neg_attestation_no_newer_than_the_last", self.mirror(V1, c1.amount, a_again, r2, k2), False)
        self.reject(self.liq_tx(V1, c1, a_again, bcoins[0], B1, r2, k2, succ=self.vault(V1.debt - r2, ta), lock=tb)[0],
                    "liquidation/neg_attestation_no_newer_than_the_last", J, control=ctl_new)

        # -- 6. the beacon rotates: B1's attestations are dead ----------------------
        rot_sig = sign_schnorr(self.oracle_sk, tagged(BEACON_TAG, B1.program + B2.program))
        fee_u = self.coin(100_000, self.Y)
        to_b2 = self.out(1, B2.spk, self.BEACON_OUT)
        filler = self.out(1000, self.borrower_wallet, self.Y_OUT)
        rot = self.mktx(bcoins + [fee_u],
                        [to_b2, filler, to_b2, filler, to_b2,
                         self.out(100_000 - FEE - 2000, self.borrower_wallet, self.Y_OUT), self.fee(FEE, self.Y_OUT)])
        for i in range(3):
            self.setwit(rot, i, B1.wit_rotate(rot_sig, B2.program))
        rid = self.ok(self.finish(rot), "beacon/rotate_b1_to_b2")
        old_b1 = bcoins[0]
        bcoins = [self.utxo_at(rid, 0), self.utxo_at(rid, 2), self.utxo_at(rid, 4)]
        assert all(b.spk == B2.spk for b in bcoins)
        self.tick()
        tc = self.mtp() - 1
        a2 = self.attest(lower, tc, B2.program)
        a2_old = self.attest(lower, tc, B1.program)
        r2 = self.vsa.pignus_vault_max_repay(c1.amount, V1.debt, lower, PRECISION, TARGET, BONUS)
        k2 = c1.amount - self.vsa.pignus_vault_max_seizure(r2, lower, PRECISION, BONUS)
        liq2, _ = self.liq_tx(V1, c1, a2, bcoins[0], B2, r2, k2, ok=True)
        self.reject(self.liq_tx(V1, c1, a2_old, bcoins[0], B2, r2, k2)[0],
                    "liquidation/neg_attestation_of_a_rotated_beacon", J, control=liq2)
        self.reject(self.liq_tx(V1, c1, a2_old, old_b1, B1, r2, k2)[0],
                    "liquidation/neg_rotated_beacon_with_its_spent_coin", "bad-txns-inputs-missingorspent",
                    mempool="missing-inputs", like=liq2)
        tl2 = self.ok(liq2, "liquidation/partial_b2", extra={"repaid": r2, "price": lower})
        V1, c1 = self.vault(V1.debt - r2, tc), self.utxo_at(tl2, 0)
        bcoins[0] = self.utxo_at(tl2, 2)
        assert c1.spk == V1.spk

        # -- 7. two vaults, one payment: input k owns outputs 2k and 2k+1 ----------
        payer = self.coin(2 * DEBT + FEE, self.Y)
        both_outs = [self.out(c2.amount, self.borrower_spk, self.X_OUT), self.out(DEBT, self.lender_spk, self.Y_OUT),
                     self.out(c3.amount, self.borrower_spk, self.X_OUT), self.out(DEBT, self.lender_spk, self.Y_OUT),
                     self.fee(FEE, self.Y_OUT)]
        both = self.mktx([c2, c3, payer], both_outs)
        both.r = self.satisfy(V2.leaf, both, 0, self.vault_witness(V2, "Left(Left(()))"), True)
        self.satisfy(V3.leaf, both, 1, self.vault_witness(V3, "Left(Left(()))"), True)
        both = self.finish(both)
        one = self.mktx([c2, c3, payer], [both_outs[0], self.out(2 * DEBT, self.lender_spk, self.Y_OUT),
                                          both_outs[2], self.fee(FEE, self.Y_OUT)])
        one.r = self.satisfy(V2.leaf, one, 0, self.vault_witness(V2, "Left(Left(()))"), True)
        self.satisfy(V3.leaf, one, 1, self.vault_witness(V3, "Left(Left(()))"), False)
        self.reject(self.finish(one), "repay/neg_two_vaults_one_payment", J, control=both, index=1)

        # -- 8. a full repay ---------------------------------------------------------
        fy2 = self.coin(DEBT + FEE, self.Y)

        def close(short=0, ok=False):
            outs = [self.out(c2.amount - short, self.borrower_spk, self.X_OUT), self.out(DEBT, self.lender_spk, self.Y_OUT)]
            if short:
                outs.append(self.out(short, self.wallet_spk(), self.X_OUT))
            return self.spend_tx(V2, c2, [fy2], outs + [self.fee(FEE, self.Y_OUT)], "Left(Left(()))", ok=ok)
        full = close(ok=True)
        self.reject(close(short=1), "repay/neg_close_returns_one_atom_short", J, control=full)
        self.ok(full, "repay/full_close", extra={"paid": DEBT, "returned": c2.amount})

        # -- 9. the loan called at maturity: the surplus forced back ----------------
        # A call is a liquidation whose lock time, the attestation's time,
        # reaches MATURITY. The call before maturity is the same transaction
        # under an attestation, and so a lock time, one second short of it.
        self.liquidator_coin = self.coin(2_000_000 * UNIT, self.Y)
        o2 = self.offer(lots=1, lot=UNIT, debt=UNIT, collateral=UNIT)
        ocoin2 = self.fund(o2.spk, UNIT, self.Y)
        self.advance_to(self.MATURITY + 600)
        te = self.mtp() - 1
        assert V1.last < self.MATURITY - 1 < self.MATURITY <= te
        a3 = self.attest(price_of(0.80), te, B2.program)
        paid = V1.debt
        s_call = self.vsa.pignus_vault_max_seizure(paid, a3["price"], PRECISION, BONUS)
        surplus = c1.amount - s_call
        self.agree("call/at_maturity", self.mirror(V1, c1.amount, a3, paid, surplus, matured=True), True)
        call, _ = self.liq_tx(V1, c1, a3, bcoins[0], B2, paid, surplus, closes=True, matured=True, ok=True)
        a_pre = self.attest(price_of(0.80), self.MATURITY - 1, B2.program)
        self.reject(self.liq_tx(V1, c1, a_pre, bcoins[0], B2, paid, surplus, closes=True, matured=True)[0],
                    "call/neg_before_maturity", J, control=call)
        self.agree("call/neg_surplus_not_returned", self.mirror(V1, c1.amount, a3, paid, 0, matured=True), False)
        stolen = self.out(surplus, self.liquidator_spk, self.X_OUT)
        self.reject(self.liq_tx(V1, c1, a3, bcoins[0], B2, paid, surplus, closes=True, matured=True,
                                borrower_out=stolen)[0], "call/neg_surplus_not_returned", J, control=call)
        self.agree("call/neg_surplus_one_atom_short", self.mirror(V1, c1.amount, a3, paid, surplus - 1, matured=True), False)
        self.reject(self.liq_tx(V1, c1, a3, bcoins[0], B2, paid, surplus - 1, closes=True, matured=True)[0],
                    "call/neg_surplus_one_atom_short", J, control=call)
        self.ok(call, "call/at_maturity_surplus_returned", extra={"repaid": paid, "seized": s_call, "returned": surplus})

        # -- 10. recovery of the third vault after its time; the offer's refund -----
        self.advance_to(self.RECOVER_AFTER + 600)
        fee_c = self.coin(FEE, self.Y)

        def recover(lock, ok=False, to=None):
            return self.spend_tx(V3, c3, [fee_c],
                                 [self.out(c3.amount, to or self.lender_spk, self.X_OUT), self.fee(FEE, self.Y_OUT)],
                                 "Right(Right(()))", lock=lock, ok=ok)
        rec_ok = recover(self.RECOVER_AFTER, ok=True)
        self.reject(recover(self.RECOVER_AFTER - 1), "recover/neg_before_its_time", J, control=rec_ok)
        self.reject(recover(self.RECOVER_AFTER, to=self.borrower_spk), "recover/neg_paid_to_the_borrower", J, control=rec_ok)
        self.ok(rec_ok, "recover/after_its_time", extra={"swept": c3.amount})
        fee_r = self.coin(FEE, self.Y)

        def refund(lock, amount=UNIT, ok=False):
            outs = [self.out(amount, self.lender_spk, self.Y_OUT)]
            if amount < UNIT:
                outs.append(self.out(UNIT - amount, self.borrower_wallet, self.Y_OUT))
            rf = self.mktx([(ocoin2, 0xfffffffe), (fee_r, 0xfffffffe)], outs + [self.fee(FEE, self.Y_OUT)], locktime=lock)
            rf.r = self.satisfy(o2.leaf, rf, 0, self.offer_witness(o2, "Right(())"), ok)
            return self.finish(rf)
        rf_ok = refund(self.EXPIRY, ok=True)
        self.reject(refund(self.EXPIRY - 1), "refund/neg_before_expiry", J, control=rf_ok)
        # 1,000 atoms short, which go elsewhere: an amount the mempool relays.
        self.reject(refund(self.EXPIRY, amount=UNIT - 1000), "refund/neg_pays_1000_atoms_less_than_the_coin", J,
                    control=rf_ok)
        self.ok(rf_ok, "refund/after_expiry")
        # -- 11. every liquidation vector, through the program on the abstract machine
        rules = json.load(open(os.path.join(REPO_ROOT, "templates", "pignus_vault", "rules.json")))
        machine = {}
        for e in rules["liquidation"]:
            got = self.machine_case(e, B2)
            want = "refused" if "refused" in e else "accepted"
            assert got["outcome"] == want, (e["name"], want, got)
            machine[e["name"]] = got
            self.log.info("MACHINE %-58s %s", e["name"], got["outcome"])
        self.rec("machine/liquidation_vectors", machine)
        self.rec("result", "PASS")

    def machine_case(self, e, B):
        """One rules.json liquidation, built as a transaction (amounts as
        large as the vector says, so it goes to no node) and run through the
        vault program by seqc against it, pruned: an accepted vector must run,
        a refused one must not."""
        def amount(x):
            v = CTxOutValue()
            v.vchCommitment = b"\x01" + int(x).to_bytes(8, "big")
            return v

        def big(x, spk, asset_out):
            o = self.out(0, spk, asset_out)
            o.nValue = amount(x)
            return o

        def coin(n, txout):
            return Utxo(sha256(b"l1 machine %d %s" % (n, e["name"].encode())).hex(), 0, txout)
        params = dict(self.terms(self.lender_spk, self.borrower_spk), PRECISION="%02x" % e["precision"],
                      LIQ_BP="%08x" % e["liq_bp"], TARGET_BP="%08x" % e["target_bp"], BONUS_BP="%08x" % e["bonus_bp"],
                      MATURITY="%08x" % 1_000_000_000)
        c, d, paid, kept = (int(e[k]) for k in ("collateral", "debt", "paid", "kept"))
        v = self.vault(d, e["last_time"], params=params)
        full = paid >= d
        if full:
            first = big(kept, self.borrower_spk, self.X_OUT) if kept else big(c, self.liquidator_spk, self.X_OUT)
        else:
            first = big(kept, self.vault(d - paid, e["time"], params=params).spk, self.X_OUT)
        ins = [(coin(0, big(c, v.spk, self.X_OUT)), 0xfffffffe), (coin(1, self.out(1, B.spk, self.BEACON_OUT)), 0xfffffffe),
               (coin(2, big(min(paid + FEE, (1 << 64) - 1), self.liquidator_spk, self.Y_OUT)), 0xfffffffe)]
        tx = self.mktx(ins, [first, big(paid, self.lender_spk, self.Y_OUT), self.out(1, B.spk, self.BEACON_OUT),
                             self.fee(FEE, self.Y_OUT)], locktime=e["time"])
        self.setwit(tx, 1, B.wit_recreate())
        att = self.attest(int(e["price"]), e["time"], B.program, precision=e["precision"])
        req = self.req(v.leaf, tx, 0, self.vault_witness(v, self.liq_path(att, 1, e["matured"])), True)
        try:
            r = seqc(req)
        except RuntimeError as err:
            return {"outcome": "refused", "seqc": str(err)[:160]}
        assert r.get("executed"), r.get("exec_error")
        return {"outcome": "accepted", "cost_bound_wu": (r["cost_milli"] + 999) // 1000}


if __name__ == "__main__":
    L1().main()
