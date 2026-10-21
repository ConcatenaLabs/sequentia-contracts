"""X2: the guarded SeqDEX order, addressed and spent from its descriptor.

The template `seqdex_guarded_order` is `seqdex/order` with two more terms,
GUARD_ASSET and GUARD_AMOUNT, and one more rule on every path: the order's
coin is not input 0, and input 0 holds exactly GUARD_AMOUNT of GUARD_ASSET,
explicitly. With the guard coin at input 0, the order at input k (k >= 1) owns
outputs 2k and 2k+1 as before.

Here the guard coin is a plain wallet coin of an issued asset G, spent and
returned at output 0. In OpenDAMP it is the verifier covenant, and the order is
then an order an asset under a covenant-enforced policy can rest in; that use
is proven in the opendamp repository.

A fill in part at input 1 is the control. Every violation of the guard is
refused by the mempool and in a block forced with `generateblock`, each beside
that control, carrying its pruned program and witness unchanged (a fill signs
nothing, so only the transaction differs): no guard coin anywhere, the order
itself at input 0, the guard coin at input 2 instead of 0, a guard coin of
another asset, one atom short and one atom over, and a confidential guard coin
with valid proofs. The order's own rules still bind beside the guard (a payment
one atom under the price). A whole fill and the refund are mined with the
guard, and the refund is refused without it.

The test also records that every fill's pruned program is one of two
constants whatever the order and k, and its witness is the data leaf's bytes
followed by one byte of PATH: a caller builds a fill with no compiler. Every
fill is paid in an issued asset and its fee in another."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

J, A = "Assertion failed inside jet", "Assertion failed"
FEE = 20_000                                 # atoms of Z, the fee asset
PATH_T = "Either<bool, ()>"
PARTIAL, WHOLE = "Left(true)", "Left(false)"
PATH_BYTE = {PARTIAL: b"\x40", WHOLE: b"\x00"}
GQ = 1_000                                   # the guard amount


def ceil_price(filled, num, den):
    return -(-filled * num // den)


class Known(Utxo):
    """A confidential coin whose amount and blinders the wallet that made it knows."""

    def __init__(self, u, amount, blinders):
        Utxo.__init__(self, u.txid, u.vout, u.txout)
        self._amount, self.blinders = amount, blinders

    @property
    def amount(self):
        return self._amount


class Order:
    """One instance: its terms, its script and its leaf."""

    def __init__(self, t, name, asset_a, asset_b, num, den, min_lot, maker_spk, expiry, refund_pk, guard, gq):
        self.t, self.name = t, name
        self.asset_a, self.asset_b, self.guard, self.gq = asset_a, asset_b, guard, gq
        self.A_OUT, self.B_OUT = t.asset_out(asset_a), t.asset_out(asset_b)
        self.num, self.den, self.min_lot = num, den, min_lot
        self.maker_spk, self.expiry, self.refund_pk = maker_spk, expiry, refund_pk
        self.p = {"ASSET_A": bytes.fromhex(asset_a)[::-1].hex(), "ASSET_B": bytes.fromhex(asset_b)[::-1].hex(),
                  "RATE_NUM": "%016x" % num, "RATE_DEN": "%016x" % den, "MIN_LOT": "%016x" % min_lot,
                  "MAKER": sha256(maker_spk).hex(), "EXPIRY": "%08x" % expiry, "REFUND_KEY": refund_pk.hex(),
                  "GUARD_ASSET": bytes.fromhex(guard)[::-1].hex(), "GUARD_AMOUNT": "%016x" % gq}
        x = t.sa.derive(t.desc, self.p, {})
        info = t.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        self.x = x
        self.spk = bytes.fromhex(x["script_pubkey"])
        self.terms = bytes.fromhex(x["leaves"]["terms"]["data"])
        assert len(self.terms) == 196
        self.leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["order"]["control_block"]))

    def price(self, filled):
        return ceil_price(filled, self.num, self.den)

    def witness(self, path, sig=bytes(64)):
        return {"ASSET_A": v256(bytes.fromhex(self.p["ASSET_A"])), "ASSET_B": v256(bytes.fromhex(self.p["ASSET_B"])),
                "RATE_NUM": vu(self.num), "RATE_DEN": vu(self.den), "MIN_LOT": vu(self.min_lot),
                "MAKER": v256(bytes.fromhex(self.p["MAKER"])), "EXPIRY": vu(self.expiry, 32),
                "REFUND_KEY": vpub(self.refund_pk), "GUARD_ASSET": v256(bytes.fromhex(self.p["GUARD_ASSET"])),
                "GUARD_AMOUNT": vu(self.gq), "PATH": vraw(path, PATH_T), "REFUND_SIG": vsig(sig)}


class X2(SimBase, BitcoinTestFramework):
    NAME = "x2"

    def set_test_params(self):
        self.chain_params()

    def coins(self, n, asset, atoms):
        """n wallet coins of `asset`, made in one transaction and one block,
        locked so the wallet's own coin selection leaves them."""
        node = self.node
        addrs = [node.getnewaddress("", "bech32") for _ in range(n)]
        txid = node.sendmany(dummy="", amounts={a: Decimal(atoms) / COIN for a in addrs},
                             output_assets={a: asset for a in addrs}, fee_asset=BITCOIN_ASSET)
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

    def g_out(self, coin):
        """The guard coin, returned to the wallet unchanged in asset and amount
        (explicitly; a confidential guard's return is blinded afterwards)."""
        asset = self.G_OUT if isinstance(coin, Known) else bytes(coin.txout.nAsset.vchCommitment)
        return self.out(coin.amount, self.wallet_spk(), asset)

    def reject_moved(self, tx, label, expect, control):
        """reject() for a negative that moves the order to input 0, where no
        accepted control can have it: the control spends the same coin, with
        the same program, at input `control.k` (1), and the mempool accepts
        it; the negative differs in that the coin is input 0."""
        assert tx.k == 0 and control.k == 1
        assert (tx.vin[0].prevout.hash, tx.vin[0].prevout.n) == \
            (control.vin[1].prevout.hash, control.vin[1].prevout.n), "the control spends another coin"
        cmr = lambda t, i: bytes(t.wit.vtxinwit[i].scriptWitness.stack[2])
        assert cmr(tx, 0) == cmr(control, 1), "the control spends another program"
        res = self.accept(control)
        assert res["allowed"], "%s: the control is refused: %s" % (label, res.get("reject-reason"))
        control.rehash()
        d = {"rejected": True, "expect": expect,
             "control": {"txid": control.hash, "same_coin": True, "at_input": 1, "testmempoolaccept": True,
                         "vsize": self.measure(control)["vsize"]}}
        res = self.accept(tx)
        assert not res["allowed"], "%s unexpectedly ACCEPTED" % label
        d["reject-reason"] = res.get("reject-reason", "")
        assert reason_matches(expect, d["reject-reason"]), (label, d)
        pos, node_height = self._logpos(), self.node.getblockcount()
        try:
            self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
            raise AssertionError("%s: tx was MINED via generateblock" % label)
        except JSONRPCException as e:
            d["block-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
        assert self.node.getblockcount() == node_height
        assert reason_matches(expect, d["block-error"]), (label, d)
        d["block-log"] = [l for l in self._logsince(pos) if "ConnectBlock" in l or "CheckInputScripts" in l][:2]
        self.log.info("REJECT %-42s block: %s (control at input 1 accepted)", label, d["block-error"])
        self.rec(label, d)

    def fill_tx(self, o, coin, filled, partial, guard, pay_coin, fee_coin, layout="guarded"):
        """A fill of `o`.

        guarded      [guard, order, pay, fee] -> [guard back, taker's A,
                     credit (2), rest (3, partial only), pay change, fee change, fee]
        order_first  [order, pay, fee] -> [credit (0), rest (1), taker's A, ...]
        pay_first    [pay, order, guard?, fee]: input 0 is the payment coin, the
                     guard coin (if any) at input 2 and returned after the rest."""
        paid = o.price(filled)
        credit = self.out(paid, o.maker_spk, o.B_OUT)
        rest = [self.out(coin.amount - filled, o.spk, o.A_OUT)] if partial else []
        taker = self.out(filled, self.taker_spk, o.A_OUT)
        tail = [self.out(pay_coin.amount - paid, self.change_spk, o.B_OUT),
                self.out(fee_coin.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)]
        F = 0xffffffff
        if layout == "guarded":
            ins = [(guard, F), (coin, F), (pay_coin, F), (fee_coin, F)]
            outs = [self.g_out(guard), taker, credit] + rest + tail
            k = 1
        elif layout == "order_first":
            ins = [(coin, F), (pay_coin, F), (fee_coin, F)]
            outs = [credit] + rest + [taker] + tail
            k = 0
        elif layout == "pay_first":
            ins = [(pay_coin, F), (coin, F)] + ([(guard, F)] if guard else []) + [(fee_coin, F)]
            outs = [taker, self.g_out(guard) if guard else self.out(1, self.change_spk, o.B_OUT), credit] + rest + tail
            if not guard:
                outs[-3] = self.out(pay_coin.amount - paid - 1, self.change_spk, o.B_OUT)
            k = 1
        else:
            raise ValueError(layout)
        tx = self.mktx(ins, outs)
        tx.k, tx.order, tx.path = k, o, PARTIAL if partial else WHOLE
        return tx

    def satisfy(self, tx):
        """Satisfies and prunes the order's program against `tx`, asserting the
        constants the template claims; the wallet signs."""
        o, k, path = tx.order, tx.k, tx.path
        r = self.sim_satisfy(o.leaf, tx, k, o.witness(path))
        prog = bytes.fromhex(r["program_hex"])
        want = self.fill_program.setdefault(path, prog)
        assert prog == want, "%s: the pruned program differs for %s at k=%d" % (path, o.name, k)
        assert bytes.fromhex(r["witness_hex"]) == o.terms + PATH_BYTE[path], "the witness is not the terms and PATH"
        tx.r = {k: r}
        return self.done(tx)

    def done(self, tx):
        keep = {k: getattr(tx, k) for k in ("k", "order", "path", "r", "sig") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in keep.items():
            setattr(t2, k, v)
        return t2

    def reuse(self, control, tx):
        """`tx` with the control's pruned program and witness at the order's input."""
        st = control.wit.vtxinwit[control.k].scriptWitness.stack
        self.setwit(tx, tx.k, list(st))
        tx.r = {tx.k: control.r[control.k]}
        return self.done(tx)

    def ok(self, tx, label, extra=None):
        m = {}
        for i, r in tx.r.items():
            mi = self.sim_measure(tx, i, r)
            m["input_%d" % i] = {k: v for k, v in mi.items() if k not in ("program_hex", "witness_hex")}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def refund_tx(self, o, coin, sk, guard=None, control=None):
        """The refund of `coin` to the wallet, its fee from a fee coin; the
        guard coin at input 0 when given, else the order is input 0."""
        fc = self.F()
        S = 0xfffffffe
        ins = ([(guard, S)] if guard else []) + [(coin, S), (fc, S)]
        outs = ([self.g_out(guard)] if guard else []) + [
            self.out(coin.amount, self.wallet_spk(), o.A_OUT),
            self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)]
        tx = self.mktx(ins, outs, locktime=o.expiry)
        k = 1 if guard else 0
        tx.k, tx.order, tx.path = k, o, "Right(())"
        sig = sign_schnorr(sk, self.sim_sighash(o.leaf, tx, k))
        if control is None:
            tx.r = {k: self.sim_satisfy(o.leaf, tx, k, o.witness("Right(())", sig))}
        else:
            st = control.wit.vtxinwit[control.k].scriptWitness.stack
            self.set_sim_wit(tx, k, o.leaf, bytes(st[1]), bit_replace(bytes(st[0]), control.sig, sig))
            tx.r = {k: control.r[control.k]}
        tx.sig = sig
        return self.done(tx)

    def confidential_guard(self, asset, amount):
        """A confidential wallet coin of `asset`, with its blinders."""
        node = self.node
        addr = node.getnewaddress("", "blech32")
        txid = node.sendtoaddress(address=addr, amount=Decimal(amount) / COIN, assetlabel=asset,
                                  fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        spk = bytes.fromhex(node.getaddressinfo(addr)["scriptPubKey"])
        u = self.utxo_of(txid, spk)
        assert u.txout.nValue.vchCommitment[0] in (0x08, 0x09), "the guard coin is not confidential"
        assert u.txout.nAsset.vchCommitment[0] in (0x0a, 0x0b), "the guard coin's asset is not blinded"
        sent = [d for d in node.gettransaction(txid, True, True)["details"] if d["vout"] == u.vout][0]
        node.lockunspent(False, [{"txid": u.txid, "vout": u.vout}])
        return Known(u, amount, (sent["amountblinder"], sent["assetblinder"]))

    def run_test(self):
        self.boot(issue=("X", "Y", "Z", "G", "H"))
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y, self.Z))
        self.sa, self.desc, self.vectors, self.sources = load_template("seqdex_guarded_order")
        self.text, self.body = self.sources["order"]
        self.fill_program = {}
        self.taker_spk, self.change_spk = self.wallet_spk(), self.wallet_spk()
        maker_spk = self.wallet_spk()
        refund_sk = generate_privkey()
        refund_pk = compute_xonly_pubkey(refund_sk)[0]
        h0 = node.getblockcount()

        # Order O: X sold for Y at 3 Y per 2 X, guarded by 1,000 atoms of G.
        O = Order(self, "O", self.X, self.Y, 3, 2, 10_000, maker_spk, h0 + 60, refund_pk, self.G, GQ)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"], "params": O.p,
                              "address": O.x["address"]["elementsregtest"], "data_leaf_bytes": len(O.terms)})

        pay = self.coins(4, self.Y, 4_000_000_000)
        fees = self.coins(30, self.Z, 100_000)
        self.F = fees.pop
        guards = self.coins(6, self.G, GQ)
        g_short, g_over = self.coins(1, self.G, GQ - 1)[0], self.coins(1, self.G, GQ + 1)[0]
        h_guard = self.coins(1, self.H, GQ)[0]
        g_conf = self.confidential_guard(self.G, GQ)

        LOCKED = 1_000_000_000
        o0 = self.fund(O.spk, LOCKED, self.X)
        r0 = self.fund(O.spk, 2_000_000, self.X)
        self.rec("funded", {"O": str(o0), "R": str(r0)})

        # ---- the control: a fill in part at input 1, the guard at input 0 -----
        F1 = 400_000_001
        g1, y1, fc = guards.pop(), pay.pop(), self.F()
        p1 = self.satisfy(self.fill_tx(O, o0, F1, True, g1, y1, fc))
        assert self.accept(p1)["allowed"], self.accept(p1)

        def neg(label, tx, expect=J, **kw):
            self.reject(self.reuse(p1, tx), label, expect, control=p1, index=tx.k, **kw)

        # The guard: absent, at another input, another asset, another amount.
        neg("guard/neg_no_guard_coin_the_payment_coin_at_input_0",
            self.fill_tx(O, o0, F1, True, None, y1, fc, layout="pay_first"))
        neg("guard/neg_the_guard_coin_at_input_2_not_0",
            self.fill_tx(O, o0, F1, True, g1, y1, fc, layout="pay_first"))
        # The order itself at input 0 (k = 0): its outputs would be 0 and 1.
        t = self.fill_tx(O, o0, F1, True, None, y1, fc, layout="order_first")
        self.reject_moved(self.reuse(p1, t), "guard/neg_the_order_at_input_0", J, p1)
        neg("guard/neg_a_guard_coin_of_another_asset", self.fill_tx(O, o0, F1, True, h_guard, y1, fc))
        neg("guard/neg_a_guard_coin_one_atom_short", self.fill_tx(O, o0, F1, True, g_short, y1, fc))
        neg("guard/neg_a_guard_coin_one_atom_over", self.fill_tx(O, o0, F1, True, g_over, y1, fc))
        # A confidential guard coin, with valid range and surjection proofs:
        # output 0 returns it blinded with the coin's own blinders.
        t = self.fill_tx(O, o0, F1, True, g_conf, y1, fc)
        ck = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        t.vout[0].nNonce = CTxOutNonce(ck)
        z = "00" * 32
        hexed = node.rawblindrawtransaction(
            t.serialize().hex(), [g_conf.blinders[0], z, z, z], [Decimal(u.amount) / COIN for u in t.prev],
            [self.G, self.X, self.Y, self.Z], [g_conf.blinders[1], z, z, z], "", False)
        tb = Tx.from_hex(hexed)
        assert tb.vout[0].nAsset.vchCommitment[0] in (0x0a, 0x0b), "the returned guard is not blinded"
        tb.prev = t.prev
        self.pad(tb)
        tb.k, tb.order, tb.path = t.k, t.order, t.path
        neg("guard/neg_a_confidential_guard_coin_valid_proofs", tb, A)
        # The order's own rule beside the guard: one atom under the price.
        t = self.fill_tx(O, o0, F1, True, g1, y1, fc)
        t.vout[2].nValue = CTxOutValue(O.price(F1) - 1)
        t.vout[4].nValue = CTxOutValue(t.vout[4].nValue.getAmount() + 1)
        neg("fill/neg_payment_one_atom_under_the_price_beside_the_guard", t)

        txid1 = self.ok(p1, "fill/partial_at_input_1_beside_the_guard",
                        extra={"filled": F1, "paid": O.price(F1), "k": 1, "guard": {"asset": "G", "amount": GQ}})
        o1 = self.utxo_at(txid1, 3)
        assert o1.spk == O.spk and o1.amount == LOCKED - F1

        # ---- the whole of the rest, at input 1 -----------------------------------
        w = self.satisfy(self.fill_tx(O, o1, o1.amount, False, guards.pop(), pay.pop(), self.F()))
        self.ok(w, "fill/whole_at_input_1_beside_the_guard", extra={"filled": o1.amount, "paid": O.price(o1.amount)})

        # ---- the refund: the guard binds it too -----------------------------------
        self.mine_to(O.expiry)
        rg = self.refund_tx(O, r0, refund_sk, guard=guards.pop())
        assert self.accept(rg)["allowed"], self.accept(rg)
        self.reject_moved(self.refund_tx(O, r0, refund_sk, guard=None, control=rg),
                          "refund/neg_without_the_guard_the_order_at_input_0", J, rg)
        self.reject(self.refund_tx(O, r0, refund_sk, guard=h_guard, control=rg),
                    "refund/neg_a_guard_coin_of_another_asset", J, control=rg, index=1)
        self.ok(rg, "refund/by_height_beside_the_guard", extra={"expiry": O.expiry})
        st = rg.wit.vtxinwit[1].scriptWitness.stack
        self.rec("refund_program", {"bytes": len(st[1]), "hex": st[1].hex()})
        self.rec("fill_program", {k: {"bytes": len(v), "hex": v.hex(), "path_byte": PATH_BYTE[k].hex()}
                                  for k, v in self.fill_program.items()})
        fills = json.load(open(os.path.join(REPO_ROOT, "templates", "seqdex_guarded_order", "fills.json")))
        assert fills["paths"]["fill"]["program"] == self.fill_program[PARTIAL].hex(), "fills.json fill differs"
        assert fills["paths"]["fill_whole"]["program"] == self.fill_program[WHOLE].hex(), "fills.json whole differs"
        assert fills["paths"]["refund_height"]["program"] == st[1].hex(), "fills.json refund differs"


if __name__ == "__main__":
    X2().main()
