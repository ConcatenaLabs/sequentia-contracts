"""X1: the SeqDEX order, addressed and spent from its descriptor.

The template `seqdex_order` is a resting order with its terms in a data leaf
beside one program that serves every order:

    P2TR(NUMS, TapBranch(TapLeaf_0xbe(order), H_TapData(terms)))

Anyone fills it at input k by paying the maker at output 2k at least
ceil(fill x RATE_NUM / RATE_DEN) of ASSET_B, the products compared at 128
bits; a partial fill leaves the rest at output 2k+1 under the same script.
The refund key takes the coin back once the lock time reaches EXPIRY, a block
height or a median time.

Each instance is derived by the Python mirror from the descriptor alone. An
order whose price times its size is far beyond 2^63, which no tapscript fill
can compute, is filled in part at input 0, again at input 1, and in whole; an
order at the extreme price (2^64-1)/(2^64-2) and an order at 1:1 are filled
together in one transaction at k = 0 and 1. Every violation is refused by the
mempool and in a block forced with `generateblock`, each for its reason; a
refusal whose error is a failed assertion names a control, a transaction that
differs from it only in the property it breaks and that the node accepts. A
negative carries its control's pruned program and witness unchanged: a fill
signs nothing, so only the transaction differs.

The test also records the claim the template makes for callers with no
compiler: every fill's pruned program is one of two constants (partial and
whole) whatever the order and k, and its witness is the data leaf's bytes
followed by one byte of PATH. Every fill is paid in an issued asset and its
fee in another; none touches the policy asset."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.key import tweak_add_pubkey  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
NONFINAL, NONFINAL_MEMPOOL = "bad-txns-nonfinal", "non-final"
FEE = 20_000                                 # atoms of Z, the fee asset
PATH_T = "Either<bool, ()>"
PARTIAL, WHOLE = "Left(true)", "Left(false)"
PATH_BYTE = {PARTIAL: b"\x40", WHOLE: b"\x00"}
INT63 = 2 ** 63 - 1


def ceil_price(filled, num, den):
    return -(-filled * num // den)


def tagged(tag, m):
    t = sha256(tag.encode())
    return sha256(t + t + m)


def p2tr_over(cmr, data):
    """The scriptPubKey of a Simplicity program `cmr` beside a data leaf
    `data`, under the NUMS key."""
    leaf = tagged("TapLeaf/elements", bytes([0xbe, 0x20]) + cmr)
    dl = tagged("TapData", data)
    root = tagged("TapBranch/elements", min(leaf, dl) + max(leaf, dl))
    tweak = tagged("TapTweak/elements", NUMS + root)
    q, _ = tweak_add_pubkey(NUMS, tweak)
    return b"\x51\x20" + q


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

    def __init__(self, t, name, asset_a, asset_b, num, den, min_lot, maker_spk, expiry, refund_pk):
        self.t, self.name = t, name
        self.asset_a, self.asset_b = asset_a, asset_b
        self.A_OUT, self.B_OUT = t.asset_out(asset_a), t.asset_out(asset_b)
        self.num, self.den, self.min_lot = num, den, min_lot
        self.maker_spk, self.expiry, self.refund_pk = maker_spk, expiry, refund_pk
        self.p = {"ASSET_A": bytes.fromhex(asset_a)[::-1].hex(), "ASSET_B": bytes.fromhex(asset_b)[::-1].hex(),
                  "RATE_NUM": "%016x" % num, "RATE_DEN": "%016x" % den, "MIN_LOT": "%016x" % min_lot,
                  "MAKER": sha256(maker_spk).hex(), "EXPIRY": "%08x" % expiry, "REFUND_KEY": refund_pk.hex()}
        x = t.sa.derive(t.desc, self.p, {})
        info = t.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        self.x = x
        self.spk = bytes.fromhex(x["script_pubkey"])
        self.terms = bytes.fromhex(x["leaves"]["terms"]["data"])
        assert len(self.terms) == 156
        self.leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["order"]["control_block"]))

    def price(self, filled):
        return ceil_price(filled, self.num, self.den)

    def with_terms(self, **kw):
        """The same template with some terms changed."""
        a = dict(asset_a=self.asset_a, asset_b=self.asset_b, num=self.num, den=self.den, min_lot=self.min_lot,
                 maker_spk=self.maker_spk, expiry=self.expiry, refund_pk=self.refund_pk)
        a.update(kw)
        return Order(self.t, self.name + "'", **a)

    def witness(self, path, sig=bytes(64)):
        w = {"ASSET_A": v256(bytes.fromhex(self.p["ASSET_A"])), "ASSET_B": v256(bytes.fromhex(self.p["ASSET_B"])),
             "RATE_NUM": vu(self.num), "RATE_DEN": vu(self.den), "MIN_LOT": vu(self.min_lot),
             "MAKER": v256(bytes.fromhex(self.p["MAKER"])), "EXPIRY": vu(self.expiry, 32),
             "REFUND_KEY": vpub(self.refund_pk), "PATH": vraw(path, PATH_T), "REFUND_SIG": vsig(sig)}
        return w


class X1(SimBase, BitcoinTestFramework):
    NAME = "x1"

    def set_test_params(self):
        self.chain_params()

    # -- coins ---------------------------------------------------------------
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

    # -- fills -----------------------------------------------------------------
    def fill_tx(self, orders, pay_coin, fee_coin, pay_out=None):
        """One transaction filling `orders`, a list of (order, coin, filled,
        partial), the i-th at input i. Its credit is at 2i and its rest, for a
        partial fill, at 2i+1; after them come the taker's asset A, the
        payment change, the fee change and the fee. A whole fill's 2i+1 is
        the taker's own receipt of the coin. Returns the unsigned transaction
        with `credit`, `rest` and `taker` holding the output indices."""
        pay_out = pay_out or orders[0][0].B_OUT
        ins, slots, tail = [], {}, []
        paid_total = 0
        tx_credit, tx_rest, tx_taker = {}, {}, {}
        for i, (o, coin, filled, partial) in enumerate(orders):
            ins.append((coin, 0xffffffff))
            paid = o.price(filled)
            paid_total += paid
            slots[2 * i] = self.out(paid, o.maker_spk, o.B_OUT)
            tx_credit[i] = 2 * i
            if partial:
                slots[2 * i + 1] = self.out(coin.amount - filled, o.spk, o.A_OUT)
                tx_rest[i] = 2 * i + 1
                tail.append((i, self.out(filled, self.taker_spk, o.A_OUT)))
            else:
                slots[2 * i + 1] = self.out(filled, self.taker_spk, o.A_OUT)
                tx_taker[i] = 2 * i + 1
        ins += [(pay_coin, 0xffffffff), (fee_coin, 0xffffffff)]
        outs = [slots[j] for j in range(2 * len(orders))]
        for i, o in tail:
            tx_taker[i] = len(outs)
            outs.append(o)
        outs.append(self.out(pay_coin.amount - paid_total, self.change_spk, pay_out))
        outs += [self.out(fee_coin.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)]
        tx = self.mktx(ins, outs)
        tx.credit, tx.rest, tx.taker, tx.orders = tx_credit, tx_rest, tx_taker, orders
        return tx

    def satisfy(self, tx):
        """Satisfies and prunes the program of every order input against `tx`,
        asserting the two constants the template claims; the wallet signs."""
        tx.r = {}
        for i, (o, coin, filled, partial) in enumerate(tx.orders):
            path = PARTIAL if partial else WHOLE
            r = self.sim_satisfy(o.leaf, tx, i, o.witness(path))
            prog = bytes.fromhex(r["program_hex"])
            want = self.fill_program.setdefault(path, prog)
            assert prog == want, "%s: the pruned %s program differs for %s at k=%d" % (path, path, o.name, i)
            assert bytes.fromhex(r["witness_hex"]) == o.terms + PATH_BYTE[path], \
                "the witness is not the terms followed by PATH"
            tx.r[i] = r
        return self.done(tx)

    def done(self, tx):
        """The wallet signs its own inputs; the order inputs keep their stacks."""
        keep = {k: getattr(tx, k) for k in ("credit", "rest", "taker", "orders", "r") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in keep.items():
            setattr(t2, k, v)
        return t2

    def reuse(self, control, tx, at=None):
        """`tx` with the control's program and witness for each order input
        (input i of the control's at input at[i] of `tx`), then signed."""
        at = at or {i: i for i in control.r}
        for i, j in at.items():
            st = control.wit.vtxinwit[i].scriptWitness.stack
            self.setwit(tx, j, list(st))
        tx.r = {at[i]: r for i, r in control.r.items()}
        return self.done(tx)

    def ok(self, tx, label, extra=None):
        m = {}
        for i, r in tx.r.items():
            mi = self.sim_measure(tx, i, r)
            m["input_%d" % i] = {k: v for k, v in mi.items() if k not in ("program_hex", "witness_hex")}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def blinded(self, tx, idx=0):
        """`tx` with output `idx` and its payment change blinded by the node,
        with valid range and surjection proofs."""
        node = self.node
        ck = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        chg = node.getaddressinfo(node.getnewaddress("", "blech32"))
        chg_spk = bytes.fromhex(node.getaddressinfo(chg["unconfidential"])["scriptPubKey"])
        n = len(tx.vout)
        tx.vout[idx].nNonce = CTxOutNonce(ck)
        tx.vout[n - 3] = self.out(tx.vout[n - 3].nValue.getAmount(), chg_spk, bytes(tx.vout[n - 3].nAsset.vchCommitment))
        tx.vout[n - 3].nNonce = CTxOutNonce(bytes.fromhex(chg["confidential_key"]))
        z = "00" * 32
        assets = [bytes(u.txout.nAsset.vchCommitment[1:])[::-1].hex() for u in tx.prev]
        amounts = [Decimal(u.amount) / COIN for u in tx.prev]
        hexed = node.rawblindrawtransaction(tx.serialize().hex(), [z] * len(tx.prev), amounts, assets,
                                            [z] * len(tx.prev), "", False)
        t2 = Tx.from_hex(hexed)
        assert t2.vout[idx].nAsset.vchCommitment[0] in (0x0a, 0x0b), "the output's asset is not blinded"
        assert t2.vout[idx].nValue.vchCommitment[0] in (0x08, 0x09), "the output's amount is not blinded"
        assert bytes(t2.vout[idx].scriptPubKey) == bytes(tx.vout[idx].scriptPubKey)
        t2.prev = tx.prev
        self.pad(t2)
        for k in ("credit", "rest", "taker", "orders"):
            setattr(t2, k, getattr(tx, k))
        return t2

    @staticmethod
    def change(tx, delta):
        """Moves `delta` atoms into the payment change, three from the end."""
        n = len(tx.vout)
        o = tx.vout[n - 3]
        tx.vout[n - 3] = CTxOut(nValue=CTxOutValue(o.nValue.getAmount() + delta), scriptPubKey=o.scriptPubKey,
                                nAsset=o.nAsset, nNonce=CTxOutNonce())
        return tx

    # -- refunds -----------------------------------------------------------------
    def refund_tx(self, o, coin, locktime, sk, seq=0xfffffffe, sig_tx=None, control=None, asset_out=None):
        """The refund of `coin` to the wallet, its fee from a fee coin. With
        `control`, the control's pruned program and witness, its signature
        replaced by one by `sk` over this transaction (or over `sig_tx`)."""
        fc = self.F()
        tx = self.mktx([(coin, seq), (fc, seq)],
                       [self.out(coin.amount, self.wallet_spk(), asset_out or o.A_OUT),
                        self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)],
                       locktime=locktime)
        if sig_tx is None:
            sig_tx = tx
        if control is None:
            sig = sign_schnorr(sk, self.sim_sighash(o.leaf, sig_tx, 0))
            tx.r = {0: self.sim_satisfy(o.leaf, tx, 0, o.witness("Right(())", sig))}
            tx.sig = sig
        else:
            sig = sign_schnorr(sk, self.sim_sighash(o.leaf, sig_tx, 0))
            st = control.wit.vtxinwit[0].scriptWitness.stack
            w = bit_replace(bytes(st[0]), control.sig, sig)
            self.set_sim_wit(tx, 0, o.leaf, bytes(st[1]), w)
            tx.r, tx.sig = control.r, sig
        t2 = self.done(tx)
        t2.sig = tx.sig
        return t2

    def run_test(self):
        self.boot(issue=("X", "Y", "Z"))
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y, self.Z))
        self.sa, self.desc, self.vectors, self.sources = load_template("seqdex_order")
        self.text, self.body = self.sources["order"]
        self.fill_program = {}
        self.taker_spk, self.change_spk = self.wallet_spk(), self.wallet_spk()
        maker_spk = self.wallet_spk()
        refund_sk = generate_privkey()
        refund_pk = compute_xonly_pubkey(refund_sk)[0]
        other_sk = generate_privkey()
        other_pk = compute_xonly_pubkey(other_sk)[0]
        h0 = node.getblockcount()
        mtp0 = node.getblockheader(node.getbestblockhash())["mediantime"]

        # Order A: 2 * 10^13 atoms of X at 9,000,000,000,007 Y for every
        # 10,000,000,000,003 X. The fill product 2e13 * 9e12 is about 1.8e26.
        LOCKED = 20_000_000_000_000
        OA = Order(self, "A", self.X, self.Y, 9_000_000_000_007, 10_000_000_000_003, 1_000_000,
                   maker_spk, h0 + 400, refund_pk)
        assert LOCKED * OA.num + OA.den - 1 > INT63
        # Order C: the extreme price (2^64-1)/(2^64-2), a median-time expiry.
        OC = Order(self, "C", self.X, self.Y, 2 ** 64 - 1, 2 ** 64 - 2, 1, maker_spk, mtp0 + 6000, refund_pk)
        # Order E: one Y for one X, the two rate terms equal.
        OE = Order(self, "E", self.X, self.Y, 1, 1, 1, maker_spk, h0 + 400, refund_pk)
        # Order R: a refund by height, soon.
        OR = Order(self, "R", self.X, self.Y, 3, 2, 1000, maker_spk, h0 + 60, refund_pk)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"],
                              "orders": {o.name: {"params": o.p, "address": o.x["address"]["elementsregtest"]}
                                         for o in (OA, OC, OE, OR)},
                              "A_locked_times_rate_num": LOCKED * OA.num})

        pay = self.coins(5, self.Y, 4_000_000_000_000)           # 4e12 Y each
        big_y = self.coins(2, self.Y, 30_000_000_000_000)        # 3e13 Y each
        z_pay = self.coins(1, self.Z, 30_000_000_000_000)[0]
        fees = self.coins(40, self.Z, 100_000)
        self.F = fees.pop

        a0 = self.fund(OA.spk, LOCKED, self.X)
        stray = self.fund(OA.spk, 10_000_000_000_000, self.Y)    # a coin of another asset at A's address
        c0 = self.fund(OC.spk, 1_000_000_000, self.X)
        e0 = self.fund(OE.spk, 500_000, self.X)
        e1 = self.fund(OE.spk, 700_000, self.X)
        r0 = self.fund(OR.spk, 2_000_000, self.X)
        r_stray = self.fund(OR.spk, 3_000_000, self.Y)          # another asset at R's address
        # A confidential coin of X at A's address, blinded by this wallet.
        ck = node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"]
        ctxid = node.sendtoaddress(address=node.createblindedaddress(OA.x["address"]["elementsregtest"], ck),
                                   amount=Decimal(LOCKED) / COIN, assetlabel=self.X, fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        conf = self.utxo_of(ctxid, OA.spk)
        assert conf.txout.nValue.vchCommitment[0] in (0x08, 0x09), "the coin is not confidential"
        sent = [d for d in node.gettransaction(ctxid, True, True)["details"] if d["vout"] == conf.vout][0]
        conf = Known(conf, LOCKED, (sent["amountblinder"], sent["assetblinder"]))
        self.rec("funded", {"A": str(a0), "stray_Y_at_A": str(stray), "C": str(c0), "E": [str(e0), str(e1)],
                            "R": str(r0)})

        # ---- A, partial, at input 0 ------------------------------------------------
        # A fill whose price rises by one atom when it takes one atom more.
        F1 = 6_000_000_000_000
        while OA.price(F1 + 1) == OA.price(F1):
            F1 += 1
        y1 = big_y.pop()
        y_other = big_y[0]
        fc = self.F()

        def fill(o, coin, f, partial=True, pc=None):
            return self.fill_tx([(o, coin, f, partial)], pc or y1, fc)

        p1 = self.satisfy(fill(OA, a0, F1))
        assert self.accept(p1)["allowed"]
        self.rec("A/fill_size", {"locked": LOCKED, "filled": F1, "paid": OA.price(F1),
                                 "filled_times_rate_num": F1 * OA.num, "over_2_63": F1 * OA.num > INT63})

        def neg(label, tx, expect=J, **kw):
            self.reject(self.reuse(p1, tx), label, expect, control=p1, **kw)

        # The price: one atom under it; and the rest one atom short, the
        # payment unchanged, which is a fill of one atom more.
        t = fill(OA, a0, F1)
        t.vout[0].nValue = CTxOutValue(OA.price(F1) - 1)
        neg("fill/neg_payment_one_atom_under_the_price", self.change(t, 1))
        t = fill(OA, a0, F1)
        t.vout[1].nValue = CTxOutValue(LOCKED - F1 - 1)
        t.vout[2].nValue = CTxOutValue(F1 + 1)
        assert OA.price(F1 + 1) == OA.price(F1) + 1
        neg("fill/neg_rest_one_atom_short_payment_unchanged", t)
        # The rest: elsewhere, under another program, under other terms.
        t = fill(OA, a0, F1); t.vout[1].scriptPubKey = CScript(self.wallet_spk())
        neg("fill/neg_rest_to_another_script", t)
        one_key_cmr = bytes.fromhex(json.load(open(os.path.join(REPO_ROOT, "templates", "one_key", "descriptor.json")))
                                    ["template"]["program"]["cmr"])
        t = fill(OA, a0, F1); t.vout[1].scriptPubKey = CScript(p2tr_over(one_key_cmr, OA.terms))
        neg("fill/neg_rest_under_another_program_same_terms", t)
        t = fill(OA, a0, F1); t.vout[1].scriptPubKey = CScript(OA.with_terms(num=OA.num - 1).spk)
        neg("fill/neg_rest_under_other_terms_a_lower_price", t)
        t = fill(OA, a0, F1); t.vout[1].scriptPubKey = CScript(OA.with_terms(refund_pk=other_pk).spk)
        neg("fill/neg_rest_under_other_terms_the_takers_refund_key", t)
        t = fill(OA, a0, F1); t.vout[1].scriptPubKey = CScript(OA.with_terms(expiry=OA.expiry - 1).spk)
        neg("fill/neg_rest_under_other_terms_an_earlier_expiry", t)
        # The rest paid in Y at A's script; all of the X goes to the taker.
        t = fill(OA, a0, F1, pc=y_other)
        t.vout[1] = self.out(LOCKED - F1, OA.spk, OA.B_OUT)
        t.vout[2].nValue = CTxOutValue(LOCKED)
        neg("fill/neg_rest_in_another_asset", self.change(t, -(LOCKED - F1)))
        t = fill(OA, a0, F1); t.vout[1].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        neg("fill/neg_rest_carries_a_nonce", t, A)
        neg("fill/neg_rest_confidential_valid_proofs", self.blinded(fill(OA, a0, F1), 1), A)
        # Minimum lots, each against its own control at the minimum exactly.
        lot_ok = self.satisfy(fill(OA, a0, OA.min_lot))
        self.reject(self.reuse(lot_ok, fill(OA, a0, OA.min_lot - 1)), "fill/neg_fill_one_atom_below_the_minimum_lot",
                    J, control=lot_ok)
        rest_ok = self.satisfy(fill(OA, a0, LOCKED - OA.min_lot))
        self.reject(self.reuse(rest_ok, fill(OA, a0, LOCKED - OA.min_lot + 1)),
                    "fill/neg_rest_one_atom_below_the_minimum_lot", J, control=rest_ok)
        # The credit: another asset, confidential, another script, a nonce.
        t = fill(OA, a0, F1, pc=z_pay)
        t.vout[0].nAsset = CTxOutAsset(self.Z_OUT)
        t.vout[3] = self.out(z_pay.amount - OA.price(F1), self.change_spk, self.Z_OUT)
        neg("fill/neg_credit_in_another_asset", t)
        neg("fill/neg_credit_confidential_valid_proofs", self.blinded(fill(OA, a0, F1), 0), A)
        t = fill(OA, a0, F1); t.vout[0].scriptPubKey = CScript(self.wallet_spk())
        neg("fill/neg_credit_to_another_script", t)
        t = fill(OA, a0, F1); t.vout[0].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        neg("fill/neg_credit_carries_a_nonce", t, A)
        # The indices: credit and rest swapped; the order at input 1 paying at
        # outputs 0 and 1, against the same order at input 1 paying at 2 and 3.
        t = fill(OA, a0, F1); t.vout[0], t.vout[1] = t.vout[1], t.vout[0]
        neg("fill/neg_credit_at_2k_plus_1_rest_at_2k", t)

        def at_input_1(coin, f, credit_at, pay_coin, fee_coin):
            o = [self.out(f, self.taker_spk, OA.A_OUT),
                 self.out(pay_coin.amount - OA.price(f), self.change_spk, OA.B_OUT)]
            sale = [self.out(OA.price(f), maker_spk, OA.B_OUT), self.out(coin.amount - f, OA.spk, OA.A_OUT)]
            outs = (o + sale) if credit_at == 2 else (sale + o)
            tx = self.mktx([(pay_coin, 0xffffffff), (coin, 0xffffffff), (fee_coin, 0xffffffff)],
                           outs + [self.out(fee_coin.amount - FEE, self.change_spk, self.Z_OUT),
                                   self.fee(FEE, self.Z_OUT)])
            tx.credit, tx.rest, tx.taker, tx.orders = {1: credit_at}, {1: credit_at + 1}, {}, [None, (OA, coin, f, True)]
            return tx

        k1 = at_input_1(a0, F1, 2, y1, fc)
        r = self.sim_satisfy(OA.leaf, k1, 1, OA.witness(PARTIAL))
        assert bytes.fromhex(r["program_hex"]) == self.fill_program[PARTIAL]
        k1.r = {1: r}
        k1 = self.done(k1)
        assert self.accept(k1)["allowed"]
        self.reject(self.reuse(k1, at_input_1(a0, F1, 0, y1, fc)), "fill/neg_input_1_paying_at_outputs_0_and_1", J,
                    control=k1, index=1)
        # A coin of another asset at A's address. The control spends A's own coin.
        t = fill(OA, stray, F1, pc=y_other)
        t.vout[1] = self.out(stray.amount - F1, OA.spk, OA.B_OUT)
        t.vout[2] = self.out(F1, self.taker_spk, OA.B_OUT)
        neg("fill/neg_coin_of_another_asset_at_the_address", t, other_coin=True)
        # A confidential coin of X at A's address: the taker's X and the payment
        # change are blinded with the coin's own blinders, so the transaction
        # balances and only the program can refuse it.
        t = fill(OA, conf, F1)
        ck1 = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        ck2 = bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "blech32"))["confidential_key"])
        t.vout[2].nNonce, t.vout[3].nNonce = CTxOutNonce(ck1), CTxOutNonce(ck2)
        z = "00" * 32
        hexed = node.rawblindrawtransaction(
            t.serialize().hex(), [conf.blinders[0], z, z], [Decimal(u.amount) / COIN for u in t.prev],
            [self.X, self.Y, self.Z], [conf.blinders[1], z, z], "", False)
        tb = Tx.from_hex(hexed)
        assert tb.vout[2].nValue.vchCommitment[0] in (0x08, 0x09), "the taker's X is not blinded"
        tb.prev = t.prev
        self.pad(tb)
        for k in ("credit", "rest", "taker", "orders"):
            setattr(tb, k, getattr(t, k))
        neg("fill/neg_confidential_coin_at_the_address", tb, A, other_coin=True)
        txid1 = self.ok(p1, "fill/A_partial_at_input_0",
                        extra={"filled": F1, "paid": OA.price(F1), "k": 0, "filled_times_rate_num": F1 * OA.num})
        a1 = self.utxo_at(txid1, 1)
        assert a1.spk == OA.spk and a1.amount == LOCKED - F1

        # ---- A, partial again, at input 1 --------------------------------------
        F2 = 5_000_000_000_001
        y2 = big_y.pop()
        fc = self.F()
        k1b = at_input_1(a1, F2, 2, y2, fc)
        r = self.sim_satisfy(OA.leaf, k1b, 1, OA.witness(PARTIAL))
        assert bytes.fromhex(r["program_hex"]) == self.fill_program[PARTIAL]
        assert bytes.fromhex(r["witness_hex"]) == OA.terms + PATH_BYTE[PARTIAL]
        k1b.r = {1: r}
        k1b = self.done(k1b)
        txid2 = self.ok(k1b, "fill/A_partial_at_input_1", extra={"filled": F2, "paid": OA.price(F2), "k": 1})
        a2 = self.utxo_at(txid2, 3)
        assert a2.spk == OA.spk and a2.amount == LOCKED - F1 - F2
        y2r = self.utxo_at(txid2, 1)
        node.lockunspent(False, [{"txid": y2r.txid, "vout": y2r.vout}])

        # ---- A, whole: output 1 is the taker's X --------------------------------
        fc = self.F()

        def whole():
            return self.fill_tx([(OA, a2, a2.amount, False)], y2r, fc)
        w = self.satisfy(whole())
        t = whole()
        t.vout[0].nValue = CTxOutValue(OA.price(a2.amount) - 1)
        self.reject(self.reuse(w, self.change(t, 1)), "fill/neg_whole_fill_one_atom_under_the_price", J, control=w)
        self.ok(w, "fill/A_whole", extra={"filled": a2.amount, "paid": OA.price(a2.amount), "k": 0,
                                          "filled_times_rate_num": a2.amount * OA.num})

        # ---- two orders in one transaction: C at input 0, E at input 1 ----------
        fc = self.F()
        y3 = pay.pop()
        FC = 400_000_000
        assert OC.price(FC) == FC + 1

        def two():
            return self.fill_tx([(OC, c0, FC, True), (OE, e0, e0.amount, False)], y3, fc)
        both = self.satisfy(two())
        t = two()
        t.vout[0].nValue = CTxOutValue(FC)
        self.reject(self.reuse(both, self.change(t, 1)), "fill/neg_extreme_price_one_atom_under", J, control=both)
        # Two coins of E at inputs 0 and 1, and one payment at output 0 for both.
        fc2 = self.F()
        pair_ok = self.satisfy(self.fill_tx([(OE, e0, e0.amount, False), (OE, e1, e1.amount, False)], y3, fc2))
        assert self.accept(pair_ok)["allowed"]
        one_pay = self.mktx([(e0, 0xffffffff), (e1, 0xffffffff), (y3, 0xffffffff), (fc2, 0xffffffff)],
                            [self.out(e0.amount + e1.amount, maker_spk, OE.B_OUT),
                             self.out(e0.amount, self.taker_spk, OE.A_OUT),
                             self.out(e1.amount, self.taker_spk, OE.A_OUT),
                             self.out(y3.amount - e0.amount - e1.amount, self.change_spk, OE.B_OUT),
                             self.out(fc2.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        self.reject(self.reuse(pair_ok, one_pay), "fill/neg_two_coins_one_payment", J, control=pair_ok, index=1)
        txid3 = self.ok(both, "fill/C_partial_at_0_and_E_whole_at_1",
                        extra={"C": {"filled": FC, "paid": OC.price(FC), "k": 0},
                               "E": {"filled": e0.amount, "paid": e0.amount, "k": 1}})
        c1 = self.utxo_at(txid3, 1)
        assert c1.spk == OC.spk and c1.amount == c0.amount - FC

        # ---- the refund, by height -------------------------------------------------
        assert node.getblockcount() < OR.expiry
        early = self.refund_tx(OR, r0, OR.expiry, refund_sk)
        self.reject(early, "refund/neg_height_lock_before_its_height_is_mined", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.mine_to(OR.expiry)
        rh = self.refund_tx(OR, r0, OR.expiry, refund_sk)
        assert self.accept(rh)["allowed"]
        self.reject(self.refund_tx(OR, r0, OR.expiry - 1, refund_sk, control=rh),
                    "refund/neg_lock_time_one_block_below_expiry", J, control=rh)
        self.reject(self.refund_tx(OR, r0, OR.expiry, refund_sk, seq=0xffffffff, control=rh),
                    "refund/neg_lock_disabled_by_final_sequences", J, control=rh)
        self.reject(self.refund_tx(OR, r0, OR.expiry, other_sk, control=rh),
                    "refund/neg_signed_by_another_key", J, control=rh)
        other = self.refund_tx(OR, r0, OR.expiry, refund_sk)
        self.reject(self.refund_tx(OR, r0, OR.expiry, refund_sk, sig_tx=other, control=rh),
                    "refund/neg_signature_over_another_transaction", J, control=rh)
        self.ok(rh, "refund/by_height_at_expiry", extra={"expiry": OR.expiry})
        self.ok(self.refund_tx(OR, r_stray, OR.expiry, refund_sk, asset_out=OR.B_OUT),
                "refund/a_coin_of_another_asset_at_the_address", extra={"expiry": OR.expiry})
        self.rec_refund_program("height", rh)

        # ---- the refund, by median time ------------------------------------------
        mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert mtp < OC.expiry, (mtp, OC.expiry)
        early = self.refund_tx(OC, c1, OC.expiry, refund_sk)
        self.reject(early, "refund/neg_time_lock_before_the_median_time", NONFINAL, mempool=NONFINAL_MEMPOOL)
        node.setmocktime(OC.expiry + 1200)
        self.generate(node, 12)
        mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert mtp >= OC.expiry, (mtp, OC.expiry)
        rt = self.refund_tx(OC, c1, OC.expiry, refund_sk)
        assert self.accept(rt)["allowed"]
        self.reject(self.refund_tx(OC, c1, OC.expiry - 1, refund_sk, control=rt),
                    "refund/neg_time_lock_one_second_below_expiry", J, control=rt)
        self.reject(self.refund_tx(OC, c1, node.getblockcount(), refund_sk, control=rt),
                    "refund/neg_height_lock_against_a_time_expiry", J, control=rt)
        self.ok(rt, "refund/by_median_time_at_expiry", extra={"expiry": OC.expiry, "median_time": mtp})
        self.rec_refund_program("time", rt)
        self.rec("fill_program", {k: {"bytes": len(v), "hex": v.hex(), "path_byte": PATH_BYTE[k].hex()}
                                  for k, v in self.fill_program.items()})

    def rec_refund_program(self, kind, tx):
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        self.R.setdefault("refund_program", {})[kind] = {"bytes": len(st[1]), "hex": st[1].hex()}
        self.dump()


if __name__ == "__main__":
    X1().main()
