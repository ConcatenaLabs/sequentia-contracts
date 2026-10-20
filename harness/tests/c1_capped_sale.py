"""C1: the capped sale, addressed and spent from its descriptor.

The template `capped_sale` sells a token at a fixed price to the buyers on an
allocation list, each up to their cap:

    P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(sale), H_TapData(params || state)), reclaim))

The state is one slot, ALLOCATIONS, the root of a 16-level Merkle tree of
(key, cap, bought) per buyer. A purchase shows the buyer's leaf and its proof,
is signed by the buyer's key over the whole transaction, pays the treasury at
output 2k for the coin at input k and re-creates the sale at 2k+1 in the state
whose tree has only that buyer's `bought` raised. The reclaim leaf is
tapscript: the project key, after the close.

Each instance is derived by the Python mirror from the descriptor alone, and
every tree by the mirror's allocation functions. Purchases at input 0 and at
input 1, a buyer's second purchase that reaches the cap exactly, a full buy
and the reclaim confirm. Every violation is refused by the mempool and in a
block forced with `generateblock`, each for its reason; a refusal whose error
is a failed assertion names a control, a transaction that differs from it
only in the property it breaks and that the node accepts. A negative reuses
its control's pruned program and witness with the values it changes replaced
in place, re-signed by the buyer for its own transaction, so it takes the
control's branches up to the check it breaks. Every purchase is paid in an
issued asset, and its fee in another; none touches the policy asset."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

J, A = "Assertion failed inside jet", "Assertion failed"
SIG = "Assertion failed inside jet"
LOCKTIME = "Locktime requirement not satisfied"
NONFINAL, NONFINAL_MEMPOOL = "bad-txns-nonfinal", "non-final"
SUPPLY = 2_000_000_000               # atoms of the token T in the sale
PRICE_NUM, PRICE_DEN = 3, 2          # 3 atoms of X for every 2 atoms of T
MIN_LOT = 10_000
FEE = 5000                           # atoms of Y, the fee asset
PROOF_T = "[(u256, bool); 16]"


def ceil_pay(amount):
    return -(-amount * PRICE_NUM // PRICE_DEN)


class Sale:
    """One instance: its parameters, the buyers, and per state its script and leaf."""

    def __init__(self, t, token, pay, treasury_spk, close, project_pk, buyers):
        self.t, self.token, self.pay = t, token, pay
        self.TOKEN_ID, self.PAY_ID = bytes.fromhex(token)[::-1], bytes.fromhex(pay)[::-1]
        self.TOKEN_OUT, self.PAY_OUT = t.asset_out(token), t.asset_out(pay)
        self.treasury_spk = treasury_spk
        self.close, self.project_pk = close, project_pk
        self.keys = [k for k, _ in buyers]           # x-only keys, list order
        self.caps = [c for _, c in buyers]
        self._cache = {}

    def params(self):
        return {"TOKEN": self.TOKEN_ID.hex(), "PAY_ASSET": self.PAY_ID.hex(),
                "PRICE_NUM": "%016x" % PRICE_NUM, "PRICE_DEN": "%016x" % PRICE_DEN,
                "TREASURY": sha256(self.treasury_spk).hex(), "MIN_LOT": "%016x" % MIN_LOT,
                "CLOSE": "%08x" % self.close, "PROJECT_KEY": self.project_pk.hex()}

    def entries(self, bought):
        return [(k, c, b) for k, c, b in zip(self.keys, self.caps, bought)]

    def root(self, bought):
        return self.t.sa.capped_sale_root(self.entries(bought))

    def at(self, bought):
        """(script_pubkey, leaf, derivation) of the sale whose buyers have `bought`."""
        bought = tuple(bought)
        if bought not in self._cache:
            t = self.t
            x = t.sa.derive(t.desc, self.params(), {"ALLOCATIONS": self.root(bought).hex()})
            info = t.node.getaddressinfo(x["address"]["elementsregtest"])
            assert info["scriptPubKey"] == x["script_pubkey"], info
            leaf = TreeLeaf(t.text, bytes.fromhex(t.body["cmr"]), bytes.fromhex(x["leaves"]["sale"]["control_block"]))
            self._cache[bought] = (bytes.fromhex(x["script_pubkey"]), leaf, x)
        return self._cache[bought]

    def spk(self, bought):
        return self.at(bought)[0]

    def reclaim_script(self, bought):
        return bytes.fromhex(self.at(bought)[2]["leaves"]["reclaim"]["script"])

    def reclaim_cb(self, bought):
        return bytes.fromhex(self.at(bought)[2]["leaves"]["reclaim"]["control_block"])


class C1(SimBase, BitcoinTestFramework):
    NAME = "c1"

    def set_test_params(self):
        self.chain_params()

    # -- witnesses and transactions -----------------------------------------
    def witness(self, sale, bought, who, amount, sig, key=None, cap=None, b=None, proof_of=None):
        """The purchase witness for buyer `who` (a list position) buying
        `amount` from the sale in state `bought`. `key`, `cap`, `b` and
        `proof_of` override what the buyer shows."""
        proof = self.sa.capped_sale_proof(sale.entries(bought), who if proof_of is None else proof_of)
        lit = "[" + ", ".join("(0x%s, %s)" % (s.hex(), "true" if left else "false") for s, left in proof) + "]"
        return {"TOKEN": v256(sale.TOKEN_ID), "PAY_ASSET": v256(sale.PAY_ID),
                "PRICE_NUM": vu(PRICE_NUM), "PRICE_DEN": vu(PRICE_DEN),
                "TREASURY": v256(sha256(sale.treasury_spk)), "MIN_LOT": vu(MIN_LOT),
                "ALLOCATIONS": v256(sale.root(bought)),
                "BUYER_KEY": vpub(sale.keys[who] if key is None else key),
                "CAP": vu(sale.caps[who] if cap is None else cap),
                "BOUGHT": vu(bought[who] if b is None else b), "AMOUNT": vu(amount),
                "PROOF": vraw(lit, PROOF_T), "BUYER_SIG": vsig(sig)}

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

    def purchase_tx(self, sale, coin, bought, who, amount, pay_coin, fee_coin, k=0, paid=None,
                    pay_out=None, treasury=None, rest=None, rest_spk=None, rest_asset=None,
                    next_bought=None, full=False, coin_asset=None):
        """The sale coin at input k (k = 0 or 1), the buyer's payment coin and
        a fee coin; the payment at 2k, the rest at 2k+1, the buyer's tokens,
        the payment change, the fee change and the fee."""
        paid = ceil_pay(amount) if paid is None else paid
        nb = list(bought)
        nb[who] += amount
        nb = tuple(nb) if next_bought is None else tuple(next_bought)
        left = coin.amount - amount if rest is None else rest
        pay_o = self.out(paid, sale.treasury_spk if treasury is None else treasury, pay_out or sale.PAY_OUT)
        mine = [self.out(coin.amount - left if not full else amount, self.buyer_spk, coin_asset or sale.TOKEN_OUT),
                self.out(pay_coin.amount - paid, self.change_spk, pay_out or sale.PAY_OUT)]
        fees = [self.out(fee_coin.amount - FEE, self.change_spk, self.Y_OUT), self.fee(FEE, self.Y_OUT)]
        if full:
            # No rest: output 2k+1 is the buyer's payment change, not the token.
            sale_o = [pay_o, mine[1]]
            mine = [mine[0]]
        else:
            sale_o = [pay_o, self.out(left, rest_spk or sale.spk(nb), rest_asset or coin_asset or sale.TOKEN_OUT)]
        if k == 0:
            ins = [(coin, 0xffffffff), (pay_coin, 0xffffffff), (fee_coin, 0xffffffff)]
            outs = sale_o + mine + fees
        else:
            ins = [(pay_coin, 0xffffffff), (coin, 0xffffffff), (fee_coin, 0xffffffff)]
            outs = mine + sale_o + fees
        tx = self.mktx(ins, outs)
        tx.next_bought, tx.k = nb, k
        return tx

    def signed(self, sale, tx, bought, who, amount, sk, **kw):
        """Satisfies and prunes the program against `tx`, the buyer's
        signature by `sk` over sig_all_hash; the wallet signs its coins."""
        leaf = sale.at(bought)[1]
        sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, tx.k))
        r = self.sim_satisfy(leaf, tx, tx.k, self.witness(sale, bought, who, amount, sig, **kw))
        tx.sig, tx.r, tx.leaf, tx.index = sig, r, leaf, tx.k
        return self.keep(tx)

    def keep(self, tx):
        saved = {k: getattr(tx, k) for k in ("sig", "r", "leaf", "index", "next_bought", "k") if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in saved.items():
            setattr(t2, k, v)
        return t2

    def reuse(self, control, tx, sk, swaps=(), leaf=None, sig=None):
        """`tx` with the control's pruned program and witness, the values in
        `swaps` [(old bytes, new bytes)] replaced in place, and the
        signature made again by `sk` for `tx` (or `sig` as given)."""
        idx = tx.k
        leaf = leaf or control.leaf
        w = bytes.fromhex(control.r["witness_hex"])
        for old, new in swaps:
            w = bit_replace(w, old, new)
        if sig is None:
            sig = sign_schnorr(sk, self.sim_sighash(leaf, tx, idx))
        w = bit_replace(w, control.sig, sig)
        self.set_sim_wit(tx, idx, leaf, bytes.fromhex(control.r["program_hex"]), w)
        tx.sig, tx.r, tx.leaf, tx.index = sig, control.r, leaf, idx
        return self.keep(tx)

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, tx.index, tx.r)
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def run_test(self):
        self.boot(issue=("X", "Y", "T"))
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.sa, self.desc, self.vectors, self.sources = load_template("capped_sale")
        self.text, self.body = self.sources["sale"]
        self.buyer_spk, self.change_spk = self.wallet_spk(), self.wallet_spk()
        treasury_spk = self.wallet_spk()
        sks = [generate_privkey() for _ in range(5)]
        pks = [compute_xonly_pubkey(s)[0] for s in sks]
        stranger_sk = generate_privkey()
        stranger_pk = compute_xonly_pubkey(stranger_sk)[0]
        project_sk = generate_privkey()
        project_pk = compute_xonly_pubkey(project_sk)[0]
        # Buyers 0..3, with buyer 4 (E) able to buy the whole sale.
        caps = [1_000_000_000, 400_000_000, 300_000_000, 77_777, SUPPLY]
        close = node.getblockcount() + 60
        S = Sale(self, self.T, self.X, treasury_spk, close, project_pk, list(zip(pks, caps)))
        B0 = (0, 0, 0, 0, 0)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": self.body["cmr"],
                              "max_cost_wu": self.body["max_cost_wu"], "params": S.params(),
                              "allocations": [{"key": k.hex(), "cap": c} for k, c in zip(pks, caps)],
                              "root": S.root(B0).hex(), "address": S.at(B0)[2]["address"]["elementsregtest"],
                              "script_pubkey": S.at(B0)[2]["script_pubkey"]})
        pay_coins = self.coins(30, self.X, 3_000_000_000)
        fee_coins = self.coins(40, self.Y, 100_000)
        P, F = pay_coins.pop, fee_coins.pop
        y_pay = self.coins(1, self.Y, 3_000_000_000)[0]

        c0 = self.fund(S.spk(B0), SUPPLY, self.T)
        # A stray coin of another asset at the sale's own address.
        stray = self.fund(S.spk(B0), SUPPLY, self.X)
        self.rec("funded", {"sale": "%s:%d" % (c0.txid, c0.vout), "stray_x": "%s:%d" % (stray.txid, stray.vout)})

        # ---- buyer 0's first purchase: 400,000,000 of a 1,000,000,000 cap --------
        a1 = 400_000_000
        pc, fc = P(), F()
        p1 = self.signed(S, self.purchase_tx(S, c0, B0, 0, a1, pc, fc), B0, 0, a1, sks[0])
        assert self.accept(p1)["allowed"]
        # A key not on the list, showing its own leaf at buyer 0's position.
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc), stranger_sk,
                               swaps=[(pks[0], stranger_pk)]),
                    "purchase/neg_key_not_on_the_list", J, control=p1)
        # A key not on the list signing for buyer 0's leaf.
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc), stranger_sk),
                    "purchase/neg_buyer_leaf_signed_by_a_stranger", SIG, control=p1)
        # Buyer 0's signature over another purchase (one atom less).
        other = self.purchase_tx(S, c0, B0, 0, a1 - 1, pc, fc)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc), None,
                               sig=sign_schnorr(sks[0], self.sim_sighash(p1.leaf, other, 0))),
                    "purchase/neg_signature_over_another_purchase", SIG, control=p1)
        # A buyer claiming a larger cap than the list gives.
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc), sks[0],
                               swaps=[(caps[0].to_bytes(8, "big"), (caps[0] + 1).to_bytes(8, "big"))]),
                    "purchase/neg_cap_claimed_larger", J, control=p1)
        # The payment: one atom short, in the wrong asset, to another script.
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, paid=ceil_pay(a1) - 1), sks[0]),
                    "purchase/neg_payment_one_atom_short", A, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, y_pay, fc, pay_out=self.Y_OUT), sks[0]),
                    "purchase/neg_payment_in_another_asset", J, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, treasury=self.wallet_spk()), sks[0]),
                    "purchase/neg_payment_to_another_script", J, control=p1)
        # The rest: one atom short, to another script, in a state that does not follow.
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, rest=SUPPLY - a1 - 1), sks[0]),
                    "purchase/neg_rest_one_atom_short", J, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, rest_spk=self.wallet_spk()), sks[0]),
                    "purchase/neg_rest_to_another_script", J, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, next_bought=B0), sks[0]),
                    "purchase/neg_state_counts_nothing_bought", J, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, next_bought=(0, a1, 0, 0, 0)), sks[0]),
                    "purchase/neg_state_charges_another_buyer", J, control=p1)
        self.reject(self.reuse(p1, self.purchase_tx(S, c0, B0, 0, a1, pc, fc, next_bought=(a1 - 1, 0, 0, 0, 0)), sks[0]),
                    "purchase/neg_state_counts_one_atom_less", J, control=p1)
        nonce = self.purchase_tx(S, c0, B0, 0, a1, pc, fc)
        nonce.vout[1].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        self.reject(self.reuse(p1, nonce, sks[0]), "purchase/neg_rest_carries_a_nonce", A, control=p1)
        # The input asset: the stray X coin at the sale's own address, against
        # the same purchase from the sale's token coin.
        self.reject(self.reuse(p1, self.purchase_tx(S, stray, B0, 0, a1, pc, fc, coin_asset=self.X_OUT), sks[0]),
                    "purchase/neg_coin_of_another_asset", J, control=p1, other_coin=True)
        # Below the minimum lot, and a rest below it.
        small = self.signed(S, self.purchase_tx(S, c0, B0, 3, MIN_LOT, pc, fc), B0, 3, MIN_LOT, sks[3])
        assert self.accept(small)["allowed"]
        self.rec("purchase/exactly_the_minimum_lot_accepted", {"testmempoolaccept": True, "amount": MIN_LOT})
        lot1 = self.signed(S, self.purchase_tx(S, c0, B0, 3, MIN_LOT + 1, pc, fc), B0, 3, MIN_LOT + 1, sks[3])
        self.reject(self._amount_swap(lot1, S, c0, B0, 3, MIN_LOT + 1, MIN_LOT - 1, pc, fc, sks[3]),
                    "purchase/neg_below_the_minimum_lot", J, control=lot1)
        big = SUPPLY - MIN_LOT
        most = self.signed(S, self.purchase_tx(S, c0, B0, 4, big, pc, fc), B0, 4, big, sks[4])
        assert self.accept(most)["allowed"]
        self.reject(self._amount_swap(most, S, c0, B0, 4, big, big + 1, pc, fc, sks[4]),
                    "purchase/neg_rest_one_atom_below_the_minimum_lot", J, control=most)
        txid1 = self.ok(p1, "purchase/first_of_buyer_0", extra={"amount": a1, "paid": ceil_pay(a1), "k": 0})
        B1 = p1.next_bought
        c1 = self.utxo_at(txid1, 1)
        assert c1.spk == S.spk(B1) and c1.amount == SUPPLY - a1

        # ---- buyer 0's second purchase: exactly what is left of the cap ----------
        a2 = caps[0] - a1
        pc, fc = P(), F()
        p2 = self.signed(S, self.purchase_tx(S, c1, B1, 0, a2, pc, fc), B1, 0, a2, sks[0])
        assert self.accept(p2)["allowed"]
        over = self.purchase_tx(S, c1, B1, 0, a2 + 1, pc, fc, next_bought=p2.next_bought)
        self.reject(self.reuse(p2, over, sks[0], swaps=[(a2.to_bytes(8, "big"), (a2 + 1).to_bytes(8, "big"))]),
                    "purchase/neg_second_purchase_one_atom_past_the_cap", J, control=p2)
        # The first state again: buyer 0 shows bought = 0 against the new root.
        self.reject(self.reuse(p2, self.purchase_tx(S, c1, B1, 0, a2, pc, fc, next_bought=(a2, 0, 0, 0, 0)), sks[0],
                               swaps=[(a1.to_bytes(8, "big"), bytes(8))]),
                    "purchase/neg_running_total_shown_as_zero", J, control=p2)
        txid2 = self.ok(p2, "purchase/buyer_0_reaches_the_cap_exactly",
                        extra={"amount": a2, "bought_before": a1, "cap": caps[0], "k": 0})
        B2 = p2.next_bought
        assert B2[0] == caps[0]
        c2 = self.utxo_at(txid2, 1)

        # ---- buyer 1 at input 1: the payment at output 2, the rest at output 3 --
        a3 = 150_000_000
        pc, fc = P(), F()
        p3 = self.signed(S, self.purchase_tx(S, c2, B2, 1, a3, pc, fc, k=1), B2, 1, a3, sks[1])
        assert self.accept(p3)["allowed"]
        # The same coin at input 1 with the payment and the rest at outputs 0 and 1.
        wrong = self.purchase_tx(S, c2, B2, 1, a3, pc, fc, k=1)
        n = len(wrong.vout)
        order = [n - 4, n - 3] + [i for i in range(n) if i not in (n - 4, n - 3)]
        wrong.vout = [wrong.vout[i] for i in order]
        self.pad(wrong)
        self.reject(self.reuse(p3, wrong, sks[1]), "purchase/neg_input_1_paying_at_outputs_0_and_1", J, control=p3)
        txid3 = self.ok(p3, "purchase/buyer_1_at_input_1", extra={"amount": a3, "k": 1})
        B3 = p3.next_bought
        c3 = self.utxo_at(txid3, 3)
        assert c3.spk == S.spk(B3)

        # ---- buyer 4 buys everything left: no rest, output 1 is not the token ---
        a4 = c3.amount
        pc, fc = P(), F()
        p4 = self.signed(S, self.purchase_tx(S, c3, B3, 4, a4, pc, fc, full=True), B3, 4, a4, sks[4])
        self.ok(p4, "purchase/buyer_4_buys_the_rest", extra={"amount": a4, "k": 0})

        # ---- the reclaim: the stray coin, by the project key, after the close ----
        def reclaim_tx(locktime, sk):
            fc = F()
            tx = self.mktx([(stray, 0xfffffffe), (fc, 0xffffffff)],
                           [self.out(stray.amount, self.wallet_spk(), self.X_OUT),
                            self.out(fc.amount - FEE, self.change_spk, self.Y_OUT), self.fee(FEE, self.Y_OUT)],
                           locktime=locktime)
            script = S.reclaim_script(B0)
            sig = self.sign(sk, tx, 0, script)
            self.setwit(tx, 0, [sig, script, S.reclaim_cb(B0)])
            return self.wallet_sign(tx)
        assert node.getblockcount() < close
        self.reject(reclaim_tx(node.getblockcount(), project_sk), "reclaim/neg_locktime_below_the_close", LOCKTIME)
        early = reclaim_tx(close, project_sk)
        self.reject(early, "reclaim/neg_before_the_close_is_mined", NONFINAL, mempool=NONFINAL_MEMPOOL)
        self.mine_to(close)
        self.reject(reclaim_tx(close, stranger_sk), "reclaim/neg_signed_by_another_key", "Invalid Schnorr signature")
        self.send(reclaim_tx(close, project_sk), "reclaim/the_stray_coin_after_the_close")

    def _amount_swap(self, control, sale, coin, bought, who, old, new, pc, fc, sk):
        """The control's purchase of `old` with AMOUNT replaced by `new`, its
        transaction built for `new`."""
        tx = self.purchase_tx(sale, coin, bought, who, new, pc, fc)
        return self.reuse(control, tx, sk, swaps=[(old.to_bytes(8, "big"), new.to_bytes(8, "big"))])


if __name__ == "__main__":
    C1().main()
