"""X4: the SeqDEX pool and the clearing round, on an anchored chain.

The template `seqdex_pool` is a maker's two coins, one of BASE and one of
QUOTE, at one address under one program with the pool's terms in a data leaf:

    P2TR(NUMS, TapBranch(TapLeaf_0xbe(pool), H_TapData(terms)))

Anyone fills it from either side at its quotes: the BASE coin at input j, the
QUOTE coin at j+1, the pool again at outputs 2j and 2j+1, never below its
reserve. Only MAKER_KEY withdraws.

The template `seqdex_round_order` is an order that fills only in a clearing
round its clearer signs: the round's last output publishes one price, N of
QUOTE per D of BASE, every order in the round reads it, each is credited
exactly ceil(fill x price) at 2k and never below its limit, and the clearer
signs SHA256(T || T || genesis || tx_hash). Its refund key takes it back after
EXPIRY.

The chain is anchored: node 0 stands in for Bitcoin, node 1 runs with
-con_bitcoin_anchor=1 -validateanchor=1, Simplicity active from genesis. A pool
is funded by its maker, filled from both sides (128-bit products well beyond
2^63) and withdrawn by its maker; four crossing round orders clear at one price
in one transaction, one of them in part; that round is reorged out with its
Bitcoin anchor and mined again. Every violation is refused by the mempool and
in a block forced with `generateblock`, each for its reason, beside a control
that differs from it only in the property it breaks and that the node accepts.
No spend of either program carries an annex: each path is refused with an
annex of 3 and of 1,000 bytes, any signature over it made over the annexed
transaction, so that the refusal is the annex rule's ("Assertion failed").
Every transaction pays its fee in an issued asset; none touches the policy
asset."""
import os
import sys
import time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
from test_framework.util import get_auth_cookie, get_datadir_path, p2p_port, rpc_port  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"
NONFINAL, NONFINAL_MEMPOOL = "bad-txns-nonfinal", "non-final"
FEE = 30_000                                   # atoms of Z, the fee asset
POOL_PATH_T = "Either<bool, Either<(), ()>>"
SELL, BUY, PAIR, WITHDRAW = "Left(true)", "Left(false)", "Right(Left(()))", "Right(Right(()))"
RO_PATH_T = "Either<(bool, (bool, (u64, u64))), ()>"
REFUND = "Right(())"
INT63 = 2 ** 63 - 1


def ceil_div(a, b):
    return -(-a // b)


def internal(display):
    return bytes.fromhex(display)[::-1]


def clearing_script(base, quote, n, d):
    """The clearing output's scriptPubKey: OP_RETURN OP_PUSHDATA1 80 base quote n d."""
    return b"\x6a\x4c\x50" + base + quote + n.to_bytes(8, "big") + d.to_bytes(8, "big")


def fill_path(partial, flip, n, d):
    return "Left((%s, (%s, (%d, %d))))" % ("true" if partial else "false", "true" if flip else "false", n, d)


def bits(b):
    return "".join("{:08b}".format(x) for x in b)


def pack(s):
    s += "0" * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def fill_witness(terms, partial, flip, n, d, sig):
    """A round order's fill witness: the terms, PATH and the clearer's signature,
    padded with zero bits to a whole byte."""
    return pack(bits(terms) + "0" + ("1" if partial else "0") + ("1" if flip else "0")
                + "{:064b}".format(n) + "{:064b}".format(d) + bits(sig))


class Pool:
    def __init__(self, t, name, base, quote, bid, ask, min_lot, reserve, maker_pk):
        self.t, self.name = t, name
        self.base, self.quote = base, quote
        self.B_OUT, self.Q_OUT = t.asset_out(base), t.asset_out(quote)
        (self.bid_num, self.bid_den), (self.ask_num, self.ask_den) = bid, ask
        self.min_lot, (self.reserve_base, self.reserve_quote) = min_lot, reserve
        self.maker_pk = maker_pk
        self.p = {"BASE": internal(base).hex(), "QUOTE": internal(quote).hex(),
                  "BID_NUM": "%016x" % self.bid_num, "BID_DEN": "%016x" % self.bid_den,
                  "ASK_NUM": "%016x" % self.ask_num, "ASK_DEN": "%016x" % self.ask_den,
                  "MIN_LOT": "%016x" % min_lot, "RESERVE_BASE": "%016x" % self.reserve_base,
                  "RESERVE_QUOTE": "%016x" % self.reserve_quote, "MAKER_KEY": maker_pk.hex()}
        x = t.pool_sa.derive(t.pool_desc, self.p, {})
        info = t.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        self.x, self.spk = x, bytes.fromhex(x["script_pubkey"])
        self.terms = bytes.fromhex(x["leaves"]["terms"]["data"])
        assert len(self.terms) == 152
        self.leaf = TreeLeaf(t.pool_text, bytes.fromhex(t.pool_body["cmr"]), bytes.fromhex(x["leaves"]["pool"]["control_block"]))

    def witness(self, path, sig=bytes(64)):
        w = {k: v256(bytes.fromhex(self.p[k])) for k in ("BASE", "QUOTE")}
        for k in ("BID_NUM", "BID_DEN", "ASK_NUM", "ASK_DEN", "MIN_LOT", "RESERVE_BASE", "RESERVE_QUOTE"):
            w[k] = vu(int(self.p[k], 16))
        w.update({"MAKER_KEY": vpub(self.maker_pk), "PATH": vraw(path, POOL_PATH_T), "MAKER_SIG": vsig(sig)})
        return w

    def ask_price(self, db):
        """The least QUOTE the pool takes in for db of BASE."""
        return ceil_div(db * self.ask_num, self.ask_den)

    def bid_price(self, db):
        """The most QUOTE the pool pays out for db of BASE."""
        return db * self.bid_num // self.bid_den


class RoundOrder:
    def __init__(self, t, name, asset_a, asset_b, limit, min_lot, maker_spk, expiry, refund_pk, clearer_pk):
        self.t, self.name = t, name
        self.asset_a, self.asset_b = asset_a, asset_b
        self.A_OUT, self.B_OUT = t.asset_out(asset_a), t.asset_out(asset_b)
        (self.limit_num, self.limit_den), self.min_lot = limit, min_lot
        self.maker_spk, self.expiry, self.refund_pk, self.clearer_pk = maker_spk, expiry, refund_pk, clearer_pk
        self.p = {"ASSET_A": internal(asset_a).hex(), "ASSET_B": internal(asset_b).hex(),
                  "LIMIT_NUM": "%016x" % self.limit_num, "LIMIT_DEN": "%016x" % self.limit_den,
                  "MIN_LOT": "%016x" % min_lot, "MAKER": sha256(maker_spk).hex(), "EXPIRY": "%08x" % expiry,
                  "REFUND_KEY": refund_pk.hex(), "CLEARER": clearer_pk.hex()}
        x = t.ro_sa.derive(t.ro_desc, self.p, {})
        info = t.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        self.x, self.spk = x, bytes.fromhex(x["script_pubkey"])
        self.terms = bytes.fromhex(x["leaves"]["terms"]["data"])
        assert len(self.terms) == 188
        self.leaf = TreeLeaf(t.ro_text, bytes.fromhex(t.ro_body["cmr"]), bytes.fromhex(x["leaves"]["order"]["control_block"]))

    def with_terms(self, **kw):
        a = dict(asset_a=self.asset_a, asset_b=self.asset_b, limit=(self.limit_num, self.limit_den),
                 min_lot=self.min_lot, maker_spk=self.maker_spk, expiry=self.expiry, refund_pk=self.refund_pk,
                 clearer_pk=self.clearer_pk)
        a.update(kw)
        return RoundOrder(self.t, self.name + "'", **a)

    def witness(self, path, clearer_sig=bytes(64), refund_sig=bytes(64)):
        w = {k: v256(bytes.fromhex(self.p[k])) for k in ("ASSET_A", "ASSET_B", "MAKER")}
        for k in ("LIMIT_NUM", "LIMIT_DEN", "MIN_LOT"):
            w[k] = vu(int(self.p[k], 16))
        w.update({"EXPIRY": vu(self.expiry, 32), "REFUND_KEY": vpub(self.refund_pk), "CLEARER": vpub(self.clearer_pk),
                  "PATH": vraw(path, RO_PATH_T), "CLEARER_SIG": vsig(clearer_sig), "REFUND_SIG": vsig(refund_sig)})
        return w

    def rate(self, base_display, n, d):
        """This order's rate (ASSET_B per ASSET_A) at the round price n/d of
        QUOTE per BASE, and whether it reads the clearing output flipped."""
        if self.asset_a == base_display:
            return (n, d), False
        assert self.asset_b == base_display
        return (d, n), True

    def accepts(self, rate):
        return rate[0] * self.limit_den >= self.limit_num * rate[1]


class X4(SimBase, BitcoinTestFramework):
    NAME = "x4"

    def set_test_params(self):
        self.chain_params()
        self.num_nodes = 2

    def setup_network(self, split=False):
        # node 0: the parent chain, standing in for Bitcoin.
        self.add_nodes(1, [["-port=%d" % p2p_port(0), "-rpcport=%d" % rpc_port(0), "-validatepegin=0",
                            "-initialfreecoins=0", "-con_blocksubsidy=5000000000", "-anyonecanspendaremine=1",
                            "-signblockscript=51"]], chain=["elementsregtest"])
        self.start_node(0)
        u, p = get_auth_cookie(get_datadir_path(self.options.tmpdir, 0), "elementsregtest")
        # node 1: the anchored chain, with the harness's own settings.
        args = list(self.extra_args[0]) + [
            "-port=%d" % p2p_port(1), "-rpcport=%d" % rpc_port(1),
            "-con_connect_genesis_outputs=1", "-con_bitcoin_anchor=1", "-validateanchor=1", "-anchorpollinterval=1",
            "-mainchainrpchost=127.0.0.1", "-mainchainrpcport=%d" % rpc_port(0),
            "-mainchainrpcuser=%s" % u, "-mainchainrpcpassword=%s" % p,
            "-parentgenesisblockhash=%s" % self.nodes[0].getblockhash(0)]
        self.add_nodes(1, [args], chain=["elementsregtest"])
        self.start_node(1)
        for n in self.nodes:
            n.createwallet(wallet_name=self.default_wallet_name)
        self.nodes[1].rescanblockchain()

    def generate(self, generator, *args, **kwargs):
        # The two nodes are two chains: nothing to sync.
        kwargs["sync_fun"] = self.no_op
        return BitcoinTestFramework.generate(self, generator, *args, **kwargs)

    def boot(self, issue=("X", "Y", "Z")):
        self.parent = self.nodes[0]
        self.parent_addr = self.parent.getnewaddress()
        self.generatetoaddress(self.parent, 5, self.parent_addr, sync_fun=self.no_op)
        time.sleep(2)
        node = self.nodes[1]
        self.node = node
        self.generate(node, 101)
        self.POL = node.dumpassetlabels()["bitcoin"]
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000, fee_asset_label=self.POL)
        self.generate(node, 1)
        self.genesis = uint256_from_str(bytes.fromhex(node.getblockhash(0))[::-1])
        self.POL_OUT = self.asset_out(self.POL)
        self.assets = {}
        for name in issue:
            a = node.issueasset(assetamount=10000000, tokenamount=0, blind=False, fee_asset=self.POL)["asset"]
            self.generate(node, 1)
            self.assets[name] = a
            setattr(self, name, a)
            setattr(self, name + "_OUT", self.asset_out(a))
        self.rates0 = node.getfeeexchangerates()
        st = node.getanchorstatus()
        self.rec("anchor", {k: st.get(k) for k in ("validateanchor", "anchorheight", "anchorstatus")})
        assert st["validateanchor"] and st["anchorstatus"] == "ok", st

    # -- coins ---------------------------------------------------------------
    def coins(self, n, asset, atoms):
        node = self.node
        addrs = [node.getnewaddress("", "bech32") for _ in range(n)]
        txid = node.sendmany(dummy="", amounts={a: Decimal(atoms) / COIN for a in addrs},
                             output_assets={a: asset for a in addrs}, fee_asset=self.POL)
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

    def fund(self, spk, atoms, asset, mine=True):
        spk = bytes(spk)
        addr = program_to_witness(1, spk[2:])
        txid = self.node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel=asset,
                                       fee_asset_label=self.POL)
        if mine:
            self.generate(self.node, 1)
        return self.utxo_of(txid, spk)

    def done(self, tx, keep=("r", "sig", "digest", "meta")):
        saved = {k: getattr(tx, k) for k in keep if hasattr(tx, k)}
        t2 = self.wallet_sign(tx)
        for k, v in saved.items():
            setattr(t2, k, v)
        return t2

    def ok(self, tx, label, extra=None):
        m = {}
        for i, r in tx.r.items():
            mi = self.sim_measure(tx, i, r)
            m["input_%d" % i] = {k: v for k, v in mi.items() if k not in ("program_hex", "witness_hex")}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    def stack(self, tx, i):
        return [bytes(x) for x in tx.wit.vtxinwit[i].scriptWitness.stack]

    # -- the pool --------------------------------------------------------------
    def pool_tx(self, P, xc, yc, x1, y1, ins, outs):
        """A fill of pool P: its BASE coin xc at input 0, its QUOTE coin yc at
        input 1, the pool again at outputs 0 and 1, then `ins` and `outs`."""
        tx = self.mktx([(xc, 0xffffffff), (yc, 0xffffffff)] + [(u, 0xffffffff) for u in ins],
                       [self.out(x1, P.spk, P.B_OUT), self.out(y1, P.spk, P.Q_OUT)] + outs)
        return tx

    def sell_tx(self, P, xc, yc, db, dq, pay, fc):
        """The pool sells db of BASE for dq of QUOTE from a taker's coin `pay`."""
        return self.pool_tx(P, xc, yc, xc.amount - db, yc.amount + dq, [pay, fc],
                            [self.out(db, self.taker_spk, P.B_OUT),
                             self.out(pay.amount - dq, self.change_spk, P.Q_OUT),
                             self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])

    def buy_tx(self, P, xc, yc, db, dq, pay, fc):
        """The pool buys db of BASE from a taker's coin `pay`, paying dq of QUOTE."""
        return self.pool_tx(P, xc, yc, xc.amount + db, yc.amount - dq, [pay, fc],
                            [self.out(dq, self.taker_spk, P.Q_OUT),
                             self.out(pay.amount - db, self.change_spk, P.B_OUT),
                             self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])

    def pool_satisfy(self, P, tx, path, j=0):
        tx.r = {j: self.sim_satisfy(P.leaf, tx, j, P.witness(path)),
                j + 1: self.sim_satisfy(P.leaf, tx, j + 1, P.witness(PAIR))}
        for i, pth in ((j, path), (j + 1, PAIR)):
            prog = bytes.fromhex(tx.r[i]["program_hex"])
            want = self.pool_program.setdefault(pth, prog)
            assert prog == want, "the pruned %s program differs" % pth
            assert bytes.fromhex(tx.r[i]["witness_hex"]) == P.terms + {SELL: b"\x40", BUY: b"\x00", PAIR: b"\x80"}[pth], \
                (pth, tx.r[i]["witness_hex"][-8:])
        return self.done(tx)

    def reuse(self, control, tx, at=None):
        """`tx` with the control's stacks for its covenant inputs (input i of
        the control at input at[i] of `tx`), then signed by the wallet."""
        at = at or {i: i for i in control.r}
        for i, j in at.items():
            self.setwit(tx, j, self.stack(control, i))
        tx.r = {at[i]: r for i, r in control.r.items()}
        return self.done(tx)

    def withdraw_tx(self, P, coins, sk, sig_tx=None, control=None, annex=None):
        """The maker withdraws `coins` of pool P to the wallet, each signed by sk
        over its own sig_all_hash (over `sig_tx`'s, when given). With `annex`,
        input 0 carries it and its signature covers it."""
        fc = self.F()
        outs = [self.out(c.amount, self.wallet_spk(), P.B_OUT if c.txout.nAsset.vchCommitment[1:] == P.B_OUT[1:]
                         else P.Q_OUT) for c in coins]
        tx = self.mktx([(c, 0xffffffff) for c in coins] + [(fc, 0xffffffff)],
                       outs + [self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        st = sig_tx or tx
        tx.r, tx.sig = {}, {}
        for i in range(len(coins)):
            a = annex if i == 0 else None
            sig = sign_schnorr(sk, self.sim_sighash(P.leaf, st, i, annex=a))
            tx.sig[i] = sig
            if control is None:
                tx.r[i] = self.sim_satisfy(P.leaf, tx, i, P.witness(WITHDRAW, sig))
            else:
                old = self.stack(control, i)
                self.set_sim_wit(tx, i, P.leaf, old[1], bit_replace(old[0], control.sig[i], sig), annex=a)
                tx.r[i] = control.r[i]
        return self.done(tx)

    # -- rounds ------------------------------------------------------------------
    def round_tx(self, fills, price, gap, fc, last=None, rest_spk=None, credit=None):
        """A clearing round. `fills` is a list of (order, coin, filled, partial),
        the k-th at input k; `price` is (base display hex, quote display hex, N, D).
        Output 2k credits order k exactly ceil(filled x rate); a partial fill's
        remainder is at 2k+1. The clearer's gap coins `gap` and fee coin come
        after the orders; its change fills the free slots, then the fee, then the
        clearing output last (or `last` in its place). `credit` overrides a
        credit {k: atoms}; `rest_spk` a remainder's script {k: spk}."""
        base, quote, n, d = price
        ins = [(c, 0xffffffff) for _, c, _, _ in fills] + [(u, 0xffffffff) for u in gap] + [(fc, 0xffffffff)]
        slots, flows, meta = {}, {}, []
        for k, (o, c, f, partial) in enumerate(fills):
            rate, flip = o.rate(base, n, d)
            paid = (credit or {}).get(k, ceil_div(f * rate[0], rate[1]))
            slots[2 * k] = self.out(paid, o.maker_spk, o.B_OUT)
            flows[o.asset_a] = flows.get(o.asset_a, 0) + c.amount
            flows[o.asset_b] = flows.get(o.asset_b, 0) - paid
            if partial:
                slots[2 * k + 1] = self.out(c.amount - f, (rest_spk or {}).get(k, o.spk), o.A_OUT)
                flows[o.asset_a] -= c.amount - f
            meta.append({"order": o.name, "k": k, "filled": f, "credited": paid, "partial": partial, "flip": flip,
                         "rate": rate})
        for u in gap:
            a = [x for x, v in self.assets.items() if self.asset_out(v) == bytes(u.txout.nAsset.vchCommitment)][0]
            flows[self.assets[a]] = flows.get(self.assets[a], 0) + u.amount
        change = [self.out(v, self.change_spk, self.asset_out(a)) for a, v in sorted(flows.items()) if v != 0]
        assert all(v >= 0 for v in flows.values()), ("the clearer's gap does not cover the round", flows)
        change.append(self.out(fc.amount - FEE, self.change_spk, self.Z_OUT))
        n_slots = 2 * len(fills)
        outs = []
        for i in range(n_slots):
            if i in slots:
                outs.append(slots[i])
            elif i < max(slots) and change:
                outs.append(change.pop(0))
            elif i < max(slots):
                raise AssertionError("no output for the free slot %d" % i)
        outs += change
        outs.append(self.fee(FEE, self.Z_OUT))
        outs.append(CTxOut(nValue=CTxOutValue(0), scriptPubKey=CScript(
            last if last is not None else clearing_script(internal(base), internal(quote), n, d)),
            nAsset=CTxOutAsset(self.Z_OUT), nNonce=CTxOutNonce()))
        tx = self.mktx(ins, outs)
        tx.meta = {"fills": meta, "price": [n, d]}
        tx.fills, tx.price = fills, price
        return tx

    def clearing_digest(self, tx, leaf, annex=None):
        """What the clearer signs for `tx`, as seqc computes it; with `annex`,
        input 0 carries it."""
        req = self.req(leaf, tx, 0)
        if annex is not None:
            req["annex"] = annex.hex()
        r = seqc(req)
        return bytes.fromhex(r["clearing_digest"]), r["tx_hash"]

    def round_satisfy(self, tx, sk):
        """The clearer signs the round and every order input gets its witness;
        each order's pruned program is asserted against the template's constant
        for its path, and its witness against the layout callers build."""
        digest, th = self.clearing_digest(tx, tx.fills[0][0].leaf)
        sig = sign_schnorr(sk, digest)
        base, quote, n, d = tx.price
        tx.r, tx.sig, tx.digest = {}, sig, digest
        for k, (o, c, f, partial) in enumerate(tx.fills):
            _, flip = o.rate(base, n, d)
            r = self.sim_satisfy(o.leaf, tx, k, o.witness(fill_path(partial, flip, n, d), clearer_sig=sig))
            key = "fill" if partial else "fill_whole"
            key += "_flip" if flip else ""
            prog = bytes.fromhex(r["program_hex"])
            want = self.ro_program.setdefault(key, prog)
            assert prog == want, "the pruned %s program differs for %s at k=%d" % (key, o.name, k)
            assert bytes.fromhex(r["witness_hex"]) == fill_witness(o.terms, partial, flip, n, d, sig), \
                "the witness is not the terms, PATH and the signature"
            tx.r[k] = r
        tx.meta["tx_hash"] = th
        return self.done(tx)

    def resign(self, control, tx, sk, sig_tx=None, annex=None):
        """`tx` with the control's programs, its witnesses carrying the clearer's
        signature by `sk` over `tx` (or over `sig_tx`), then signed by the wallet.
        With `annex`, input 0 carries it and the signature covers it."""
        digest, _ = self.clearing_digest(sig_tx or tx, tx.fills[0][0].leaf, annex)
        sig = sign_schnorr(sk, digest)
        for k in control.r:
            st = self.stack(control, k)
            self.set_sim_wit(tx, k, tx.fills[k][0].leaf, st[1], bit_replace(st[0], control.sig, sig),
                             annex=annex if k == 0 else None)
        tx.r, tx.sig = dict(control.r), sig
        return self.done(tx)

    def orphan_anchor_of(self, txid):
        """Invalidate, on the parent chain, the parent block the block holding
        `txid` anchors to, and mine a longer parent branch; wait until the
        anchored node has dropped every block anchored to it."""
        node, parent = self.node, self.parent
        blk = node.getrawtransaction(txid, True)["blockhash"]
        hdr = node.getblockheader(blk)
        anchor_h, anchor = hdr["anchorheight"], hdr["anchorhash"]
        tip = parent.getblockcount()
        parent.invalidateblock(anchor)
        self.generatetoaddress(parent, tip - anchor_h + 2, parent.getnewaddress(), sync_fun=self.no_op)
        t0 = time.time()
        while time.time() - t0 < 90:
            if node.getrawtransaction(txid, True).get("confirmations", 0) == 0:
                return {"orphaned_parent_block": anchor, "anchor_height": anchor_h, "dropped_block": blk,
                        "in_mempool": txid in node.getrawmempool(), "seconds": round(time.time() - t0, 1)}
            time.sleep(0.5)
        raise AssertionError("the round's block was not dropped with its anchor")

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y, self.Z))
        self.pool_sa, self.pool_desc, _, src = load_template("seqdex_pool")
        self.pool_text, self.pool_body = src["pool"]
        self.ro_sa, self.ro_desc, _, src = load_template("seqdex_round_order")
        self.ro_text, self.ro_body = src["order"]
        self.pool_program, self.ro_program = {}, {}
        self.taker_spk, self.change_spk = self.wallet_spk(), self.wallet_spk()
        maker_sk, other_sk, clearer_sk, refund_sk = (generate_privkey() for _ in range(4))
        maker_pk, other_pk, clearer_pk, refund_pk = (compute_xonly_pubkey(k)[0] for k in
                                                     (maker_sk, other_sk, clearer_sk, refund_sk))
        fees = self.coins(40, self.Z, 200_000)
        self.F = fees.pop

        # ======== the pool ========================================================
        # Bid 0.9 Y, ask 1.1 Y per X, both as ratios of two numbers near 10^13, so
        # every fill's products are near 10^26, far beyond 2^63.
        P = Pool(self, "P", self.X, self.Y, (9_000_000_000_007, 10_000_000_000_003),
                 (11_000_000_000_017, 10_000_000_000_003), 1_000_000, (5_000_000_000, 5_000_000_000), maker_pk)
        self.rec("pool", {"template_hash": self.pool_desc["template_hash"], "cmr": self.pool_body["cmr"],
                          "max_cost_wu": self.pool_body["max_cost_wu"], "params": P.p,
                          "address": P.x["address"]["elementsregtest"]})
        X0, Y0 = 20_000_000_000_000, 20_000_000_000_000
        xc = self.fund(P.spk, X0, self.X)
        yc = self.fund(P.spk, Y0, self.Y)
        self.rec("pool/funded_by_its_maker", {"base_coin": str(xc), "quote_coin": str(yc), "base": X0, "quote": Y0})
        pay_y = self.coins(3, self.Y, 50_000_000_000_000)
        pay_x = self.coins(3, self.X, 50_000_000_000_000)

        # ---- sell: a taker buys X from the pool at its ask --------------------
        DB = 7_000_000_000_001
        sell = self.pool_satisfy(P, self.sell_tx(P, xc, yc, DB, P.ask_price(DB), pay_y[0], self.F()), SELL)
        assert DB * P.ask_num > INT63
        assert self.accept(sell)["allowed"], self.accept(sell)
        fc = sell.prev[3]

        def neg(label, tx, expect=J, control=None, **kw):
            c = control or sell
            self.reject(self.reuse(c, tx), label, expect, control=c, **kw)

        t = self.sell_tx(P, xc, yc, DB, P.ask_price(DB) - 1, pay_y[0], fc)
        neg("pool/neg_sell_one_atom_under_the_ask", t)
        t = self.sell_tx(P, xc, yc, DB, P.ask_price(DB), pay_y[0], fc)
        t.vout[1].scriptPubKey = CScript(self.wallet_spk())
        neg("pool/neg_quote_coin_not_the_pool_again", t)
        t = self.sell_tx(P, xc, yc, DB, P.ask_price(DB), pay_y[0], fc)
        t.vout[0].nNonce = CTxOutNonce(b"\x02" + compute_xonly_pubkey(generate_privkey())[0])
        neg("pool/neg_base_coin_again_with_a_nonce", t, A)
        # The pool's QUOTE coin replaced at input 1 by a taker's coin of Y.
        t = self.mktx([(xc, 0xffffffff), (pay_y[1], 0xffffffff), (pay_y[0], 0xffffffff), (fc, 0xffffffff)],
                      [self.out(X0 - DB, P.spk, P.B_OUT), self.out(Y0 + P.ask_price(DB), P.spk, P.Q_OUT),
                       self.out(DB, self.taker_spk, P.B_OUT),
                       self.out(pay_y[1].amount + pay_y[0].amount - Y0 - P.ask_price(DB), self.change_spk, P.Q_OUT),
                       self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        self.setwit(t, 0, self.stack(sell, 0))
        t.r = {0: sell.r[0]}
        self.reject(self.done(t), "pool/neg_partner_at_input_1_not_the_pools", J, control=sell)
        # The reserve: a sell to exactly RESERVE_BASE is accepted, one atom more refused.
        big = X0 - P.reserve_base
        to_reserve = self.pool_satisfy(P, self.sell_tx(P, xc, yc, big, P.ask_price(big), pay_y[1], fc), SELL)
        assert self.accept(to_reserve)["allowed"], self.accept(to_reserve)
        self.reject(self.reuse(to_reserve, self.sell_tx(P, xc, yc, big + 1, P.ask_price(big + 1), pay_y[1], fc)),
                    "pool/neg_sell_leaves_base_below_its_reserve", J, control=to_reserve)
        lot = self.pool_satisfy(P, self.sell_tx(P, xc, yc, P.min_lot, P.ask_price(P.min_lot), pay_y[1], fc), SELL)
        self.reject(self.reuse(lot, self.sell_tx(P, xc, yc, P.min_lot - 1, P.ask_price(P.min_lot - 1), pay_y[1], fc)),
                    "pool/neg_sell_moves_one_atom_under_the_min_lot", J, control=lot)
        # An annex on either coin: a fill signs nothing, so anyone relaying it
        # could add one.
        for n in (3, 1000):
            for i, what in ((0, "base_coin"), (1, "quote_coin")):
                t = self.reuse(sell, self.sell_tx(P, xc, yc, DB, P.ask_price(DB), pay_y[0], fc))
                t.wit.vtxinwit[i].scriptWitness.stack.append(b"\x50" + bytes([0xab]) * (n - 1))
                self.reject(t, "pool/neg_%s_with_an_annex_of_%d_bytes" % (what, n), A, control=sell, index=i)
        txid = self.ok(sell, "pool/sell_at_the_ask", extra={"base_out": DB, "quote_in": P.ask_price(DB),
                                                             "base_times_ask_num": DB * P.ask_num})
        xc, yc = self.utxo_at(txid, 0), self.utxo_at(txid, 1)
        assert (xc.amount, yc.amount) == (X0 - DB, Y0 + P.ask_price(DB))

        # ---- buy: a taker sells X to the pool at its bid ----------------------
        DB2 = 3_000_000_000_007
        fc = self.F()
        buy = self.pool_satisfy(P, self.buy_tx(P, xc, yc, DB2, P.bid_price(DB2), pay_x[0], fc), BUY)
        assert self.accept(buy)["allowed"], self.accept(buy)
        neg("pool/neg_buy_pays_one_atom_over_the_bid", self.buy_tx(P, xc, yc, DB2, P.bid_price(DB2) + 1, pay_x[0], fc),
            control=buy)
        # The reserve: a buy that pays QUOTE out down to exactly RESERVE_QUOTE.
        dq = yc.amount - P.reserve_quote
        db = ceil_div(dq * P.bid_den, P.bid_num)
        assert P.bid_price(db) >= dq
        to_rq = self.pool_satisfy(P, self.buy_tx(P, xc, yc, db, dq, pay_x[1], fc), BUY)
        assert self.accept(to_rq)["allowed"], self.accept(to_rq)
        db1 = ceil_div((dq + 1) * P.bid_den, P.bid_num)
        assert P.bid_price(db1) >= dq + 1
        self.reject(self.reuse(to_rq, self.buy_tx(P, xc, yc, db1, dq + 1, pay_x[1], fc)),
                    "pool/neg_buy_leaves_quote_below_its_reserve", J, control=to_rq)
        # The QUOTE coin taken beside a BASE coin that is not the pool's.
        t = self.mktx([(pay_x[2], 0xffffffff), (yc, 0xffffffff), (fc, 0xffffffff)],
                      [self.out(yc.amount, self.taker_spk, P.Q_OUT), self.out(pay_x[2].amount, self.change_spk, P.B_OUT),
                       self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        self.setwit(t, 1, self.stack(buy, 1))
        t.r = {1: buy.r[1]}
        self.reject(self.done(t), "pool/neg_quote_coin_beside_a_base_coin_not_the_pools", J, control=buy, index=1)
        txid = self.ok(buy, "pool/buy_at_the_bid", extra={"base_in": DB2, "quote_out": P.bid_price(DB2)})
        xc, yc = self.utxo_at(txid, 0), self.utxo_at(txid, 1)
        assert (xc.amount, yc.amount) == (X0 - DB + DB2, Y0 + P.ask_price(DB) - P.bid_price(DB2))

        # ---- withdraw: the maker only ----------------------------------------
        w = self.withdraw_tx(P, [xc, yc], maker_sk)
        assert self.accept(w)["allowed"], self.accept(w)
        self.reject(self.withdraw_tx(P, [xc, yc], other_sk, control=w), "pool/neg_withdraw_signed_by_another_key", J,
                    control=w)
        other = self.withdraw_tx(P, [xc, yc], maker_sk)
        self.reject(self.withdraw_tx(P, [xc, yc], maker_sk, sig_tx=other, control=w),
                    "pool/neg_withdraw_signature_over_another_transaction", J, control=w)
        for n in (3, 1000):
            self.reject(self.withdraw_tx(P, [xc, yc], maker_sk, control=w, annex=bytes([0xab]) * (n - 1)),
                        "pool/neg_withdraw_with_an_annex_of_%d_bytes_the_maker_signed" % n, A, control=w)
        # Taking both coins through the fill path, paying nothing.
        t = self.pool_tx(P, xc, yc, P.reserve_base, yc.amount, [w.prev[2]],
                         [self.out(xc.amount - P.reserve_base, self.taker_spk, P.B_OUT),
                          self.out(w.prev[2].amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)])
        self.setwit(t, 0, self.stack(sell, 0))
        self.setwit(t, 1, self.stack(sell, 1))
        t.r = dict(sell.r)
        self.reject(self.done(t), "pool/neg_taken_through_the_fill_path_for_nothing", J, control=w)
        for i in w.r:
            self.pool_program.setdefault(WITHDRAW, bytes.fromhex(w.r[i]["program_hex"]))
            assert bytes.fromhex(w.r[i]["program_hex"]) == self.pool_program[WITHDRAW]
        self.ok(w, "pool/withdrawn_by_its_maker", extra={"base": xc.amount, "quote": yc.amount})
        self.rec("pool_program", {k: {"bytes": len(v), "hex": v.hex()} for k, v in self.pool_program.items()})

        # ======== the round =========================================================
        # Two asks of X for Y and two bids (orders selling Y for X), one clearer.
        maker_spk = self.wallet_spk()
        h0 = node.getblockcount()
        A1 = RoundOrder(self, "A1", self.X, self.Y, (1, 1), 1000, maker_spk, h0 + 60, refund_pk, clearer_pk)
        A2 = RoundOrder(self, "A2", self.X, self.Y, (105, 100), 1000, maker_spk, h0 + 400, refund_pk, clearer_pk)
        # A bid's limit is X per Y: at most 1.25 and 1.15 Y per X.
        B1 = RoundOrder(self, "B1", self.Y, self.X, (100, 125), 1000, maker_spk, h0 + 400, refund_pk, clearer_pk)
        B2 = RoundOrder(self, "B2", self.Y, self.X, (100, 115), 1000, maker_spk, h0 + 60, refund_pk, clearer_pk)
        self.rec("round_order", {"template_hash": self.ro_desc["template_hash"], "cmr": self.ro_body["cmr"],
                                 "max_cost_wu": self.ro_body["max_cost_wu"],
                                 "orders": {o.name: {"params": o.p, "address": o.x["address"]["elementsregtest"]}
                                            for o in (A1, A2, B1, B2)}})
        a1, a2 = self.fund(A1.spk, 4_000_000, self.X), self.fund(A2.spk, 3_000_000, self.X)
        b1, b2 = self.fund(B1.spk, 5_000_000, self.Y), self.fund(B2.spk, 4_000_000, self.Y)
        a2b, b1b = self.fund(A2.spk, 3_000_000, self.X), self.fund(B1.spk, 5_000_000, self.Y)
        gap = [self.coins(1, self.X, 1_000)[0], self.coins(1, self.Y, 1_000)[0]]
        # The clearing price: asks hold 7,000,000 X at limits 1.00 and 1.05; bids
        # 9,000,000 Y up to 1.25 and 1.15. Every price up to 1.15 clears all 7e6 X,
        # and 1.15 leaves the least unmatched, so the price is 23 Y per 20 X. The
        # asks fill whole; B1 (the better bid) whole; B2 takes the rest of the X.
        N, D = 23, 20
        x_b1 = ceil_div(5_000_000 * D, N)
        g2 = (7_000_000 - x_b1) * N // D
        fills = [(A1, a1, 4_000_000, False), (A2, a2, 3_000_000, False), (B1, b1, 5_000_000, False),
                 (B2, b2, g2, True)]
        price = (self.X, self.Y, N, D)
        for o, c, f, _ in fills:
            assert o.accepts(o.rate(self.X, N, D)[0]), o.name
        fc = self.F()
        rnd = self.round_satisfy(self.round_tx(fills, price, gap, fc), clearer_sk)
        assert self.accept(rnd)["allowed"], self.accept(rnd)
        self.rec("round/clearing", {"price": "%d/%d" % (N, D), "fills": rnd.meta["fills"],
                                    "tx_hash": rnd.meta["tx_hash"], "clearer_digest": rnd.digest.hex()})

        def rneg(label, tx, expect=J, index=0, sk=clearer_sk, sig_tx=None, control=None, annex=None):
            c = control or rnd
            self.reject(self.resign(c, tx, sk, sig_tx, annex), label, expect, control=c, index=index)

        # A fill at another price than the published one: A1 credited at its own
        # limit (1.00), the clearer keeping the difference; and A1 credited one
        # atom above the exact price.
        rneg("round/neg_credit_at_the_orders_own_limit_not_the_published_price",
             self.round_tx(fills, price, gap, fc, credit={0: 4_000_000}))
        rneg("round/neg_credit_one_atom_over_the_published_price",
             self.round_tx(fills, price, gap + [self.coins(1, self.Y, 1_000)[0]], fc,
                           credit={0: ceil_div(4_000_000 * N, D) + 1}))
        # The price is read from the last output and only there.
        t = self.round_tx(fills, price, gap, fc)
        t.vout[-1], t.vout[-2] = t.vout[-2], t.vout[-1]
        rneg("round/neg_clearing_output_not_the_last", t)
        rneg("round/neg_clearing_output_names_another_asset",
             self.round_tx(fills, price, gap, fc, last=clearing_script(internal(self.X), internal(self.Z), N, D)))
        rneg("round/neg_clearing_output_another_price_than_the_credits",
             self.round_tx(fills, price, gap, fc, last=clearing_script(internal(self.X), internal(self.Y), N + 1, D)))
        # The clearer's signature.
        rneg("round/neg_signed_by_another_key", self.round_tx(fills, price, gap, fc), sk=other_sk)
        other_round = self.round_tx(fills, price, gap, fc)
        other_round.vout[1].scriptPubKey = CScript(self.wallet_spk())
        rneg("round/neg_signature_over_another_round", self.round_tx(fills, price, gap, fc), sig_tx=other_round)
        # B2's remainder under other terms: another clearer.
        rneg("round/neg_remainder_under_another_clearer",
             self.round_tx(fills, price, gap, fc, rest_spk={3: B2.with_terms(clearer_pk=other_pk).spk}), index=3)
        # A bid reading the clearing output the other way round: B1 (input 2)
        # with the program and witness of an unflipped whole fill.
        t = self.round_tx(fills, price, gap, fc)
        dg, _ = self.clearing_digest(t, A1.leaf)
        sig = sign_schnorr(clearer_sk, dg)
        for k in rnd.r:
            st = self.stack(rnd, k)
            self.set_sim_wit(t, k, fills[k][0].leaf, st[1], bit_replace(st[0], rnd.sig, sig))
        self.set_sim_wit(t, 2, B1.leaf, self.ro_program["fill_whole"], fill_witness(B1.terms, False, False, N, D, sig))
        t.r = dict(rnd.r)
        self.reject(self.done(t), "round/neg_bid_reads_the_price_unflipped", J, control=rnd, index=2)

        # An annex on A1's input, the clearer signing the annexed round.
        for n in (3, 1000):
            rneg("round/neg_order_with_an_annex_of_%d_bytes_the_clearer_signed" % n,
                 self.round_tx(fills, price, gap, fc), A, annex=bytes([0xab]) * (n - 1))
        # A price below a limit: A2 and B1 alone at A2's limit, 105/100, accepted;
        # at 104,999/100,000, A2 refuses.
        def two(n, d):
            x = ceil_div(3_000_000 * n, d)       # B1 pays what A2 is credited
            return self.round_tx([(A2, a2b, 3_000_000, False), (B1, b1b, x, True)], (self.X, self.Y, n, d),
                                 gap, fc)
        at_limit = self.round_satisfy(two(105, 100), clearer_sk)
        assert self.accept(at_limit)["allowed"], self.accept(at_limit)
        rneg("round/neg_price_one_step_below_a_limit", two(104_999, 100_000), control=at_limit)

        # A parent block of its own under the round's block, so that orphaning
        # it takes the round's block and none before.
        self.generatetoaddress(self.parent, 1, self.parent_addr, sync_fun=self.no_op)
        time.sleep(2)
        txid = self.ok(rnd, "round/four_orders_at_one_price", extra={"price": [N, D], "fills": rnd.meta["fills"]})
        rest = self.utxo_at(txid, 7)
        assert rest.spk == B2.spk and rest.amount == 4_000_000 - g2
        dec = node.decoderawtransaction(rnd.serialize().hex())
        last = dec["vout"][-1]["scriptPubKey"]
        self.rec("round/published", {"last_output": last.get("asm"), "hex": last["hex"], "type": last.get("type")})

        # ---- the round reorged out with its Bitcoin anchor, and mined again ------
        o = self.orphan_anchor_of(txid)
        assert o["in_mempool"], o
        time.sleep(2)
        self.generate(node, 1)
        again = node.getrawtransaction(txid, True)
        assert again.get("confirmations", 0) >= 1
        o["mined_again_in"] = again["blockhash"]
        o["new_anchor"] = node.getblockheader(again["blockhash"])["anchorhash"]
        self.rec("round/reorged_out_with_its_anchor_and_mined_again", o)
        self.log.info("REORG round %s dropped with parent block %s, mined again in %s", txid[:16],
                      o["orphaned_parent_block"][:16], again["blockhash"][:16])

        # ---- the refund of B2's remainder, by height ------------------------------
        self.mine_to(B2.expiry)
        fc = self.F()

        def refund(coin, sk, sig_tx=None, control=None, annex=None):
            tx = self.mktx([(coin, 0xfffffffe), (fc, 0xfffffffe)],
                           [self.out(coin.amount, self.wallet_spk(), B2.A_OUT),
                            self.out(fc.amount - FEE, self.change_spk, self.Z_OUT), self.fee(FEE, self.Z_OUT)],
                           locktime=B2.expiry)
            sig = sign_schnorr(sk, self.sim_sighash(B2.leaf, sig_tx or tx, 0, annex=annex))
            if control is None:
                tx.r = {0: self.sim_satisfy(B2.leaf, tx, 0, B2.witness(REFUND, refund_sig=sig))}
            else:
                st = self.stack(control, 0)
                self.set_sim_wit(tx, 0, B2.leaf, st[1], bit_replace(st[0], control.sig, sig), annex=annex)
                tx.r = control.r
            tx.sig = sig
            return self.done(tx)
        rf = refund(rest, refund_sk)
        assert self.accept(rf)["allowed"], self.accept(rf)
        self.reject(refund(rest, other_sk, control=rf), "refund/neg_signed_by_another_key", J, control=rf)
        for n in (3, 1000):
            self.reject(refund(rest, refund_sk, control=rf, annex=bytes([0xab]) * (n - 1)),
                        "refund/neg_with_an_annex_of_%d_bytes_the_refund_key_signed" % n, A, control=rf)
        self.ok(rf, "refund/by_height_at_expiry", extra={"expiry": B2.expiry})
        self.ro_program["refund_height"] = self.stack(rf, 0)[1]
        self.rec("round_order_program", {k: {"bytes": len(v), "hex": v.hex()} for k, v in self.ro_program.items()})


if __name__ == "__main__":
    X4().main()
