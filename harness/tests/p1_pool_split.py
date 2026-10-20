"""P1: the pool split covenant, in Simplicity and in tapscript, claimed by the
claim tool and every violation refused in a block.

The templates `pool_split` (Simplicity, a table of up to 63 rows) and
`pool_split_tap3` (tapscript, three rows) hold a staking pool's payouts:

    P2TR(NUMS, {claim, [params,] follow})

A claim spends coins of the pool's script in one asset: input 0 by the claim
leaf, any others by the follow leaf. It may withhold at most the cap for its fee
and its claimer; of the rest each row from 1 gets exactly
floor(net * numerator / DENOM) at its output, and row 0, the pool, what
remains. Anyone can claim; nobody signs.

Here the coins are paid in by the wallet, on the harness's chain, where
`generateblock` forces a transaction into a block. Test p2 runs the same
covenant as a pool's payout script on a proof-of-stake chain, with coinbase
rewards and their maturity. Each claim is built by tools/pool-claim; each
negative is a claim the tool built, changed in one property, refused by the
mempool and in a block, against the claim it was made from as the control. The
tool itself refuses each before the chain does.
"""
import copy
import os
import subprocess
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from poolsplit import *  # noqa: E402,F401,F403

EQV = "Script failed an OP_EQUALVERIFY operation"
VFY = "Script failed an OP_VERIFY operation"
FALSE = "Script evaluated without error but finished with a false/empty top stack element"
TOOL = os.path.join(REPO_ROOT, "tools", "pool-claim", "pool_claim.py")


def _coin_of(u):
    """A wallet Utxo as the tool's Coin."""
    return pc.Coin(u.txid, u.vout, pc.TxOut.explicit(bytes(u.txout.nAsset.vchCommitment[1:]), u.amount, u.spk),
                   None, False, 1)


class P1(SimBase, BitcoinTestFramework):
    NAME = "p1"

    def set_test_params(self):
        self.chain_params()

    def cli(self):
        return "%s -datadir=%s" % (os.environ["BITCOINCLI"], self.node.datadir)

    def tool(self, *args):
        p = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True,
                           env=dict(os.environ, SEQC=SEQC))
        return p.returncode, p.stdout, p.stderr.strip()

    def record(self, template, rows, denom=10000, cap=100):
        return {"pool_record": 1, "template": template, "denom": denom, "withhold_cap_bp": cap,
                "rows": [{"label": l, "script": s.hex(), "numerator": n} for l, s, n in rows]}

    def pay(self, pool, atoms, asset):
        addr = pool.address("elementsregtest")
        return self.node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel=asset,
                                       fee_asset_label=BITCOIN_ASSET)

    def claim(self, pool, coins, keep=0, rate=3):
        """A claim at `rate` atoms per vbyte: above the floor, so that a negative
        a few bytes larger still meets it and is refused for its own reason."""
        c = pc.Claim(pool, coins, self.genesis_hex, keep, self.claimer if keep else None, SEQC)
        t = c.make(self.rpc, rate)
        t.claim = c
        return t

    def ok(self, pool, t, coins, label, extra=None):
        """Send a claim; check what each row got on chain against the rule."""
        summary = pc.verify(pool, t, self.rpc, 100)
        m = {"collected": summary["collected"], "withheld": summary["withheld"], "cap": summary["cap"],
             "payouts": [p["amount"] for p in summary["payouts"]], "coins": len(coins)}
        c = t.claim
        if c.cost is not None:
            m.update({"cost_wu": c.cost, "budget_wu": c.budget, "annex_pad": c.annex_pad,
                      "program_bytes": len(t.wit[0][1]), "witness_bytes": len(t.wit[0][0])})
        else:
            m.update({"script_bytes": len(t.wit[0][1]), "witness_stack_items_bytes": [len(x) for x in t.wit[0]]})
        m.update(extra or {})
        txid = self.send(fw(t, coins), label, extra=m)
        tx = self.node.getrawtransaction(txid, True)
        want = pool.payouts(summary["collected"], summary["withheld"])
        for i, (script, _, _) in enumerate(pool.rows):
            o = tx["vout"][i]
            assert o["scriptPubKey"]["hex"] == script.hex(), (label, i)
            assert pc.atoms(o["value"]) == want[i], (label, i, o["value"], want[i])
        return txid

    def refused_by_tool(self, label, pool, t, why):
        try:
            pc.verify(pool, t, self.rpc, 100)
        except pc.Refused as e:
            assert why in str(e), (label, str(e))
            d = self.R[label]
            d["tool"] = str(e)
            self.rec(label, d)
            return
        raise AssertionError("%s: the tool's verify accepted it" % label)

    # -- one template --------------------------------------------------------
    def run_template(self, template, tag, rows):
        node, rpc = self.node, self.rpc
        simplicity = template == "sequentia/pool-split"
        claim_error = J if simplicity else EQV
        pool = pc.Pool(self.record(template, rows))
        addr = pool.address("elementsregtest")
        assert node.getaddressinfo(addr)["scriptPubKey"] == pool.script_pubkey.hex()
        self.rec(tag + "/instance", {"template": template, "address": addr, "params": pool.params,
                                     "script_pubkey": pool.script_pubkey.hex(),
                                     "rows": [{"label": l, "script": s.hex(), "numerator": n} for s, n, l in pool.rows]})

        amounts = [123456789, 50000001, 33333333]
        txids = [self.pay(pool, a, self.POL) for a in amounts]
        tx_x = self.pay(pool, 7777777, self.X)
        self.generate(node, 1)
        spk = pool.script_pubkey
        c0, c1, c2 = [coin(rpc, t, self.utxo_of(t, spk).vout) for t in txids]
        cx = coin(rpc, tx_x, self.utxo_of(tx_x, spk).vout)

        # The control: one coin, the fee from what it withholds.
        good = self.claim(pool, [c0])
        S, W = good.claim.collected, good.claim.withheld
        assert self.accept(fw(good, [c0]))["allowed"]
        asset = c0.txout.asset
        pay = pool.payouts(S, W)

        # A wrong share: one atom moved from row 0 to row 1.
        outs = [explicit(asset, pay[0] - 1, pool.rows[0][0]), explicit(asset, pay[1] + 1, pool.rows[1][0])] + good.vout[2:]
        bad = changed(good, outputs=outs)
        self.reject(fw(bad, [c0]), tag + "/neg_wrong_share_one_atom", claim_error, control=fw(good, [c0]))
        self.refused_by_tool(tag + "/neg_wrong_share_one_atom", pool, bad, "wrong share")

        # Rows swapped: the right amounts to each other's scripts.
        outs = [good.vout[0], explicit(asset, pay[1], pool.rows[2][0]), explicit(asset, pay[2], pool.rows[1][0])] + good.vout[3:]
        bad = changed(good, outputs=outs)
        self.reject(fw(bad, [c0]), tag + "/neg_rows_swapped", claim_error, control=fw(good, [c0]))
        self.refused_by_tool(tag + "/neg_rows_swapped", pool, bad, "pays another script")

        # A row's output carrying a nonce.
        o = explicit(asset, pay[1], pool.rows[1][0])
        o.nonce = b"\x02" + bytes(range(32))
        bad = changed(good, outputs=[good.vout[0], o] + good.vout[2:])
        # Simplicity's nonce check is a plain assert!, reported without "inside jet".
        self.reject(fw(bad, [c0]), tag + "/neg_row_output_with_a_nonce", A if simplicity else EQV,
                    control=fw(good, [c0]))
        self.refused_by_tool(tag + "/neg_row_output_with_a_nonce", pool, bad, "no nonce")

        # The witness names another withheld amount than the outputs leave.
        bad = replace_withheld(good, W, W + 1)
        self.reject(fw(bad, [c0]), tag + "/neg_witness_names_another_withheld", claim_error, control=fw(good, [c0]))

        # Withheld over the cap: the control withholds the cap exactly (the fee
        # and the claimer's part), the negative one atom more, with every row's
        # share computed for what it withholds.
        cap = pool.cap(S)
        at_cap = self.claim(pool, [c0], keep="max")
        assert at_cap.claim.withheld == cap, (at_cap.claim.withheld, cap)
        assert self.accept(fw(at_cap, [c0]))["allowed"]
        net = S - cap - 1
        shares = [net * n // pool.denom for _, n, _ in pool.rows[1:]]
        outs = [explicit(asset, net - sum(shares), pool.rows[0][0])]
        outs += [explicit(asset, s, pool.rows[i + 1][0]) for i, s in enumerate(shares)]
        outs += [explicit(asset, at_cap.claim.keep + 1, self.claimer)] + at_cap.vout[len(pool.rows) + 1:]
        over = replace_withheld(changed(at_cap, outputs=outs), cap, cap + 1)
        self.reject(fw(over, [c0]), tag + "/neg_withheld_one_atom_over_the_cap", A if simplicity else VFY,
                    control=fw(at_cap, [c0]))
        self.refused_by_tool(tag + "/neg_withheld_one_atom_over_the_cap", pool, over, "over the cap")
        try:
            self.claim(pool, [c0], keep=at_cap.claim.keep + 1)
            raise AssertionError("the tool built a claim over the cap")
        except pc.Refused as e:
            assert "withheld over the cap" in str(e), str(e)
            self.rec(tag + "/tool_refuses_to_build_over_the_cap", {"refused": str(e)})

        # Two coins: the control counts both.
        two = self.claim(pool, [c0, c1])
        assert self.accept(fw(two, [c0, c1]))["allowed"]
        S2, W2 = two.claim.collected, two.claim.withheld
        # The follower's value taken: rows paid on input 0 alone, the rest elsewhere.
        net0 = c0.txout.value - W2
        sh = [net0 * n // pool.denom for _, n, _ in pool.rows[1:]]
        outs = [explicit(asset, net0 - sum(sh), pool.rows[0][0])] + [explicit(asset, s, pool.rows[i + 1][0]) for i, s in enumerate(sh)]
        outs += [explicit(asset, c1.txout.value, self.claimer)] + two.vout[len(pool.rows):]
        bad = changed(two, outputs=outs)
        self.reject(fw(bad, [c0, c1]), tag + "/neg_follower_value_taken", claim_error, control=fw(two, [c0, c1]))
        self.refused_by_tool(tag + "/neg_follower_value_taken", pool, bad, "over the cap")

        # A coin of the pool in another asset beside the claim: the claim's own
        # scan refuses it at input 0, before the follow leaf runs.
        # It pays input 0's claim as before and takes the other coin whole.
        bad = changed(good, vin=[good.vin[0], [cx.txid, cx.vout, 0xffffffff]],
                      outputs=good.vout + [explicit(cx.txout.asset, cx.txout.value, self.claimer)],
                      wit=[good.wit[0], list(two.wit[1])])
        self.reject(fw(bad, [c0, cx]), tag + "/neg_follower_in_another_asset", claim_error,
                    control=fw(two, [c0, c1]), index=1, other_coin=True)
        self.refused_by_tool(tag + "/neg_follower_in_another_asset", pool, bad, "another asset")

        # The follow leaf at input 0, with no claim.
        fscript, fcb = pool.leaf("follow")
        bad = changed(good, wit=[[fscript, fcb]])
        self.reject(fw(bad, [c0]), tag + "/neg_follow_leaf_at_input_0", VFY)

        # The follow leaf beside a foreign input 0, which takes the coin whole.
        mine = self.wallet_utxo(100000)
        bad = pc.Tx()
        bad.vin = [[mine.txid, mine.vout, 0xffffffff], [c0.txid, c0.vout, 0xffffffff]]
        bad.vout = [explicit(asset, 100000 + c0.txout.value - 5000, self.claimer), explicit(asset, 5000, b"")]
        bad.wit = [[], [fscript, fcb]]
        foreign = self.wallet_sign(fw(bad, [_coin_of(mine), c0]))
        self.reject(foreign, tag + "/neg_follow_beside_a_foreign_input_0", EQV)

        # The claims: one coin, then two (the second a follower), then the other asset.
        self.ok(pool, good, [c0], tag + "/claim_one_coin")
        last = self.claim(pool, [c1, c2])
        self.ok(pool, last, [c1, c2], tag + "/claim_two_coins")
        if simplicity:
            tx_x2 = self.pay(pool, 2222222, self.X)
            self.generate(node, 1)
            cx2 = coin(rpc, tx_x2, self.utxo_of(tx_x2, spk).vout)
            self.ok(pool, self.claim(pool, [cx, cx2]), [cx, cx2], tag + "/claim_in_another_asset")
        return pool

    def sizes(self, n):
        """A Simplicity claim of one coin into n rows."""
        rows = [("pool", self.wallet_spk(), 1)] + [("row %d" % i, self.p2tr()[0], 1) for i in range(1, n)]
        pool = pc.Pool(self.record("sequentia/pool-split", rows, denom=n, cap=100))
        t = self.pay(pool, 10 ** 9, self.POL)
        self.generate(self.node, 1)
        c = coin(self.rpc, t, self.utxo_of(t, pool.script_pubkey).vout)
        self.ok(pool, self.claim(pool, [c]), [c], "simplicity/claim_%d_rows" % n)

    def run_test(self):
        self.boot()
        node = self.node
        self.rpc = node_rpc(node)
        self.genesis_hex = node.getblockhash(0)
        self.rec("whitelist", self.whitelist(self.X))
        self.claimer = self.wallet_spk()
        rows = [("pool", self.wallet_spk(), 500),
                ("alice (P2TR)", self.p2tr()[0], 6000),
                ("bob (P2PKH)", bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "legacy"))["scriptPubKey"]), 3500)]
        pool = self.run_template("sequentia/pool-split", "simplicity", rows)
        self.run_template("sequentia/pool-split-tap3", "tapscript", rows)

        # The command line: an address with no node, a claim the tool refuses.
        with open(os.path.join(self.options.tmpdir, "pool.json"), "w") as f:
            json.dump(self.record("sequentia/pool-split", rows), f)
        rc, out, err = self.tool("address", "--record", f.name, "--chain-name", "elementsregtest")
        assert rc == 0 and json.loads(out)["address"] == pool.address("elementsregtest"), (rc, out, err)
        t = self.pay(pool, 5 * 10 ** 7, self.POL)
        self.generate(node, 1)
        rc, out, err = self.tool("claim", "--record", f.name, "--cli", self.cli(), "--maturity", "100",
                                 "--keep", str(10 ** 6), "--claimer", node.getnewaddress(), "--dry-run")
        assert rc == 3 and "withheld over the cap" in err, (rc, out, err)
        self.rec("cli/claim_refused_over_the_cap", {"exit": rc, "stderr": err})
        rc, out, err = self.tool("claim", "--record", f.name, "--cli", self.cli(), "--maturity", "100")
        assert rc == 0, (rc, out, err)
        res = json.loads(out)
        self.generate(node, 1)
        assert node.getrawtransaction(res["broadcast"], True)["confirmations"] == 1
        self.rec("cli/claim", res)

        for n in (10, 20, 63):
            self.sizes(n)
        self.many_coins(rows)

    def many_coins(self, rows):
        """Many coins in one claim: the tapscript twin's limit of eight inputs,
        and a Simplicity claim of 70 coins, whose cost outgrows what its witness
        earns, so the tool pads it with an annex."""
        node, rpc = self.node, self.rpc
        pt = pc.Pool(self.record("sequentia/pool-split-tap3", rows))
        txids = [self.pay(pt, 10 ** 6 + i, self.POL) for i in range(9)]
        self.generate(node, 1)
        cs = [coin(rpc, t, self.utxo_of(t, pt.script_pubkey).vout) for t in txids]
        eight = self.claim(pt, cs[:8])
        assert self.accept(fw(eight, cs[:8]))["allowed"]
        c = pc.Claim(pt, cs[:8], self.genesis_hex, 0, None, SEQC)
        c.collected = sum(x.txout.value for x in cs)
        nine = c.build(eight.claim.withheld)
        nine.vin.append([cs[8].txid, cs[8].vout, 0xffffffff])
        nine.wit.append(list(eight.wit[1]))
        self.reject(fw(nine, cs), "tapscript/neg_nine_inputs", VFY)
        try:
            pc.Claim(pt, cs, self.genesis_hex, 0, None, SEQC)
            raise AssertionError("the tool built a claim of nine coins under the twin")
        except pc.Refused as e:
            assert "at most 8 coins" in str(e), str(e)
        self.ok(pt, eight, cs[:8], "tapscript/claim_eight_coins")

        ps = pc.Pool(self.record("sequentia/pool-split", rows))
        txids = [self.pay(ps, 10 ** 6 + i, self.POL) for i in range(70)]
        self.generate(node, 1)
        cs = [coin(rpc, t, self.utxo_of(t, ps.script_pubkey).vout) for t in txids]
        many = self.claim(ps, cs)
        assert many.claim.annex_pad is not None and many.claim.annex_pad > 0, many.claim.annex_pad
        # One byte less of padding: the budget falls short of the cost.
        short = copy.deepcopy(many.claim).build(many.claim.withheld - many.claim.keep, annex_pad=many.claim.annex_pad - 1)
        self.reject(fw(short, cs), "simplicity/neg_70_coins_padding_one_byte_short",
                    "Program's execution cost could exceed budget")
        self.ok(ps, many, cs, "simplicity/claim_70_coins")


if __name__ == "__main__":
    P1().main()
