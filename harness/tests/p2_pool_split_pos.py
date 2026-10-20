"""P2: the pool split covenant as a staking pool's payout script, on a
proof-of-stake chain.

The chain is the node's `elementsregtest` proof of stake as its functional tests
run it (`-con_pos=1 -posvrf=1`, one staker from configuration that produces
every block), with Simplicity active from genesis, fees payable in an issued
asset, and the real chains' coinbase maturity of 1,000 blocks.

The pool announces a direct payout to the covenant's script
(`announcepayout direct ... payout_script=<script>`), and later to the tapscript
twin's address (`... address=<address>`). From each activation every block's
reward is paid to the covenant, one coinbase output per fee asset. A claim of a
coin under 1,000 confirmations is refused by the claim tool, by the mempool and
in a block, at 999 confirmations as well as earlier; at 1,000 the claim tool
claims it, and each row gets exactly its share. A wrong share and a withheld
amount over the cap are refused in a block against the claim they were made
from.

`generateblock` cannot make a block on a proof-of-stake chain (the block has no
VRF proof: `bad-posvrf-missing`). A transaction is forced into a block here the
same way, through the consensus check generateblock runs: a block the staker
produced is taken back (`invalidateblock`), the transaction added to it with its
merkle root and witness commitment remade, and the block handed to
`testproposedblock`, which runs TestBlockValidity on it; the produced block is
then restored (`reconsiderblock`).
"""
import os
import subprocess
import sys
from io import BytesIO
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from poolsplit import *  # noqa: E402,F401,F403
from test_framework.key import ECKey  # noqa: E402
from test_framework.address import byte_to_base58  # noqa: E402
from test_framework.messages import CBlock, ser_uint256  # noqa: E402
from test_framework.blocktools import get_witness_script, WITNESS_COMMITMENT_HEADER  # noqa: E402
import test_framework.util as fw_util  # noqa: E402
from test_framework.descriptors import descsum_create  # noqa: E402

MATURITY = 1000
NOTICE = 10
TOOL = os.path.join(REPO_ROOT, "tools", "pool-claim", "pool_claim.py")
PREMATURE = "bad-txns-premature-spend-of-coinbase"


class P2(SimBase, BitcoinTestFramework):
    NAME = "p2"

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        k = ECKey()
        k.generate(compressed=True)
        self.staker_key = k
        self.wif = byte_to_base58(k.get_bytes() + b"\x01", 239)
        self.signer = k.get_pubkey().get_bytes().hex()
        self.extra_args = [[
            "-con_pos=1", "-posvrf=1", "-posunbonding=5", "-posslotinterval=1",
            "-pospayoutnotice=%d" % NOTICE, "-signblockscript=51",
            "-initialfreecoins=1000000000000", "-anyonecanspendaremine=1", "-con_blocksubsidy=0",
            "-con_connect_genesis_outputs=1", "-staker=%s:%d" % (self.signer, 100 * COIN),
            "-validatepegin=0", "-txindex=1", "-par=1",
            "-evbparams=simplicity:-1:::",
            "-con_coinbase_maturity=%d" % MATURITY,
            "-blindedaddresses=0", "-con_default_blinded_addresses=0", "-con_any_asset_fees=1",
            "-maxtxfee=100.0",
        ]]
        self.R = {}

    # -- the chain -----------------------------------------------------------
    def mine(self, n=1):
        for _ in range(n):
            self.node.generateposblock(self.wif)

    def mine_to(self, height):
        while self.node.getblockcount() < height:
            self.mine()

    def force(self, txs):
        """Validate a block holding `txs` (raw hex): the error TestBlockValidity
        gives, or None when the block is valid. The block is the one the staker
        produces next, at the height the mempool judged the transaction for;
        that produced block, without `txs`, is the tip afterwards."""
        node = self.node
        assert node.getrawmempool() == [], "the produced block must hold no other transaction"
        produced = node.generateposblock(self.wif)["hash"]
        b = CBlock()
        b.deserialize(BytesIO(bytes.fromhex(node.getblock(produced, 0))))
        node.invalidateblock(produced)
        for h in txs:
            b.vtx.append(tx_from_hex(h))
        cb = b.vtx[0]
        at = [i for i, o in enumerate(cb.vout) if bytes(o.scriptPubKey)[:6] == b"\x6a\x24" + WITNESS_COMMITMENT_HEADER]
        nonce = cb.wit.vtxinwit[0].scriptWitness.stack[0]
        root = uint256_from_str(bytes.fromhex(b.calc_witness_merkle_root())[::-1])
        cb.vout[at[-1]] = CTxOut(0, get_witness_script(root, uint256_from_str(nonce)))
        cb.rehash()
        b.hashMerkleRoot = b.calc_merkle_root()
        b.rehash()
        try:
            node.testproposedblock(b.serialize().hex(), True)
            err = None
        except JSONRPCException as e:
            err = "%s (code %s)" % (e.error["message"], e.error["code"])
        node.reconsiderblock(produced)
        assert node.getbestblockhash() == produced
        return err

    def refuse(self, t, coins, label, expect, mempool=None, control=None):
        """The mempool and a forced block both refuse `t` for `expect`; the
        control, when given, is accepted by both."""
        d = {"expect": expect, "vsize": self.node.decoderawtransaction(t.hex())["vsize"]}
        if control is not None:
            assert self.accept_hex(control.hex())["allowed"], label
            assert self.force([control.hex()]) is None, label
            d["control"] = {"txid": control.txid(), "testmempoolaccept": True, "block": "valid"}
        res = self.accept_hex(t.hex())
        assert not res["allowed"], label
        d["reject-reason"] = res["reject-reason"]
        assert reason_matches(mempool or expect, res["reject-reason"]), (label, res)
        d["block-error"] = self.force([t.hex()])
        assert d["block-error"] is not None and reason_matches(expect, d["block-error"]), (label, d)
        self.log.info("REJECT %-44s block: %s%s", label, d["block-error"], " (control accepted)" if control else "")
        self.rec(label, d)

    def accept_hex(self, h):
        return self.node.testmempoolaccept([h])[0]

    def tool(self, *args):
        cli = "%s -datadir=%s" % (os.environ["BITCOINCLI"], self.node.datadir)
        p = subprocess.run([sys.executable, TOOL] + list(args[:1]) + ["--cli", cli] + list(args[1:]),
                           capture_output=True, text=True, env=dict(os.environ, SEQC=SEQC))
        return p.returncode, p.stdout, p.stderr.strip()

    def coinbase_outputs(self, height):
        blk = self.node.getblock(self.node.getblockhash(height), 2)
        return [(v["scriptPubKey"]["hex"], v.get("asset"), pc.atoms(v["value"]), blk["tx"][0]["txid"], v["n"])
                for v in blk["tx"][0]["vout"] if v.get("value", 0) > 0]

    def fee_blocks(self, pool, n, label):
        """n blocks whose fees are paid in two assets; each block's reward must
        go to the covenant, one coinbase output per fee asset."""
        node = self.node
        coins = []
        for _ in range(n):
            node.sendtoaddress(address=node.getnewaddress(), amount=1, fee_asset_label="bitcoin")
            node.sendtoaddress(address=node.getnewaddress(), amount=1, assetlabel=self.X, fee_asset_label=self.X)
            self.mine()
            h = node.getblockcount()
            outs = self.coinbase_outputs(h)
            assert len(outs) == 2, outs
            for spk, asset, value, txid, vout in outs:
                assert spk == pool.script_pubkey.hex(), (label, spk)
                coins.append((txid, vout, asset, value, h))
        self.rec(label + "/coinbase_rewards", [{"txid": c[0], "vout": c[1], "asset": c[2], "atoms": c[3], "height": c[4]}
                                               for c in coins])
        return coins

    def claim_and_check(self, pool, asset, label, coins_expected):
        """Claim every mature coin of `asset` with the command-line tool, mine
        it, and check each row's output against the rule."""
        node = self.node
        rc, out, err = self.tool("claim", "--record", pool.path, "--maturity", str(MATURITY), "--asset", asset,
                                 "--fee-rate", "2")
        assert rc == 0, (label, rc, out, err)
        res = json.loads(out)
        assert res["coins"] == len(coins_expected), (label, res["coins"], len(coins_expected))
        assert res["collected"] == sum(c[3] for c in coins_expected), (label, res)
        self.mine()
        tx = node.getrawtransaction(res["broadcast"], True)
        assert tx["confirmations"] == 1
        want = pool.payouts(res["collected"], res["withheld"])
        got = [pc.atoms(tx["vout"][i]["value"]) for i in range(len(pool.rows))]
        assert got == want, (label, got, want)
        for i, (script, _, _) in enumerate(pool.rows):
            assert tx["vout"][i]["scriptPubKey"]["hex"] == script.hex()
            assert tx["vout"][i]["asset"] == asset
        res["outputs_on_chain"] = got
        res["exact"] = got == want
        self.log.info("PASS %-46s vsize=%d collected=%d withheld=%d rows=%s", label, res["vsize"],
                      res["collected"], res["withheld"], got)
        self.rec(label, res)
        return res

    # -- the test ------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]
        self.node = node
        fw_util.node_fastmerkle = node
        self.rpc = node_rpc(node)
        self.mine(1)

        # The staker's key in the wallet, so that it can announce for its signer.
        if node.getwalletinfo().get("descriptors"):
            for d in ("wpkh(%s)" % self.wif, "pkh(%s)" % self.wif):
                r = node.importdescriptors([{"desc": descsum_create(d), "timestamp": "now"}])
                assert r[0]["success"], r
        else:
            node.importprivkey(self.wif, "staker", False)
        a = node.issueasset(assetamount=1000000, tokenamount=0, blind=False, fee_asset="bitcoin")
        self.X = a["asset"]
        self.mine(1)
        rates = node.getfeeexchangerates()
        rates[self.X] = 100000000
        node.setfeeexchangerates(rates)
        self.rec("whitelist", node.getfeeexchangerates())
        # Fat fees, so that a block's reward outgrows a claim's own fee a
        # hundredfold: a claim may withhold 1% of what it collects.
        node.settxfee(Decimal("0.1"))

        signer_spk = bytes.fromhex(node.getaddressinfo(
            node.getnewaddress("", "bech32"))["scriptPubKey"])
        rows = [("pool", signer_spk, 500), ("alice", self.wallet_spk_of(node), 6000), ("bob (P2TR)", self.p2tr()[0], 3500)]
        pools = {}
        for template, tag in (("sequentia/pool-split", "simplicity"), ("sequentia/pool-split-tap3", "tapscript")):
            rec = {"pool_record": 1, "template": template, "denom": 10000, "withhold_cap_bp": 100,
                   "rows": [{"label": l, "script": s.hex(), "numerator": n} for l, s, n in rows]}
            path = os.path.join(self.options.tmpdir, tag + ".json")
            with open(path, "w") as f:
                json.dump(rec, f)
            p = pc.Pool(rec)
            p.path = path
            pools[tag] = p
        ps, pt = pools["simplicity"], pools["tapscript"]

        # The pool pays the Simplicity covenant: its script as the payout script.
        act = node.getblockcount() + NOTICE + 3
        ann = node.announcepayout(mode="direct", signer=self.signer, activation=act, payout_script=ps.script_pubkey.hex())
        assert ann["payout_script"] == ps.script_pubkey.hex(), ann
        self.mine()
        info = node.getpayoutinfo(self.signer)[self.signer][0]
        assert info["payout_script"] == ps.script_pubkey.hex(), info
        self.rec("simplicity/announce", {"announce": ann, "payoutinfo": info})
        self.mine_to(act - 1)
        sc = self.fee_blocks(ps, 3, "simplicity")

        # Then the tapscript twin, named by its address.
        act2 = node.getblockcount() + NOTICE + 3
        ann2 = node.announcepayout(mode="direct", signer=self.signer, activation=act2,
                                   address=pt.address("elementsregtest"))
        assert ann2["payout_script"] == pt.script_pubkey.hex(), ann2
        self.rec("tapscript/announce", {"announce": ann2})
        self.mine_to(act2 - 1)
        tc = self.fee_blocks(pt, 2, "tapscript")
        pol = sc[0][2] if sc[0][2] != self.X else sc[1][2]

        # Immature: the tool refuses, then the mempool and a forced block.
        first = [c for c in sc if c[2] == pol][0]
        rc, out, err = self.tool("claim", "--record", ps.path, "--maturity", str(MATURITY),
                                 "--coin", "%s:%d" % (first[0], first[1]))
        assert rc == 3 and "immature coinbase coin" in err, (rc, out, err)
        self.rec("simplicity/tool_refuses_an_immature_coin", {"exit": rc, "stderr": err})
        rc, out, err = self.tool("claim", "--record", ps.path, "--maturity", str(MATURITY))
        assert rc == 3 and "no mature coin" in err, (rc, out, err)
        self.rec("simplicity/tool_finds_no_mature_coin", {"exit": rc, "stderr": err})

        def build(pool, coin_tuples, keep=0):
            cs = [coin(self.rpc, c[0], c[1]) for c in coin_tuples]
            claimer = self.wallet_spk_of(node) if keep else None
            c = pc.Claim(pool, cs, node.getblockhash(0), keep, claimer, SEQC)
            t = c.make(self.rpc, 2)
            t.claim, t.coins = c, cs
            return t

        early = build(ps, [first])
        self.refuse(early, None, "simplicity/neg_immature_%d_confirmations" % early.claim.coins[0].confirmations, PREMATURE)
        self.mine_to(first[4] + MATURITY - 2)
        c = coin(self.rpc, first[0], first[1])
        assert c.confirmations == MATURITY - 1, c.confirmations
        try:
            pc.verify(ps, early, self.rpc, MATURITY)
            raise AssertionError("the tool accepted an immature coin")
        except pc.Refused as e:
            assert "immature" in str(e), str(e)
        self.refuse(early, None, "simplicity/neg_immature_999_confirmations", PREMATURE)
        # force() restored the block the staker produced: one block more.
        assert coin(self.rpc, first[0], first[1]).confirmations == MATURITY
        good = build(ps, [first])
        assert self.accept_hex(good.hex())["allowed"]
        assert pc.verify(ps, good, self.rpc, MATURITY)
        self.rec("simplicity/accepted_at_1000_confirmations", {"vsize": node.decoderawtransaction(good.hex())["vsize"]})

        # A wrong share, and a withheld amount over the cap, in a block.
        for pool, tag, coins_all in ((ps, "simplicity", sc), (pt, "tapscript", tc)):
            self.mine_to(max(x[4] for x in coins_all) + MATURITY - 1)
            mine_pol = [x for x in coins_all if x[2] == pol]
            ctl = build(pool, mine_pol[:1])
            S, W = ctl.claim.collected, ctl.claim.withheld
            asset = ctl.claim.asset
            pay = pool.payouts(S, W)
            outs = [explicit(asset, pay[0] - 1, pool.rows[0][0]), explicit(asset, pay[1] + 1, pool.rows[1][0])] + ctl.vout[2:]
            bad = changed(ctl, outputs=outs)
            self.refuse(bad, None, tag + "/neg_wrong_share_one_atom", J if tag == "simplicity" else "Script failed an OP_EQUALVERIFY operation", control=ctl)
            at_cap = build(pool, mine_pol[:1], keep="max")
            cap = pool.cap(S)
            assert at_cap.claim.withheld == cap
            net = S - cap - 1
            shares = [net * n // pool.denom for _, n, _ in pool.rows[1:]]
            outs = [explicit(asset, net - sum(shares), pool.rows[0][0])]
            outs += [explicit(asset, s, pool.rows[i + 1][0]) for i, s in enumerate(shares)]
            outs += [explicit(asset, at_cap.claim.keep + 1, at_cap.claim.claimer_script)] + at_cap.vout[len(pool.rows) + 1:]
            over = replace_withheld(changed(at_cap, outputs=outs), cap, cap + 1)
            self.refuse(over, None, tag + "/neg_withheld_one_atom_over_the_cap",
                        A if tag == "simplicity" else "Script failed an OP_VERIFY operation", control=at_cap)

        # The claims, by the command-line tool: every reward, in both assets,
        # through both covenants, each row paid exactly its share.
        # The coins to expect: every fee-bearing coinbase output from each
        # activation on, read block by block. Each must pay the covenant in
        # force at its height; the pool's own transactions paid fees too.
        top = node.getblockcount()
        expect = {"simplicity": [], "tapscript": []}
        for h in range(act, top + 1):
            tag = "simplicity" if h < act2 else "tapscript"
            for spk, asset, value, txid, vout in self.coinbase_outputs(h):
                assert spk == pools[tag].script_pubkey.hex(), (h, spk)
                if h + MATURITY - 1 <= top:
                    expect[tag].append((txid, vout, asset, value, h))
        self.rec("coinbase_rewards_to_the_covenants", {k: len(v) for k, v in expect.items()})
        self.claim_and_check(ps, pol, "simplicity/claim_policy_asset", [x for x in expect["simplicity"] if x[2] == pol])
        self.claim_and_check(ps, self.X, "simplicity/claim_issued_asset", [x for x in expect["simplicity"] if x[2] == self.X])
        self.claim_and_check(pt, pol, "tapscript/claim_policy_asset", [x for x in expect["tapscript"] if x[2] == pol])
        self.claim_and_check(pt, self.X, "tapscript/claim_issued_asset", [x for x in expect["tapscript"] if x[2] == self.X])
        rc, out, err = self.tool("status", "--record", ps.path, "--maturity", str(MATURITY))
        assert rc == 0, (rc, out, err)
        left = json.loads(out)["assets"]
        assert all(v["mature"] == 0 for v in left.values()), left
        self.rec("simplicity/status_after_the_claims", json.loads(out))

    @staticmethod
    def wallet_spk_of(node):
        return bytes.fromhex(node.getaddressinfo(node.getnewaddress("", "bech32"))["scriptPubKey"])


if __name__ == "__main__":
    P2().main()
