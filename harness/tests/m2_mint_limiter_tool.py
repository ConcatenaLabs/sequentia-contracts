"""M2: the mint-limiter tool against a node.

`tools/mint-limiter` builds and signs spends of the mint limiter for the
bridges that mint through it. It reaches no node: this test plays the bridge,
reading the chain and the wallet itself, handing the tool the coins as the
transactions that made them, letting the wallet sign the fee coin, and
broadcasting. Every path the tool builds is mined: mints within one window and
in the next, the brake applied with a signature made in advance, the brake
lifted, applied again with the same signature, and the recovery once its delay
has passed. `follow` reads each spend back to the state it led to. The tool
refuses, before any transaction exists, a mint over the allowance, a coin
younger than two blocks, a mnemonic that is not the instance's key, and a
coin that is not the instance in the state it is told."""
import os
import subprocess
import sys
import tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

TOOL = os.environ.get("MINT_LIMITER", os.path.join(REPO_ROOT, "tools", "mint-limiter", "target", "release", "mint-limiter"))
WINDOW, ALLOWANCE, DELAY = 10, 10**9, 2
FEE = 3000


class M2(SimBase, BitcoinTestFramework):
    NAME = "m2"

    def set_test_params(self):
        self.chain_params()

    def tool(self, *args, request=None, ok=True):
        p = subprocess.run([TOOL] + list(args), input=(json.dumps(request) if request is not None else "").encode(),
                           capture_output=True)
        if ok:
            assert p.returncode == 0, p.stderr.decode()
            return json.loads(p.stdout.decode())
        assert p.returncode != 0, "the tool accepted: %s" % p.stdout.decode()[:400]
        return p.stderr.decode().strip()

    def raw(self, txid):
        return self.node.getrawtransaction(txid)

    def fee_pool(self, n, atoms=50_000):
        """n wallet coins of the fee asset X, made in one transaction and one
        block, and locked so the wallet's own coin selection leaves them."""
        node = self.node
        addrs = [node.getnewaddress("", "bech32") for _ in range(n)]
        txid = node.sendmany(dummy="", amounts={a: Decimal(atoms) / COIN for a in addrs},
                             output_assets={a: self.X for a in addrs}, fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        raw = self.raw(txid)
        tx = tx_from_hex(raw)
        self.pool = []
        for a in addrs:
            spk = bytes.fromhex(node.getaddressinfo(a)["scriptPubKey"])
            for i, o in enumerate(tx.vout):
                if bytes(o.scriptPubKey) == spk:
                    self.pool.append({"tx": raw, "vout": i})
        node.lockunspent(False, [{"txid": txid, "vout": c["vout"]} for c in self.pool])

    def fee_coin(self):
        return self.pool.pop()

    def age(self, txid):
        """The age a spend in the next block finds the coin made by `txid`."""
        node = self.node
        h = node.getblockheader(node.getrawtransaction(txid, True)["blockhash"])["height"]
        return node.getblockcount() + 1 - h

    def request(self, path, coin, state, **kw):
        r = {"path": path, "coin": coin, "state": state,
             "fee": {"coins": [kw.pop("fee_coin", None) or self.fee_coin()], "atoms": FEE,
                     "change_to": self.wallet_spk().hex()}}
        r.update(kw)
        return r

    def finish(self, built, label):
        """The wallet signs its fee coin; the transaction is mined; its id is
        the one the tool returned."""
        tx = self.node.signrawtransactionwithwallet(built["hex"])
        assert tx["complete"], tx
        d = self.node.decoderawtransaction(tx["hex"])
        assert d["txid"] == built["txid"], (d["txid"], built["txid"])
        res = self.node.testmempoolaccept([tx["hex"]])[0]
        assert res["allowed"], (label, res)
        txid = self.node.sendrawtransaction(tx["hex"])
        self.generate(self.node, 1)
        assert self.node.getrawtransaction(txid, True)["confirmations"] >= 1
        m = {"txid": txid, "vsize": d["vsize"], "weight": d["weight"], "program_bytes": built["program_bytes"],
             "witness_bytes": built["witness_bytes"], "cost_bound_milli_wu": built["cost_bound_milli_wu"],
             "budget_wu": built["budget_wu"], "next_state": built.get("next_state")}
        self.log.info("PASS %-44s vsize=%d", label, d["vsize"])
        self.rec(label, m)
        return txid

    def follows(self, coin, state, txid, label):
        f = self.tool("follow", "--instance", self.inst_path,
                      request={"coin": coin, "state": state, "tx": self.raw(txid)})
        self.rec(label, f)
        return f

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.fee_pool(30)
        tmp = tempfile.mkdtemp(prefix="m2-", dir=self.options.tmpdir)
        op_file, cold_file, other_file = (os.path.join(tmp, n) for n in ("operator.words", "cold.words", "other.words"))
        op = self.tool("key", "--new", "--mnemonic-file", op_file)["key"]
        cold = self.tool("key", "--new", "--mnemonic-file", cold_file)["key"]
        self.tool("key", "--new", "--mnemonic-file", other_file)
        assert oct(os.stat(op_file).st_mode & 0o777) == "0o600"
        assert "File exists" in self.tool("key", "--new", "--mnemonic-file", op_file, ok=False)

        z = node.issueasset(assetamount=Decimal(1) / COIN, tokenamount=1, blind=False, fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        args = ["--asset", z["asset"], "--token", z["token"], "--entropy", z["entropy"], "--operator-key", op,
                "--cold-key", cold, "--window", str(WINDOW), "--allowance", str(ALLOWANCE),
                "--recovery-delay", str(DELAY), "--genesis", node.getblockhash(0)]
        inst = self.tool("instance", *args)
        # The tool refuses an instance that could not work.
        bad = list(args)
        bad[bad.index("--cold-key") + 1] = op
        self.rec("instance/refuses_one_key_for_both", self.tool("instance", *bad, ok=False))
        bad = list(args)
        bad[bad.index("--token") + 1] = self.X
        self.rec("instance/refuses_a_token_of_another_asset", self.tool("instance", *bad, ok=False))
        self.inst_path = os.path.join(tmp, "instance.json")
        with open(self.inst_path, "w") as f:
            json.dump({k: v for k, v in inst.items() if k != "address"}, f)
        self.rec("instance", inst)
        addr = inst["address"]["elementsregtest"]
        info = node.getaddressinfo(addr)

        # The token moves in: the issuance's whole token, to the instance with nothing minted.
        t_in = node.sendtoaddress(address=addr, amount=1, assetlabel=z["token"], fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        vout = self.utxo_of(t_in, bytes.fromhex(info["scriptPubKey"])).vout
        coin = {"tx": self.raw(t_in), "vout": vout}
        S = {"minted": 0, "elapsed": 0, "armed": 0}
        mint_to = self.wallet_spk().hex()

        # Refused by the tool before any transaction: a coin one block old.
        assert self.age(t_in) == 1
        req = self.request("mint", coin, S, entropy=z["entropy"], age=1, amount=10, mint_to=mint_to)
        self.rec("tool/refuses_a_coin_one_block_old", self.tool("build", "--instance", self.inst_path,
                                                              "--mnemonic-file", op_file, request=req, ok=False))
        self.generate(node, 1)
        assert self.age(t_in) == 2
        half = ALLOWANCE // 2
        req = self.request("mint", coin, S, entropy=z["entropy"], age=2, amount=half, mint_to=mint_to)
        self.rec("tool/refuses_another_key", self.tool("build", "--instance", self.inst_path, "--mnemonic-file",
                                                       other_file, request=req, ok=False))
        self.rec("tool/refuses_the_cold_key_for_a_mint", self.tool("build", "--instance", self.inst_path,
                                                                   "--mnemonic-file", cold_file, request=req, ok=False))
        over = dict(req, amount=ALLOWANCE + 1)
        self.rec("tool/refuses_a_mint_over_the_allowance", self.tool("build", "--instance", self.inst_path,
                                                                     "--mnemonic-file", op_file, request=over, ok=False))
        wrong = dict(req, state={"minted": 1, "elapsed": 0, "armed": 0})
        self.rec("tool/refuses_a_coin_in_another_state", self.tool("build", "--instance", self.inst_path,
                                                                   "--mnemonic-file", op_file, request=wrong, ok=False))
        m1 = self.tool("build", "--instance", self.inst_path, "--mnemonic-file", op_file, request=req)
        assert m1["next_state"] == {"minted": half, "elapsed": 2, "armed": 0}, m1
        tx1 = self.finish(m1, "mint/half")
        f = self.follows(coin, S, tx1, "follow/mint_half")
        assert f["path"] == "mint" and f["next_state"] == m1["next_state"] and f["minted"] == half, f
        coin, S = {"tx": self.raw(tx1), "vout": 0}, m1["next_state"]

        # The rest of the allowance, then a refusal, then the next window.
        self.generate(node, 1)
        assert self.age(tx1) == 2
        m2 = self.tool("build", "--instance", self.inst_path, "--mnemonic-file", op_file,
                       request=self.request("mint", coin, S, entropy=z["entropy"], age=2, amount=half, mint_to=mint_to))
        tx2 = self.finish(m2, "mint/the_rest_of_the_allowance")
        coin, S = {"tx": self.raw(tx2), "vout": 0}, m2["next_state"]
        assert S == {"minted": ALLOWANCE, "elapsed": 4, "armed": 0}, S
        self.generate(node, 1)
        r = self.request("mint", coin, S, entropy=z["entropy"], age=2, amount=1, mint_to=mint_to)
        self.rec("tool/refuses_one_atom_over_in_the_window",
                 self.tool("build", "--instance", self.inst_path, "--mnemonic-file", op_file, request=r, ok=False))
        need = WINDOW - S["elapsed"]
        self.mine_to(node.getblockcount() + need - 2)
        assert self.age(tx2) == need, (self.age(tx2), need)
        m3 = self.tool("build", "--instance", self.inst_path, "--mnemonic-file", op_file,
                       request=self.request("mint", coin, S, entropy=z["entropy"], age=need, amount=ALLOWANCE,
                                            mint_to=mint_to))
        assert m3["next_state"] == {"minted": ALLOWANCE, "elapsed": 0, "armed": 0}, m3
        tx3 = self.finish(m3, "mint/a_whole_allowance_in_the_next_window")
        f = self.follows(coin, S, tx3, "follow/new_window")
        assert f["next_state"] == m3["next_state"], f
        coin, S = {"tx": self.raw(tx3), "vout": 0}, m3["next_state"]

        # The brake, with a signature made from the cold key's words alone.
        arm = self.tool("arm-signature", "--instance", self.inst_path, "--mnemonic-file", cold_file)
        self.rec("arm/signature", arm)
        self.rec("tool/refuses_to_make_an_arm_signature_with_the_operator_key", self.tool(
            "arm-signature", "--instance", self.inst_path, "--mnemonic-file", op_file, ok=False))
        forged = arm["arm_signature"][:-2] + ("00" if arm["arm_signature"][-2:] != "00" else "01")
        self.rec("tool/refuses_a_broken_arm_signature", self.tool(
            "build", "--instance", self.inst_path, ok=False,
            request=self.request("arm", coin, S, arm_signature=forged)))
        a1 = self.tool("build", "--instance", self.inst_path,
                       request=self.request("arm", coin, S, arm_signature=arm["arm_signature"]))
        txa = self.finish(a1, "arm/applied")
        f = self.follows(coin, S, txa, "follow/arm")
        assert f["path"] == "arm" and f["next_state"]["armed"] == 1, f
        coin, S = {"tx": self.raw(txa), "vout": 0}, a1["next_state"]
        r = self.request("mint", coin, S, entropy=z["entropy"], age=2, amount=1, mint_to=mint_to)
        self.generate(node, 2)
        self.rec("tool/refuses_a_mint_while_braked",
                 self.tool("build", "--instance", self.inst_path, "--mnemonic-file", op_file, request=r, ok=False))
        d1 = self.tool("build", "--instance", self.inst_path, "--mnemonic-file", cold_file,
                       request=self.request("disarm", coin, S))
        txd = self.finish(d1, "disarm/lifted")
        f = self.follows(coin, S, txd, "follow/disarm")
        assert f["path"] == "disarm" and f["next_state"]["armed"] == 0, f
        coin, S = {"tx": self.raw(txd), "vout": 0}, d1["next_state"]
        a2 = self.tool("build", "--instance", self.inst_path,
                       request=self.request("arm", coin, S, arm_signature=arm["arm_signature"]))
        txa2 = self.finish(a2, "arm/the_same_signature_again")
        coin, S = {"tx": self.raw(txa2), "vout": 0}, a2["next_state"]

        # Recovery once the brake has held its delay.
        h = node.getblockheader(node.getrawtransaction(txa2, True)["blockhash"])["height"]
        base = node.getblockheader(node.getblockhash(h - 1))["mediantime"]
        t = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(max(t, base) + DELAY * 512 + 60)
        self.generate(node, 12)
        rec_to = self.wallet_spk().hex()
        rc = self.tool("build", "--instance", self.inst_path, "--mnemonic-file", cold_file,
                       request=self.request("recover", coin, S, recover_to=rec_to))
        self.rec("tool/refuses_recovery_by_the_operator", self.tool(
            "build", "--instance", self.inst_path, "--mnemonic-file", op_file,
            request=self.request("recover", coin, S, recover_to=rec_to), ok=False))
        txr = self.finish(rc, "recover/after_the_delay")
        f = self.follows(coin, S, txr, "follow/recover")
        assert f["path"] == "recover" and f["token_to"][0]["script_pubkey"] == rec_to, f


if __name__ == "__main__":
    M2().main()
