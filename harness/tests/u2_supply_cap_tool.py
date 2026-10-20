"""U2: the token-covenants tool's supply cap against a node.

`tools/token-covenants` builds and signs spends of the supply cap for the
services that mint through it. It reaches no node: this test plays the
service, reading the chain and the wallet itself, handing the tool the coins
as the transactions that made them, letting the wallet sign the fee coin, and
broadcasting. Every path the tool builds is mined: a mint signed from a
mnemonic, a rekey to an operator key kept as a raw key file, a mint by that
key up to the cap exactly, and the retirement. `follow` reads each spend back.
The tool refuses, before any transaction exists, a mint over the cap, a key
that is not the path's, a coin that is not the instance holding the count it
is told, and an instance or rekey whose two keys are one."""
import os
import subprocess
import sys
import tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

TOOL = os.environ.get("TOKEN_COVENANTS", os.path.join(REPO_ROOT, "tools", "token-covenants", "target", "release",
                                                      "token-covenants"))
CAP = 10**9
FEE = 3000


class U2(SimBase, BitcoinTestFramework):
    NAME = "u2"

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

    def cap(self, cmd, *args, **kw):
        return self.tool("supply-cap", cmd, *args, **kw)

    def raw(self, txid):
        return self.node.getrawtransaction(txid)

    def fee_pool(self, n, atoms=50_000):
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

    def request(self, path, coin, minted, **kw):
        r = {"path": path, "coin": coin, "minted": str(minted),
             "fee": {"coins": [self.pool.pop()], "atoms": str(FEE), "change_to": self.wallet_spk().hex()}}
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
             "budget_wu": built["budget_wu"], "next_minted": built["next_minted"]}
        self.log.info("PASS %-44s vsize=%d", label, d["vsize"])
        self.rec(label, m)
        return txid

    def follows(self, inst_path, coin, minted, txid, label, **extra):
        f = self.cap("follow", "--instance", inst_path,
                     request=dict({"coin": coin, "minted": str(minted), "tx": self.raw(txid)}, **extra))
        self.rec(label, f)
        return f

    def save(self, inst, name):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            json.dump({k: v for k, v in inst.items() if k != "address"}, f)
        return path

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.fee_pool(20)
        tmp = self.tmp = tempfile.mkdtemp(prefix="u2-", dir=self.options.tmpdir)
        op_file, cold_file, other_file = (os.path.join(tmp, n) for n in ("operator.words", "cold.words", "other.words"))
        op2_file = os.path.join(tmp, "operator2.key")
        op = self.tool("key", "--new", "--mnemonic-file", op_file)["key"]
        cold = self.tool("key", "--new", "--mnemonic-file", cold_file)["key"]
        self.tool("key", "--new", "--mnemonic-file", other_file)
        op2 = self.tool("key", "--new", "--key-file", op2_file)["key"]
        assert self.tool("key", "--key-file", op2_file)["key"] == op2
        for f in (op_file, op2_file):
            assert oct(os.stat(f).st_mode & 0o777) == "0o600"
        assert "File exists" in self.tool("key", "--new", "--key-file", op2_file, ok=False)

        z = node.issueasset(assetamount=Decimal(1) / COIN, tokenamount=1, blind=False, fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        args = ["--asset", z["asset"], "--token", z["token"], "--entropy", z["entropy"], "--operator-key", op,
                "--cold-key", cold, "--cap", str(CAP), "--genesis", node.getblockhash(0)]
        inst = self.cap("instance", *args)
        bad = list(args)
        bad[bad.index("--cold-key") + 1] = op
        self.rec("instance/refuses_one_key_for_both", self.cap("instance", *bad, ok=False))
        bad = list(args)
        bad[bad.index("--token") + 1] = self.X
        self.rec("instance/refuses_a_token_of_another_asset", self.cap("instance", *bad, ok=False))
        inst_path = self.save(inst, "instance.json")
        self.rec("instance", inst)
        addr = inst["address"]["elementsregtest"]
        assert self.cap("address", "--instance", inst_path)["address"]["elementsregtest"] == addr

        # The token moves in: the issuance's whole token, to the instance with nothing minted.
        t_in = node.sendtoaddress(address=addr, amount=1, assetlabel=z["token"], fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        vout = self.utxo_of(t_in, bytes.fromhex(node.getaddressinfo(addr)["scriptPubKey"])).vout
        coin = {"tx": self.raw(t_in), "vout": vout}
        mint_to = self.wallet_spk().hex()
        third = CAP // 3

        req = self.request("mint", coin, 0, entropy=z["entropy"], amount=str(third), mint_to=mint_to)
        self.rec("tool/refuses_another_key", self.cap("build", "--instance", inst_path, "--mnemonic-file",
                                                      other_file, request=req, ok=False))
        self.rec("tool/refuses_the_cold_key_for_a_mint", self.cap("build", "--instance", inst_path,
                                                                  "--mnemonic-file", cold_file, request=req, ok=False))
        self.rec("tool/refuses_a_mint_over_the_cap", self.cap(
            "build", "--instance", inst_path, "--mnemonic-file", op_file, ok=False,
            request=dict(req, amount=str(CAP + 1))))
        self.rec("tool/refuses_a_coin_holding_another_count", self.cap(
            "build", "--instance", inst_path, "--mnemonic-file", op_file, ok=False, request=dict(req, minted="1")))
        m1 = self.cap("build", "--instance", inst_path, "--mnemonic-file", op_file, request=req)
        assert m1["next_minted"] == str(third), m1
        tx1 = self.finish(m1, "mint/a_third_from_a_mnemonic")
        f = self.follows(inst_path, coin, 0, tx1, "follow/mint")
        assert f["path"] == "mint" and f["next_minted"] == str(third), f
        coin = {"tx": self.raw(tx1), "vout": 0}

        # The cold key moves the covenant to an operator key kept as a raw key file.
        rq = self.request("rekey", coin, third, new_operator_key=op2, new_cold_key=cold)
        self.rec("tool/refuses_a_rekey_by_the_operator", self.cap(
            "build", "--instance", inst_path, "--mnemonic-file", op_file, request=rq, ok=False))
        self.rec("tool/refuses_a_rekey_to_one_key_for_both", self.cap(
            "build", "--instance", inst_path, "--mnemonic-file", cold_file, ok=False,
            request=dict(rq, new_cold_key=op2)))
        rk = self.cap("build", "--instance", inst_path, "--mnemonic-file", cold_file, request=rq)
        txr = self.finish(rk, "rekey/to_a_raw_key")
        f = self.follows(inst_path, coin, third, txr, "follow/rekey", new_operator_key=op2, new_cold_key=cold)
        assert f["path"] == "rekey" and f["next_instance"]["params"]["OPERATOR_KEY"] == op2, f
        inst2_path = self.save(rk["next_instance"], "instance2.json")
        coin = {"tx": self.raw(txr), "vout": 0}

        # The old operator key is refused; the new one mints exactly the room left.
        req = self.request("mint", coin, third, entropy=z["entropy"], amount=str(CAP - third), mint_to=mint_to)
        self.rec("tool/refuses_the_old_operator_key", self.cap(
            "build", "--instance", inst2_path, "--mnemonic-file", op_file, request=req, ok=False))
        self.rec("tool/refuses_one_atom_over_the_room_left", self.cap(
            "build", "--instance", inst2_path, "--key-file", op2_file, ok=False,
            request=dict(req, amount=str(CAP - third + 1))))
        m2 = self.cap("build", "--instance", inst2_path, "--key-file", op2_file, request=req)
        assert m2["next_minted"] == str(CAP), m2
        tx2 = self.finish(m2, "mint/the_room_left_by_a_raw_key")
        coin = {"tx": self.raw(tx2), "vout": 0}
        self.rec("tool/refuses_any_mint_at_the_cap", self.cap(
            "build", "--instance", inst2_path, "--key-file", op2_file, ok=False,
            request=self.request("mint", coin, CAP, entropy=z["entropy"], amount="1", mint_to=mint_to)))

        # Retired: both keys the NUMS point.
        ret = self.cap("build", "--instance", inst2_path, "--mnemonic-file", cold_file,
                       request=self.request("rekey", coin, CAP, new_operator_key=NUMS.hex(), new_cold_key=NUMS.hex()))
        txt = self.finish(ret, "rekey/retired")
        f = self.follows(inst2_path, coin, CAP, txt, "follow/retired", new_operator_key=NUMS.hex(),
                         new_cold_key=NUMS.hex())
        assert f["next_instance"]["params"]["COLD_KEY"] == NUMS.hex(), f
        minted = sum(int(Decimal(str(node.getrawtransaction(t, True)["vin"][0]["issuance"]["assetamount"])) * COIN)
                     for t in (tx1, tx2))
        assert minted == CAP, minted
        self.rec("cap/minted_on_chain", {"minted": minted, "cap": CAP})


if __name__ == "__main__":
    U2().main()
