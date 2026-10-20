"""V2: the token-covenants tool's verifier token against a node.

The issuer key is a raw key file, as OpenDAMP's issuer keys are. The test
plays the issuer's tooling: two stand-in verifiers (the one-key program
OpenDAMP's issuer path is, under two data leaves) hold the verifier amount in
turn; the halt is laid out and its verifier input signed here, as `opendamp
halt` does, and `token-covenants verifier-token record` signs the token
covenant into it; the resume is built whole by `verifier-token build`. Both are
mined and read back with `follow`, and the resumed verifier is spent again by
its issuer path. The tool refuses, before any transaction is broadcast, a key
that is not the issuer's, an input 0 that does not hold the verifier amount, an
output 1 that records another script, and a coin that does not record the
verifier it is told."""
import os
import subprocess
import sys
import tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

TOOL = os.environ.get("TOKEN_COVENANTS", os.path.join(REPO_ROOT, "tools", "token-covenants", "target", "release",
                                                      "token-covenants"))
Q = 1000
FEE = 3000
BURN = bytes([0x6a])


class V2(SimBase, BitcoinTestFramework):
    NAME = "v2"

    def set_test_params(self):
        self.chain_params()

    def tool(self, *args, request=None, ok=True):
        p = subprocess.run([TOOL, "verifier-token"] + list(args),
                           input=(json.dumps(request) if request is not None else "").encode(), capture_output=True)
        if ok:
            assert p.returncode == 0, p.stderr.decode()
            return json.loads(p.stdout.decode())
        assert p.returncode != 0, "the tool accepted: %s" % p.stdout.decode()[:400]
        return p.stderr.decode().strip()

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
                    self.pool.append(Utxo(txid, i, o))
        node.lockunspent(False, [{"txid": u.txid, "vout": u.vout} for u in self.pool])

    def mine(self, hex_, label, extra=None):
        signed = self.node.signrawtransactionwithwallet(hex_)
        assert signed["complete"], signed
        d = self.node.decoderawtransaction(signed["hex"])
        res = self.node.testmempoolaccept([signed["hex"]])[0]
        assert res["allowed"], (label, res)
        txid = self.node.sendrawtransaction(signed["hex"])
        self.generate(self.node, 1)
        assert self.node.getrawtransaction(txid, True)["confirmations"] >= 1
        m = {"txid": txid, "vsize": d["vsize"], "weight": d["weight"]}
        m.update(extra or {})
        self.log.info("PASS %-44s vsize=%d", label, d["vsize"])
        self.rec(label, m)
        return txid

    @staticmethod
    def prevout(o):
        """{asset, value, script_pubkey} of an explicit output, as the tool reads prevouts."""
        return {"asset": bytes(o.nAsset.vchCommitment[1:])[::-1].hex(), "value": str(o.nValue.getAmount()),
                "script_pubkey": bytes(o.scriptPubKey).hex()}

    def verifier_sign(self, prog, tx):
        sig = sign_schnorr(self.issuer_sk, self.sim_sighash(prog, tx, 0))
        self.sim_satisfy(prog, tx, 0, {"SIG": vsig(sig)})

    def halt_tx(self, vcoin, verifier_prog, tcoin, succ_spk, fee):
        """The halt as `opendamp halt` lays it out: the verifier at input 0,
        burned at output 0; the token covenant at input 1, re-created at output
        1; a fee coin. Input 0 is signed here, input 1 by the tool."""
        tx = self.mktx([(vcoin, 0xffffffff), (tcoin, 0xffffffff), (fee, 0xffffffff)],
                       [self.out(vcoin.amount, BURN, self.V_OUT), self.out(tcoin.amount, succ_spk, self.TOKEN_OUT),
                        self.out(fee.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.verifier_sign(verifier_prog, tx)
        return tx

    def record_request(self, tx, recorded):
        return {"tx": tx.serialize().hex(), "prevouts": [self.prevout(u.txout) for u in tx.prev],
                "verifier": recorded.hex()}

    def run_test(self):
        self.boot()
        node = self.node
        self.fee_pool(12)
        tmp = tempfile.mkdtemp(prefix="v2-", dir=self.options.tmpdir)
        key_file, other_file = os.path.join(tmp, "issuer.key"), os.path.join(tmp, "other.key")
        with open(key_file, "w") as f:
            self.issuer_sk = generate_privkey()
            f.write(self.issuer_sk.hex() + "\n")
        with open(other_file, "w") as f:
            f.write(generate_privkey().hex() + "\n")
        issuer_pk = compute_xonly_pubkey(self.issuer_sk)[0]
        out = subprocess.run([TOOL, "key", "--key-file", key_file], capture_output=True, check=True)
        assert json.loads(out.stdout)["key"] == issuer_pk.hex()

        r = node.issueasset(assetamount=Decimal(3 * Q) / COIN, tokenamount=1, blind=False, fee_asset=BITCOIN_ASSET)
        self.generate(node, 1)
        self.rec("whitelist", self.whitelist(self.X, self.Y, r["asset"]))
        self.V_OUT, self.TOKEN_OUT = self.asset_out(r["asset"]), self.asset_out(r["token"])
        VA = SimProg(src("p2pk.simf"), {"PK": vpub(issuer_pk)}, data=b"policy A")
        VB = VA.with_data(b"policy B")

        args = ["--verifier-asset", r["asset"], "--token", r["token"], "--entropy", r["entropy"], "--amount", str(Q),
                "--issuer-key", issuer_pk.hex(), "--verifier", VA.spk.hex(), "--genesis", node.getblockhash(0)]
        inst = self.tool("instance", *args)
        bad = list(args)
        bad[bad.index("--token") + 1] = self.X
        self.rec("instance/refuses_a_token_of_another_asset", self.tool("instance", *bad, ok=False))
        inst_path = os.path.join(tmp, "instance.json")
        with open(inst_path, "w") as f:
            json.dump({k: v for k, v in inst.items() if k not in ("address", "verifier_script_pubkey")}, f)
        self.rec("instance", inst)
        addr_b = self.tool("address", "--instance", inst_path, "--verifier", VB.spk.hex())

        # The issuance's end: the verifier amount in A, the token in the covenant recording A.
        pay = lambda spk, atoms, asset: node.sendtoaddress(address=program_to_witness(1, spk[2:]),
                                                           amount=Decimal(atoms) / COIN, assetlabel=asset,
                                                           fee_asset_label=BITCOIN_ASSET)
        t_va = pay(VA.spk, Q, r["asset"])
        t_tok = node.sendtoaddress(address=inst["address"]["elementsregtest"], amount=1, assetlabel=r["token"],
                                   fee_asset_label=BITCOIN_ASSET)
        t_less = pay(VB.spk, Q - 1, r["asset"])
        self.generate(node, 1)
        va = self.utxo_of(t_va, VA.spk)
        tok = self.utxo_of(t_tok, bytes.fromhex(node.getaddressinfo(inst["address"]["elementsregtest"])["scriptPubKey"]))
        less = self.utxo_of(t_less, VB.spk)

        # The update A -> B through the issuer path.
        fee = self.pool.pop()
        up = self.mktx([(va, 0xffffffff), (fee, 0xffffffff)],
                       [self.out(Q, VB.spk, self.V_OUT), self.out(fee.amount - FEE, self.wallet_spk(), self.X_OUT),
                        self.fee(FEE, self.X_OUT)])
        self.verifier_sign(VA, up)
        t_vb = self.mine(self.wallet_sign(up).serialize().hex(), "update/A_to_B")
        vb = self.utxo_at(t_vb, 0)

        # The halt, laid out here with its verifier input signed; the tool signs the record.
        fee = self.pool.pop()
        succ_spk = bytes.fromhex(addr_b["script_pubkey"])
        halt = self.halt_tx(vb, VB, tok, succ_spk, fee)
        req = self.record_request(halt, VA.spk)
        self.rec("tool/refuses_a_record_by_another_key", self.tool(
            "record", "--instance", inst_path, "--key-file", other_file, request=req, ok=False))
        self.rec("tool/refuses_a_coin_recording_another_verifier", self.tool(
            "record", "--instance", inst_path, "--key-file", key_file, request=dict(req, verifier=VB.spk.hex()),
            ok=False))
        wrong = self.halt_tx(vb, VB, tok, bytes.fromhex(self.tool("address", "--instance", inst_path, "--verifier",
                                                                    self.wallet_spk().hex())["script_pubkey"]), fee)
        self.rec("tool/refuses_an_output_1_recording_another_script", self.tool(
            "record", "--instance", inst_path, "--key-file", key_file, request=self.record_request(wrong, VA.spk),
            ok=False))
        short = self.halt_tx(less, VB, tok, succ_spk, fee)
        self.rec("tool/refuses_an_input_0_short_of_the_verifier_amount", self.tool(
            "record", "--instance", inst_path, "--key-file", key_file, request=self.record_request(short, VA.spk),
            ok=False))
        rec = self.tool("record", "--instance", inst_path, "--key-file", key_file, request=req)
        t_halt = self.mine(rec["hex"], "halt/burned_and_recorded_by_the_tool",
                           extra={k: rec[k] for k in ("program_bytes", "witness_bytes", "cost_bound_milli_wu",
                                                      "budget_wu")})
        f = self.tool("follow", "--instance", inst_path, request={
            "coin": {"tx": self.raw(t_tok), "vout": tok.vout}, "verifier": VA.spk.hex(), "tx": self.raw(t_halt),
            "input_0": {"tx": self.raw(t_vb), "vout": 0}})
        assert f["path"] == "record" and f["recorded"] == VB.spk.hex(), f
        self.rec("follow/record", f)
        assert node.gettxout(t_halt, 0) is None

        # The resume, built whole by the tool.
        coin = {"tx": self.raw(t_halt), "vout": 1}
        fee = self.pool.pop()
        rr = {"path": "resume", "coin": coin, "verifier": VB.spk.hex(), "entropy": r["entropy"],
              "fee": {"coins": [{"tx": self.raw(fee.txid), "vout": fee.vout}], "atoms": str(FEE),
                      "change_to": self.wallet_spk().hex()}}
        self.rec("tool/refuses_a_resume_by_another_key", self.tool(
            "build", "--instance", inst_path, "--key-file", other_file, request=rr, ok=False))
        self.rec("tool/refuses_a_resume_into_another_verifier", self.tool(
            "build", "--instance", inst_path, "--key-file", key_file, request=dict(rr, verifier=VA.spk.hex()),
            ok=False))
        res = self.tool("build", "--instance", inst_path, "--key-file", key_file, request=rr)
        t_res = self.mine(res["hex"], "resume/by_the_tool",
                          extra={k: res[k] for k in ("program_bytes", "witness_bytes", "cost_bound_milli_wu",
                                                     "budget_wu")})
        f = self.tool("follow", "--instance", inst_path,
                      request={"coin": coin, "verifier": VB.spk.hex(), "tx": self.raw(t_res)})
        assert f["path"] == "resume" and f["minted"]["atoms"] == str(Q) and f["minted"]["script_pubkey"] == VB.spk.hex(), f
        self.rec("follow/resume", f)

        # The verifier lives again: its issuer path spends it.
        vb2 = self.utxo_at(t_res, 1)
        assert vb2.spk == VB.spk and vb2.amount == Q
        fee = self.pool.pop()
        again = self.mktx([(vb2, 0xffffffff), (fee, 0xffffffff)],
                          [self.out(Q, VA.spk, self.V_OUT), self.out(fee.amount - FEE, self.wallet_spk(), self.X_OUT),
                           self.fee(FEE, self.X_OUT)])
        self.verifier_sign(VB, again)
        self.mine(self.wallet_sign(again).serialize().hex(), "update/the_resumed_verifier_moves_on")


if __name__ == "__main__":
    V2().main()
