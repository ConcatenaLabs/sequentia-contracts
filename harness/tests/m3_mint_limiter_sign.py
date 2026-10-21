"""M3: the mint-limiter tool signs a mint inside a transaction built elsewhere.

`mint-limiter sign` takes a transaction whose input 0 spends the limiter's coin
with a reissuance and whose output 0 is the coin's successor, with the output
every input spends, and returns it with input 0 satisfied and signed. This is
how a program that builds its own transactions mints into them: an Arca
operator reissues refresh liquidity straight into the batch output of its
round, beside the round's other inputs (one of which issues a new asset) and
outputs. The wallet signs its inputs afterwards; the covenant's signature,
over the whole transaction, is unchanged by them.

Mined: a round-shaped mint of the whole allowance, read back by `follow`; a
second in the next window. `sighash` agrees with the harness's own
computation of the program's signature hash. Refused by the tool before any
signature: a mint over the allowance, output 0 not the successor, an age in
time, a transaction of version 1, an issuance that is no reissuance against
the explicit token, another entropy, a missing spent output, a denomination
other than 8, and a mnemonic that is not the operator key's. Forced into a
block beside the tool's own mint as control: the same round minting one atom
over the allowance, re-signed by the operator key for its own transaction."""
import hashlib
import hmac
import os
import sys
import tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from m1_mint_limiter import *  # noqa: E402,F401,F403
from m1_mint_limiter import M1, Limiter  # noqa: E402
from test_framework.key import ECKey  # noqa: E402

TOOL = os.environ.get("MINT_LIMITER", os.path.join(REPO_ROOT, "tools", "mint-limiter", "target", "release", "mint-limiter"))
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def contract_key(words):
    """The secret contract key a twelve-word mnemonic derives at
    m/8383h/1h/0h/0/0 (BIP39 seed with no passphrase, BIP32), as the tool
    derives it: so this test can sign what the tool refuses to."""
    seed = hashlib.pbkdf2_hmac("sha512", words.encode(), b"mnemonic", 2048)
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(i[:32], "big"), i[32:]
    for idx in (8383 | 1 << 31, 1 | 1 << 31, 0 | 1 << 31, 0, 0):
        if idx & 1 << 31:
            data = b"\x00" + k.to_bytes(32, "big") + idx.to_bytes(4, "big")
        else:
            e = ECKey()
            e.set(k.to_bytes(32, "big"), True)
            data = e.get_pubkey().get_bytes() + idx.to_bytes(4, "big")
        i = hmac.new(c, data, hashlib.sha512).digest()
        k, c = (int.from_bytes(i[:32], "big") + k) % SECP_N, i[32:]
    return k.to_bytes(32, "big")


class M3(M1):
    NAME = "m3"

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

    def round_tx(self, lim, coin, state, x, age, issuer, fee_coin, version=2, seq=None, claim=None, nonce=1,
                 entropy=None, denomination=8):
        """A round-shaped mint: the covenant at input 0 reissuing `x`, a wallet
        coin of X at input 1 issuing one atom of a new asset, a fee coin at
        input 2; the successor at output 0, `x` of the asset to a stand-in
        batch output at 1, the new asset's atom at 2, the change and the fee."""
        minted, elapsed, _ = state
        nxt = (x, 0, 0) if elapsed + age >= lim.window else (minted + x, elapsed + age, 0)
        nxt = claim or nxt
        new_asset = self.issued_asset(issuer)
        outs = [self.out(coin.amount, lim.spk(nxt), lim.TOKEN_OUT),
                self.out(x, self.batch, lim.ASSET_OUT),
                self.out(1, self.batch, self.asset_out(new_asset)),
                self.out(issuer.amount + fee_coin.amount - FEE, self.change_spk, self.X_OUT),
                self.fee(FEE, self.X_OUT)]
        tx = self.mktx([(coin, age if seq is None else seq), (issuer, 0xffffffff), (fee_coin, 0xffffffff)], outs,
                       version=version)
        iss = CAssetIssuance()
        iss.assetBlindingNonce = nonce
        iss.assetEntropy = int(entropy or lim.entropy, 16)
        iss.nAmount = CTxOutValue(x)
        iss.denomination = denomination
        tx.vin[0].assetIssuance = iss
        new = CAssetIssuance()
        new.assetBlindingNonce = 0
        new.assetEntropy = 0
        new.nAmount = CTxOutValue(1)
        tx.vin[1].assetIssuance = new
        tx.next_state = nxt
        tx.prev = [coin, issuer, fee_coin]
        return tx

    def issued_asset(self, issuer):
        """The asset a new issuance on `issuer` makes, with a zero contract
        hash, as the node computes it."""
        d = self.node.decoderawtransaction(self.round_probe(issuer))
        return d["vin"][0]["issuance"]["asset"]

    def round_probe(self, issuer):
        tx = self.mktx([(issuer, 0xffffffff)], [self.out(1, self.batch, self.X_OUT)], version=2)
        new = CAssetIssuance()
        new.assetBlindingNonce = 0
        new.assetEntropy = 0
        new.nAmount = CTxOutValue(1)
        tx.vin[0].assetIssuance = new
        return tx.serialize().hex()

    def request(self, lim, tx, state, entropy=None, prevouts=None):
        prev = prevouts if prevouts is not None else [p.txout.serialize().hex() for p in tx.prev]
        return {"tx": tx.serialize().hex(), "prevouts": prev,
                "state": {"minted": str(state[0]), "elapsed": state[1], "armed": state[2]},
                "entropy": entropy or lim.entropy}

    def tool_signed(self, lim, tx, state, words_file):
        """`tx` with input 0 as the tool signs it, then the wallet's inputs
        signed; the tool's answer rides on it as the control's record."""
        r = self.tool("sign", "--instance", self.inst_path, "--mnemonic-file", words_file,
                      request=self.request(lim, tx, state))
        assert r["next_state"] == {"minted": str(tx.next_state[0]), "elapsed": tx.next_state[1], "armed": 0}, r
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes.fromhex(w) for w in r["witness"]]
        tx.sig = bytes.fromhex(r["signature"])
        tx.r = {"witness_hex": r["witness"][0], "program_hex": r["witness"][1], "cost_milli": r["cost_bound_milli_wu"]}
        tx.leaf = lim.at(state)[1]
        tx.index = 0
        signed = self.wallet_sign_keep(tx)
        signed.prev = tx.prev
        signed.rehash()
        assert signed.hash == r["txid"], (signed.hash, r["txid"])
        signed.tool = r
        return signed

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.dest = self.wallet_spk()
        self.change_spk = self.wallet_spk()
        self.batch = self.p2tr()[0]
        self.sa, self.desc, self.vectors, self.sources = load_template("mint_limiter")
        self.text, self.body = self.sources["limiter"]
        self.fees = self.fee_coins(40)
        tmp = tempfile.mkdtemp(prefix="m3-", dir=self.options.tmpdir)
        op_file, other_file = os.path.join(tmp, "operator.words"), os.path.join(tmp, "other.words")
        op_pk = bytes.fromhex(self.tool("key", "--new", "--mnemonic-file", op_file)["key"])
        self.tool("key", "--new", "--mnemonic-file", other_file)
        with open(op_file) as f:
            self.op_sk = contract_key(" ".join(f.read().split()))
        assert compute_xonly_pubkey(self.op_sk)[0] == op_pk, "the contract key is not the tool's"
        self.cold_sk = generate_privkey()
        cold_pk = compute_xonly_pubkey(self.cold_sk)[0]

        z = self.issue(TOKEN_ATOMS)
        L = Limiter(self, z["asset"], z["token"], z["entropy"], op_pk, cold_pk)
        inst = self.tool("instance", "--asset", z["asset"], "--token", z["token"], "--entropy", z["entropy"],
                         "--operator-key", op_pk.hex(), "--cold-key", cold_pk.hex(), "--window", str(WINDOW),
                         "--allowance", str(ALLOWANCE), "--recovery-delay", str(RECOVERY_UNITS),
                         "--genesis", node.getblockhash(0))
        S0 = (0, 0, 0)
        assert inst["address"]["elementsregtest"] == L.at(S0)[2]["address"]["elementsregtest"], inst
        self.inst_path = os.path.join(tmp, "instance.json")
        with open(self.inst_path, "w") as f:
            json.dump({k: v for k, v in inst.items() if k != "address"}, f)
        self.rec("instance", {"params": L.params(), "address": inst["address"]["elementsregtest"]})
        t_in = node.sendtoaddress(address=program_to_witness(1, L.spk(S0)[2:]), amount=Decimal(TOKEN_ATOMS) / COIN,
                                  assetlabel=L.token, fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        c0 = self.utxo_of(t_in, L.spk(S0))
        self.to_age(t_in, 2)

        # ---- the tool refuses, before it signs anything --------------------------
        issuer, fc = self.fee_coin(), self.fee_coin()
        sign = lambda tx, state, words=op_file, **kw: self.tool(
            "sign", "--instance", self.inst_path, "--mnemonic-file", words, ok=False,
            request=self.request(L, tx, state, **kw))
        refusals = {
            "over_the_allowance": sign(self.round_tx(L, c0, S0, ALLOWANCE + 1, 2, issuer, fc), S0),
            "output_0_not_the_successor": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc,
                                                             claim=(ALLOWANCE - 1, 2, 0)), S0),
            "an_age_in_time": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc, seq=TIME | 2), S0),
            "an_age_of_one_block": sign(self.round_tx(L, c0, S0, ALLOWANCE, 1, issuer, fc), S0),
            "version_1": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc, version=1), S0),
            "a_new_issuance_not_a_reissuance": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc, nonce=0), S0),
            "another_entropy": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc), S0, entropy="11" * 32),
            "a_missing_spent_output": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc), S0,
                                           prevouts=[c0.txout.serialize().hex()]),
            "a_denomination_other_than_8": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc,
                                                              denomination=0), S0),
            "another_key": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc), S0, words=other_file),
            "a_coin_in_another_state": sign(self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc), (1, 0, 0)),
        }
        for k, v in refusals.items():
            self.log.info("REFUSED by the tool %-34s %s", k, v)
        self.rec("tool/refusals", refusals)

        # ---- the whole allowance, minted into a round-shaped transaction ---------
        m1 = self.tool_signed(L, self.round_tx(L, c0, S0, ALLOWANCE, 2, issuer, fc), S0, op_file)
        h = self.tool("sighash", "--instance", self.inst_path, request=self.request(L, m1, S0))
        assert h["sig_all_hash"] == self.sim_sighash(L.at(S0)[1], m1, 0).hex(), h
        self.rec("sighash/agrees_with_the_harness", h)
        # One atom over the allowance, re-signed for its own transaction: the
        # chain refuses it, beside the tool's mint as control.
        over = self.reuse(m1, self.round_tx(L, c0, S0, ALLOWANCE + 1, 2, issuer, fc), self.op_sk)
        self.reject(over, "sign/neg_one_atom_over_the_allowance", J, control=m1)
        tx1 = self.ok(m1, "sign/the_whole_allowance_into_a_round", extra={"tool": {
            k: m1.tool[k] for k in ("program_bytes", "witness_bytes", "cost_bound_milli_wu", "budget_wu", "age")}})
        f = self.tool("follow", "--instance", self.inst_path,
                      request={"coin": {"tx": node.getrawtransaction(t_in), "vout": c0.vout},
                               "state": {"minted": "0", "elapsed": 0, "armed": 0},
                               "tx": node.getrawtransaction(tx1)})
        assert f["path"] == "mint" and f["minted"] == str(ALLOWANCE), f
        self.rec("follow/the_round", f)
        S1, c1 = m1.next_state, self.coin_at(tx1, 0)

        # ---- nothing more in that window; the next window takes a whole one ------
        self.to_age(tx1, 2)
        issuer, fc = self.fee_coin(), self.fee_coin()
        self.rec("tool/refuses_a_second_mint_in_the_full_window",
                 sign(self.round_tx(L, c1, S1, 1, 2, issuer, fc), S1))
        need = WINDOW - S1[1]
        self.to_age(tx1, need)
        m2 = self.tool_signed(L, self.round_tx(L, c1, S1, ALLOWANCE, need, issuer, fc), S1, op_file)
        assert m2.next_state == (ALLOWANCE, 0, 0), m2.next_state
        self.ok(m2, "sign/a_whole_allowance_in_the_next_window")


if __name__ == "__main__":
    M3().main()
