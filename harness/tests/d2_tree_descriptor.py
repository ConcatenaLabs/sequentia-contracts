"""D2: a tree of three leaves, addressed and spent from its descriptor alone.

The template `one_key_exit` is a Simplicity one-key leaf beside the data leaf
that holds its key, and a tapscript exit leaf with a relative delay:

    P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(CMR), H_TapData(PK)),
                         TapLeaf_0xc4(<EXIT_DELAY> CSV DROP <EXIT_KEY> CHECKSIG)))

Each instance here is one of the template's golden vectors, which the Rust
crate and the Python, JavaScript and Go mirrors all derive the same, so the
address funded is the one all four compute. The Python mirror gives the
script, each leaf's control block and the exit script; the program is compiled
from the source the descriptor names, whose hash it records. Each leaf is
spent, and each violation is refused by the mempool and in a block forced with
`generateblock`, for its reason. With one key for both paths, each path's
signature is offered on the other and refused: the program signs
sig_all_hash, which commits to its own leaf and path, and the exit signs the
BIP341 hash of its own leaf."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

TESTNET_GENESIS = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e"
AMT, FEE = 1_0000_0000, 1000
J = "Assertion failed inside jet"


def secret(n):
    return int(n).to_bytes(32, "big")


class D2(SimBase, BitcoinTestFramework):
    NAME = "d2"

    def set_test_params(self):
        self.chain_params()

    def instance(self, name):
        """A golden vector by name, re-derived by the Python mirror, and the
        node's reading of its address."""
        case = next(c for c in self.vectors["addresses"] if c["name"] == name)
        got = self.sa.derive(self.desc, case["params"], case["slots"])
        assert got == {k: case[k] for k in got}, name
        info = self.node.getaddressinfo(case["address"]["elementsregtest"])
        assert info["scriptPubKey"] == case["script_pubkey"], (name, info)
        self.rec("instance/" + name, {"params": case["params"], "address": case["address"]["elementsregtest"],
                                      "script_pubkey": case["script_pubkey"],
                                      "node_decodes_address_to": info["scriptPubKey"],
                                      "leaves": case["leaves"]})
        return case

    def fund_vector(self, case):
        """Pays the vector's regtest address, from the address alone."""
        txid = self.node.sendtoaddress(address=case["address"]["elementsregtest"], amount=Decimal(AMT) / COIN,
                                       assetlabel=self.X, fee_asset_label=BITCOIN_ASSET)
        return txid

    def spend_leaf(self, case):
        text, body = self.sources["spend"]
        return TreeLeaf(text, bytes.fromhex(body["cmr"]), bytes.fromhex(case["leaves"]["spend"]["control_block"]))

    def key_spend(self, case, leaf, coin, sk):
        """The spend leaf's spend of `coin`, signed by `sk` over sig_all_hash."""
        tx = self.mktx([coin], [self.out(AMT - FEE, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
        msg = self.sim_sighash(leaf, tx, 0)
        sig = sign_schnorr(sk, msg)
        pk = bytes.fromhex(case["params"]["PK"])
        r = self.sim_satisfy(leaf, tx, 0, {"PK": vpub(pk), "SIG": vsig(sig)})
        return tx, r, msg, sig

    def exit_spend(self, case, coin, sk, sequence=None, version=2):
        """The exit leaf's spend of `coin`, signed by `sk`, from the script and
        control block the mirror derived."""
        script = bytes.fromhex(case["leaves"]["exit"]["script"])
        cb = bytes.fromhex(case["leaves"]["exit"]["control_block"])
        seq = int(case["params"]["EXIT_DELAY"], 16) if sequence is None else sequence
        tx = self.mktx([(coin, seq)], [self.out(AMT - FEE, self.dest, self.X_OUT), self.fee(FEE, self.X_OUT)],
                       version=version)
        sig = self.sign(sk, tx, 0, script)
        self.setwit(tx, 0, [sig, script, cb])
        return tx

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        self.dest = self.wallet_spk()
        self.sa, self.desc, self.vectors, self.sources = load_template("one_key_exit")
        self.rec("template", {"template_hash": self.desc["template_hash"],
                              "spend_cmr": self.sources["spend"][1]["cmr"],
                              "spend_max_cost_wu": self.sources["spend"][1]["max_cost_wu"]})

        a = self.instance("secret keys 1 and 2, exit after 1,024 seconds")
        b = self.instance("secret key 3 for both paths, exit after 1,024 seconds")
        assert a["output_key_parity"] == 1
        sk1, sk2, sk3 = secret(1), secret(2), secret(3)
        assert compute_xonly_pubkey(sk1)[0].hex() == a["params"]["PK"]
        assert compute_xonly_pubkey(sk2)[0].hex() == a["params"]["EXIT_KEY"]
        assert compute_xonly_pubkey(sk3)[0].hex() == b["params"]["PK"] == b["params"]["EXIT_KEY"]

        # Two coins at each instance, all confirmed in one block.
        txids = [self.fund_vector(a), self.fund_vector(a), self.fund_vector(b), self.fund_vector(b)]
        self.generate(node, 1)
        spk_a, spk_b = bytes.fromhex(a["script_pubkey"]), bytes.fromhex(b["script_pubkey"])
        a1, a2 = self.utxo_of(txids[0], spk_a), self.utxo_of(txids[1], spk_a)
        b1, b2 = self.utxo_of(txids[2], spk_b), self.utxo_of(txids[3], spk_b)
        funded_at = node.getblockcount()

        # --- The Simplicity leaf ------------------------------------------------
        la = self.spend_leaf(a)
        good, r, msg, sig = self.key_spend(a, la, a1, sk1)
        # Another key, which signs correctly, in place of the one in the data leaf.
        tx, r2, msg2, sig2 = self.key_spend(a, la, a1, sk1)
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        other_pk = compute_xonly_pubkey(sk2)[0]
        w = bit_replace(st[0], bytes.fromhex(a["params"]["PK"]), other_pk)
        w = bit_replace(w, sig2, sign_schnorr(sk2, msg2))
        self.set_sim_wit(tx, 0, la, st[1], w)
        self.reject(tx, "spend/neg_key_not_in_the_data_leaf", J, control=good)
        # The right key, a signature by another.
        tx, r2, msg2, sig2 = self.key_spend(a, la, a1, sk1)
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        self.set_sim_wit(tx, 0, la, st[1], bit_replace(st[0], sig2, sign_schnorr(sk2, msg2)))
        self.reject(tx, "spend/neg_signature_by_another_key", J, control=good)
        # The right key's signature over the same transaction on another chain.
        tx, r2, msg2, sig2 = self.key_spend(a, la, a1, sk1)
        req = self.req(la, tx, 0)
        req["genesis"] = TESTNET_GENESIS
        elsewhere = bytes.fromhex(seqc(req)["sighash_all"])
        assert elsewhere != msg2
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        self.set_sim_wit(tx, 0, la, st[1], bit_replace(st[0], sig2, sign_schnorr(sk1, elsewhere)))
        self.reject(tx, "spend/neg_signed_for_another_chain", J, control=good)
        # The program revealed under the exit leaf's control block.
        tx, _, _, _ = self.key_spend(a, la, a1, sk1)
        st = list(tx.wit.vtxinwit[0].scriptWitness.stack)
        st[3] = bytes.fromhex(a["leaves"]["exit"]["control_block"])
        self.setwit(tx, 0, st)
        self.reject(tx, "spend/neg_under_the_exit_control_block", "Witness program hash mismatch",
                    mempool="bad-witness-nonstandard")
        m = self.sim_measure(good, 0, r)
        assert m["cost_bound_wu"] <= self.sources["spend"][1]["max_cost_wu"], m
        self.send(good, "spend/by_the_simplicity_leaf", extra=m)

        # --- The tapscript exit -------------------------------------------------
        early = self.exit_spend(a, a2, sk2)
        self.reject(early, "exit/neg_before_its_delay", "bad-txns-nonfinal", mempool="non-BIP68-final")
        # Wait out the delay: the median time past moves 2 x 512 seconds and more.
        coin_time = node.getblockheader(node.getblockhash(funded_at - 1))["mediantime"]
        t = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(t + 1500)
        self.generate(node, 12)
        tip_mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert tip_mtp >= coin_time + 2 * 512, (tip_mtp, coin_time)
        self.rec("exit/delay", {"coin_time": coin_time, "tip_median_time": tip_mtp,
                                "waited_seconds": tip_mtp - coin_time, "delay_seconds": 1024})
        good_exit = self.exit_spend(a, a2, sk2)
        assert self.accept(good_exit)["allowed"]
        self.reject(self.exit_spend(a, a2, sk2, sequence=0x00400001), "exit/neg_sequence_below_the_delay",
                    "Locktime requirement not satisfied")
        self.reject(self.exit_spend(a, a2, sk2, sequence=0x00000002), "exit/neg_a_lock_in_blocks_not_time",
                    "Locktime requirement not satisfied")
        self.reject(self.exit_spend(a, a2, sk2, sequence=0xffffffff), "exit/neg_the_lock_disabled",
                    "Locktime requirement not satisfied")
        self.reject(self.exit_spend(a, a2, sk2, version=1), "exit/neg_version_1",
                    "Locktime requirement not satisfied")
        self.reject(self.exit_spend(a, a2, sk1), "exit/neg_signed_by_the_owner_key", "Invalid Schnorr signature")
        self.send(good_exit, "exit/by_the_tapscript_leaf",
                  extra={"witness_stack": [len(x) for x in good_exit.wit.vtxinwit[0].scriptWitness.stack]})

        # --- One key for both paths: each path's signature on the other ---------
        lb = self.spend_leaf(b)
        good_b, rb, _, _ = self.key_spend(b, lb, b1, sk3)
        tx, _, _, sigb = self.key_spend(b, lb, b1, sk3)
        exit_sig = self.sign(sk3, tx, 0, bytes.fromhex(b["leaves"]["exit"]["script"]))
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        self.set_sim_wit(tx, 0, lb, st[1], bit_replace(st[0], sigb, exit_sig))
        self.reject(tx, "same_key/neg_spend_leaf_with_the_exit_signature", J, control=good_b)
        good_b_exit = self.exit_spend(b, b2, sk3)
        tx = self.exit_spend(b, b2, sk3)
        st = list(tx.wit.vtxinwit[0].scriptWitness.stack)
        st[0] = sign_schnorr(sk3, self.sim_sighash(lb, tx, 0))
        self.setwit(tx, 0, st)
        self.reject(tx, "same_key/neg_exit_with_the_spend_leaf_signature", "Invalid Schnorr signature",
                    control=good_b_exit)
        self.send(good_b, "same_key/by_the_simplicity_leaf", extra=self.sim_measure(good_b, 0, rb))
        self.send(good_b_exit, "same_key/by_the_tapscript_leaf")


if __name__ == "__main__":
    D2().main()
