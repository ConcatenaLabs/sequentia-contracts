"""D1: the one-key template, addressed from its descriptor with no compiler.

The address of an instance is derived by the Python mirror from the descriptor
and the owner's key alone, the node decodes it to the scriptPubKey the harness
builds from the compiled program, the wallet pays to that address, and the
owner spends it. A key that is not the one in the data leaf, and a signature by
another key, are each refused by the mempool and in a block."""
import json
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
sys.path.insert(0, os.path.join(REPO_ROOT, "mirrors", "python"))
import sequentia_address  # noqa: E402

TEMPLATE = os.path.join(REPO_ROOT, "templates", "one_key")


class D1(SimBase, BitcoinTestFramework):
    NAME = "d1"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        with open(os.path.join(TEMPLATE, "descriptor.json")) as f:
            descriptor = json.load(f)
        with open(os.path.join(TEMPLATE, descriptor["template"]["program"]["source"])) as f:
            source = f.read()

        sec = generate_privkey()
        pk = compute_xonly_pubkey(sec)[0]
        other_sec = generate_privkey()
        other_pk = compute_xonly_pubkey(other_sec)[0]

        # The address, from the descriptor alone.
        derived = sequentia_address.derive(descriptor, {"PK": pk.hex()})
        address = derived["address"]["elementsregtest"]
        info = node.getaddressinfo(address)
        prog = SimProg(source, {}).with_data(pk)
        assert prog.cmr.hex() == descriptor["template"]["program"]["cmr"]
        assert info["scriptPubKey"] == derived["script_pubkey"] == prog.spk.hex(), (info, derived)
        self.rec("instance", {"template_hash": descriptor["template_hash"], "PK": pk.hex(),
                              "address": address, "script_pubkey": derived["script_pubkey"],
                              "node_decodes_address_to": info["scriptPubKey"]})

        AMT, FEE = 1_0000_0000, 300
        dest = self.wallet_spk()
        txid = node.sendtoaddress(address=address, amount=Decimal(AMT) / COIN, assetlabel=self.X,
                                  fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        u = self.utxo_of(txid, prog.spk)

        def spend():
            tx = self.mktx([u], [self.out(AMT - FEE, dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
            msg = self.sim_sighash(prog, tx, 0)
            sig = sign_schnorr(sec, msg)
            r = self.sim_satisfy(prog, tx, 0, {"PK": vpub(pk), "SIG": vsig(sig)})
            return tx, r, msg, sig

        # Another key, which signs correctly, in place of the key in the data leaf.
        tx, r, msg, sig = spend()
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        w = bit_replace(st[0], pk, other_pk)
        w = bit_replace(w, sig, sign_schnorr(other_sec, msg))
        self.set_sim_wit(tx, 0, prog, st[1], w)
        self.reject(tx, "one_key/neg_key_not_in_data_leaf")

        # The right key, a signature by another.
        tx, r, msg, sig = spend()
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        w = bit_replace(st[0], sig, sign_schnorr(other_sec, msg))
        self.set_sim_wit(tx, 0, prog, st[1], w)
        self.reject(tx, "one_key/neg_signature_by_another_key")

        # The owner's spend.
        tx, r, msg, sig = spend()
        m = self.sim_measure(tx, 0, r)
        self.send(tx, "one_key/spend", extra=m)


if __name__ == "__main__":
    D1().main()
