"""S1 (part 1): pay to a one-key Simplicity program and spend it."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403


class S1(SimBase, BitcoinTestFramework):
    NAME = "s1"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("deployment", node.getdeploymentinfo()["deployments"]["simplicity"])
        self.rec("whitelist", self.whitelist(self.X))
        sec = generate_privkey()
        pk = compute_xonly_pubkey(sec)[0]
        prog = SimProg(src("p2pk.simf"), {"PK": vpub(pk)})
        self.rec("p2pk/program", prog.info())
        AMT, FEE = 1_0000_0000, 300
        dest = self.wallet_spk()

        def spend(u, signer=sec, annex=None, sign_annex=True):
            """A one-key spend. With `annex`, the annex is attached to the input;
            `sign_annex` chooses whether the signed sig_all_hash commits to it."""
            tx = self.mktx([u], [self.out(AMT - FEE, dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
            msg = self.sim_sighash(prog, tx, 0, annex=annex if sign_annex else None)
            sig = sign_schnorr(signer, msg)
            ok = signer == sec and (annex is None or sign_annex)
            # pruning replays the program, so a spend the program refuses cannot be
            # pruned; p2pk has no branches, so the unpruned encoding is identical.
            r = self.sim_satisfy(prog, tx, 0, {"SIG": vsig(sig)}, annex=annex,
                                 prune=ok, must_exec=ok)
            return tx, r, msg

        u = self.fund(prog.spk, AMT, self.X)
        # negatives first (the utxo survives). The control of each is the
        # owner's spend of the same coin into the same outputs.
        good, _, _ = spend(u)
        tx, r, _ = spend(u, signer=generate_privkey())
        self.rec("p2pk/neg_wrong_key_local", {"executed": r["executed"], "exec_error": r.get("exec_error")})
        self.reject(tx, "p2pk/neg_wrong_key", "Assertion failed inside jet", control=good)
        # a witness-stack with the wrong CMR
        tx, r, _ = spend(u)
        st = tx.wit.vtxinwit[0].scriptWitness.stack
        tx.wit.vtxinwit[0].scriptWitness.stack = [st[0], st[1][:-1] + bytes([st[1][-1] ^ 0x10]), st[2], st[3]]
        self.reject(tx, "p2pk/neg_program_bitflip", "Illegal padding in final byte of program")
        # key path attempt on the NUMS key
        tx, r, _ = spend(u)
        self.setwit(tx, 0, [os.urandom(64)])
        self.reject(tx, "p2pk/neg_keypath_random_sig", "Invalid Schnorr signature")
        # positive
        tx, r, msg = spend(u)
        m = self.sim_measure(tx, 0, r)
        m["sighash_all"] = msg.hex()
        self.send(tx, "p2pk/spend", extra=m)

        # The same spend with an 8-byte annex. The node's sig_all_hash commits to
        # the annex. A signature over the hash computed WITHOUT it must be refused;
        # one over the hash computed WITH it (the pinned library reads the annex
        # from the input's witness, as the node does) must be accepted.
        u = self.fund(prog.spk, AMT, self.X)
        annex = b"\x00" * 8
        tx, r, _ = spend(u, annex=annex, sign_annex=False)
        self.rec("p2pk/annex8_sig_without_annex_local", {"executed": r.get("executed"),
                                                         "exec_error": r.get("exec_error")})
        signed_over_annex, _, _ = spend(u, annex=annex, sign_annex=True)
        self.reject(tx, "p2pk/annex8_sig_without_annex", "Assertion failed inside jet",
                    control=signed_over_annex)
        tx, r, msg = spend(u, annex=annex, sign_annex=True)
        m = self.sim_measure(tx, 0, r)
        m["sighash_all_with_annex"] = msg.hex()
        m["annex_item_bytes"] = len(tx.wit.vtxinwit[0].scriptWitness.stack[-1])
        self.send(tx, "p2pk/spend_annex8_signed_over_annex", extra=m)

if __name__ == "__main__":
    S1().main()
