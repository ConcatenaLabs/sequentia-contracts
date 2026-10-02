"""S1 (part 3): budget bought with witness data instead of an annex, the
memory (cell) limit, and the largest cost carried by a relay-standard tx here."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
import time

SEC = b"\x11" * 32
CELLS_MAX = 0x500000


class S1D(SimBase, BitcoinTestFramework):
    NAME = "s1d"

    def set_test_params(self):
        self.chain_params()
        self.rpc_timeout = 600

    def psrc(self, K, PAD):
        pk = compute_xonly_pubkey(SEC)[0]
        msg = sha256(b"s1 ceiling")
        sig = sign_schnorr(SEC, msg)
        line = "    jet::bip_0340_verify((0x%s, 0x%s), 0x%s);\n" % (pk.hex(), msg.hex(), sig.hex())
        return src("loop_verify_padded.simf.in").replace("%%PAD%%", str(PAD)).replace("%%BODY%%", line * K)

    def build(self, K, PAD, annex_len=None, amount=1_0000_0000, auto_annex=False):
        prog = SimProg(self.psrc(K, PAD))
        u = self.fund(prog.spk, amount, self.X)
        w = {"PAD": vraw("[" + ", ".join("0x" + os.urandom(32).hex() for _ in range(PAD)) + "]", "[u256; %d]" % PAD)}
        fee = 1000
        for _ in range(3):
            tx = self.mktx([u], [self.out(amount - fee, self.wallet_spk(), self.X_OUT), self.fee(fee, self.X_OUT)])
            annex = None if annex_len is None else b"\x00" * annex_len
            r = self.sim_satisfy(prog, tx, 0, w, annex=annex)
            fee = self.measure(tx)["vsize"] + 50
            if auto_annex:
                need = (r["cost_milli"] + 999) // 1000
                have = self.budget(tx, 0)
                if have < need:
                    annex_len = (annex_len or 0) + -(-(need - have) // 4) + 6
        return prog, tx, r

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X))

        # (a) witness data that is read buys budget: no annex at all
        prog, tx, r = self.build(1, 200)
        d = {**self.sim_measure(tx, 0, r), "extra_cells": r["extra_cells"]}
        self.send(tx, "pad/K1_PAD200_no_annex", extra=d)

        # (b) memory limit: CELLS_MAX = 5,242,880 bits
        for PAD in (4000, 6000, 8000):
            prog, tx, r = self.build(1, PAD)
            d = {**self.sim_measure(tx, 0, r), "extra_cells_rust_bound": r["extra_cells"], "CELLS_MAX": CELLS_MAX}
            self.rec("mem/PAD%d/program" % PAD, d)
            m = self.try_mempool(tx, "mem/PAD%d/mempool" % PAD)
            if m["testmempoolaccept"]:
                self.send(tx, "mem/PAD%d/spend" % PAD, extra=d)
            else:
                self.try_block(tx, "mem/PAD%d/block" % PAD)

        # (c) > 1,000,000 WU in one relay-standard transaction:
        #     100,000-byte annex cap + read witness data
        prog, tx, r = self.build(70, 5000, auto_annex=True)
        d = {**self.sim_measure(tx, 0, r), "extra_cells_rust_bound": r["extra_cells"],
             "annex_item_bytes": len(tx.wit.vtxinwit[0].scriptWitness.stack[-1])}
        self.rec("big/K70_PAD5000/program", d)
        t0 = time.time()
        res = self.accept(tx)
        d["testmempoolaccept_seconds"] = round(time.time() - t0, 2)
        self.send(tx, "big/K70_PAD5000/spend", extra=d)


if __name__ == "__main__":
    S1D().main()
