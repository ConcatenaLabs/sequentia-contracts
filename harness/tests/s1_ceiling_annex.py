"""S1 (part 2): how large and how costly a program can a transaction carry.

Budget rule (interpreter.cpp): budget_WU = min(4 * serialized_witness_stack_bytes + 50, 4_000_050),
and the program's STATIC cost bound (milli-WU) must be <= budget * 1000.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403
import time

SEC = b"\x11" * 32


class S1C(SimBase, BitcoinTestFramework):
    NAME = "s1c"

    def set_test_params(self):
        self.chain_params()
        self.rpc_timeout = 600

    def loop_src(self, K, ctr="u8"):
        pk = compute_xonly_pubkey(SEC)[0]
        msg = sha256(b"s1 ceiling")
        sig = sign_schnorr(SEC, msg)
        line = "    jet::bip_0340_verify((0x%s, 0x%s), 0x%s);\n" % (pk.hex(), msg.hex(), sig.hex())
        return (src("loop_verify.simf.in").replace("%%K%%", str(K)).replace("%%ITERS%%", str(1 << int(ctr[1:])))
                .replace("%%CTR%%", ctr).replace("%%BODY%%", line * K))

    def big_src(self, N, loopK=0):
        body = "".join("    assert!(jet::eq_256(0x%s, 0x%s));\n" % (h, h)
                       for h in (sha256(b"c%d" % i).hex() for i in range(N)))
        return src("big_consts.simf.in").replace("%%N%%", str(N)).replace("%%BODY%%", body)

    def build(self, prog, annex_len=None, amount=1_0000_0000, u=None):
        """Spend a (signature-free) program output; fee = 1 atom per vB + margin."""
        u = u or self.fund(prog.spk, amount, self.X)
        dest = self.wallet_spk()
        annex = None if annex_len is None else b"\x00" * annex_len
        fee = 1000
        for _ in range(2):
            tx = self.mktx([u], [self.out(amount - fee, dest, self.X_OUT), self.fee(fee, self.X_OUT)])
            r = self.sim_satisfy(prog, tx, 0, {}, annex=annex)
            fee = self.measure(tx)["vsize"] + 50
        return u, tx, r

    def annex_len_for(self, prog, r, tx_noannex, cost_milli):
        """Smallest annex payload length L such that 4*stack+50 >= ceil(cost/1000)."""
        need_wu = (cost_milli + 999) // 1000
        need_bytes = -(-(need_wu - BUDGET_OFFSET) // BUDGET_PER_BYTE)
        base = wit_bytes(tx_noannex.wit.vtxinwit[0].scriptWitness.stack)
        for L in range(max(0, need_bytes - base - 8), need_bytes + 8):
            item = L + 1                                   # + the 0x50 tag
            if base + (1 if item < 253 else 3 if item < 65536 else 5) + item >= need_bytes:
                return L, need_wu, need_bytes
        raise AssertionError

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X))
        self.rec("policy", {"MAX_STANDARD_TX_WEIGHT": 400000, "MAX_STANDARD_SIMPLICITY_ANNEX_SIZE": 100000,
                            "SIMPLICITY_BUDGET_PER_WITNESS_BYTE": 4, "SIMPLICITY_BUDGET_MAX": 4000050})
        self.e0_annex_probe()
        self.e1_threshold()
        self.e2_standard_annex_cap()
        self.e4_program_size()
        self.e3_budget_max()

    # -- E0: is the annex visible to a program, and does the Rust env see it?
    def e0_annex_probe(self):
        annex = b"\xaa" * 8
        want = sha256(b"\x01" + sha256(annex))          # inputAnnexesHash for one input with an annex
        none = sha256(b"\x00")
        s = "fn main() { assert!(jet::eq_256(jet::input_annexes_hash(), param::H)); }"
        for name, h, ann in (("expects_annex", want, annex), ("expects_none", none, None)):
            prog = SimProg(s, {"H": v256(h)})
            u = self.fund(prog.spk, 1_0000_0000, self.X)
            tx = self.mktx([u], [self.out(1_0000_0000 - 300, self.wallet_spk(), self.X_OUT), self.fee(300, self.X_OUT)])
            r = self.sim_satisfy(prog, tx, 0, {}, annex=ann, prune=False, must_exec=False)
            res = self.accept(tx)
            self.rec("e0/" + name, {"rust_bitmachine_executed": r["executed"], "rust_error": r.get("exec_error"),
                                    "node_testmempoolaccept": res["allowed"], "node_reject": res.get("reject-reason")})
            self.log.info("E0 %s rust=%s node=%s", name, r["executed"], res["allowed"])
            if res["allowed"]:
                self.send(tx, "e0/%s_spend" % name)

    # -- E1: exact budget threshold
    def e1_threshold(self):
        prog = SimProg(self.loop_src(1))
        self.rec("e1/program", prog.info())
        u, tx0, r = self.build(prog)
        cost = r["cost_milli"]
        base = self.sim_measure(tx0, 0, r)
        self.rec("e1/no_annex", base)
        self.reject(tx0, "e1/neg_no_annex")
        L, need_wu, need_bytes = self.annex_len_for(prog, r, tx0, cost)
        self.rec("e1/threshold", {"cost_milli": cost, "need_budget_wu": need_wu, "need_stack_bytes": need_bytes,
                                  "annex_payload_bytes": L})
        _, tx, r = self.build(prog, L - 1, u=u)
        d = self.sim_measure(tx, 0, r)
        self.rec("e1/one_byte_short", d)
        assert d["budget_wu"] < need_wu
        self.reject(tx, "e1/neg_one_byte_short")
        _, tx, r = self.build(prog, L, u=u)
        d = self.sim_measure(tx, 0, r)
        assert d["budget_wu"] >= need_wu
        self.send(tx, "e1/exact_annex", extra=d)

    # -- E2: the relay-standard annex cap (100,000 bytes including the tag)
    def e2_standard_annex_cap(self):
        for K in (29, 30):
            prog = SimProg(self.loop_src(K))
            u, tx0, r = self.build(prog)
            L, need_wu, need_bytes = self.annex_len_for(prog, r, tx0, r["cost_milli"])
            tag = "e2/K%d" % K
            self.rec(tag + "/need", {"cost_milli": r["cost_milli"], "need_budget_wu": need_wu,
                                     "annex_item_bytes_needed": L + 1, "program_bytes": r["program_bytes"]})
            if L + 1 <= 100000:
                _, tx, r = self.build(prog, 99999, u=u)       # item = 100,000 bytes: the cap
                d = self.sim_measure(tx, 0, r)
                t0 = time.time()
                self.send(tx, tag + "/annex_100000_standard", extra=d)
                self.rec(tag + "/seconds_accept_and_mine", round(time.time() - t0, 2))
                u2 = self.fund(prog.spk, 1_0000_0000, self.X)
                _, tx, r = self.build(prog, 100000, u=u2)     # item = 100,001 bytes: one past
                self.try_mempool(tx, tag + "/annex_100001_mempool")
                self.try_block(tx, tag + "/annex_100001_block")
            else:
                _, tx, r = self.build(prog, 99999, u=u)
                self.reject(tx, tag + "/neg_annex_100000_too_small")
                _, tx, r = self.build(prog, L, u=u)
                self.rec(tag + "/min_annex", self.sim_measure(tx, 0, r))
                self.try_mempool(tx, tag + "/min_annex_mempool")
                self.try_block(tx, tag + "/min_annex_block")

    # -- E4: program size
    def e4_program_size(self):
        for N in (1000, 4000, 8100):
            t0 = time.time()
            prog = SimProg(self.big_src(N))
            tag = "e4/N%d" % N
            u, tx, r = self.build(prog)
            d = self.sim_measure(tx, 0, r)
            d["compile_seconds"] = round(time.time() - t0, 1)
            d.update(self.measure(tx))
            self.rec(tag + "/program", d)
            self.log.info("E4 N=%d program=%d B weight=%d cost=%d WU budget=%d", N, d["program_bytes"],
                          d["weight"], d["cost_bound_wu"], d["budget_wu"])
            m = self.try_mempool(tx, tag + "/mempool")
            if m["testmempoolaccept"]:
                self.send(tx, tag + "/spend")
            else:
                self.try_block(tx, tag + "/block")

    # -- E3: the consensus cap BUDGET_MAX = 4,000,050 WU
    def e3_budget_max(self):
        # K=295 -> just under the cap; needs about 1 MB of witness
        for K, ctr in ((295, "u8"), (296, "u8")):
            prog = SimProg(self.loop_src(K, ctr))
            tag = "e3/K%d_%s" % (K, ctr)
            u, tx0, r = self.build(prog)
            cost = r["cost_milli"]
            need_wu = (cost + 999) // 1000
            self.rec(tag + "/need", {"cost_milli": cost, "need_budget_wu": need_wu, "over_BUDGET_MAX": need_wu > BUDGET_MAX})
            if need_wu <= BUDGET_MAX:
                L, _, _ = self.annex_len_for(prog, r, tx0, cost)
            else:
                L = 1_000_100
            _, tx, r = self.build(prog, L, u=u, amount=1_0000_0000)
            self.rec(tag + "/tx", {**self.sim_measure(tx, 0, r), **self.measure(tx)})
            self.try_mempool(tx, tag + "/mempool")
            self.try_block(tx, tag + "/block")


if __name__ == "__main__":
    S1C().main()
