"""S6: relative timelocks. What the broken lock jets (check_lock_distance,
check_lock_duration, tx_lock_distance, tx_lock_duration; spelled
broken_do_not_use_* by the pinned compiler) actually return on this node, the
bypass that defeats them, and the safe form that refuses it.

The broken-jet programs are the lint's reject fixtures; this test is the only
place allowed to compile them (allow_banned=True), to prove on-chain why the
lint exists. The safe forms are the lint's accept fixtures."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

AMT = 1_0000_0000
FEE = 600
N = 10
TYPE_FLAG = 1 << 22


class S6(SimBase, BitcoinTestFramework):
    NAME = "s6"

    def set_test_params(self):
        self.chain_params()

    def mine(self, n, step=600):
        for _ in range(n):
            self.t += step
            self.node.setmocktime(self.t)
            self.generate(self.node, 1)

    def fund_now(self, spk):
        u = self.fund(spk, AMT, self.X, mine=False)
        self.mine(1)
        return u

    def spend(self, prog, u, seq, version=2, extra=(), locktime=0, witness=None, P=None, W=None):
        """[covenant(seq)] + extra [(utxo, seq)] -> wallet + fee. Returns tx with witness set
        (pruned against itself when it executes; else re-using P/W)."""
        ins = [(u, seq)] + list(extra)
        outs = [self.out(AMT - FEE, self.wallet_spk(), self.X_OUT)]
        for e, _ in extra:
            outs.append(self.out(e.amount, self.wallet_spk(), self.POL_OUT))
        outs.append(self.fee(FEE, self.X_OUT))
        tx = self.mktx(ins, outs, locktime, version)
        if P is not None:
            self.set_sim_wit(tx, 0, prog, P, W)
            r = None
        else:
            rr = seqc(self.req(prog, tx, 0, witness or {}, False))
            if rr["executed"]:
                r = self.sim_satisfy(prog, tx, 0, witness or {})
            else:
                self.set_sim_wit(tx, 0, prog, bytes.fromhex(rr["program_hex"]), bytes.fromhex(rr["witness_hex"]))
                r = rr
        if extra:
            tx = self.wallet_sign(tx)
        return tx, r

    def outcome(self, tx, label, expect_ok, r=None):
        """Record mempool + block outcome without presuming it; assert the expectation."""
        res = self.accept(tx)
        d = {"expected": "accepted" if expect_ok else "refused", "testmempoolaccept": bool(res["allowed"]),
             "reject-reason": res.get("reject-reason"), **self.measure(tx),
             "nVersion": tx.nVersion, "nLockTime": tx.nLockTime,
             "nSequence": ["0x%08x" % i.nSequence for i in tx.vin], "height": self.node.getblockcount()}
        if r is not None and "executed" in r:
            d["rust_bitmachine_executed"] = r["executed"]
        if res["allowed"]:
            txid = self.node.sendrawtransaction(tx.serialize().hex())
            self.mine(1)
            d["confirmed"] = self.node.getrawtransaction(txid, True).get("confirmations", 0) >= 1
            self.log.info("ACCEPTED %-46s seq=%s v=%d", label, d["nSequence"], tx.nVersion)
        else:
            try:
                self.node.sendrawtransaction(tx.serialize().hex())
            except JSONRPCException as e:
                d["rpc-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
            bd = self.try_block(tx, label + "/block")
            d["block"] = bd
            # A refusal counts only when the block refuses it too.
            assert expect_ok or not bd["mined"], (label, "refused by the mempool but MINED", bd)
            self.log.info("REFUSED  %-46s %s | mined-in-block=%s", label, d.get("rpc-error"), bd["mined"])
        self.rec(label, d)
        assert res["allowed"] == expect_ok, (label, d)
        return d

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X))
        self.t = node.getblockheader(node.getbestblockhash())["time"]
        sources = {"lock_distance": banned_src("broken_check_lock_distance.simf"),
                   "lock_duration": banned_src("broken_check_lock_duration.simf"),
                   "lock_probe": banned_src("broken_lock_probe.simf"),
                   "safe_distance": safe_src("safe_distance.simf"),
                   "safe_duration": safe_src("safe_duration.simf")}
        for name, text in sources.items():
            self.rec("source/" + name, text)
        dist = SimProg(sources["lock_distance"], {"N": vu(N, 16)}, allow_banned=True)
        dur = SimProg(sources["lock_duration"], {"N": vu(2, 16)}, allow_banned=True)
        probe = SimProg(sources["lock_probe"], allow_banned=True)
        sdist = SimProg(sources["safe_distance"], {"N": vu(N, 16)})
        sdur = SimProg(sources["safe_duration"], {"N": vu(2, 16)})
        for k, p in (("lock_distance", dist), ("lock_duration", dur), ("lock_probe", probe),
                     ("safe_distance", sdist), ("safe_duration", sdur)):
            self.rec("program/" + k, p.info())

        # old wallet coins (policy asset) that will be >= 12 blocks and >= 2 h deep
        old = [self.wallet_utxo(40_000 + i) for i in range(12)]
        self.mine(12)

        # ------------------------------------------------------------ probes
        def probe_case(label, seq, version=2, extra=(), locktime=0, want=None):
            u = self.fund_now(probe.spk)
            w = {"DIST": vu(want["dist"], 16), "DUR": vu(want["dur"], 16), "HEIGHT": vu(want["height"], 32),
                 "TIME": vu(want["time"], 32), "SEQ": vu(seq, 32), "VERSION": vu(version, 32),
                 "FINAL": vu(want["final"], 1)}
            tx, r = self.spend(probe, u, seq, version, extra, locktime, witness=w)
            d = self.outcome(tx, "probe/" + label, True, r)
            d["jets_returned"] = want
            self.rec("probe/" + label, d)

        h = node.getblockcount()
        mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        probe_case("v2_seq_final", 0xffffffff, want=dict(dist=0, dur=0, height=0, time=0, final=1))
        probe_case("v2_seq_0", 0, want=dict(dist=0, dur=0, height=0, time=0, final=0))
        probe_case("v2_seq_fffffffe_locktime_h", 0xfffffffe, locktime=h,
                   want=dict(dist=0, dur=0, height=h, time=0, final=0))
        probe_case("v2_seq_final_locktime_h_IGNORED", 0xffffffff, locktime=h,
                   want=dict(dist=0, dur=0, height=0, time=0, final=1))
        probe_case("v2_seq_fffffffe_locktime_mtp", 0xfffffffe, locktime=mtp - 1,
                   want=dict(dist=0, dur=0, height=0, time=mtp - 1, final=0))
        probe_case("v2_seq_1_own", 1, want=dict(dist=1, dur=0, height=0, time=0, final=0))
        probe_case("v2_other_input_seq_7", 0xffffffff, extra=[(old[0], 7)],
                   want=dict(dist=7, dur=0, height=0, time=0, final=0))
        probe_case("v2_other_inputs_seq_7_and_time_3", 0xffffffff, extra=[(old[1], 7), (old[2], TYPE_FLAG | 3)],
                   want=dict(dist=7, dur=3, height=0, time=0, final=0))
        probe_case("v2_other_input_bit31_set_ignored", 0xffffffff, extra=[(old[3], 0x80000000 | 9)],
                   want=dict(dist=0, dur=0, height=0, time=0, final=0))
        probe_case("v2_other_input_high_bits_masked", 0xffffffff, extra=[(old[4], 0x003f0000 | 5)],
                   want=dict(dist=5, dur=0, height=0, time=0, final=0))
        probe_case("v1_other_input_seq_7", 0xffffffff, version=1, extra=[(old[5], 7)],
                   want=dict(dist=0, dur=0, height=0, time=0, final=0))

        # ------------------------------------------------------------ check_lock_distance(10)
        u = self.fund_now(dist.spk)                         # 1 confirmation
        tx, r = self.spend(dist, u, N)
        self.outcome(tx, "distance/own_seq_10_too_early", False, r)
        # THE FLAW: own sequence final, ANOTHER input (an old wallet coin) carries nSequence = 10
        u_bug = self.fund_now(dist.spk)
        tx, r = self.spend(dist, u_bug, 0xffffffff, extra=[(old[6], N)])
        self.rec("distance/BYPASS_note", {"covenant_coin_confirmations": node.gettxout(u_bug.txid, u_bug.vout)["confirmations"]})
        self.outcome(tx, "distance/BYPASS_other_input_carries_the_distance", True, r)
        # the same on the safe program
        us = self.fund_now(sdist.spk)
        us2 = self.fund_now(sdist.spk)
        # a pruned program + witness from a spend that WILL be valid later
        txv, rv = self.spend(sdist, us, N)
        simv = seqc(self.req(sdist, txv, 0, {}, True))
        PS, WS = bytes.fromhex(simv["program_hex"]), bytes.fromhex(simv["witness_hex"])
        tx, _ = self.spend(sdist, us2, 0xffffffff, extra=[(old[7], N)], P=PS, W=WS)
        self.outcome(tx, "safe_distance/other_input_carries_the_distance", False)
        tx, _ = self.spend(sdist, us2, N, P=PS, W=WS)
        self.outcome(tx, "safe_distance/own_seq_10_too_early", False)
        tx, _ = self.spend(sdist, us2, N, version=1, P=PS, W=WS)
        self.outcome(tx, "safe_distance/version_1", False)
        self.mine(N)
        # now `u` and `us`, `us2` have >= 10 confirmations
        tx, r = self.spend(dist, u, N - 1)
        self.outcome(tx, "distance/own_seq_9_after_10_blocks", False, r)
        tx, r = self.spend(dist, u, N, version=1)
        self.outcome(tx, "distance/own_seq_10_version_1", False, r)
        tx, r = self.spend(dist, u, TYPE_FLAG | N)
        self.outcome(tx, "distance/own_seq_is_a_TIME_lock_of_10", False, r)
        tx, r = self.spend(dist, u, N)
        self.outcome(tx, "distance/own_seq_10_after_10_blocks", True, r)
        tx, _ = self.spend(sdist, us2, TYPE_FLAG | N, P=PS, W=WS)
        self.outcome(tx, "safe_distance/own_seq_is_a_TIME_lock", False)
        tx, _ = self.spend(sdist, us2, N - 1, P=PS, W=WS)
        self.outcome(tx, "safe_distance/own_seq_9", False)
        tx, _ = self.spend(sdist, us2, N, P=PS, W=WS)
        self.outcome(tx, "safe_distance/own_seq_10_after_10_blocks", True)
        tx, r = self.spend(sdist, us, 0x003f0000 | N)
        self.outcome(tx, "safe_distance/own_seq_10_with_unused_bits_set", True, r)

        # ------------------------------------------------------------ check_lock_duration(2)  (2 x 512 s)
        ud = self.fund_now(dur.spk)
        tx, r = self.spend(dur, ud, TYPE_FLAG | 2)
        self.outcome(tx, "duration/own_seq_time2_too_early", False, r)
        ud_bug = self.fund_now(dur.spk)
        tx, r = self.spend(dur, ud_bug, 0xffffffff, extra=[(old[8], TYPE_FLAG | 2)])
        self.outcome(tx, "duration/BYPASS_other_input_carries_the_duration", True, r)
        usd = self.fund_now(sdur.spk)
        txv, rv = self.spend(sdur, usd, TYPE_FLAG | 2)
        simv = seqc(self.req(sdur, txv, 0, {}, True))
        PD, WD = bytes.fromhex(simv["program_hex"]), bytes.fromhex(simv["witness_hex"])
        tx, _ = self.spend(sdur, usd, 0xffffffff, extra=[(old[9], TYPE_FLAG | 2)], P=PD, W=WD)
        self.outcome(tx, "safe_duration/other_input_carries_the_duration", False)
        tx, _ = self.spend(sdur, usd, TYPE_FLAG | 2, P=PD, W=WD)
        self.outcome(tx, "safe_duration/own_seq_time2_too_early", False)
        self.mine(8, step=600)                              # MTP moves well past 1024 s
        tx, r = self.spend(dur, ud, TYPE_FLAG | 1)
        self.outcome(tx, "duration/own_seq_time1_after_wait", False, r)
        tx, r = self.spend(dur, ud, 2)
        self.outcome(tx, "duration/own_seq_is_a_BLOCK_lock_of_2", False, r)
        tx, r = self.spend(dur, ud, TYPE_FLAG | 2)
        self.outcome(tx, "duration/own_seq_time2_after_wait", True, r)
        tx, _ = self.spend(sdur, usd, TYPE_FLAG | 2, P=PD, W=WD)
        self.outcome(tx, "safe_duration/own_seq_time2_after_wait", True)


if __name__ == "__main__":
    S6().main()
