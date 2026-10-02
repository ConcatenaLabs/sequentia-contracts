"""S0: what a 0xbe leaf is worth on a chain where Simplicity is NOT active
(the default of every custom chain, including elementsregtest)."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403


class S0(SimBase, BitcoinTestFramework):
    NAME = "s0"
    EXTRA = []                      # no -evbparams: the custom-chain default

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        node = self.node
        dep = node.getdeploymentinfo()["deployments"]
        self.rec("deployment_default", {"simplicity_listed": "simplicity" in dep, "listed": sorted(dep.keys()),
                                        "simplicity": dep.get("simplicity")})
        self.whitelist(self.X)
        sec = generate_privkey()
        prog = SimProg(src("p2pk.simf"), {"PK": vpub(compute_xonly_pubkey(sec)[0])})
        u = self.fund(prog.spk, 1_0000_0000, self.X)
        # a thief with NO key: garbage "program" and "witness", correct CMR and control block
        tx = self.mktx([u], [self.out(1_0000_0000 - 300, self.wallet_spk(), self.X_OUT), self.fee(300, self.X_OUT)])
        self.set_sim_wit(tx, 0, prog, b"\x00", b"")
        m = self.try_mempool(tx, "inactive/keyless_spend_mempool")
        b = self.try_block(tx, "inactive/keyless_spend_block")
        # The trap this test exists to show: relay policy runs Simplicity and
        # refuses the theft, but consensus does not, so a block takes it.
        assert "simplicity" not in dep
        assert not m["testmempoolaccept"], m
        assert b["mined"], b


if __name__ == "__main__":
    S0().main()
