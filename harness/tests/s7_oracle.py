"""S7: BIP340 oracle statement over (asset id, price, timestamp) and a
128-bit collateral check."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

COLL = 5_000_000_000                 # 50.00000000 units of collateral
DEBT = 200_000_000_000_000
THRESHOLD = 150_000_000              # 1.5 in 1e8 fixed point
RHS = DEBT * THRESHOLD               # 3e22, far above 2^64
BOUNDARY = RHS // COLL               # price at which COLL * price == RHS exactly
FEE = 500
TAG = b"ArcaOrc1"


def oracle_msg(asset32, price, ts):
    return sha256(TAG + asset32 + int(price).to_bytes(8, "big") + int(ts).to_bytes(4, "big"))


class S7(SimBase, BitcoinTestFramework):
    NAME = "s7"

    def set_test_params(self):
        self.chain_params()

    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        o_sec, l_sec = generate_privkey(), generate_privkey()
        o_x, l_x = compute_xonly_pubkey(o_sec)[0], compute_xonly_pubkey(l_sec)[0]
        NOT_BEFORE = 1_790_000_000
        source = src("oracle_liquidation.simf")
        self.rec("source", source)
        prog = SimProg(source, {"ORACLE": vpub(o_x), "LENDER": vpub(l_x), "DEBT": vu(DEBT), "THRESHOLD": vu(THRESHOLD),
                                "NOT_BEFORE": vu(NOT_BEFORE, 32)})
        assert COLL * BOUNDARY == RHS and RHS > 2 ** 64
        # a healthy price whose 64-bit-truncated product would look "below" the threshold
        trap = -(-((RHS // 2 ** 64 + 1) * 2 ** 64) // COLL)      # first price whose product wraps past 2^64 again
        assert trap > BOUNDARY and (COLL * trap) % 2 ** 64 < RHS % 2 ** 64 and COLL * trap > RHS
        self.rec("program", {**prog.info(), "collateral_atoms": COLL, "debt": DEBT, "threshold": THRESHOLD,
                             "rhs_debt_times_threshold": str(RHS), "rhs_bits": RHS.bit_length(),
                             "boundary_price": BOUNDARY, "trap_price": trap,
                             "trap_lhs": str(COLL * trap), "trap_lhs_low64": str((COLL * trap) % 2 ** 64),
                             "rhs_low64": str(RHS % 2 ** 64)})
        u = self.fund(prog.spk, COLL, self.X)
        uy = self.fund(prog.spk, COLL, self.Y)
        dest = self.wallet_spk()

        def build(u, price, ts, asset_out, asset_id, oracle_sec=o_sec, lender_sec=l_sec, signed_price=None,
                  signed_asset=None, ok=True):
            tx = self.mktx([u], [self.out(COLL - FEE, dest, asset_out), self.fee(FEE, asset_out)])
            osig = sign_schnorr(oracle_sec, oracle_msg(signed_asset or asset_id, price if signed_price is None else signed_price, ts))
            lsig = sign_schnorr(lender_sec, self.sim_sighash(prog, tx, 0))
            W = {"PRICE": vu(price), "TIMESTAMP": vu(ts, 32), "ORACLE_SIG": vsig(osig), "LENDER_SIG": vsig(lsig)}
            r = self.sim_satisfy(prog, tx, 0, W, prune=ok, must_exec=ok)
            return tx, r

        ts = NOT_BEFORE + 3600
        X, XO = self.X_ID, self.X_OUT
        J = "Assertion failed inside jet"
        # The negatives are not pruned (pruning replays the program, which
        # refuses them). Their control is a liquidation at a price below the
        # boundary, built the same way, which the node accepts; each negative
        # differs from it in the one value it gets wrong.
        ctl, _ = build(u, BOUNDARY - 1, ts, XO, X, ok=False)
        ctl_y, _ = build(uy, BOUNDARY - 1, ts, self.Y_OUT, self.Y_ID, ok=False)
        tx, _ = build(u, BOUNDARY, ts, XO, X, ok=False)
        self.reject(tx, "neg_price_exactly_at_boundary", J, control=ctl)
        tx, _ = build(u, BOUNDARY + 1, ts, XO, X, ok=False)
        self.reject(tx, "neg_healthy_price_boundary_plus_1", J, control=ctl)
        tx, _ = build(u, trap, ts, XO, X, ok=False)
        self.reject(tx, "neg_healthy_price_that_a_64bit_product_would_pass", J, control=ctl)
        tx, _ = build(u, BOUNDARY - 1, ts, XO, X, oracle_sec=generate_privkey(), ok=False)
        self.reject(tx, "neg_price_signed_by_another_key", J, control=ctl)
        tx, _ = build(u, BOUNDARY - 1, ts, XO, X, signed_price=BOUNDARY + 5, ok=False)
        self.reject(tx, "neg_witness_price_differs_from_signed_price", J, control=ctl)
        tx, _ = build(u, BOUNDARY - 1, NOT_BEFORE - 1, XO, X, ok=False)
        self.reject(tx, "neg_statement_older_than_not_before", J, control=ctl)
        tx, _ = build(u, BOUNDARY - 1, ts, XO, X, lender_sec=generate_privkey(), ok=False)
        self.reject(tx, "neg_lender_signature_by_stranger", J, control=ctl)
        # a low price the oracle signed for asset X, used on a coin of asset Y
        tx, _ = build(uy, BOUNDARY - 1, ts, self.Y_OUT, self.Y_ID, signed_asset=X, ok=False)
        self.reject(tx, "neg_price_for_asset_X_used_on_coin_of_asset_Y", J, control=ctl_y)

        tx, r = build(u, BOUNDARY - 1, ts, XO, X)
        self.send(tx, "liquidate_at_boundary_minus_1", extra=self.sim_measure(tx, 0, r))
        tx, r = build(uy, 1, ts, self.Y_OUT, self.Y_ID)
        self.send(tx, "liquidate_asset_Y_price_1", extra=self.sim_measure(tx, 0, r))


if __name__ == "__main__":
    S7().main()
