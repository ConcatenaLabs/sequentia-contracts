"""F1: the faucet drip covenant, addressed and spent from its descriptor.

The template `faucet_drip` holds a faucet's reserve:

    P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(drip), H_TapData(params)),
                         TapLeaf_0xc4(<RECOVERY_DELAY> CSV DROP <TREASURY_KEY> CHECKSIG)))

A drip spends the reserve (input 0), pays at most the tier for its amount to
output 1, pays fees of at most the cap in the reserve's asset, and re-creates
the reserve at output 0 with exactly the rest; the reserve's own sequence must
show the interval has passed, and the faucet key signs. The recovery leaf lets
the treasury key take everything once the reserve has gone a long delay
without a drip.

The instance is derived by the Python mirror from the descriptor alone: the
address, both leaves' control blocks and the recovery script. A drip confirms,
and its successor is spent by the next drip. Every violation is refused by the
mempool and in a block forced with `generateblock`, each for its reason; a
refusal whose error is a failed assertion names a control, a transaction that
differs from it only in the property it breaks and that the node accepts. A
negative reuses its control's pruned program, re-signed for its own
transaction, so it takes the control's branches up to the check it breaks."""
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

J, A = "Assertion failed inside jet", "Assertion failed"
TIME = 1 << 22
INTERVAL = 2                         # units of 512 seconds
RECOVERY_UNITS = 4
FEE, FEE_CAP = 2000, 3000
TIERS = {"TIER1_FLOOR": 10**12, "TIER1_MAX": 5 * 10**8, "TIER2_FLOOR": 10**11, "TIER2_MAX": 2 * 10**8,
         "TIER3_FLOOR": 10**10, "TIER3_MAX": 2 * 10**7, "TIER4_MAX": 2 * 10**6}
RESERVE = 2 * 10**12


class F1(SimBase, BitcoinTestFramework):
    NAME = "f1"

    def set_test_params(self):
        self.chain_params()

    # -- the instance --------------------------------------------------------
    def params(self, faucet_pk, treasury_pk):
        p = {"ASSET": self.X_ID.hex(), "FAUCET_KEY": faucet_pk.hex(), "INTERVAL": "%04x" % INTERVAL,
             "FEE_CAP": "%016x" % FEE_CAP, "RECOVERY_DELAY": "%08x" % (TIME | RECOVERY_UNITS),
             "TREASURY_KEY": treasury_pk.hex()}
        p.update({k: "%016x" % v for k, v in TIERS.items()})
        return p

    def instance(self, faucet_pk, treasury_pk):
        x = self.sa.derive(self.desc, self.params(faucet_pk, treasury_pk))
        info = self.node.getaddressinfo(x["address"]["elementsregtest"])
        assert info["scriptPubKey"] == x["script_pubkey"], info
        return x

    def witness(self, sig, overrides=None):
        w = {"ASSET": v256(self.X_ID), "FAUCET_KEY": vpub(self.faucet_pk), "INTERVAL": vu(INTERVAL, 16),
             "FEE_CAP": vu(FEE_CAP, 64), "SIG": vsig(sig)}
        w.update({k: vu(v, 64) for k, v in TIERS.items()})
        w.update(overrides or {})
        return w

    # -- transactions --------------------------------------------------------
    def drip_tx(self, coin, drip, fee=FEE, succ=None, succ_spk=None, succ_asset=None, drip_spk=None,
                drip_asset=None, seq=None, version=2, ins=(), outs=()):
        """A drip of `drip` from `coin`; each argument changes one property."""
        reserve = coin.amount
        succ = reserve - drip - fee if succ is None else succ
        o = [self.out(succ, succ_spk or self.spk, succ_asset or self.X_OUT),
             self.out(drip, drip_spk or self.dest, drip_asset or self.X_OUT)]
        o += list(outs) + [self.fee(fee, self.X_OUT)]
        return self.mktx([(coin, TIME | INTERVAL if seq is None else seq)] + list(ins), o, version=version)

    def signed(self, tx, sk=None):
        """Satisfies and prunes the drip against `tx`, signed by the faucet key."""
        msg = self.sim_sighash(self.leaf, tx, 0)
        sig = sign_schnorr(sk or self.faucet_sk, msg)
        r = self.sim_satisfy(self.leaf, tx, 0, self.witness(sig))
        tx.sig, tx.r = sig, r
        return tx

    def reuse(self, control, tx, witness=None, sig=None):
        """`tx` with the control's pruned program and witness, its signature
        made again for `tx` (or `sig`, as given)."""
        w = bytes.fromhex(control.r["witness_hex"]) if witness is None else witness
        new = sig if sig is not None else sign_schnorr(self.faucet_sk, self.sim_sighash(self.leaf, tx, 0))
        self.set_sim_wit(tx, 0, self.leaf, bytes.fromhex(control.r["program_hex"]), bit_replace(w, control.sig, new))
        return tx

    def recovery_tx(self, coin, sk, seq=None):
        script = bytes.fromhex(self.inst["leaves"]["recover"]["script"])
        cb = bytes.fromhex(self.inst["leaves"]["recover"]["control_block"])
        tx = self.mktx([(coin, TIME | RECOVERY_UNITS if seq is None else seq)],
                       [self.out(coin.amount - FEE, self.treasury_dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.setwit(tx, 0, [self.sign(sk, tx, 0, script), script, cb])
        return tx

    def advance(self, seconds):
        """Moves the median time past forward by at least `seconds`."""
        node = self.node
        before = node.getblockheader(node.getbestblockhash())["mediantime"]
        t = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(t + seconds + 60)
        self.generate(node, 12)
        after = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert after >= before + seconds, (before, after)

    def waited(self, coin_txid):
        """Seconds of median time past since the coin's confirmation counts from."""
        node = self.node
        h = node.getrawtransaction(coin_txid, True)["blockhash"]
        height = node.getblockheader(h)["height"]
        start = node.getblockheader(node.getblockhash(height - 1))["mediantime"]
        return node.getblockheader(node.getbestblockhash())["mediantime"] - start

    def ok(self, tx, label, extra=None):
        m = self.sim_measure(tx, 0, tx.r) if hasattr(tx, "r") else {}
        m.update(extra or {})
        return self.send(tx, label, extra=m)

    # -- the test ------------------------------------------------------------
    def run_test(self):
        self.boot()
        node = self.node
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.dest = self.wallet_spk()
        self.treasury_dest = self.wallet_spk()
        self.sa, self.desc, self.vectors, self.sources = load_template("faucet_drip")
        text, body = self.sources["drip"]
        self.faucet_sk, self.treasury_sk = generate_privkey(), generate_privkey()
        self.faucet_pk = compute_xonly_pubkey(self.faucet_sk)[0]
        self.treasury_pk = compute_xonly_pubkey(self.treasury_sk)[0]
        self.inst = self.instance(self.faucet_pk, self.treasury_pk)
        self.spk = bytes.fromhex(self.inst["script_pubkey"])
        self.leaf = TreeLeaf(text, bytes.fromhex(body["cmr"]), bytes.fromhex(self.inst["leaves"]["drip"]["control_block"]))
        other = self.instance(compute_xonly_pubkey(generate_privkey())[0], self.treasury_pk)
        self.rec("instance", {"template_hash": self.desc["template_hash"], "cmr": body["cmr"],
                              "max_cost_wu": body["max_cost_wu"], "params": self.params(self.faucet_pk, self.treasury_pk),
                              "address": self.inst["address"]["elementsregtest"], "script_pubkey": self.inst["script_pubkey"],
                              "leaves": self.inst["leaves"]})

        # The reserve, a second reserve of the same amount, one just under the
        # first tier's floor, and a coin of another asset, all at the covenant
        # address, confirmed together.
        addr = self.inst["address"]["elementsregtest"]
        pay = lambda atoms, asset: node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel=asset,
                                                      fee_asset_label=BITCOIN_ASSET)
        t0, t2 = pay(RESERVE, self.X), pay(RESERVE, self.X)
        tb, ty = pay(TIERS["TIER1_FLOOR"] - 1, self.X), pay(RESERVE, self.Y)
        old = self.wallet_utxo(50_000)              # an old coin of the spender's own, for the bypass
        self.generate(node, 1)
        c0, c2 = self.utxo_of(t0, self.spk), self.utxo_of(t2, self.spk)
        cb, cy = self.utxo_of(tb, self.spk), self.utxo_of(ty, self.spk)
        D1 = TIERS["TIER1_MAX"]

        # A drip before the interval has passed.
        early = self.signed(self.drip_tx(c0, D1))
        self.reject(early, "drip/neg_before_the_interval", "bad-txns-nonfinal", mempool="non-BIP68-final")

        self.advance(INTERVAL * 512)
        self.rec("drip/waited_seconds", self.waited(t0))
        good = self.signed(self.drip_tx(c0, D1))
        assert self.accept(good)["allowed"]

        # The interval, through this input's own sequence.
        self.reject(self.reuse(good, self.drip_tx(c0, D1, seq=TIME | (INTERVAL - 1))),
                    "drip/neg_sequence_below_the_interval", J, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1, seq=0xffffffff)),
                    "drip/neg_lock_disabled", A, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1, seq=INTERVAL)),
                    "drip/neg_lock_in_blocks", A, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1, version=1)),
                    "drip/neg_version_1", J, control=good)
        # The bypass that defeats the broken jets: this input's lock off, an old
        # coin of the spender's own carrying it. The control has the same two
        # inputs and outputs, the lock on the reserve.
        # One fee asset per transaction: the old coin goes back whole, and the
        # reserve's asset pays the fee.
        extra = [self.out(50_000, self.wallet_spk(), self.POL_OUT)]
        unsigned = self.signed(self.drip_tx(c0, D1, ins=[(old, 0xffffffff)], outs=extra))
        ctl = self.wallet_sign(unsigned)
        ctl.r, ctl.sig = unsigned.r, unsigned.sig
        bad = self.reuse(ctl, self.drip_tx(c0, D1, seq=0xffffffff, ins=[(old, TIME | INTERVAL)], outs=extra))
        self.reject(self.wallet_sign(bad), "drip/neg_lock_on_another_input", A, control=ctl)

        # The tier.
        self.reject(self.reuse(good, self.drip_tx(c0, D1 + 1)), "drip/neg_one_atom_above_the_tier", J, control=good)
        under = self.signed(self.drip_tx(cb, TIERS["TIER2_MAX"]))
        self.reject(self.reuse(under, self.drip_tx(cb, D1)), "drip/neg_first_tier_from_a_reserve_under_its_floor",
                    J, control=under)
        # A witness that names a larger tier than the data leaf holds.
        w = bit_replace(bytes.fromhex(good.r["witness_hex"]), D1.to_bytes(8, "big"), (2 * D1).to_bytes(8, "big"))
        self.reject(self.reuse(good, self.drip_tx(c0, 2 * D1), witness=w),
                    "drip/neg_witness_names_a_larger_tier", J, control=good)

        # The drip output.
        wy = self.wallet_utxo(D1, self.Y)
        bad = self.reuse(good, self.drip_tx(c0, D1, drip_asset=self.Y_OUT, ins=[(wy, 0xffffffff)],
                                            outs=[self.out(D1, self.dest, self.X_OUT)]))
        self.reject(self.wallet_sign(bad), "drip/neg_drip_in_another_asset", J, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1, drip_spk=self.spk)),
                    "drip/neg_drip_back_into_the_covenant", J, control=good)

        # The successor.
        self.reject(self.reuse(good, self.drip_tx(c0, D1, succ_spk=self.wallet_spk())),
                    "drip/neg_successor_to_another_script", J, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1, succ_spk=bytes.fromhex(other["script_pubkey"]))),
                    "drip/neg_successor_to_another_faucet_key", J, control=good)
        left = RESERVE - D1 - FEE
        wy2 = self.wallet_utxo(left, self.Y)
        bad = self.reuse(good, self.drip_tx(c0, D1, succ_asset=self.Y_OUT, ins=[(wy2, 0xffffffff)],
                                            outs=[self.out(left, self.wallet_spk(), self.X_OUT)]))
        self.reject(self.wallet_sign(bad), "drip/neg_successor_in_another_asset", J, control=good)
        # A remainder short by 1,000 atoms, which go elsewhere: an amount the
        # mempool relays, so that both refusals are the covenant's.
        self.reject(self.reuse(good, self.drip_tx(c0, D1, succ=left - 1000, outs=[self.out(1000, self.dest, self.X_OUT)])),
                    "drip/neg_remainder_1000_atoms_short", J, control=good)

        # The fee.
        at_cap = self.signed(self.drip_tx(c0, D1, fee=FEE_CAP))
        self.reject(self.reuse(at_cap, self.drip_tx(c0, D1, fee=FEE_CAP + 1)), "drip/neg_fee_one_atom_over_the_cap",
                    J, control=at_cap)

        # The faucet key.
        tx = self.drip_tx(c0, D1)
        other_sk = generate_privkey()
        self.reject(self.reuse(good, tx, sig=sign_schnorr(other_sk, self.sim_sighash(self.leaf, tx, 0))),
                    "drip/neg_signed_by_another_key", J, control=good)
        self.reject(self.reuse(good, self.drip_tx(c0, D1), sig=sign_schnorr(self.faucet_sk, self.sim_sighash(
            self.leaf, self.drip_tx(c0, D1 - 1), 0))), "drip/neg_signature_over_another_drip", J, control=good)

        # The reserve: of the template's asset, and alone.
        coin_y = self.signed(self.drip_tx(c0, D1))
        bad = self.reuse(good, self.drip_tx(cy, D1, succ_asset=self.Y_OUT, drip_asset=self.Y_OUT))
        bad.vout[-1] = self.fee(FEE, self.Y_OUT)
        self.reuse(good, bad)
        self.reject(bad, "drip/neg_reserve_of_another_asset", J, control=coin_y, other_coin=True)
        # Two reserves of one amount, sharing one successor: the second, at
        # input 1, would pass every check input 0 passes but its index.
        both = self.drip_tx(c0, D1, ins=[(c2, TIME | INTERVAL)], outs=[self.out(RESERVE, self.dest, self.X_OUT)])
        self.reuse(good, both)
        msg1 = self.sim_sighash(TreeLeaf(text, bytes.fromhex(body["cmr"]), self.leaf.cb), both, 1)
        st = both.wit.vtxinwit[0].scriptWitness.stack
        w1 = bit_replace(bytes.fromhex(good.r["witness_hex"]), good.sig, sign_schnorr(self.faucet_sk, msg1))
        both.wit.vtxinwit[1].scriptWitness.stack = [w1, st[1], st[2], st[3]]
        self.reject(both, "drip/neg_second_reserve_shares_the_successor", J, control=good)

        # The drip, and the next one from its successor.
        txid = self.ok(good, "drip/first", extra={"reserve": RESERVE, "drip": D1, "fee": FEE})
        s1 = self.utxo_at(txid, 0)
        assert s1.spk == self.spk and s1.amount == RESERVE - D1 - FEE
        second = self.signed(self.drip_tx(s1, D1))
        self.reject(second, "drip/neg_second_drip_too_early", "bad-txns-nonfinal", mempool="non-BIP68-final")
        self.advance(INTERVAL * 512)
        second = self.signed(self.drip_tx(s1, D1))
        txid2 = self.ok(second, "drip/second_from_the_successor")
        s2 = self.utxo_at(txid2, 0)
        self.ok(self.signed(self.drip_tx(cb, TIERS["TIER2_MAX"])), "drip/second_tier")

        # The recovery leaf.
        self.reject(self.recovery_tx(s2, self.treasury_sk), "recover/neg_before_its_delay", "bad-txns-nonfinal",
                    mempool="non-BIP68-final")
        self.advance(RECOVERY_UNITS * 512)
        self.reject(self.recovery_tx(s2, self.treasury_sk, seq=TIME | (RECOVERY_UNITS - 1)),
                    "recover/neg_sequence_below_its_delay", "Locktime requirement not satisfied")
        self.reject(self.recovery_tx(s2, self.faucet_sk), "recover/neg_signed_by_the_faucet_key",
                    "Invalid Schnorr signature")
        rec = self.recovery_tx(s2, self.treasury_sk)
        self.send(rec, "recover/after_its_delay",
                  extra={"witness_stack": [len(x) for x in rec.wit.vtxinwit[0].scriptWitness.stack],
                         "waited_seconds": self.waited(txid2)})


if __name__ == "__main__":
    F1().main()
