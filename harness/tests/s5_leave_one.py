"""S5: leave one, keep the rest. A single output commits to a Merkle root of
leaf records (owner key, amount); one owner exits with a Merkle path, the
remainder is re-created under the same program with that leaf marked spent.
Tapscript tree reference: 1,119 vB for one exit out of 16 leaves, 2,475 vB out
of 1,024 (extrapolated in the round-2 report)."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from simplicity import *  # noqa: E402,F401,F403

SPENT = b"\x00" * 32
FEE = 1000


def leaf_hash(key, amount):
    return sha256(key + int(amount).to_bytes(8, "big"))


def node(l, r):
    return sha256_block(SHA256_IV, l + r)


class Tree:
    """Sparse fixed-depth Merkle tree; absent leaves are the spent marker."""

    def __init__(self, depth, leaves):
        self.depth = depth
        self.leaves = dict(leaves)           # idx -> 32-byte leaf value
        self.empty = [SPENT]
        for _ in range(depth):
            self.empty.append(node(self.empty[-1], self.empty[-1]))
        self._build()

    def _build(self):
        self.levels = [dict(self.leaves)]
        for d in range(self.depth):
            cur, nxt = self.levels[-1], {}
            for i in set(k >> 1 for k in cur):
                nxt[i] = node(cur.get(2 * i, self.empty[d]), cur.get(2 * i + 1, self.empty[d]))
            self.levels.append(nxt)

    @property
    def root(self):
        return self.levels[self.depth].get(0, self.empty[self.depth])

    def path(self, idx):
        """[(sibling, is_right)] from the leaf up; is_right = our node is the right child."""
        out = []
        for d in range(self.depth):
            out.append((self.levels[d].get(idx ^ 1, self.empty[d]), bool(idx & 1)))
            idx >>= 1
        return out

    def spend(self, idx):
        self.leaves[idx] = SPENT
        self._build()


def path_value(path):
    return vraw("[" + ", ".join("(0x%s, %s)" % (s.hex(), "true" if r else "false") for s, r in path) + "]",
                "[(u256, bool); %d]" % len(path))


class S5(SimBase, BitcoinTestFramework):
    NAME = "s5"

    def set_test_params(self):
        self.chain_params()
        self.rpc_timeout = 600

    def run_test(self):
        self.boot()
        self.rec("whitelist", self.whitelist(self.X, self.Y))
        self.rec("source/depth4", src("leave_one.simf.in").replace("%%DEPTH%%", "4"))
        self.pool(4, 16, exits=[5, 10, 0, 15], negatives=True)
        self.pool(10, 1024, exits=[341, 1023, 0])
        self.pool(20, 3, exits=[699050, 0], sparse=[0, 699050, 1048575])
        self.pool(4, 1, exits=[6], sparse=[6], last=True)

    def pool(self, depth, n, exits, negatives=False, sparse=None, last=False):
        node_ = self.node
        tag = "depth%d%s" % (depth, "_last_leaf" if last else "")
        self.log.info("=== S5 %s (%d live leaves) ===", tag, n)
        idxs = sparse if sparse is not None else list(range(n))
        secs = {i: generate_privkey() for i in idxs}
        keys = {i: compute_xonly_pubkey(secs[i])[0] for i in idxs}
        amts = {i: 1_0000_0000 + 7919 * (j + 1) for j, i in enumerate(idxs)}
        tree = Tree(depth, {i: leaf_hash(keys[i], amts[i]) for i in idxs})
        base = SimProg(src("leave_one.simf.in").replace("%%DEPTH%%", str(depth)), {}, data=tree.root)
        total = sum(amts.values())
        self.rec(tag + "/program", {**base.info(), "leaves": 1 << depth, "live_leaves": len(idxs),
                                    "root": tree.root.hex(), "pool_amount": total})
        u = self.fund(base.spk, total, self.X)
        cov = base
        dest = self.wallet_spk()

        def exit_tx(u, cov, tree, i, owner_sec=None, amount=None, rem_spk=None, rem_amt=None, rem_asset=None,
                    extra_in=(), extra_outs=(), key=None, pay=None):
            amount = amts[i] if amount is None else amount
            t2 = Tree(depth, tree.leaves)
            t2.spend(i)
            nxt = base.with_data(t2.root)
            rem = u.amount - amount if rem_amt is None else rem_amt
            outs = []
            if rem > 0:
                outs.append(self.out(rem, nxt.spk if rem_spk is None else rem_spk, rem_asset or self.X_OUT))
            outs.append(self.out((amts[i] if pay is None else pay) - FEE, dest, self.X_OUT))
            outs += list(extra_outs) + [self.fee(FEE, self.X_OUT)]
            tx = self.mktx([u] + list(extra_in), outs)
            sig = sign_schnorr(owner_sec or secs[i], self.sim_sighash(cov, tx, 0))
            W = {"OWNER": vpub(key or keys[i]), "AMOUNT": vu(amount), "PATH": path_value(tree.path(i)), "SIG": vsig(sig)}
            return tx, W, sig, nxt, t2

        for n_exit, i in enumerate(exits):
            tx, W, sig, nxt, t2 = exit_tx(u, cov, tree, i)
            r = self.sim_satisfy(cov, tx, 0, W)
            PB, WB = tx.wit.vtxinwit[0].scriptWitness.stack[1], tx.wit.vtxinwit[0].scriptWitness.stack[0]
            meas = self.sim_measure(tx, 0, r)
            meas["leaf_index"] = i

            if negatives and n_exit == 0:
                J = "Assertion failed inside jet"

                def build(wb_edit=None, **kw):
                    t, _, s, _, _ = exit_tx(u, cov, tree, i, **kw)
                    wb = bit_replace(WB, sig, s)
                    if wb_edit:
                        wb = wb_edit(wb)
                    self.set_sim_wit(t, 0, cov, PB, wb)
                    if kw.get("extra_in"):
                        t = self.wallet_sign(t)
                    return t

                def neg(label, ctl=None, **kw):
                    """A refused exit, and its control: the valid exit (`tx`), or the
                    exit built with `ctl` in place of the broken property."""
                    self.reject(build(**kw), tag + "/" + label, J,
                                control=tx if ctl is None else build(**ctl))

                A = amts[i]
                be = lambda v: int(v).to_bytes(8, "big")
                # the remainder keeps the OLD root (leaf not marked spent)
                neg("neg_remainder_keeps_old_root", rem_spk=cov.spk)
                # the remainder marks a DIFFERENT leaf spent
                t3 = Tree(depth, tree.leaves); t3.spend(i ^ 1)
                neg("neg_remainder_marks_other_leaf", rem_spk=base.with_data(t3.root).spk)
                # remainder one atom short (owner takes one atom more)
                neg("neg_remainder_short_by_1", rem_amt=u.amount - A - 1, pay=A + 1)
                # owner claims one atom more than the record says (and remainder matches the claim)
                neg("neg_claims_amount_plus_1", amount=A + 1, pay=A + 1,
                    wb_edit=lambda wb: bit_replace(wb, be(A), be(A + 1)))
                # remainder paid to a different program with the right data leaf
                other = SimProg(src("p2pk.simf"), {"PK": vpub(keys[i])}, data=t2.root)
                neg("neg_remainder_to_other_program", rem_spk=other.spk)
                # remainder in another asset
                y = self.wallet_utxo(u.amount - A, self.Y)
                wy = self.wallet_spk()
                neg("neg_remainder_in_other_asset", rem_asset=self.Y_OUT, extra_in=[y],
                    extra_outs=[self.out(u.amount - A, wy, self.X_OUT)],
                    ctl=dict(extra_in=[y], extra_outs=[self.out(u.amount - A, wy, self.Y_OUT)]))
                # no remainder output at all (everything else to the owner)
                t = self.mktx([u], [self.out(u.amount - FEE, dest, self.X_OUT), self.fee(FEE, self.X_OUT)])
                s = sign_schnorr(secs[i], self.sim_sighash(cov, t, 0))
                self.set_sim_wit(t, 0, cov, PB, bit_replace(WB, sig, s))
                self.reject(t, tag + "/neg_no_remainder_output", J, control=tx)
                # a stranger signs with the owner's record in the witness
                neg("neg_signed_by_stranger", owner_sec=generate_privkey())
                # a stranger puts their OWN key in the witness (record not in the tree)
                st_sec = generate_privkey()
                st_key = compute_xonly_pubkey(st_sec)[0]
                neg("neg_stranger_key_not_in_tree", owner_sec=st_sec,
                    wb_edit=lambda wb: bit_replace(wb, keys[i], st_key))
                # another leaf's owner uses THIS leaf's path
                j = exits[1]
                neg("neg_other_owner_with_this_path", owner_sec=secs[j],
                    wb_edit=lambda wb: bit_replace(bit_replace(wb, keys[i], keys[j]), be(A), be(amts[j])),
                    amount=amts[j], pay=amts[j])

            txid = self.send(tx, tag + "/exit_%d_leaf_%d" % (n_exit, i), extra=meas)
            if tx.vout[0].nValue.getAmount() == u.amount - amts[i] and u.amount - amts[i] > 0:
                old_u, old_cov, old_tree = u, cov, tree
                u = self.utxo_at(txid, 0)
                assert u.spk == nxt.spk
                cov, tree = nxt, t2
                if negatives and n_exit == 0:
                    # The control of both: the next owner's exit from the updated pool.
                    ctl, W2, _, _, _ = exit_tx(u, cov, tree, exits[1])
                    self.sim_satisfy(cov, ctl, 0, W2)
                    # the same owner tries to exit AGAIN from the updated pool, with the old path
                    t, _, s, _, _ = exit_tx(u, cov, old_tree, i)
                    self.set_sim_wit(t, 0, cov, PB, bit_replace(WB, sig, s))
                    self.reject(t, tag + "/neg_double_exit_old_path", "Assertion failed inside jet", control=ctl)
                    # ... and with the CURRENT path of their (now spent) leaf
                    t, _, s, _, _ = exit_tx(u, cov, tree, i)
                    wb = bit_replace(WB, sig, s)
                    self.set_sim_wit(t, 0, cov, PB, wb)
                    self.reject(t, tag + "/neg_double_exit_current_path", "Assertion failed inside jet", control=ctl)
            else:
                self.rec(tag + "/pool_closed", {"remainder": 0, "outputs": len(tx.vout)})


if __name__ == "__main__":
    S5().main()
