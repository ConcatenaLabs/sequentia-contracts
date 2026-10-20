"""Pool split helpers shared by the harness tests p1 and p2.

The claims are built by the claim tool itself (tools/pool-claim/pool_claim.py),
through an RPC adapter over the test framework's node, so the tests prove the
tool as well as the covenant. A negative is a control's transaction changed in
one property, with the control's witness (its pruned program, which takes the
same branches up to the check the negative breaks); where the negative states
another WITHHELD amount, that value's bits are replaced in the witness.
"""
import copy
import os
import sys

from simplicity import *  # noqa: F401,F403

sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "pool-claim"))
import pool_claim as pc  # noqa: E402

J, A = "Assertion failed inside jet", "Assertion failed"


def node_rpc(node):
    """The tool's rpc(method, *args) over a framework node."""
    def rpc(method, *args):
        return getattr(node, method)(*args)
    return rpc


def coin(rpc, txid, vout):
    c = pc.fetch_coin(rpc, txid, vout)
    assert c is not None, (txid, vout)
    return c


def fw(t, coins):
    """The tool's transaction as the framework's, with its prevouts, for send()
    and reject()."""
    x = Tx.from_hex(t.hex())
    ChainBase.pad(x)
    by = {(c.txid, c.vout): c for c in coins}
    x.prev = [_utxo(by[(txid, n)]) for txid, n, _ in t.vin]
    return x


def _utxo(c):
    out = CTxOut()
    from io import BytesIO
    out.deserialize(BytesIO(c.txout.serialize()))
    return Utxo(c.txid, c.vout, out)


def changed(t, outputs=None, wit=None, vin=None):
    """A copy of tool transaction `t` with its outputs, witnesses or inputs
    replaced."""
    u = copy.deepcopy(t)
    if outputs is not None:
        u.vout = outputs
    if vin is not None:
        u.vin = vin
    if wit is not None:
        u.wit = wit
    return u


def explicit(asset, value, script):
    return pc.TxOut.explicit(asset, value, script)


def replace_withheld(t, old, new):
    """The leader's witness with WITHHELD changed from `old` to `new`: the
    Simplicity witness blob's bits, or the tapscript twin's first item."""
    u = copy.deepcopy(t)
    st = u.wit[0]
    if len(st) == 3:                     # tapscript: [W, script, cb]
        st[0] = pc.le8(new)
    else:
        st[0] = bit_replace(st[0], old.to_bytes(8, "big"), new.to_bytes(8, "big"))
    return u
