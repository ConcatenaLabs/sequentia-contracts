"""Simplicity helpers for the regtest harness.

SimplicityHL is compiled, satisfied, pruned and costed by `seqc run`, the
repository's command line on the pinned compiler, which also refuses any
program the lints refuse. Everything else (taproot, transactions, signing,
RPC) is Python on the node's functional test framework, through chain.py.
"""
from chain import *          # noqa: F401,F403
import subprocess
from test_framework.script import TaggedHash, LEAF_VERSION_TAPSIMPLICITY
from test_framework.key import verify_schnorr

REPO_ROOT = os.path.dirname(HARNESS)
SEQC = os.environ.get("SEQC", os.path.join(REPO_ROOT, "target", "release", "seqc"))
PROGDIR = os.path.join(HARNESS, "programs")
REJECT_FIXTURES = os.path.join(REPO_ROOT, "lints", "fixtures", "reject")

BUDGET_PER_BYTE = 4
BUDGET_OFFSET = 50
BUDGET_MAX = 4000050


def seqc(req):
    """One `seqc run` request. Raises on any error, lint findings included."""
    p = subprocess.run([SEQC, "run"], input=json.dumps(req).encode(), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("seqc crashed: " + p.stderr.decode()[-2000:])
    r = json.loads(p.stdout.decode())
    if "error" in r:
        raise RuntimeError("seqc: " + r["error"])
    return r


def src(name):
    """A program source from harness/programs."""
    with open(os.path.join(PROGDIR, name)) as f:
        return f.read()


def safe_src(name):
    """A program from lints/fixtures/accept: the safe relative locks."""
    with open(os.path.join(REPO_ROOT, "lints", "fixtures", "accept", name)) as f:
        return f.read()


def banned_src(name):
    """A program from lints/fixtures/reject: one the lints refuse. Only the
    demonstration of the broken timelock jets loads these."""
    with open(os.path.join(REJECT_FIXTURES, name)) as f:
        return f.read()


def tapdata_hash(data):
    """Hidden taproot node carrying covenant state: plain-tag 'TapData' hash,
    the value jet::tapdata_init() starts from."""
    tag = sha256(b"TapData")
    return sha256(tag + tag + data)


# ---- SimplicityHL value literals -----------------------------------------
def v256(b):
    return {"value": "0x" + bytes(b).hex(), "type": "u256"}


def vpub(b):
    return {"value": "0x" + bytes(b).hex(), "type": "Pubkey"}


def vsig(b):
    return {"value": "0x" + bytes(b).hex(), "type": "Signature"}


def vu(n, bits=64):
    return {"value": str(int(n)), "type": "u%d" % bits}


def vraw(value, ty):
    return {"value": value, "type": ty}


def bits_of(b):
    return "".join("{:08b}".format(x) for x in b)


def bit_replace(blob, old, new):
    """Replace the bit pattern of `old` by `new` (same length) inside `blob`,
    at any bit offset. Used to re-sign a pruned program for a different
    transaction without re-pruning (pruning replays the program and so cannot
    be run against a transaction the covenant refuses)."""
    assert len(old) == len(new)
    B, o, n = bits_of(blob), bits_of(old), bits_of(new)
    assert B.count(o) == 1, "pattern occurs %d times" % B.count(o)
    B = B.replace(o, n)
    return bytes(int(B[i:i + 8], 2) for i in range(0, len(B), 8))


class SimProg:
    """A compiled SimplicityHL program committed in a taproot output.
    default     : P2TR(NUMS, TapLeaf_0xbe(CMR))                           control block 33 B
    data=bytes  : P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR), H_TapData(data)))             65 B
    sibling=(name, script) : P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR), TapLeaf_0xc4(script)))  65 B
    """

    def __init__(self, source, args=None, data=None, sibling=None, internal=NUMS, allow_banned=False):
        self.source = source
        self.args = args or {}
        self.allow_banned = allow_banned
        r = seqc({"source": source, "args": self.args, "allow_banned_jets": allow_banned})
        self.cmr = bytes.fromhex(r["cmr"])
        self.compiler_version = r["compiler_version"]
        self.commit_bytes = r["commit_program_bytes"]
        self.internal = internal
        self.sibling = sibling
        self._tree(data)

    def _tree(self, data):
        self.data = data
        leaf = ("sim", self.cmr, LEAF_VERSION_TAPSIMPLICITY)
        if data is not None:
            dh = tapdata_hash(data)
            self.tap = taproot_construct(self.internal, [leaf, lambda h: dh])
        elif self.sibling is not None:
            self.tap = taproot_construct(self.internal, [leaf, self.sibling])
        else:
            self.tap = taproot_construct(self.internal, [leaf])
        self.spk = bytes(self.tap.scriptPubKey)
        self.cb = control_block(self.tap, "sim")
        self.leaf_hash = self.tap.leaves["sim"].leaf_hash

    def with_data(self, data):
        p = SimProg.__new__(SimProg)
        p.__dict__.update(self.__dict__)
        p._tree(data)
        return p

    def info(self):
        return {"cmr": self.cmr.hex(), "commit_program_bytes": self.commit_bytes,
                "compiler_version": self.compiler_version,
                "scriptPubKey": self.spk.hex(), "control_block_bytes": len(self.cb),
                "args": {k: v["value"] for k, v in self.args.items()}}


def output_hash(asset32, value, spk, nonce=None):
    """What jet::output_hash(i) returns for an EXPLICIT output:
    SHA256(0x01||asset || 0x01||value_be8 || nonce_rec || SHA256(spk) || SHA256(rangeproof = empty))
    nonce_rec = 0x00 for a null nonce, else prefix(0x02/0x03 -> same byte)||x."""
    n = b"\x00" if not nonce else bytes(nonce)
    return sha256(b"\x01" + asset32 + b"\x01" + int(value).to_bytes(8, "big") + n
                  + sha256(bytes(spk)) + sha256(b""))


_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
SHA256_IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")


def sha256_block(state, block):
    """The raw SHA256 compression function: what jet::sha_256_block(h, b1, b2) computes."""
    assert len(state) == 32 and len(block) == 64
    M = 0xffffffff
    rr = lambda x, n: ((x >> n) | (x << (32 - n))) & M
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
    h = [int.from_bytes(state[i:i + 4], "big") for i in range(0, 32, 4)]
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        t1 = (hh + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & M & g)) + _K[i] + w[i]) & M
        t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M
        a, b, c, d, e, f, g, hh = (t1 + t2) & M, a, b, c, (d + t1) & M, e, f, g
    out = [(x + y) & M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in out)


class SimBase(ChainBase):
    """ChainBase + Simplicity active from genesis (`-evbparams=simplicity:-1:::`).
    The form `simplicity:0:::` would only activate at height 384."""
    EXTRA = ["-evbparams=simplicity:-1:::"]

    def wallet_utxo(self, atoms, asset=None):
        """A fresh wallet P2WPKH utxo, LOCKED so the wallet's own coin selection
        cannot spend it before the hand-built transaction that uses it."""
        u = ChainBase.wallet_utxo(self, atoms, asset)
        self.node.lockunspent(False, [{"txid": u.txid, "vout": u.vout}])
        return u

    def req(self, prog, tx, idx, witness=None, prune=True):
        self.pad(tx)
        r = {"source": prog.source, "args": prog.args,
             "tx": tx.serialize().hex(),
             "utxos": [u.txout.serialize().hex() for u in tx.prev],
             "index": idx, "control_block": prog.cb.hex(),
             "genesis": self.node.getblockhash(0),
             "allow_banned_jets": prog.allow_banned}
        if witness is not None:
            r["witness"] = witness
            r["prune"] = prune
        return r

    def sim_sighash(self, prog, tx, idx, annex=None):
        """sig_all_hash for input idx as the pinned library computes it; with
        `annex`, the hash commits to it, as the node's does."""
        r = self.req(prog, tx, idx)
        if annex is not None:
            r["annex"] = annex.hex()
        return bytes.fromhex(seqc(r)["sighash_all"])

    def sim_satisfy(self, prog, tx, idx, witness, annex=None, prune=True, must_exec=True):
        """Compile + satisfy + prune against `tx`, set the witness stack
        [witness, program, CMR, control block] (+ annex). Returns the seqc reply."""
        req = self.req(prog, tx, idx, witness, prune)
        if annex is not None:
            req["annex"] = annex.hex()
        r = seqc(req)
        if must_exec:
            assert r.get("executed"), r.get("exec_error")
        self.set_sim_wit(tx, idx, prog, bytes.fromhex(r["program_hex"]),
                         bytes.fromhex(r["witness_hex"]), annex)
        return r

    def set_sim_wit(self, tx, idx, prog, program, witness, annex=None):
        stack = [witness, program, prog.cmr, prog.cb]
        if annex is not None:
            stack.append(b"\x50" + annex)
        self.setwit(tx, idx, stack)

    @staticmethod
    def budget(tx, idx):
        """Execution budget (weight units) the node grants input idx."""
        n = wit_bytes(tx.wit.vtxinwit[idx].scriptWitness.stack)
        return min(n * BUDGET_PER_BYTE + BUDGET_OFFSET, BUDGET_MAX)

    def sim_measure(self, tx, idx, r):
        st = tx.wit.vtxinwit[idx].scriptWitness.stack
        d = {"program_bytes": len(st[1]), "witness_bytes": len(st[0]),
             "stack_serialized_bytes": wit_bytes(st),
             "budget_wu": self.budget(tx, idx),
             "cost_bound_milli_wu": r["cost_milli"],
             "cost_bound_wu": (r["cost_milli"] + 999) // 1000,
             "program_hex": st[1].hex() if len(st[1]) <= 4096 else "(%d bytes)" % len(st[1]),
             "witness_hex": st[0].hex() if len(st[0]) <= 4096 else "(%d bytes)" % len(st[0])}
        return d

    # -- debug.log scraping: the block-level RPC error is generic, the node's
    #    log carries the script error that made block validation fail.
    def _logpath(self):
        return os.path.join(self.node.datadir, self.chain, "debug.log")

    def _logpos(self):
        return os.path.getsize(self._logpath())

    def _logsince(self, pos, needles=("ERROR", "failed", "invalid")):
        with open(self._logpath(), "rb") as f:
            f.seek(pos)
            txt = f.read().decode(errors="replace")
        out = []
        for ln in txt.splitlines():
            if any(n in ln for n in needles):
                ln = ln.split("Z ", 1)[-1]
                if ln not in out:
                    out.append(ln[:400])
        return out

    def reject(self, tx, label, expect=None, consensus=True):
        pos = self._logpos()
        reason = ChainBase.reject(self, tx, label, expect, consensus)
        if consensus:
            d = self.R[label]
            d["block-log"] = [l for l in self._logsince(pos) if "ConnectBlock" in l or "CheckInputScripts" in l][:2]
            self.rec(label, d)
        return reason

    def try_block(self, tx, label):
        """Mine `tx` directly (bypassing relay policy); record success or the error."""
        pos = self._logpos()
        d = {"vsize": self.measure(tx)["vsize"], "weight": self.measure(tx)["weight"]}
        t0 = __import__("time").time()
        try:
            self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
            tx.rehash()
            d["mined"] = self.node.getrawtransaction(tx.hash, True).get("confirmations", 0) >= 1
        except JSONRPCException as e:
            d["mined"] = False
            d["block-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
            d["block-log"] = [l for l in self._logsince(pos) if "ConnectBlock" in l or "CheckInputScripts" in l][:2]
        d["seconds"] = round(__import__("time").time() - t0, 2)
        self.log.info("BLOCK %-42s %s", label, {k: v for k, v in d.items()})
        self.rec(label, d)
        return d

    def try_mempool(self, tx, label):
        res = self.accept(tx)
        d = {"testmempoolaccept": bool(res["allowed"]), "reject-reason": res.get("reject-reason"),
             "vsize": self.measure(tx)["vsize"], "weight": self.measure(tx)["weight"]}
        self.log.info("MEMPOOL %-40s %s", label, d)
        self.rec(label, d)
        return d

    def reject2(self, tx, label):
        """Like reject(), but returns the record (mempool + block strings)."""
        self.reject(tx, label)
        return self.R[label]
