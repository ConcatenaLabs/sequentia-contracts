#!/usr/bin/env python3
"""Claims of the pool split covenant: build one, and check one.

A pool that sets its payout script to the covenant's address has every block's
reward paid there, in whatever asset the block's fees were paid, and anyone can
claim those coins into the pool's fixed shares, exact to the atom
(docs/pool-split.md). This module builds such a claim from the pool's record and
checks a claim against the rule and the chain:

    pool = Pool(record)                      # the record, checked; its instance
    claim = Claim(pool, coins, genesis)      # coins of one asset at the pool's script
    tx = claim.make(rpc)                     # the fee at the node's floor, witnesses set
    verify(pool, tx, rpc, maturity)          # raises Refused, naming the reason

`rpc(method, *args)` is any way to call the node. The record is JSON:

    {"pool_record": 1,
     "template": "sequentia/pool-split",          (or "sequentia/pool-split-tap3")
     "denom": 10000,
     "withhold_cap_bp": 100,
     "rows": [{"label": "pool", "script": "<scriptPubKey hex>", "numerator": 500},
              {"label": "alice", "address": "<address>", "numerator": 6000}, ...]}

Row 0 is the pool's own row: it is paid its share and every rounding remainder.
Each row names a `script` or an `address` (resolved through the node). The
numerators are positive and sum to `denom`, which is below 2^31.

It needs Python 3 alone, and `seqc` from this repository for a Simplicity claim
(default `target/release/seqc`).
"""
import hashlib
import io
import json
import os
import shlex
import struct
import subprocess
import sys
from decimal import Decimal, ROUND_CEILING

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "mirrors", "python"))
import sequentia_address as sa  # noqa: E402

TEMPLATES = {
    "sequentia/pool-split": "pool_split",
    "sequentia/pool-split-tap3": "pool_split_tap3",
}
MAX_INPUTS = {"sequentia/pool-split": 255, "sequentia/pool-split-tap3": 8}
# Coinbase maturity on the chains that pin it; a custom chain takes --maturity.
CHAIN_MATURITY = {"test": 1000, "sequentia": 1000}
BUDGET_PER_BYTE, BUDGET_OFFSET, BUDGET_MAX = 4, 50, 4000050
COIN = 100_000_000


class Refused(Exception):
    """A claim the covenant, or the chain, would refuse."""


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


# ---------------------------------------------------------------------------
# Elements transactions, explicit values only
# ---------------------------------------------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b):
    return compact(len(b)) + bytes(b)


def read_compact(f):
    c = f.read(1)[0]
    if c < 0xfd:
        return c
    return struct.unpack({0xfd: "<H", 0xfe: "<I", 0xff: "<Q"}[c], f.read({0xfd: 2, 0xfe: 4, 0xff: 8}[c]))[0]


def read_var(f):
    n = read_compact(f)
    b = f.read(n)
    if len(b) != n:
        raise ValueError("truncated")
    return b


def read_commitment(f, sizes):
    p = f.read(1)
    if not p:
        raise ValueError("truncated")
    n = sizes.get(p[0])
    if n is None:
        raise ValueError("bad commitment prefix %02x" % p[0])
    return p + f.read(n)


class TxOut:
    """An output. `asset` is the 32-byte id in internal order and `value` an
    int when explicit; `asset_c`, `value_c`, `nonce` are the raw commitments."""

    def __init__(self, asset_c, value_c, nonce, script):
        self.asset_c, self.value_c, self.nonce, self.script = asset_c, value_c, nonce, bytes(script)

    @classmethod
    def explicit(cls, asset, value, script):
        return cls(b"\x01" + asset, b"\x01" + value.to_bytes(8, "big"), b"\x00", script)

    @property
    def asset(self):
        return self.asset_c[1:] if self.asset_c[:1] == b"\x01" else None

    @property
    def value(self):
        return int.from_bytes(self.value_c[1:], "big") if self.value_c[:1] == b"\x01" else None

    def serialize(self):
        return self.asset_c + self.value_c + self.nonce + varbytes(self.script)

    @classmethod
    def read(cls, f):
        a = read_commitment(f, {0: 0, 1: 32, 0x0a: 32, 0x0b: 32})
        v = read_commitment(f, {0: 0, 1: 8, 0x08: 32, 0x09: 32})
        n = read_commitment(f, {0: 0, 1: 32, 2: 32, 3: 32})
        return cls(a, v, n, read_var(f))


class Tx:
    def __init__(self):
        self.version, self.locktime = 2, 0
        self.vin = []        # [txid display hex, vout, sequence]
        self.vout = []       # [TxOut]
        self.wit = []        # per input: list of stack items
        self.annex = {}

    def serialize(self, witness=True):
        has_wit = witness and any(self.wit)
        r = struct.pack("<i", self.version) + bytes([1 if has_wit else 0])
        r += compact(len(self.vin))
        for txid, n, seq in self.vin:
            r += bytes.fromhex(txid)[::-1] + struct.pack("<I", n) + varbytes(b"") + struct.pack("<I", seq)
        r += compact(len(self.vout))
        for o in self.vout:
            r += o.serialize()
        r += struct.pack("<I", self.locktime)
        if has_wit:
            for i in range(len(self.vin)):
                st = self.wit[i] if i < len(self.wit) else []
                r += varbytes(b"") + varbytes(b"") + compact(len(st)) + b"".join(varbytes(x) for x in st) + compact(0)
            for _ in self.vout:
                r += varbytes(b"") + varbytes(b"")
        return r

    def txid(self):
        return sha256d(self.serialize(False))[::-1].hex()

    def hex(self):
        return self.serialize().hex()

    @classmethod
    def parse(cls, raw):
        f = io.BytesIO(bytes.fromhex(raw) if isinstance(raw, str) else raw)
        t = cls()
        t.version = struct.unpack("<i", f.read(4))[0]
        flags = f.read(1)[0]
        for _ in range(read_compact(f)):
            h = f.read(32)[::-1].hex()
            n = struct.unpack("<I", f.read(4))[0]
            if n != 0xffffffff and n & 0xc0000000:
                raise Refused("an input carries an issuance or a peg-in, which no claim has")
            read_var(f)
            seq = struct.unpack("<I", f.read(4))[0]
            t.vin.append([h, n, seq])
        for _ in range(read_compact(f)):
            t.vout.append(TxOut.read(f))
        t.locktime = struct.unpack("<I", f.read(4))[0]
        t.wit = [[] for _ in t.vin]
        if flags & 1:
            for i in range(len(t.vin)):
                read_var(f)
                read_var(f)
                t.wit[i] = [read_var(f) for _ in range(read_compact(f))]
                for _ in range(read_compact(f)):
                    read_var(f)
            for _ in t.vout:
                read_var(f)
                read_var(f)
        if f.read(1):
            raise ValueError("trailing bytes")
        return t


def wit_bytes(stack):
    return len(compact(len(stack))) + sum(len(varbytes(x)) for x in stack)


def le8(n):
    return int(n).to_bytes(8, "little")


# ---------------------------------------------------------------------------
# The pool record and its instance
# ---------------------------------------------------------------------------

class Pool:
    """A pool record, checked, with its instance derived from the template."""

    def __init__(self, record, resolve=None):
        if record.get("pool_record") != 1:
            raise ValueError("not a pool record (pool_record: 1)")
        self.template_name = record["template"]
        if self.template_name not in TEMPLATES:
            raise ValueError("unknown template %s" % self.template_name)
        tdir = os.path.join(ROOT, "templates", TEMPLATES[self.template_name])
        with open(os.path.join(tdir, "descriptor.json")) as f:
            self.descriptor = sa.loads(f.read())
        self.model = sa.model(self.descriptor)
        self.denom = int(record["denom"])
        self.cap_bp = int(record["withhold_cap_bp"])
        self.rows = []
        for i, r in enumerate(record["rows"]):
            script = r.get("script")
            if script is None:
                if "address" not in r or resolve is None:
                    raise ValueError("row %d names no script (or an address with no node to read it)" % i)
                script = resolve(r["address"])
            self.rows.append((bytes.fromhex(script), int(r["numerator"]), r.get("label", "row %d" % i)))
        self._check()
        self.params = self._params()
        self.tree = sa.derive_tree(self.model, self.params, {})
        self.script_pubkey = bytes.fromhex(self.tree["script_pubkey"])

    def _check(self):
        n = len(self.rows)
        if self.template_name == "sequentia/pool-split-tap3":
            if n != 3:
                raise ValueError("the tapscript template takes exactly 3 rows; this record has %d" % n)
        elif not 1 <= n <= sa.POOL_SPLIT_MAX_ROWS:
            raise ValueError("a table has 1 to %d rows; this record has %d" % (sa.POOL_SPLIT_MAX_ROWS, n))
        if not 1 <= self.denom < 1 << 31:
            raise ValueError("the denominator is from 1 to 2^31 - 1")
        if not 0 <= self.cap_bp <= 10000:
            raise ValueError("the withhold cap is 0 to 10,000 basis points")
        for script, num, label in self.rows:
            if num <= 0:
                raise ValueError("%s: every numerator is positive; a row owed nothing would be paid a zero output" % label)
            if not 1 <= len(script) <= 10000:
                raise ValueError("%s: a script of %d bytes" % (label, len(script)))
            if len(script) >= 2 and 0x52 <= script[0] <= 0x60 and script[1] == len(script) - 2:
                raise ValueError("%s: a witness version 2 or higher, which the tapscript twin cannot rebuild" % label)
        if sum(num for _, num, _ in self.rows) != self.denom:
            raise ValueError("the numerators sum to %d, not the denominator %d"
                             % (sum(num for _, num, _ in self.rows), self.denom))

    def _params(self):
        if self.template_name == "sequentia/pool-split":
            table = sa.pool_split_table([(s, n) for s, n, _ in self.rows])
            return {"TABLE": table.hex(), "DENOM": "%08x" % self.denom, "WITHHOLD_CAP_BP": "%04x" % self.cap_bp}
        (s0, _, _), (s1, n1, _), (s2, n2, _) = self.rows
        return {"ROW0_SCRIPT": sha256(s0).hex(), "ROW1_SCRIPT": sha256(s1).hex(), "ROW1_NUM": "%08x" % n1,
                "ROW2_SCRIPT": sha256(s2).hex(), "ROW2_NUM": "%08x" % n2,
                "DENOM": "%08x" % self.denom, "WITHHOLD_CAP_BP": "%04x" % self.cap_bp}

    def address(self, chain_name):
        for c in self.descriptor["chains"]:
            if c["name"] == chain_name:
                return sa.segwit_v1_address(c["bech32_hrp"], self.script_pubkey[2:])
        raise ValueError("the template names no chain %s" % chain_name)

    def leaf(self, name):
        lv = self.tree["leaves"][name]
        return bytes.fromhex(lv.get("script", "")), bytes.fromhex(lv["control_block"])

    def payouts(self, collected, withheld):
        try:
            return sa.pool_split_payouts([n for _, n, _ in self.rows], self.denom, self.cap_bp, collected, withheld)
        except ValueError as e:
            raise Refused(str(e))

    def cap(self, collected):
        """The most a claim on `collected` may withhold."""
        return collected * self.cap_bp // 10000

    def instance(self, genesis=None):
        return {"instance": 2, "template_hash": self.descriptor["template_hash"],
                "params": self.params, "slots": {}, "genesis": genesis}


# ---------------------------------------------------------------------------
# The node
# ---------------------------------------------------------------------------

def cli_rpc(cli):
    """An RPC call through sequentia-cli: rpc(method, *args), each argument a
    string (passed as it is) or a JSON value."""
    base = shlex.split(cli)

    def rpc(method, *args):
        cmd = base + [method] + [a if isinstance(a, str) else json.dumps(a) for a in args]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError("%s: %s" % (method, (p.stderr or p.stdout).strip()))
        out = p.stdout.strip()
        try:
            return json.loads(out, parse_float=Decimal)
        except json.JSONDecodeError:
            return out
    return rpc


def atoms(v):
    return int((Decimal(str(v)) * COIN).to_integral_value())


def display_asset(asset):
    return asset[::-1].hex()


class Coin:
    def __init__(self, txid, vout, txout, height, coinbase, confirmations):
        self.txid, self.vout, self.txout = txid, vout, txout
        self.height, self.coinbase, self.confirmations = height, coinbase, confirmations

    def outpoint(self):
        return "%s:%d" % (self.txid, self.vout)


def fetch_coin(rpc, txid, vout):
    """An unspent coin as the chain holds it, or None."""
    u = rpc("gettxout", txid, vout, True)
    if not u:
        return None
    spk = bytes.fromhex(u["scriptPubKey"]["hex"])
    if "asset" in u and "value" in u:
        out = TxOut.explicit(bytes.fromhex(u["asset"])[::-1], atoms(u["value"]), spk)
    else:
        raw = rpc("getrawtransaction", txid)
        out = Tx.parse(raw).vout[vout]
    return Coin(txid, vout, out, None, bool(u.get("coinbase")), int(u.get("confirmations", 0)))


def chain_maturity(rpc, override):
    if override is not None:
        return override
    chain = rpc("getblockchaininfo")["chain"]
    if chain in CHAIN_MATURITY:
        return CHAIN_MATURITY[chain]
    raise Refused("chain %s does not pin its coinbase maturity; pass --maturity (a custom chain's "
                  "-con_coinbase_maturity, 100 when unset)" % chain)


def mature(coin, maturity):
    """A coinbase coin can be spent once it has `maturity` confirmations,
    counting the block the claim would confirm in."""
    return not coin.coinbase or coin.confirmations >= maturity


def pool_coins(rpc, pool):
    r = rpc("scantxoutset", "start", ["raw(%s)" % pool.script_pubkey.hex()])
    coins = []
    for u in r.get("unspents", []):
        c = fetch_coin(rpc, u["txid"], u["vout"])
        if c is not None:
            c.height = u.get("height")
            coins.append(c)
    return coins


def fee_rate(rpc, asset):
    """The node's floor for `asset`, in its atoms per vbyte: the mempool's
    minimum (reference units per kvB) converted at the node's exchange rate."""
    rates = rpc("getfeeexchangerates")
    hexid = display_asset(asset)
    rate = rates.get(hexid)
    if rate is None:
        labels = rpc("dumpassetlabels")
        for label, a in labels.items():
            if a == hexid and label in rates:
                rate = rates[label]
    if not rate:
        raise Refused("this node does not accept %s for fees: the covenant lets a claim pay its fee in another "
                      "asset, from a coin the claimer brings, which this tool does not build" % hexid)
    floor_rfa_per_vb = Decimal(str(rpc("getmempoolinfo")["mempoolminfee"])) * COIN / 1000
    return floor_rfa_per_vb * COIN / Decimal(rate)


# ---------------------------------------------------------------------------
# Building a claim
# ---------------------------------------------------------------------------

def seqc_run(seqc, req):
    p = subprocess.run([seqc, "run"], input=json.dumps(req).encode(), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("seqc: " + p.stderr.decode()[-2000:])
    r = json.loads(p.stdout.decode())
    if "error" in r:
        raise RuntimeError("seqc: " + r["error"])
    return r


class Claim:
    """A claim of `coins` (one asset, all at the pool's script) under `pool`."""

    def __init__(self, pool, coins, genesis, withheld_extra=0, claimer_script=None, seqc=None):
        if not coins:
            raise Refused("no coin to claim")
        assets = {c.txout.asset for c in coins}
        if None in assets:
            raise Refused("a confidential coin cannot be claimed: the covenant reads explicit amounts only")
        if len(assets) != 1:
            raise Refused("a claim spends coins of one asset")
        for c in coins:
            if c.txout.script != pool.script_pubkey:
                raise Refused("%s is not at the pool's script" % c.outpoint())
            if c.txout.value is None:
                raise Refused("%s has a confidential amount" % c.outpoint())
        if len(coins) > MAX_INPUTS[pool.template_name]:
            raise Refused("a claim under %s spends at most %d coins" % (pool.template_name, MAX_INPUTS[pool.template_name]))
        self.pool, self.coins, self.genesis = pool, list(coins), genesis
        self.asset = coins[0].txout.asset
        self.collected = sum(c.txout.value for c in coins)
        # "max": the claimer keeps whatever the cap leaves beyond the fee.
        self.keep_max = withheld_extra == "max"
        self.keep = pool.cap(self.collected) if self.keep_max else int(withheld_extra)
        self.claimer_script = claimer_script
        if self.keep and claimer_script is None:
            raise Refused("an amount kept for the claimer needs the claimer's script")
        self.seqc = seqc or os.path.join(ROOT, "target", "release", "seqc")
        self.cost = None

    def build(self, fee, annex_pad=None):
        """The claim with `fee` paid in the coins' asset, its witnesses set."""
        withheld = fee + self.keep
        cap = self.pool.cap(self.collected)
        if withheld > cap:
            raise Refused("withheld over the cap: the fee %d and the claimer's %d come to %d of %s, and the cap "
                          "allows %d of the %d collected (%d bp)" % (fee, self.keep, withheld,
                                                                    display_asset(self.asset), cap,
                                                                    self.collected, self.pool.cap_bp))
        pay = self.pool.payouts(self.collected, withheld)
        for (script, _, label), amount in zip(self.pool.rows, pay):
            if amount == 0:
                raise Refused("%s's share of %d is zero: wait for more coins" % (label, self.collected - withheld))
        t = Tx()
        for c in self.coins:
            t.vin.append([c.txid, c.vout, 0xffffffff])
        for (script, _, _), amount in zip(self.pool.rows, pay):
            t.vout.append(TxOut.explicit(self.asset, amount, script))
        if self.keep:
            t.vout.append(TxOut.explicit(self.asset, self.keep, self.claimer_script))
        if fee:
            t.vout.append(TxOut.explicit(self.asset, fee, b""))
        t.wit = [[] for _ in t.vin]
        fscript, fcb = self.pool.leaf("follow")
        for i in range(1, len(t.vin)):
            t.wit[i] = [fscript, fcb]
        self.withheld = withheld
        self.payout = pay
        self._witness_leader(t, withheld, annex_pad)
        return t

    def _witness_leader(self, t, withheld, annex_pad):
        if self.pool.template_name == "sequentia/pool-split-tap3":
            script, cb = self.pool.leaf("claim")
            t.wit[0] = [le8(withheld), script, cb]
            return
        cb = bytes.fromhex(self.pool.tree["leaves"]["claim"]["control_block"])
        cmr = bytes.fromhex(self.pool.model_leaf_cmr())
        rows = ", ".join("(0x%s, %d)" % (sha256(s).hex(), n) for s, n, _ in self.pool.rows)
        req = {"source": self.pool.claim_source(),
               "witness": {"DENOM": {"value": str(self.pool.denom), "type": "u32"},
                           "WITHHOLD_CAP_BP": {"value": str(self.pool.cap_bp), "type": "u16"},
                           "WITHHELD": {"value": str(withheld), "type": "u64"},
                           "ROWS": {"value": "list![%s]" % rows, "type": "List<(u256, u32), 64>"}},
               "tx": t.hex(), "utxos": [c.txout.serialize().hex() for c in self.coins],
               "index": 0, "control_block": cb.hex(), "genesis": self.genesis, "prune": True}
        r = seqc_run(self.seqc, req)
        if not r.get("executed"):
            raise Refused("the claim program refuses this transaction: %s" % r.get("exec_error"))
        stack = [bytes.fromhex(r["witness_hex"]), bytes.fromhex(r["program_hex"]), cmr, cb]
        self.cost = (r["cost_milli"] + 999) // 1000
        budget = lambda st: min(BUDGET_PER_BYTE * wit_bytes(st) + BUDGET_OFFSET, BUDGET_MAX)
        if annex_pad is None and budget(stack) < self.cost:
            annex_pad = 0
            while budget(stack + [b"\x50" + bytes(annex_pad)]) < self.cost:
                annex_pad += 1
        if annex_pad is not None:
            stack.append(b"\x50" + bytes(annex_pad))
        self.annex_pad = annex_pad
        self.budget = budget(stack)
        t.wit[0] = stack

    def make(self, rpc, rate=None, rounds=4):
        """Build with the fee the transaction's size needs at `rate` (atoms of
        the asset per vbyte; the node's floor when None)."""
        if rate is None:
            rate = fee_rate(rpc, self.asset)
        fee = 0
        for _ in range(rounds):
            if self.keep_max:
                self.keep = self.pool.cap(self.collected) - fee
                if self.keep < 0:
                    raise Refused("withheld over the cap: the fee alone is %d and the cap allows %d"
                                  % (fee, self.pool.cap(self.collected)))
            t = self.build(fee)
            vsize = rpc("decoderawtransaction", t.hex())["vsize"]
            need = int((Decimal(vsize) * Decimal(rate)).to_integral_value(ROUND_CEILING))
            if need <= fee:
                return t
            fee = need
        return self.build(fee)


def _model_leaf_cmr(self):
    for (kind, name, body), _ in sa._leaves(self.model["tree"]):
        if kind == "simplicity" and name == "claim":
            return body["cmr"]
    raise ValueError("no Simplicity claim leaf")


def _claim_source(self):
    for (kind, name, body), _ in sa._leaves(self.model["tree"]):
        if kind == "simplicity" and name == "claim":
            path = os.path.join(ROOT, "templates", TEMPLATES[self.template_name], body["source"])
            seqc = os.environ.get("SEQC", os.path.join(ROOT, "target", "release", "seqc"))
            text = subprocess.run([seqc, "expand", path], capture_output=True, check=True).stdout.decode()
            if sha256(text.encode()).hex() != body["source_sha256"]:
                raise ValueError("the source does not hash to the descriptor's source_sha256")
            return text
    raise ValueError("no Simplicity claim leaf")


Pool.model_leaf_cmr = _model_leaf_cmr
Pool.claim_source = _claim_source


# ---------------------------------------------------------------------------
# Checking a claim
# ---------------------------------------------------------------------------

def verify(pool, tx, rpc, maturity):
    """Check a claim transaction against the rule and the chain. Returns a
    summary; raises Refused naming the first thing the covenant or the chain
    would refuse."""
    coins = []
    for i, (txid, n, _) in enumerate(tx.vin):
        c = fetch_coin(rpc, txid, n)
        if c is None:
            raise Refused("input %d (%s:%d) is not an unspent coin" % (i, txid, n))
        coins.append(c)
    mine = [i for i, c in enumerate(coins) if c.txout.script == pool.script_pubkey]
    if not mine:
        raise Refused("the transaction spends no coin of this pool")
    if mine[0] != 0:
        raise Refused("input 0 must be a coin of the pool's script, which the claim leaf spends")
    if len(tx.vin) > MAX_INPUTS[pool.template_name]:
        raise Refused("a claim under %s has at most %d inputs" % (pool.template_name, MAX_INPUTS[pool.template_name]))
    asset = coins[0].txout.asset
    if asset is None:
        raise Refused("input 0 is confidential")
    collected = 0
    for i in mine:
        c = coins[i]
        if c.txout.asset != asset or c.txout.value is None:
            raise Refused("input %d is a coin of the pool in another asset, or confidential" % i)
        if not mature(c, maturity):
            raise Refused("input %d (%s) is an immature coinbase coin: %d of %d confirmations, counting the next "
                          "block" % (i, c.outpoint(), c.confirmations, maturity))
        collected += c.txout.value
    if len(tx.vout) < len(pool.rows):
        raise Refused("the claim has %d outputs for %d rows" % (len(tx.vout), len(pool.rows)))
    paid = []
    for i, (script, _, label) in enumerate(pool.rows):
        o = tx.vout[i]
        if o.asset != asset or o.value is None or o.nonce != b"\x00":
            raise Refused("output %d (%s) is not explicit in the claimed asset with no nonce" % (i, label))
        if o.script != script:
            raise Refused("output %d pays another script than %s's" % (i, label))
        paid.append(o.value)
    withheld = collected - sum(paid)
    if withheld < 0:
        raise Refused("the rows are paid %d, more than the %d collected" % (sum(paid), collected))
    if withheld > pool.cap(collected):
        raise Refused("withheld over the cap: %d of %d collected, and the cap allows %d (%d bp)"
                      % (withheld, collected, pool.cap(collected), pool.cap_bp))
    want = pool.payouts(collected, withheld)
    for i, (got, w) in enumerate(zip(paid, want)):
        if got != w:
            raise Refused("wrong share: output %d (%s) pays %d, and the rule gives %d"
                          % (i, pool.rows[i][2], got, w))
    if pool.template_name == "sequentia/pool-split-tap3":
        st = tx.wit[0]
        if not st or st[0] != le8(withheld):
            raise Refused("the witness states another withheld amount than the outputs leave")
    return {"asset": display_asset(asset), "coins": len(mine), "collected": collected, "withheld": withheld,
            "cap": pool.cap(collected), "payouts": [{"row": pool.rows[i][2], "amount": a} for i, a in enumerate(paid)]}
