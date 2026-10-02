"""Chain helpers for the regtest harness: transactions, funding, broadcasting,
and forcing a transaction into a block.

The node's own functional test framework does the node management and RPC.
It is imported from a Sequentia checkout (`SEQUENTIA_REPO`, set by
`harness/run.py`), read-only: bytecode writing is off and every data
directory lives under the run's --tmpdir.
"""
import sys
sys.dont_write_bytecode = True
import os
REPO = os.environ["SEQUENTIA_REPO"]
sys.path.insert(0, os.path.join(REPO, "test", "functional"))

import json
import os
import hashlib
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import BITCOIN_ASSET
from test_framework.address import program_to_witness
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.messages import (
    COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxOutAsset,
    CTxOutNonce, CTxOutValue, CTxOutWitness, uint256_from_str, tx_from_hex,
)
from test_framework.script import (
    CScript, CScriptOp, taproot_construct, TaprootSignatureHash,
    OP_0, OP_1, OP_1NEGATE, OP_CAT, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGFROMSTACK, OP_CHECKSIGFROMSTACKVERIFY,
    OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK,
    OP_IF, OP_SHA256, OP_SIZE, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, OP_RETURN,
    OP_2, OP_ADD, OP_ROT, OP_WITHIN, OP_GREATERTHAN, OP_2DUP, OP_INSPECTNUMINPUTS,
    OP_INSPECTVERSION, OP_INSPECTINPUTSEQUENCE, OP_INSPECTOUTPUTNONCE, OP_NOTIF, OP_OVER, OP_NIP,
    OP_INSPECTINPUTVALUE, OP_INSPECTINPUTASSET, OP_PUSHCURRENTINPUTINDEX,
    OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTVALUE, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_INSPECTNUMOUTPUTS, OP_INSPECTLOCKTIME,
    OP_SHA256INITIALIZE, OP_SHA256UPDATE, OP_SHA256FINALIZE,
)

HARNESS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDS = os.environ.get("HARNESS_RECORDS", os.path.join(HARNESS, "records"))

# BIP341 nothing-up-my-sleeve point: no known discrete log, so no key path.
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def sha256(b):
    return hashlib.sha256(b).digest()


def le8(n):
    assert 0 <= n < (1 << 63)
    return int(n).to_bytes(8, "little")


def asm(script):
    """Human-readable opcode form of a script."""
    out = []
    for el in CScript(script):
        if isinstance(el, CScriptOp):
            out.append(str(el))
        elif isinstance(el, int):
            out.append("OP_%d" % el if 0 <= el <= 16 else ("OP_1NEGATE" if el == -1 else str(el)))
        elif len(el) == 0:
            out.append("OP_0")
        elif len(el) <= 4:
            # a short push is a script number (timelock, size): show it in decimal
            b = bytes(el)
            n = int.from_bytes(b[:-1] + bytes([b[-1] & 0x7f]), "little")
            out.append("<%d>" % (-n if b[-1] & 0x80 else n))
        else:
            out.append("<%s>" % bytes(el).hex())
    return " ".join(out)


def control_block(tap, name):
    leaf = tap.leaves[name]
    return bytes([leaf.version + tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def wit_bytes(stack):
    """Serialized size of a witness stack (count + length-prefixed items)."""
    n = 1
    for it in stack:
        l = len(it)
        n += (1 if l < 253 else 3 if l < 65536 else 5) + l
    return n


class Tx(CTransaction):
    """CTransaction without __slots__, so it can carry its prevouts (.prev)."""

    @classmethod
    def from_hex(cls, h):
        from io import BytesIO
        t = cls()
        t.deserialize(BytesIO(bytes.fromhex(h)))
        return t


class Utxo:
    def __init__(self, txid, vout, txout):
        self.txid, self.vout, self.txout = txid, vout, txout

    @property
    def amount(self):
        return self.txout.nValue.getAmount()

    @property
    def spk(self):
        return bytes(self.txout.scriptPubKey)

    def __repr__(self):
        return "Utxo(%s:%d)" % (self.txid, self.vout)


def sweep_leaf(expiry, s_x):
    """A tapscript sibling leaf: <expiry> CLTV DROP <S> CHECKSIG."""
    return CScript([expiry, OP_CHECKLOCKTIMEVERIFY, OP_DROP, s_x, OP_CHECKSIG])


# --------------------------------------------------------------------------
# Framework base
# --------------------------------------------------------------------------

class ChainBase:
    """Mixin: use as `class T(ChainBase, BitcoinTestFramework)` and define
    set_test_params (calling self.chain_params()) and run_test in the subclass --
    the framework's metaclass insists both live in the concrete class.

    The chain is a custom chain (`elementsregtest`) with transparent defaults:
    unblinded addresses, any-asset fees on. Results go to RECORDS/<NAME>.json."""
    NAME = "base"
    EXTRA = []

    def chain_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-initialfreecoins=2100000000000000",
            "-anyonecanspendaremine=1",
            "-blindedaddresses=0",
            "-con_default_blinded_addresses=0",
            "-validatepegin=0",
            "-con_parent_chain_signblockscript=51",
            "-con_any_asset_fees=1",
            "-maxtxfee=100.0",
            "-txindex=1",
        ] + list(self.EXTRA)]
        self.R = {}          # results, dumped as JSON

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()

    # -- results ---------------------------------------------------------
    def rec(self, key, value):
        self.R[key] = value
        self.dump()

    def dump(self):
        os.makedirs(RECORDS, exist_ok=True)
        with open(os.path.join(RECORDS, self.NAME + ".json"), "w") as f:
            json.dump(self.R, f, indent=1, default=str)

    # -- chain bootstrap -------------------------------------------------
    def boot(self, issue=("X", "Y")):
        node = self.nodes[0]
        self.node = node
        self.generate(node, 101)
        node.sendtoaddress(address=node.getnewaddress(), amount=1000000,
                           fee_asset_label=BITCOIN_ASSET)
        self.generate(node, 1)
        self.genesis = uint256_from_str(bytes.fromhex(node.getblockhash(0))[::-1])
        self.POL = BITCOIN_ASSET
        self.POL_OUT = self.asset_out(BITCOIN_ASSET)
        self.assets = {}
        for name in issue:
            a = node.issueasset(assetamount=1000000, tokenamount=0, blind=False,
                                fee_asset=BITCOIN_ASSET)["asset"]
            self.generate(node, 1)
            self.assets[name] = a
            setattr(self, name, a)
            setattr(self, name + "_OUT", self.asset_out(a))
            setattr(self, name + "_ID", bytes.fromhex(a)[::-1])
        self.rates0 = node.getfeeexchangerates()
        self.log.info("fee whitelist at boot: %s", self.rates0)

    def whitelist(self, *assets):
        """Fee whitelist = boot whitelist + the named assets at 1:1."""
        rates = dict(self.rates0)
        for a in assets:
            rates[a] = 100000000
        self.node.setfeeexchangerates(rates)
        return self.node.getfeeexchangerates()

    # -- output / utxo helpers ------------------------------------------
    @staticmethod
    def asset_out(display_hex):
        return b"\x01" + bytes.fromhex(display_hex)[::-1]

    @staticmethod
    def out(amount, spk, asset_out):
        return CTxOut(nValue=CTxOutValue(amount), scriptPubKey=spk,
                      nAsset=CTxOutAsset(asset_out), nNonce=CTxOutNonce())

    @staticmethod
    def fee(amount, asset_out):
        return CTxOut(nValue=CTxOutValue(amount), scriptPubKey=b"",
                      nAsset=CTxOutAsset(asset_out), nNonce=CTxOutNonce())

    def wallet_spk(self):
        a = self.node.getnewaddress("", "bech32")
        info = self.node.getaddressinfo(a)
        u = info.get("unconfidential", a)
        return bytes.fromhex(self.node.getaddressinfo(u)["scriptPubKey"])

    def utxo_of(self, txid, spk, hexraw=None):
        tx = tx_from_hex(hexraw or self.node.getrawtransaction(txid))
        for i, o in enumerate(tx.vout):
            if bytes(o.scriptPubKey) == bytes(spk):
                return Utxo(txid, i, o)
        raise AssertionError("spk not found in " + txid)

    def utxo_at(self, txid, vout):
        tx = tx_from_hex(self.node.getrawtransaction(txid))
        return Utxo(txid, vout, tx.vout[vout])

    def fund(self, spk, atoms, asset, mine=True):
        """Pay `atoms` of `asset` to a witness-v1 spk from the wallet."""
        spk = bytes(spk)
        ver = 0 if spk[0] == 0 else spk[0] - 0x50
        addr = program_to_witness(ver, spk[2:])
        txid = self.node.sendtoaddress(address=addr, amount=Decimal(atoms) / COIN,
                                       assetlabel=asset, fee_asset_label=BITCOIN_ASSET)
        if mine:
            self.generate(self.node, 1)
        return self.utxo_of(txid, spk)

    def wallet_utxo(self, atoms, asset=None):
        """A fresh wallet-owned P2WPKH utxo of exactly `atoms`."""
        asset = asset or BITCOIN_ASSET
        spk = self.wallet_spk()
        return self.fund(spk, atoms, asset)

    # -- tx assembly -----------------------------------------------------
    def mktx(self, ins, outs, locktime=0, version=2):
        """ins: [Utxo] or [(Utxo, nSequence)]; outs: [CTxOut]."""
        tx = Tx()
        tx.nVersion = version
        tx.nLockTime = locktime
        self._prev = []
        for i in ins:
            u, seq = i if isinstance(i, tuple) else (i, 0xfffffffe if locktime else 0xffffffff)
            tx.vin.append(CTxIn(COutPoint(int(u.txid, 16), u.vout), nSequence=seq))
            self._prev.append(u)
        tx.vout = list(outs)
        self.pad(tx)
        tx.prev = list(self._prev)
        return tx

    @staticmethod
    def pad(tx):
        while len(tx.wit.vtxinwit) < len(tx.vin):
            tx.wit.vtxinwit.append(CTxInWitness())
        while len(tx.wit.vtxoutwit) < len(tx.vout):
            tx.wit.vtxoutwit.append(CTxOutWitness())

    def wallet_sign(self, tx):
        """Let the wallet sign its own inputs; covenant witnesses are kept."""
        prev = tx.prev
        saved = [list(w.scriptWitness.stack) for w in tx.wit.vtxinwit]
        r = self.node.signrawtransactionwithwallet(tx.serialize().hex())
        tx2 = Tx.from_hex(r["hex"])
        self.pad(tx2)
        for i, st in enumerate(saved):
            if st and not tx2.wit.vtxinwit[i].scriptWitness.stack:
                tx2.wit.vtxinwit[i].scriptWitness.stack = st
        tx2.prev = prev
        return tx2

    def sighash(self, tx, idx, leaf_script, hash_type=0):
        self.pad(tx)
        return TaprootSignatureHash(tx, [u.txout for u in tx.prev], hash_type,
                                    self.genesis, idx, scriptpath=True,
                                    script=CScript(leaf_script))

    def sign(self, sec, tx, idx, leaf_script):
        return sign_schnorr(sec, self.sighash(tx, idx, leaf_script))

    @staticmethod
    def setwit(tx, idx, stack):
        tx.wit.vtxinwit[idx].scriptWitness.stack = [bytes(x) for x in stack]

    # -- measuring / broadcasting ---------------------------------------
    def measure(self, tx):
        d = self.node.decoderawtransaction(tx.serialize().hex())
        m = {"size": d["size"], "vsize": d["vsize"], "weight": d["weight"],
             "nin": len(d["vin"]), "nout": len(d["vout"])}
        if "discountvsize" in d:
            m["discountvsize"] = d["discountvsize"]
        return m

    def accept(self, tx):
        return self.node.testmempoolaccept([tx.serialize().hex()])[0]

    def send(self, tx, label, mine=True, extra=None):
        """testmempoolaccept -> sendrawtransaction -> mine -> confirm. Records sizes."""
        m = self.measure(tx)
        res = self.accept(tx)
        m["testmempoolaccept"] = bool(res["allowed"])
        if not res["allowed"]:
            m["reject-reason"] = res.get("reject-reason")
            self.rec(label, m)
            raise AssertionError("%s not accepted: %s" % (label, res))
        if "fees" in res:
            m["fees"] = res["fees"]
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        m["txid"] = txid
        if mine:
            self.generate(self.node, 1)
            v = self.node.getrawtransaction(txid, True)
            assert v.get("confirmations", 0) >= 1, "not confirmed"
            m["confirmed"] = True
            m["block_height"] = self.node.getblockcount()
        if extra:
            m.update(extra)
        m["witness_input0_bytes"] = wit_bytes(tx.wit.vtxinwit[0].scriptWitness.stack)
        self.log.info("PASS %-44s vsize=%d weight=%d size=%d", label, m["vsize"], m["weight"], m["size"])
        self.rec(label, m)
        return txid

    def reject(self, tx, label, expect=None, consensus=True):
        """Assert a tx is rejected; record both the testmempoolaccept reason and
        the exact sendrawtransaction RPC error."""
        res = self.accept(tx)
        assert not res["allowed"], "%s unexpectedly ACCEPTED" % label
        reason = res.get("reject-reason", "")
        rpc = None
        try:
            self.node.sendrawtransaction(tx.serialize().hex())
            raise AssertionError("%s unexpectedly broadcast" % label)
        except JSONRPCException as e:
            rpc = "%s (code %s)" % (e.error["message"], e.error["code"])
        d = {"rejected": True, "reject-reason": reason, "rpc-error": rpc}
        if consensus:
            # Bypass mempool policy entirely: ask the node to build a block
            # containing the raw tx. A consensus-invalid tx makes block
            # assembly/validation fail; nothing is mined.
            h0 = self.node.getblockcount()
            try:
                self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()],
                                        invalid_call=False)
                raise AssertionError("%s: tx was MINED via generateblock (policy-only reject)" % label)
            except JSONRPCException as e:
                d["block-error"] = "%s (code %s)" % (e.error["message"], e.error["code"])
            assert self.node.getblockcount() == h0
        self.log.info("REJECT %-42s %s | block: %s", label, rpc, d.get("block-error"))
        if expect is not None:
            assert expect in reason or expect in rpc, (label, reason, rpc)
        self.rec(label, d)
        return reason

    def probe(self, tx, label):
        """Record what the mempool says, without asserting either way."""
        res = self.accept(tx)
        d = {"probe": True, "testmempoolaccept": bool(res["allowed"]),
             "reject-reason": res.get("reject-reason"), "vsize": self.measure(tx)["vsize"]}
        self.log.info("PROBE %-43s allowed=%s %s", label, d["testmempoolaccept"], d["reject-reason"])
        self.rec(label, d)
        return d

    def mine_raw(self, tx, label):
        """Mine a tx directly into a block (bypassing relay policy). Used to show
        a tx is consensus-valid even when policy refuses to relay it."""
        m = self.measure(tx)
        res = self.accept(tx)
        m["testmempoolaccept"] = bool(res["allowed"])
        m["reject-reason"] = res.get("reject-reason")
        self.node.generateblock(self.node.getnewaddress(), [tx.serialize().hex()], invalid_call=False)
        tx.rehash()
        v = self.node.getrawtransaction(tx.hash, True)
        assert v.get("confirmations", 0) >= 1
        m["txid"] = tx.hash
        m["confirmed_via_generateblock"] = True
        self.log.info("MINED(raw) %-38s vsize=%d policy-allowed=%s (%s)", label, m["vsize"],
                      m["testmempoolaccept"], m["reject-reason"])
        self.rec(label, m)
        return tx.hash

    def rec_script(self, label, script, tap=None, name=None):
        d = {"asm": asm(script), "hex": bytes(script).hex(), "bytes": len(bytes(script))}
        if tap is not None:
            d["scriptPubKey"] = bytes(tap.scriptPubKey).hex()
            if name:
                d["control_block_bytes"] = len(control_block(tap, name))
        self.rec(label, d)
        return d

    def mine_to(self, height):
        n = height - self.node.getblockcount()
        if n > 0:
            self.generate(self.node, n)

    def p2tr(self, sec=None):
        """A plain key-path taproot spk for a random key (pinned-child stand-in)."""
        sec = sec or generate_privkey()
        x = compute_xonly_pubkey(sec)[0]
        tap = taproot_construct(x)
        return bytes(tap.scriptPubKey), sec


# --------------------------------------------------------------------------
# Tree builder (used by T3, T8, T9)
