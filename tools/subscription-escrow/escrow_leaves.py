#!/usr/bin/env python3
"""The tapscript leaves of templates/subscription_escrow, as descriptor items.

    python3 tools/subscription-escrow/escrow_leaves.py          # the three leaves, as JSON
    python3 tools/subscription-escrow/escrow_leaves.py --asm    # the same, as opcodes

The descriptor stores each leaf as items, which is what every reader hashes;
this file is how those items were written. It is not read at run time.

Parameters are pushed as their bytes, which the data leaf convention gives in
big-endian order, and the 64-bit opcodes read little-endian numbers, so each
64-bit parameter is reversed in the script with OP_SUBSTR and OP_CAT before it
is compared (`le64_param`). The locktimes are script numbers, as
OP_CHECKLOCKTIMEVERIFY reads them.
"""
import json
import sys

OP = dict(
    OP_0=0x00, OP_1NEGATE=0x4f, OP_1=0x51, OP_IF=0x63, OP_ELSE=0x67, OP_ENDIF=0x68, OP_VERIFY=0x69,
    OP_DROP=0x75, OP_DUP=0x76, OP_NIP=0x77, OP_OVER=0x78, OP_ROT=0x7b, OP_SWAP=0x7c, OP_CAT=0x7e,
    OP_SUBSTR=0x7f, OP_SIZE=0x82, OP_EQUAL=0x87, OP_EQUALVERIFY=0x88, OP_ADD=0x93, OP_0NOTEQUAL=0x92,
    OP_SHA256=0xa8, OP_CHECKSIG=0xac, OP_CHECKLOCKTIMEVERIFY=0xb1,
    OP_INSPECTINPUTASSET=0xc8, OP_INSPECTINPUTVALUE=0xc9, OP_PUSHCURRENTINPUTINDEX=0xcd,
    OP_INSPECTOUTPUTASSET=0xce, OP_INSPECTOUTPUTVALUE=0xcf, OP_INSPECTOUTPUTNONCE=0xd0,
    OP_INSPECTOUTPUTSCRIPTPUBKEY=0xd1, OP_ADD64=0xd7, OP_GREATERTHANOREQUAL64=0xdf,
)
NAME = {v: k for k, v in OP.items()}


class Asm:
    def __init__(self):
        self.items = []     # bytes, or ("push"|"num", NAME)

    def op(self, *names):
        for n in names:
            self.items.append(bytes([OP[n]]))

    def raw(self, bs):
        self.items.append(bytes(bs))

    def num(self, n):
        assert 0 <= n <= 16
        self.raw([OP["OP_0"]] if n == 0 else [0x50 + n])

    def param(self, kind, name):
        self.items.append((kind, name))

    def to_descriptor(self):
        out, buf = [], b""
        for it in self.items:
            if isinstance(it, bytes):
                buf += it
            else:
                if buf:
                    out.append(buf.hex())
                    buf = b""
                out.append({it[0]: it[1]})
        if buf:
            out.append(buf.hex())
        return out

    def to_asm(self):
        out = []
        for it in self.items:
            if isinstance(it, tuple):
                out.append("<%s>" % it[1])
                continue
            i = 0
            while i < len(it):
                b = it[i]
                if 1 <= b <= 75:
                    out.append(it[i + 1:i + 1 + b].hex())
                    i += 1 + b
                    continue
                out.append(NAME.get(b, "OP_%d" % (b - 0x50) if 0x51 <= b <= 0x60 else hex(b)))
                i += 1
        return " ".join(out)


def le64_param(a, name):
    """Push the 8-byte parameter `name`, reversed into the little-endian form
    the 64-bit opcodes read."""
    a.param("push", name)                                   # x (big-endian)
    a.op("OP_DUP")
    a.num(7)
    a.num(1)
    a.op("OP_SUBSTR", "OP_SWAP")                            # acc=x[7], x
    for i in range(6, -1, -1):
        a.op("OP_DUP")
        a.num(i)
        a.num(1)
        a.op("OP_SUBSTR", "OP_ROT", "OP_SWAP", "OP_CAT", "OP_SWAP")   # acc||x[i], x
    a.op("OP_DROP")


def output_script_hash(a):
    """With an output index on the stack, SHA256 of that output's
    scriptPubKey, rebuilt from what the opcode gives: a witness program and
    its version, or the hash and -1 for any other script."""
    a.op("OP_INSPECTOUTPUTSCRIPTPUBKEY", "OP_DUP", "OP_1NEGATE", "OP_EQUAL", "OP_IF", "OP_DROP", "OP_ELSE")
    a.op("OP_DUP", "OP_0NOTEQUAL", "OP_IF")
    a.raw([1, 0x50])
    a.op("OP_ADD", "OP_ELSE", "OP_DROP")
    a.raw([1, 0x00])
    a.op("OP_ENDIF", "OP_OVER", "OP_SIZE", "OP_NIP", "OP_CAT", "OP_SWAP", "OP_CAT", "OP_SHA256", "OP_ENDIF")


def pinned_output(a, index, asset, script_param):
    """The output at `index` (emitted by the callable `index`, which pushes it)
    is explicit, holds the asset `asset` pushes, pays the script whose hash is
    `script_param`, and carries no nonce; leaves its explicit value, as 8
    little-endian bytes, on the stack."""
    index()
    a.op("OP_INSPECTOUTPUTASSET")
    a.num(1)
    a.op("OP_EQUALVERIFY")
    asset()
    a.op("OP_EQUALVERIFY")
    index()
    output_script_hash(a)
    a.param("push", script_param)
    a.op("OP_EQUALVERIFY")
    index()
    a.op("OP_INSPECTOUTPUTNONCE", "OP_0", "OP_EQUALVERIFY")
    index()
    a.op("OP_INSPECTOUTPUTVALUE")
    a.num(1)
    a.op("OP_EQUALVERIFY")


def refund_to_subscriber(a):
    """Output k, for this coin at input k, returns the coin's own asset to
    REFUND_SCRIPT, explicitly, holding at least the coin's value less
    FEE_CAP: out + FEE_CAP >= in."""
    cur = lambda: a.op("OP_PUSHCURRENTINPUTINDEX")

    def coin_asset():
        cur()
        a.op("OP_INSPECTINPUTASSET")
        a.num(1)
        a.op("OP_EQUALVERIFY")
    pinned_output(a, cur, coin_asset, "REFUND_SCRIPT")      # out
    le64_param(a, "FEE_CAP")
    a.op("OP_ADD64", "OP_VERIFY")                           # out + cap
    cur()
    a.op("OP_INSPECTINPUTVALUE")
    a.num(1)
    a.op("OP_EQUALVERIFY")                                  # out + cap, in
    a.op("OP_GREATERTHANOREQUAL64", "OP_VERIFY")


def release():
    """After CLOSE, ISSUER_KEY's signature; output 0 pays ISSUER_SCRIPT at
    least MINIMUM of PAY_ASSET, explicitly."""
    a = Asm()
    a.param("num", "CLOSE")
    a.op("OP_CHECKLOCKTIMEVERIFY", "OP_DROP")
    pinned_output(a, lambda: a.num(0), lambda: a.param("push", "PAY_ASSET"), "ISSUER_SCRIPT")
    le64_param(a, "MINIMUM")
    a.op("OP_GREATERTHANOREQUAL64", "OP_VERIFY")
    a.param("push", "ISSUER_KEY")
    a.op("OP_CHECKSIG")
    return a


def cancel():
    """At any time, ISSUER_KEY's signature; the coin goes back to the subscriber."""
    a = Asm()
    refund_to_subscriber(a)
    a.param("push", "ISSUER_KEY")
    a.op("OP_CHECKSIG")
    return a


def refund():
    """After DEADLINE, anyone; the coin goes back to the subscriber."""
    a = Asm()
    a.param("num", "DEADLINE")
    a.op("OP_CHECKLOCKTIMEVERIFY", "OP_DROP")
    refund_to_subscriber(a)
    a.num(1)
    return a


LEAVES = {"release": release, "cancel": cancel, "refund": refund}


def main(argv):
    if "--asm" in argv:
        for name, f in LEAVES.items():
            print("%s: %s\n" % (name, f().to_asm()))
        return
    print(json.dumps({name: f().to_descriptor() for name, f in LEAVES.items()}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
