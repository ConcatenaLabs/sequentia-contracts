#!/usr/bin/env python3
"""The tapscript claim leaf of templates/pool_split_tap3, as descriptor items.

    python3 tools/pool-claim/twin_script.py        # print the "tapscript" item list

The descriptor stores the leaf as items, which is what every reader hashes; this
file is how those items were written, and `--asm` prints them as opcodes. It is
not read at run time. The rule is the Simplicity program's
(templates/pool_split/pool_split.simf) for a fixed table of three rows: row 0,
the pool, whose numerator is DENOM less the other two, and rows 1 and 2.

The witness is one item, WITHHELD, as 8 little-endian bytes. Numbers the 64-bit
opcodes read are 8-byte little-endian; a parameter pushed as a script number is
converted with OP_SCRIPTNUMTOLE64, which reads at most 4 bytes, so DENOM and the
numerators are below 2^31.
"""
import json
import sys

OP = dict(
    OP_0=0x00, OP_1NEGATE=0x4f, OP_1=0x51, OP_IF=0x63, OP_NOTIF=0x64, OP_ELSE=0x67,
    OP_ENDIF=0x68, OP_VERIFY=0x69, OP_TOALTSTACK=0x6b, OP_FROMALTSTACK=0x6c,
    OP_2DROP=0x6d, OP_DROP=0x75, OP_DUP=0x76, OP_NIP=0x77, OP_OVER=0x78, OP_PICK=0x79,
    OP_ROT=0x7b, OP_SWAP=0x7c, OP_CAT=0x7e, OP_SIZE=0x82, OP_EQUAL=0x87,
    OP_EQUALVERIFY=0x88, OP_ADD=0x93, OP_NOT=0x91, OP_0NOTEQUAL=0x92, OP_BOOLAND=0x9a,
    OP_LESSTHAN=0x9f, OP_GREATERTHAN=0xa0, OP_SHA256=0xa8,
    OP_INSPECTINPUTASSET=0xc8, OP_INSPECTINPUTVALUE=0xc9, OP_INSPECTINPUTSCRIPTPUBKEY=0xca,
    OP_PUSHCURRENTINPUTINDEX=0xcd, OP_INSPECTOUTPUTASSET=0xce, OP_INSPECTOUTPUTVALUE=0xcf,
    OP_INSPECTOUTPUTNONCE=0xd0, OP_INSPECTOUTPUTSCRIPTPUBKEY=0xd1, OP_INSPECTNUMINPUTS=0xd4,
    OP_ADD64=0xd7, OP_SUB64=0xd8, OP_MUL64=0xd9, OP_DIV64=0xda,
    OP_GREATERTHANOREQUAL64=0xdf, OP_SCRIPTNUMTOLE64=0xe0,
)
NAME = {v: k for k, v in OP.items()}

MAX_INPUTS = 8        # inputs a claim may have, input 0 included
ROWS = 3              # row 0 (the pool), row 1, row 2


def small(n):
    """A minimal push of a small script number."""
    if n == 0:
        return [OP["OP_0"]]
    if 1 <= n <= 16:
        return [0x50 + n]
    b = n.to_bytes((n.bit_length() + 8) // 8, "little")
    return [len(b)] + list(b)


def le8(n):
    return [8] + list(n.to_bytes(8, "little"))


class Asm:
    def __init__(self):
        self.items = []     # bytes, or ("push"|"num", NAME)

    def op(self, *names):
        for n in names:
            self.items.append(bytes([OP[n]]))

    def raw(self, bs):
        self.items.append(bytes(bs))

    def num(self, n):
        self.raw(small(n))

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


def param_le64(a, name):
    a.param("num", name)
    a.op("OP_SCRIPTNUMTOLE64")


def output_script_hash(a, i):
    """SHA256 of output i's scriptPubKey, rebuilt from what the opcode gives:
    a witness program and its version, or the hash and -1 for any other script."""
    a.num(i)
    a.op("OP_INSPECTOUTPUTSCRIPTPUBKEY", "OP_DUP", "OP_1NEGATE", "OP_EQUAL", "OP_IF", "OP_DROP", "OP_ELSE")
    a.op("OP_DUP", "OP_0NOTEQUAL", "OP_IF")
    a.raw([1, 0x50])
    a.op("OP_ADD", "OP_ELSE", "OP_DROP")
    a.raw([1, 0x00])
    a.op("OP_ENDIF", "OP_OVER", "OP_SIZE", "OP_NIP", "OP_CAT", "OP_SWAP", "OP_CAT", "OP_SHA256", "OP_ENDIF")


def require_output(a, i, asset_depth, script_param):
    """Output i: the value on top of the stack (consumed), explicitly, in the
    asset `asset_depth` below the top once the value is gone, to the row's
    script, with no nonce."""
    a.num(i)
    a.op("OP_INSPECTOUTPUTVALUE")
    a.num(1)
    a.op("OP_EQUALVERIFY", "OP_EQUALVERIFY")
    a.num(i)
    a.op("OP_INSPECTOUTPUTASSET")
    a.num(1)
    a.op("OP_EQUALVERIFY")
    a.num(asset_depth + 1)
    a.op("OP_PICK", "OP_EQUALVERIFY")
    output_script_hash(a, i)
    a.param("push", script_param)
    a.op("OP_EQUALVERIFY")
    a.num(i)
    a.op("OP_INSPECTOUTPUTNONCE", "OP_0", "OP_EQUALVERIFY")


def build():
    a = Asm()
    # The leader: this coin is input 0.
    a.op("OP_PUSHCURRENTINPUTINDEX", "OP_NOT", "OP_VERIFY")
    # WITHHELD: 8 bytes, not negative.                                   [W]
    a.op("OP_SIZE")
    a.num(8)
    a.op("OP_EQUALVERIFY", "OP_DUP")
    a.raw(le8(0))
    a.op("OP_GREATERTHANOREQUAL64", "OP_VERIFY")
    # The asset of input 0, explicit.                                    [W A]
    a.op("OP_0", "OP_INSPECTINPUTASSET")
    a.num(1)
    a.op("OP_EQUALVERIFY")
    # Every input of this script, summed; at most MAX_INPUTS inputs.     [W A S]
    a.op("OP_INSPECTNUMINPUTS")
    a.num(MAX_INPUTS + 1)
    a.op("OP_LESSTHAN", "OP_VERIFY")
    a.raw(le8(0))
    for j in range(MAX_INPUTS):
        a.op("OP_INSPECTNUMINPUTS")
        a.num(j)
        a.op("OP_GREATERTHAN", "OP_IF")
        a.num(j)
        a.op("OP_INSPECTINPUTSCRIPTPUBKEY", "OP_0", "OP_INSPECTINPUTSCRIPTPUBKEY",
             "OP_ROT", "OP_EQUAL", "OP_TOALTSTACK", "OP_EQUAL", "OP_FROMALTSTACK", "OP_BOOLAND", "OP_IF")
        a.num(j)
        a.op("OP_INSPECTINPUTASSET")
        a.num(1)
        a.op("OP_EQUALVERIFY")
        a.num(2)
        a.op("OP_PICK", "OP_EQUALVERIFY")
        a.num(j)
        a.op("OP_INSPECTINPUTVALUE")
        a.num(1)
        a.op("OP_EQUALVERIFY", "OP_ADD64", "OP_VERIFY", "OP_ENDIF", "OP_ENDIF")
    # The cap: W <= floor(S * cap / 10,000), computed without overflow.  [W A S]
    a.op("OP_DUP")
    a.raw(le8(10000))
    a.op("OP_DIV64", "OP_VERIFY")                                      # [W A S r q]
    param_le64(a, "WITHHOLD_CAP_BP")
    a.op("OP_MUL64", "OP_VERIFY", "OP_SWAP")                           # [W A S qc r]
    param_le64(a, "WITHHOLD_CAP_BP")
    a.op("OP_MUL64", "OP_VERIFY")
    a.raw(le8(10000))
    a.op("OP_DIV64", "OP_VERIFY", "OP_NIP", "OP_ADD64", "OP_VERIFY")   # [W A S capS]
    a.num(3)
    a.op("OP_PICK", "OP_GREATERTHANOREQUAL64", "OP_VERIFY")            # [W A S]
    # net = S - W.                                                       [A net]
    a.num(2)
    a.op("OP_PICK", "OP_SUB64", "OP_VERIFY", "OP_ROT", "OP_DROP")
    # (r, q) = divmod(net, DENOM); paid = 0.                             [A net r q paid]
    a.op("OP_DUP")
    param_le64(a, "DENOM")
    a.op("OP_DIV64", "OP_VERIFY")
    a.raw(le8(0))
    for i in range(1, ROWS):
        n = "ROW%d_NUM" % i
        a.num(1)
        a.op("OP_PICK")
        param_le64(a, n)
        a.op("OP_MUL64", "OP_VERIFY")                                  # [.. paid q*n]
        a.num(3)
        a.op("OP_PICK")
        param_le64(a, n)
        a.op("OP_MUL64", "OP_VERIFY")                                  # [.. paid q*n r*n]
        param_le64(a, "DENOM")
        a.op("OP_DIV64", "OP_VERIFY", "OP_NIP", "OP_ADD64", "OP_VERIFY")  # [.. paid share]
        a.op("OP_DUP")                                                 # [A net r q paid share share]
        require_output(a, i, 5, "ROW%d_SCRIPT" % i)                    # [A net r q paid share]
        a.op("OP_ADD64", "OP_VERIFY")                                  # [A net r q paid]
    # Row 0, the pool: net less what the other rows were paid.
    a.num(3)
    a.op("OP_PICK", "OP_SWAP", "OP_SUB64", "OP_VERIFY")                # [A net r q rest]
    require_output(a, 0, 3, "ROW0_SCRIPT")                             # [A net r q]
    a.op("OP_2DROP", "OP_2DROP", "OP_1")
    return a


def asm(items):
    out = []
    for it in items:
        if isinstance(it, dict):
            out.append("<%s>" % next(iter(it.values())))
            continue
        b, i = bytes.fromhex(it), 0
        while i < len(b):
            c = b[i]
            if 1 <= c <= 75:
                out.append("<%s>" % b[i + 1:i + 1 + c].hex())
                i += 1 + c
                continue
            out.append(NAME.get(c, "OP_%d" % (c - 0x50) if 0x51 <= c <= 0x60 else hex(c)))
            i += 1
    return " ".join(out)


if __name__ == "__main__":
    items = build().to_descriptor()
    print(asm(items) if "--asm" in sys.argv else json.dumps(items))
