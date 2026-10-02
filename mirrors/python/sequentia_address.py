"""Address derivation for fixed-root contract descriptors, with no compiler.

A version 1 descriptor's output is

    P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))

so an instance's address takes one hash and one curve tweak. This module needs
only the Python standard library. docs/descriptor.md is the specification.
"""
import hashlib
import json

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

LEAF_VERSION_SIMPLICITY = 0xBE
WIDTHS = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16, "u256": 32, "Pubkey": 32}


def sha256(b):
    return hashlib.sha256(b).digest()


def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def canonical_json(value):
    """Object keys sorted, no whitespace. Descriptors are printable ASCII."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def template_hash(template):
    return sha256(canonical_json(template).encode()).hex()


def param_bytes(template, params):
    if len(params) != len(template["params"]):
        raise ValueError("%d parameters given, the template has %d" % (len(params), len(template["params"])))
    out = b""
    for p in template["params"]:
        value = bytes.fromhex(params[p["name"]])
        if len(value) != WIDTHS[p["type"]]:
            raise ValueError("parameter %s has the wrong width" % p["name"])
        out += value
    return out


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _lift_x(x):
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - x ** 3 - 7) % P:
        raise ValueError("not a point")
    return (x, y if y % 2 == 0 else P - y)


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def segwit_v1_address(hrp, program):
    """bech32m (BIP350), witness version 1."""
    data, acc, bits = [1], 0, 0
    for b in program:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(hrp_exp + data + [0] * 6) ^ 0x2BC830A3
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def derive(descriptor, params):
    t = descriptor["template"]
    assert t["layout"] == "fixed-root"
    data = param_bytes(t, params)
    cmr = bytes.fromhex(t["program"]["cmr"])
    data_leaf = tagged("TapData", data)
    program_leaf = tagged("TapLeaf/elements", bytes([LEAF_VERSION_SIMPLICITY, len(cmr)]) + cmr)
    root = tagged("TapBranch/elements", b"".join(sorted([data_leaf, program_leaf])))
    internal = bytes.fromhex(t["internal_key"])
    tweak = tagged("TapTweak/elements", internal + root)
    q = _add(_lift_x(int.from_bytes(internal, "big")), _mul(int.from_bytes(tweak, "big") % N, G))
    output_key = q[0].to_bytes(32, "big")
    return {
        "param_bytes": data.hex(),
        "data_leaf": data_leaf.hex(),
        "program_leaf": program_leaf.hex(),
        "merkle_root": root.hex(),
        "tweak": tweak.hex(),
        "output_key": output_key.hex(),
        "output_key_parity": q[1] & 1,
        "script_pubkey": "5120" + output_key.hex(),
        "address": {c["name"]: segwit_v1_address(c["bech32_hrp"], output_key) for c in descriptor["chains"]},
    }
