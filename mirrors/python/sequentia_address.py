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
NUMS_KEY = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
INTEGER_LIMIT = 2**53

# The shape of a version 1 template: every field, its type, and which are
# optional (a "?" suffix). A template with any other field is refused.
_STR, _INT = "str", "int"
_TEMPLATE = {
    "name": _STR, "version": _INT, "summary": _STR, "layout": _STR,
    "internal_key": _STR, "key_path?": _STR,
    "program": {"source": _STR, "source_sha256": _STR, "cmr": _STR,
                "compiler": {"name": _STR, "version": _STR},
                "witness": [{"name": _STR, "type": _STR, "source": _STR}]},
    "params": [{"name": _STR, "type": _STR, "role": _STR, "label": _STR}],
    "paths": [{"name": _STR, "who": _STR, "effect": _STR}],
}
_DESCRIPTOR = {
    "descriptor": _INT, "template": _TEMPLATE, "template_hash": _STR,
    "chains": [{"name": _STR, "genesis": "str|null", "bech32_hrp": _STR}],
    "measured?": "any",
}


def _check(value, shape, at):
    if shape == "any":
        return
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            raise ValueError("%s is not an object" % at)
        fields = {k.rstrip("?"): k.endswith("?") for k in shape}
        for k in value:
            if k not in fields:
                raise ValueError("%s: unknown field %s" % (at, k))
        for k, optional in fields.items():
            if k in value:
                _check(value[k], shape[k + "?" if optional else k], "%s.%s" % (at, k))
            elif not optional:
                raise ValueError("%s: missing field %s" % (at, k))
    elif isinstance(shape, list):
        if not isinstance(value, list):
            raise ValueError("%s is not an array" % at)
        for i, item in enumerate(value):
            _check(item, shape[0], "%s[%d]" % (at, i))
    elif shape == _INT:
        if type(value) is not int or not 0 <= value < INTEGER_LIMIT:
            raise ValueError("%s: %r is not an integer in [0, 2^53)" % (at, value))
    elif shape == _STR:
        if not isinstance(value, str):
            raise ValueError("%s is not a string" % at)
    elif shape == "str|null":
        if value is not None and not isinstance(value, str):
            raise ValueError("%s is not a string or null" % at)


def _integers(value, at):
    """Every number anywhere is an integer in [0, 2^53)."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _integers(v, "%s.%s" % (at, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _integers(v, "%s[%d]" % (at, i))
    elif type(value) is not int or not 0 <= value < INTEGER_LIMIT:
        raise ValueError("%s: %r is not an integer in [0, 2^53)" % (at, value))


def check_descriptor(descriptor):
    """Refuse a descriptor whose shape is not version 1's, that holds a number
    other than an integer in [0, 2^53), or whose key path is not declared."""
    _integers(descriptor, "descriptor")
    _check(descriptor, _DESCRIPTOR, "descriptor")
    t = descriptor["template"]
    if descriptor["descriptor"] != 1:
        raise ValueError("descriptor version %d is not 1" % descriptor["descriptor"])
    if t["layout"] != "fixed-root":
        raise ValueError("layout %s is not fixed-root" % t["layout"])
    if template_hash(t) != descriptor["template_hash"]:
        raise ValueError("template_hash does not match the template")
    nums = t["internal_key"] == NUMS_KEY
    if nums and "key_path" in t:
        raise ValueError("key_path is declared, but the internal key is the NUMS key")
    if not nums:
        if "key_path" not in t:
            raise ValueError("the internal key is not the NUMS key and the template declares no key path")
        if t["key_path"] not in [p["name"] for p in t["paths"]]:
            raise ValueError("key_path %s is not one of the template's paths" % t["key_path"])
    for p in t["params"]:
        if p["type"] not in WIDTHS:
            raise ValueError("parameter %s: type %s is not allowed" % (p["name"], p["type"]))


def loads(text):
    """Read a descriptor from JSON text, refusing what check_descriptor refuses."""
    def no_float(s):
        raise ValueError("%s is not an integer in [0, 2^53)" % s)
    d = json.loads(text, parse_float=no_float, parse_constant=no_float)
    check_descriptor(d)
    return d


def unhex(s, width=None):
    """Lowercase hex, of exactly `width` bytes when given."""
    if not isinstance(s, str) or len(s) % 2 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("not lowercase hex: %r" % (s,))
    b = bytes.fromhex(s)
    if width is not None and len(b) != width:
        raise ValueError("%d bytes where %d are needed" % (len(b), width))
    return b


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
        if p["name"] not in params:
            raise ValueError("parameter %s is missing" % p["name"])
        try:
            out += unhex(params[p["name"]], WIDTHS[p["type"]])
        except ValueError as e:
            raise ValueError("parameter %s: %s" % (p["name"], e))
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
    check_descriptor(descriptor)
    t = descriptor["template"]
    data = param_bytes(t, params)
    cmr = unhex(t["program"]["cmr"], 32)
    data_leaf = tagged("TapData", data)
    program_leaf = tagged("TapLeaf/elements", bytes([LEAF_VERSION_SIMPLICITY, len(cmr)]) + cmr)
    root = tagged("TapBranch/elements", b"".join(sorted([data_leaf, program_leaf])))
    internal = unhex(t["internal_key"], 32)
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
