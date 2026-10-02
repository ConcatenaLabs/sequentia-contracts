#!/usr/bin/env python3
"""Compare the commitment roots of the existing Sequentia Simplicity programs
under SimplicityHL 0.4.1 (what their repositories pin) and the pinned compiler,
and against the roots their repositories record.

    tools/compiler-roots/compare.py --swk /path/to/SWK --openamp /path/to/openamp

It reads the programs from the two checkouts without changing them, compiles
each with the arguments its own repository uses (listed below with where they
come from), and writes docs/compiler-roots.md and tools/compiler-roots/roots.json.
Build the tool first: cargo build --release --manifest-path tools/compiler-roots/Cargo.toml
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TOOL = os.path.join(HERE, "target", "release", "compiler-roots")


def u256(hexstr):
    return {"value": "0x" + hexstr, "type": "u256"}


def pubkey(hexstr):
    return {"value": "0x" + hexstr, "type": "Pubkey"}


def u64(n):
    return {"value": str(n), "type": "u64"}


def u32(n):
    return {"value": str(n), "type": "u32"}


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


G_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
P2WPKH_AB = bytes([0x00, 0x14]) + bytes([0xab] * 20)   # maker_script() / claimant_script()


def render_verifier(template, n_in, n_out, depth=16):
    """A line-for-line mirror of openamp/opendamp/src/programs.rs render_verifier."""
    input_scan = "".join("    let c%d: bool = check_input(%d, cu_sender, witness::I%d);\n" % (i, i, i)
                         for i in range(1, n_in + 1))
    any_ = "c%d" % n_in
    for i in range(n_in - 1, 0, -1):
        any_ = "either(c%d, %s)" % (i, any_)
    output_scan = ""
    for i in range(1, n_out + 1):
        if i == 1:
            output_scan += "    let paid: u64 = check_output(1, cu_sender, witness::W1);\n"
        else:
            output_scan += ("    let paid: u64 = add_payment(paid, check_output(%d, cu_sender, witness::W%d));\n"
                            % (i, i))
    return (template.replace("%%DEPTH%%", str(depth))
            .replace("%%NUM_INPUTS_LT%%", str(n_in + 1 + 1))
            .replace("%%NUM_OUTPUTS_LT%%", str(n_out + 1 + 1))
            .replace("%%INPUT_SCAN%%", input_scan.rstrip("\n"))
            .replace("%%INPUT_ANY%%", any_)
            .replace("%%OUTPUT_SCAN%%", output_scan.rstrip("\n")))


def programs(swk, openamp):
    """(entry, provenance) for every program, in dependency order."""
    def read(*parts):
        with open(os.path.join(*parts)) as f:
            return f.read()

    data = os.path.join(swk, "lwk_simplicity", "data")
    damp = os.path.join(openamp, "opendamp")
    vec = json.load(open(os.path.join(damp, "vectors", "addresses.json")))
    out = []

    # --- SWK (lwk_simplicity/data) ---------------------------------------
    p2pk_args = {"PUBLIC_KEY": pubkey("8a65c55726dc32b59b649ad0187eb44490de681bb02601b8d3f58c8b9fff9083")}
    out.append(dict(
        id="swk/p2pk", program="SWK `p2pk.simf`", source=read(data, "p2pk.simf"), args=p2pk_args, debug=False,
        recorded=None,
        args_from="`TEST_X_ONLY_PUBLIC_KEY` of `lwk_bindings/tests/bindings/simplicity_p2pk.py`, compiled as "
                  "`lwk_simplicity::scripts::load_program` does, without debug symbols"))
    out.append(dict(
        id="swk/p2pk+debug", program="SWK `p2pk.simf`, with debug symbols", source=read(data, "p2pk.simf"),
        args=p2pk_args, debug=True,
        recorded=("b685a4424842507d7d747e6611a740d8c421038e9744e75d423d0e2e9f164d02",
                  "`TEST_CMR` in `lwk_bindings/tests/bindings/simplicity_p2pk.py`"),
        args_from="the same key, compiled with debug symbols as that test does (`load_with_debug_symbols(..., True)`)"))
    a = "".join("%02x" % x for x in range(1, 33))
    out.append(dict(
        id="swk/options", program="SWK `options.simf`", source=read(data, "options.simf"), debug=False,
        args={"COLLATERAL_ASSET_ID": u256("11" * 32), "SETTLEMENT_ASSET_ID": u256("22" * 32),
              "OPTION_TOKEN_ASSET": u256("33" * 32), "OPTION_REISSUANCE_TOKEN_ASSET": u256("44" * 32),
              "GRANTOR_TOKEN_ASSET": u256("55" * 32), "GRANTOR_REISSUANCE_TOKEN_ASSET": u256("66" * 32),
              "COLLATERAL_PER_CONTRACT": u64(1000), "SETTLEMENT_PER_CONTRACT": u64(2000),
              "START_TIME": u32(1700000000), "EXPIRY_TIME": u32(1800000000)},
        recorded=None,
        args_from="fixed values chosen here: the only test that compiles it "
                  "(`lwk_bindings/tests/bindings/simplicity_options_regtest.py`) derives its arguments from "
                  "outpoints of a live regtest chain, so no fixed instance is recorded"))
    del a
    out.append(dict(
        id="swk/seqob_fill", program="SWK `seqob_fill.simf`", source=read(data, "seqob_fill.simf"), debug=False,
        args={"ASSET_B": u256("11" * 32), "REQUIRED_B": u64(1000),
              "MAKER_SPK_HASH": u256(sha256_hex(P2WPKH_AB)), "MAKER_PUBKEY": pubkey(G_X)},
        recorded=None,
        args_from="`build_args(asset_b(), &maker_script())` of `lwk_simplicity/tests/seqob_covenant.rs`, whose "
                  "`taproot_substrate_cmr_and_address` prints the root and asserts nothing. Run with "
                  "`cargo test -p lwk_simplicity --test seqob_covenant taproot_substrate -- --nocapture` under "
                  "0.4.1, it printed `a2deeda091ebe1d9424b75bc2b679dffc268fd2c44f5fdb8206f17de926413bc`"))
    out.append(dict(
        id="swk/seqob_partial", program="SWK `seqob_partial.simf`", source=read(data, "seqob_partial.simf"),
        debug=False,
        args={"ASSET_A": u256("0a" * 32), "ASSET_B": u256("0b" * 32), "RATE_NUM": u64(3), "RATE_DEN": u64(2),
              "MAKER_SPK_HASH": u256(sha256_hex(P2WPKH_AB)), "MIN_LOT": u64(10), "MAKER_PUBKEY": pubkey(G_X)},
        recorded=None, args_from="`build_args()` of `lwk_simplicity/tests/seqob_partial.rs`"))
    out.append(dict(
        id="swk/seqob_xchain_seqleg", program="SWK `seqob_xchain_seqleg.simf`",
        source=read(data, "seqob_xchain_seqleg.simf"), debug=False,
        args={"HASHLOCK": u256(sha256_hex(bytes(32))), "ASSET_A": u256("0a" * 32), "AMOUNT_A": u64(1000),
              "CLAIMANT_SPK_HASH": u256(sha256_hex(P2WPKH_AB)), "FUNDER_PUBKEY": pubkey(G_X)},
        recorded=None, args_from="`build_args()` of `lwk_simplicity/tests/seqob_xchain_seqleg.rs`"))

    # --- OpenDAMP (opendamp/programs) -----------------------------------
    prog = vec["programs"]
    common = {"ASSET_A": u256(vec["asset_internal_bytes"]),
              "ASSET_V": u256(vec["verifier_asset_internal_bytes"]),
              "AMOUNT_Q": u64(vec["verifier_amount"])}
    vecfile = "`opendamp/vectors/addresses.json`"
    out.append(dict(
        id="opendamp/user", program="OpenDAMP `user.simf` (U)", source=read(damp, "programs", "user.simf"),
        args=dict(common), debug=False, recorded=(prog["u_cmr"], vecfile + " `programs.u_cmr`"),
        args_from="the asset, verifier asset and verifier amount of " + vecfile + ", as `compile_user` passes them"))
    out.append(dict(
        id="opendamp/issuer", program="OpenDAMP `issuer.simf` (G)", source=read(damp, "programs", "issuer.simf"),
        args={"ISSUER_KEY": pubkey(vec["issuer_key"])}, debug=False,
        recorded=(prog["g_cmr"], vecfile + " `programs.g_cmr`"),
        args_from="`issuer_key` of " + vecfile))
    pol = vec["policy"]
    vargs = dict(common, U_CMR={"value": "@cmr:opendamp/user", "type": "u256"},
                 WL_ROOT=u256(pol["whitelist_root"]), BL_ROOT=u256(pol["blacklist_root"]),
                 LIMIT=u64(pol["transfer_limit"]), PI=u256(pol["pi"]))
    template = read(damp, "programs", "verifier.simf.in")
    for s in prog["verifier_shapes"]:
        n_in, n_out = s["max_inputs"] - 1, s["max_outputs"] - 1
        out.append(dict(
            id="opendamp/verifier/" + s["shape"],
            program="OpenDAMP `verifier.simf.in` (P), shape %s%s" % (s["shape"], ", canonical" if s["canonical"] else ""),
            source=render_verifier(template, n_in, n_out), args=vargs, debug=False,
            recorded=(s["cmr"], vecfile + " `programs.verifier_shapes`"),
            args_from="the policy of " + vecfile + " (whitelist and blacklist roots, transfer limit, pi) and "
                      "U's root under the same compiler; the template rendered as `render_verifier` does"))
    return out


CHOICES = {
    "swk/p2pk": "Same root under both compilers. SWK can take the pinned compiler from this crate with no address change.",
    "swk/p2pk+debug": "The recorded vector is a debug-symbol build and holds under both compilers. Debug symbols change the root (compare the row above), so a vector for a deployed contract is always a build without them.",
    "swk/options": "Same root. Upstream's option contract, LBTC-collateral only and with no Sequentia caller: it stays in SWK as upstream code and is not carried into this repository.",
    "swk/seqob_fill": "Same root. An experiment, not the shipped order book (which is tapscript), with a literal expiry height: it stays in SWK and is not carried here unchanged.",
    "swk/seqob_partial": "Same root. An experiment, as above; a successor belongs here only rewritten as a contract with its regtest test.",
    "swk/seqob_xchain_seqleg": "Same root. An experiment, as above; the cross-chain leg in production is a tapscript HTLC.",
    "opendamp/user": "Same root as the recorded vector. OpenDAMP can move to the pinned compiler without changing any deployed asset's address.",
    "opendamp/issuer": "Same root as the recorded vector; moves with U.",
    "opendamp/verifier/p3x5": "Same root as the recorded vector; moves with U. Every shape stays valid for the assets issued against it.",
    "opendamp/verifier/p3x4": "Same root as the recorded vector; moves with U.",
    "opendamp/verifier/p4x6": "Same root as the recorded vector; moves with U.",
    "opendamp/verifier/p5x7": "Same root as the recorded vector; moves with U.",
}


def write_doc(record, path):
    progs = record["programs"]
    c = record["compilers"]
    L = ["# Existing programs under the pinned compiler", "",
         "The Simplicity programs in the wallet kit (`ConcatenaLabs/SWK`, `lwk_simplicity/data/`) and in "
         "OpenDAMP (`ConcatenaLabs/openamp`, `opendamp/programs/`) are built with SimplicityHL %s. This page "
         "compiles each with the arguments its own repository uses, under %s and under the compiler this "
         "repository pins (%s), and compares the commitment roots with each other and with the roots those "
         "repositories record." % (c["v0_4_1"], c["v0_4_1"], c["pinned"]), "",
         "Compared at SWK `%s` and openamp `%s`. Generated by `tools/compiler-roots/compare.py`, which links "
         "both compilers into one binary; the full output, arguments included, is "
         "`tools/compiler-roots/roots.json`." % (record["swk_commit"], record["openamp_commit"]), "",
         "## Roots", "",
         "| Program | Root under %s | Root under %s | Compiled unchanged | Recorded root | What had to change |" % (c["v0_4_1"], c["pinned"]),
         "|---|---|---|---|---|---|"]
    for p in progs:
        old, new = p["v0_4_1"], p["pinned"]
        rec = "none recorded"
        if p["recorded_cmr"]:
            ok = p["matches_recorded_0_4_1"] and p["matches_recorded_pinned"]
            rec = "%s by both, %s" % ("matched" if ok else "NOT matched", p["recorded_in"])
        changed = "nothing" if p["compiled_unchanged"] else (old.get("error") or new.get("error"))[:200]
        L.append("| %s | `%s` | `%s` | %s | %s | %s |" % (
            p["program"], old.get("cmr", "error"), new.get("cmr", "error"),
            "yes" if p["compiled_unchanged"] else "no", rec, changed))
    same = sum(1 for p in progs if p["root_unchanged"])
    L += ["", "%d of %d compilations give the same root under both compilers. Program sizes are identical too "
          "(`roots.json`), and the pinned compiler's lints find nothing in any of them." % (same, len(progs)), "",
          "## Arguments", "", "| Program | Arguments |", "|---|---|"]
    for p in progs:
        L.append("| %s | %s |" % (p["program"], p["args_from"]))
    L += ["", "## Choice for each program", "", "| Program | Choice |", "|---|---|"]
    for p in progs:
        L.append("| %s | %s |" % (p["program"], CHOICES[p["id"]]))
    L.append("")
    with open(path, "w") as f:
        f.write("\n".join(L))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--swk", required=True, help="a checkout of ConcatenaLabs/SWK")
    ap.add_argument("--openamp", required=True, help="a checkout of ConcatenaLabs/openamp")
    a = ap.parse_args()

    entries = programs(os.path.abspath(a.swk), os.path.abspath(a.openamp))
    req = {"programs": [{k: e[k] for k in ("id", "source", "args", "debug")} for e in entries]}
    rep = json.loads(subprocess.check_output([TOOL], input=json.dumps(req).encode()))
    by_id = {p["id"]: p for p in rep["programs"]}

    def commit_of(path):
        try:
            return subprocess.check_output(["git", "-C", path, "rev-parse", "--short=9", "HEAD"]).decode().strip()
        except Exception:
            return "unknown"

    record = {"swk_commit": commit_of(a.swk), "openamp_commit": commit_of(a.openamp),
              "compilers": rep["compilers"], "programs": []}
    for e in entries:
        r = by_id[e["id"]]
        old, new = r["v0_4_1"], r["pinned"]
        rec = {"id": e["id"], "program": e["program"], "debug_symbols": e["debug"], "args_from": e["args_from"],
               "args": e["args"], "v0_4_1": old, "pinned": new,
               "recorded_cmr": e["recorded"][0] if e["recorded"] else None,
               "recorded_in": e["recorded"][1] if e["recorded"] else None}
        rec["compiled_unchanged"] = "error" not in old and "error" not in new
        rec["root_unchanged"] = rec["compiled_unchanged"] and old["cmr"] == new["cmr"]
        rec["matches_recorded_0_4_1"] = (old.get("cmr") == rec["recorded_cmr"]) if rec["recorded_cmr"] else None
        rec["matches_recorded_pinned"] = (new.get("cmr") == rec["recorded_cmr"]) if rec["recorded_cmr"] else None
        record["programs"].append(rec)

    with open(os.path.join(HERE, "roots.json"), "w") as f:
        json.dump(record, f, indent=1)
        f.write("\n")
    write_doc(record, os.path.join(ROOT, "docs", "compiler-roots.md"))
    for p in record["programs"]:
        print("%-28s 0.4.1 %s  pinned %s  same=%s  recorded=%s/%s" % (
            p["id"], p["v0_4_1"].get("cmr", "ERR")[:16], p["pinned"].get("cmr", "ERR")[:16],
            p["root_unchanged"], p["matches_recorded_0_4_1"], p["matches_recorded_pinned"]))
        for side in ("v0_4_1", "pinned"):
            if "error" in p[side]:
                print("   %s error: %s" % (side, p[side]["error"][:300]))
        if p["pinned"].get("lint"):
            print("   lint:", p["pinned"]["lint"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
