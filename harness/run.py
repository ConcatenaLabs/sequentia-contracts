#!/usr/bin/env python3
"""Run the regtest harness against a Sequentia node.

    harness/run.py                                  # every test but the ceilings
    harness/run.py s2 s6                            # some of them
    harness/run.py --ceilings                       # also the slow S1 ceiling runs
    harness/run.py --node-repo /path/to/Sequentia --sequentiad /path/to/sequentiad

Each test starts its own node on a custom chain (`elementsregtest`) with
Simplicity active from genesis and transparent defaults, builds and broadcasts
its spends, forces every negative case into a block with `generateblock`, and
writes its record to harness/records/<name>.json.

The node's functional test framework is imported from --node-repo
(test/functional); the binary is --sequentiad. Programs are compiled by `seqc`,
built here from this repository with the pinned compiler.
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HARNESS)

TESTS = [
    ("s0", "s0_activation", "A 0xbe output on a chain where Simplicity is not active"),
    ("s1", "s1_one_key", "One-key program, wrong key, bit flip, key path, annex"),
    ("s2", "s2_tree_node", "Covenant tree node, radix 2, 4 and 8, three encodings"),
    ("s3", "s3_rebind", "Custom signature hash that names no outpoint"),
    ("s4", "s4_state", "State carried across transactions in a data leaf"),
    ("s5", "s5_leave_one", "One owner leaves a shared output"),
    ("s6", "s6_timelocks", "Relative timelocks: the broken jets and the safe form"),
    ("s7", "s7_oracle", "Oracle-signed price and 128-bit arithmetic"),
    ("d1", "d1_descriptor", "The one-key template, addressed from its descriptor with no compiler"),
    ("d2", "d2_tree_descriptor", "A tree of a Simplicity leaf, a data leaf and a tapscript exit, spent by each path"),
    ("h1", "h1_helpers", "The shared helpers, each accepted and refused"),
    ("f1", "f1_faucet_drip", "The faucet drip covenant: drips, every violation refused, and the recovery"),
    ("o1", "o1_attestation", "One price attestation (format 2) through a Simplicity leaf and a tapscript leaf"),
    ("o2", "o2_beacon", "Fresh attestations: a beacon coin, its rotation, and old attestations refused after it"),
    ("p1", "p1_pool_split", "The pool split covenant, Simplicity and tapscript: claims by the tool, every violation refused"),
    ("p2", "p2_pool_split_pos", "The pool split covenant as a pool's payout script on a proof-of-stake chain, maturity 1,000"),
    ("m1", "m1_mint_limiter", "The mint limiter: mints within a window's allowance, the window's reset, the brake and the recovery"),
    ("m2", "m2_mint_limiter_tool", "The mint-limiter tool: every path it builds is mined, and each is read back"),
    ("u1", "u1_supply_cap", "The supply cap: mints up to the cap on each side of a rekey, the retirement; every violation refused"),
    ("u2", "u2_supply_cap_tool", "The token-covenants tool's supply cap: every path it builds is mined, and each is read back"),
    ("v1", "v1_verifier_token", "The verifier token: a halt that burns the verifier records it, the resume mints it back there; every violation refused"),
    ("v2", "v2_verifier_token_tool", "The token-covenants tool's verifier token: a record signed into a halt and a resume, both mined and read back"),
    ("l1", "l1_pignus_vault", "The Pignus vault and offer, version 2: a loan above version 1's limit taken, topped up, repaid and liquidated in part, called, recovered; every violation refused"),
    ("l2", "l2_pignus_vault_threshold", "The Pignus vault and offer under three oracles: a 2-of-3 loan taken and liquidated with two signatures, refused with one; every violation refused"),
    ("c1", "c1_capped_sale", "The capped sale: purchases within each buyer's cap at any input index, a full buy and the reclaim; every violation refused"),
    ("b1", "b1_oracle_bond", "The oracle bond: a conflict slashed (half burned, half to the presenter), notice and withdrawal after the wait; every violation refused"),
    ("e1", "e1_subscription_escrow", "The subscription escrow, tapscript: a release of two subscriptions, a cancel and a refund by anyone after the deadline; every violation refused"),
]
CEILINGS = [
    ("s1c", "s1_ceiling_annex", "Budget threshold, annex cap, program size, consensus cost cap"),
    ("s1d", "s1_ceiling_witness", "Budget bought with witness data; memory"),
]

CONFIG = """[environment]
PACKAGE_NAME=Sequentia Core
PACKAGE_BUGREPORT=https://github.com/ConcatenaLabs/Sequentia/issues
SRCDIR={repo}
BUILDDIR={repo}
EXEEXT=
RPCAUTH={repo}/share/rpcauth/rpcauth.py

[components]
ENABLE_WALLET=true
USE_SQLITE=true
USE_BDB=true
ENABLE_CLI=true
ENABLE_WALLET_TOOL=true
ENABLE_BITCOIND=true
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tests", nargs="*", help="test ids (s0 ... s7, d1, d2, h1, f1, o1, o2, p1, p2, m1, m2, u1, u2, v1, v2, l1, l2, c1, b1, e1, s1c, s1d); default all but s1c and s1d")
    ap.add_argument("--node-repo",
                    default=os.environ.get("SEQUENTIA_REPO", os.path.join(os.path.dirname(ROOT), "Sequentia")),
                    help="a Sequentia checkout, for its functional test framework "
                         "(default: $SEQUENTIA_REPO, else a Sequentia checkout beside this repository)")
    ap.add_argument("--sequentiad", help="the node binary (default <node-repo>/src/sequentiad)")
    ap.add_argument("--ceilings", action="store_true", help="also run the slow S1 ceiling tests")
    ap.add_argument("--tmpdir", default=os.path.join(HARNESS, "tmp"),
                    help="where node data directories go (removed after a passing test)")
    ap.add_argument("--no-build", action="store_true", help="use the seqc and the tools already built")
    a = ap.parse_args()

    repo = os.path.abspath(a.node_repo)
    sequentiad = os.path.abspath(a.sequentiad or os.path.join(repo, "src", "sequentiad"))
    cli = os.path.join(os.path.dirname(sequentiad), "sequentia-cli")
    for path in (os.path.join(repo, "test", "functional", "test_framework"), sequentiad, cli):
        if not os.path.exists(path):
            sys.exit("missing: %s" % path)

    known = {t[0]: t for t in TESTS + CEILINGS}
    chosen = [known[t] for t in a.tests] if a.tests else TESTS + (CEILINGS if a.ceilings else [])
    if a.tests and a.ceilings:
        chosen += [c for c in CEILINGS if c not in chosen]

    if not a.no_build:
        subprocess.check_call(["cargo", "build", "--release", "--locked", "--features", "sequentia-tx",
                               "--bin", "seqc"], cwd=ROOT)
        # m2 drives the mint-limiter tool, which builds in its own workspace.
        if any(t[0] == "m2" for t in chosen) and not os.environ.get("MINT_LIMITER"):
            subprocess.check_call(["cargo", "build", "--release", "--locked", "--manifest-path",
                                   os.path.join(ROOT, "tools", "mint-limiter", "Cargo.toml")], cwd=ROOT)
        # u2 and v2 drive the token-covenants tool, which builds in its own workspace too.
        if any(t[0] in ("u2", "v2") for t in chosen) and not os.environ.get("TOKEN_COVENANTS"):
            subprocess.check_call(["cargo", "build", "--release", "--locked", "--manifest-path",
                                   os.path.join(ROOT, "tools", "token-covenants", "Cargo.toml")], cwd=ROOT)
    seqc = os.path.join(ROOT, "target", "release", "seqc")

    os.makedirs(a.tmpdir, exist_ok=True)
    config = os.path.join(a.tmpdir, "config.ini")
    with open(config, "w") as f:
        f.write(CONFIG.format(repo=repo))
    records = os.path.join(HARNESS, "records")
    os.makedirs(records, exist_ok=True)
    logs = os.path.join(a.tmpdir, "logs")
    os.makedirs(logs, exist_ok=True)

    version = subprocess.check_output([sequentiad, "-version"]).decode().splitlines()[0]
    compiler = subprocess.check_output([seqc, "version"]).decode().strip()
    print("node: %s (%s)\ncompiler: %s\n" % (version, sequentiad, compiler))

    env = dict(os.environ, SEQUENTIA_REPO=repo, BITCOIND=sequentiad, BITCOINCLI=cli,
               SEQC=seqc, HARNESS_RECORDS=records, PYTHONDONTWRITEBYTECODE="1")
    results = []
    for tid, script, what in chosen:
        tmp = os.path.join(a.tmpdir, tid)
        shutil.rmtree(tmp, ignore_errors=True)
        log = os.path.join(logs, tid + ".log")
        t0 = time.time()
        with open(log, "w") as out:
            rc = subprocess.call(
                [sys.executable, os.path.join(HARNESS, "tests", script + ".py"),
                 "--configfile=" + config, "--tmpdir=" + tmp,
                 "--cachedir=" + os.path.join(a.tmpdir, "cache")],
                env=env, stdout=out, stderr=subprocess.STDOUT)
        secs = time.time() - t0
        results.append((tid, rc, secs))
        print("%-4s %-4s %6.0f s  %s%s" % (tid, "PASS" if rc == 0 else "FAIL", secs, what,
                                          "" if rc == 0 else "   (log: %s)" % log))
    failed = [r for r in results if r[1] != 0]
    print("\n%d passed, %d failed; records in %s" % (len(results) - len(failed), len(failed), records))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
