# Helpers

`helpers/` holds SimplicityHL functions that contracts share. The pinned
compiler keeps imports behind an unstable flag, so a program includes a helper
as source:

```rust
// include output_reader
// include wide_arith

fn main() {
    let (asset, amount, script): (u256, u64, u256) = out_explicit(0);
    // ...
}
```

A line that is exactly `// include <name>` is replaced by `helpers/<name>.simf`
before the program is compiled or linted. `seqc` does this everywhere it reads a
source (`run`, `lint`, `descriptor`), and `seqc expand <file>` prints the result.
A helper is included once however often it is named; helpers name their
functions with a common prefix so they do not collide. The commitment root
depends only on the expanded text, and a descriptor's `source_sha256` is the hash
of that text.

Each helper is proven on a regtest chain by `harness/tests/h1_helpers.py`: a
program that uses it is spent, and each violation is refused by the mempool and
then forced into a block with `generateblock`, which refuses it too. The figures
below come from `harness/records/h1.json`. The cost bound is the static bound the
node checks, rounded up to weight units; the budget is what the spend's witness
buys (4 weight units per witness byte, plus 50).

## The helpers

### `output_reader`

| Function | Does |
|---|---|
| `out_explicit(i) -> (asset, amount, script_hash)` | Reads output `i`, refusing one that is missing or whose asset or amount is confidential |
| `out_no_nonce(i)` | Output `i` carries no nonce |
| `out_require(i, asset, amount, script_hash)` | Output `i` pays exactly that amount of that asset to that script, explicitly and with no nonce |
| `in_explicit_current() -> (asset, amount)` | Reads the coin being spent, refusing a confidential one |

Asset ids are in internal byte order, the reverse of the hex an RPC prints. A
covenant can only police explicit outputs, which is why the reader refuses the
rest instead of guessing. An explicit output still has a nonce field, which
anyone building the transaction can fill, with a blinding key for instance; an
output a covenant pins exactly has none, so `out_require` checks that too.

### `wide_arith`

| Function | Does |
|---|---|
| `wide_mul(a, b) -> u128` | The full 128-bit product of two `u64` |
| `wide_add(a, b) -> u128`, `wide_sub(a, b) -> u128` | Refuse a result that does not fit |
| `wide_lt(a, b)`, `wide_le(a, b)` | 128-bit comparisons |
| `wide_mul_div(a, b, c, q) -> u64` | Checks that the spender's `q` is `floor(a * b / c)` and returns it |

Division is verified, not computed: `q * c <= a * b < (q + 1) * c`. The jet
`div_mod_128_64` is defined only for a divisor of at least 2^63 with a quotient
that fits in 64 bits, and returns all ones otherwise, so dividing by an ordinary
scale such as 10^8 cannot use it directly.

### `state`

| Function | Does |
|---|---|
| `state_require_current(state)` | The spent coin's data leaf holds `state`, checked through `jet::tappath(0)` |
| `state_script_hash(state) -> u256` | The script hash of this same program holding `state` |
| `state_require_successor(i, state)` | Output `i` is this program holding `state` |

One 32-byte slot in the data leaf, which a version 2
[descriptor](descriptor.md) records as a storage slot. The successor is built from this input's own leaf
and internal key, so no constant names the program.

### `relative_lock`

| Function | Does |
|---|---|
| `rel_lock_blocks(n)` | This input has waited at least `n` blocks |
| `rel_lock_time(n)` | This input has waited at least `n` units of 512 seconds |

Both read the sequence of the input being spent, and require a transaction
version of at least 2 and a sequence that BIP68 enforces. The four
relative-timelock jets read the largest lock over every input instead, and a
spender defeats them with an old coin of their own; the lints refuse them.

### `merkle`

| Function | Does |
|---|---|
| `merkle_leaf(data) -> u256` | `SHA256(0x00 \|\| data)` |
| `merkle_node(left, right) -> u256` | `SHA256(0x01 \|\| left \|\| right)` |
| `merkle_root_8(leaf, proof)`, `merkle_root_16(leaf, proof)` | Folds a proof of `(sibling, sibling_is_left)` pairs, leaf first |

The distinct prefixes keep a leaf from passing for an inner node. A proof's
depth is fixed by the template, so every position costs the same.

### `fee_cap`

| Function | Does |
|---|---|
| `fee_cap_require(asset, cap)` | The transaction's fees in `asset` total at most `cap` |

The cap is per asset: `jet::total_fee(asset)` counts only fee outputs in that
asset, and a fee paid in another asset was accepted under a cap of 500 on
regtest. A keyless path that must bound every fee caps each asset it lets pay
one, or requires the fee to be paid in the asset it holds.

### `attestation`

| Function | Does |
|---|---|
| `att_digest(key, base, quote, price, precision, time, beacon) -> u256` | The tagged hash a format-2 price attestation is signed over |
| `att_verify(key, base, quote, price, precision, time, beacon, sig)` | `sig` is `key`'s format-2 attestation of exactly these fields |
| `att_beacon_script_hash(beacon) -> u256` | SHA256 of `OP_1 <beacon>`, the form `jet::input_script_hash` returns |
| `att_beacon_check(beacon, beacon_asset, at)` | Input `at` spends an explicit coin of `beacon_asset` from the output script `beacon` names: the attestation's beacon is live |
| `att_verify_fresh(key, base, quote, price, precision, time, beacon, sig, beacon_asset, at)` | `att_verify` and `att_beacon_check` together |
| `att_le16`, `att_le32`, `att_le64` | Reverse the bytes of an integer |

The format belongs to [`sequentia-oracle`](https://github.com/ConcatenaLabs/sequentia-oracle)
(`doc/format.md` there): a 142-byte message of version, signer key, base and
quote asset ids, price, precision, time and beacon, signed with BIP340 over its
tagged hash (tag `Sequentia/oracle/price`). Integers are little-endian in the
message, so the helper reverses `price` and `time` before hashing them; asset
ids are in internal byte order. A contract fixes the key, the pair, the
precision as parameters and takes the price and the time from the witness, so
an attestation of anything else fails the signature check. A contract that
does not check freshness pins the beacon too (a zero one, for a signer without
a beacon); a contract that does takes the beacon from the witness and pins the
oracle's **beacon asset** instead, and `att_beacon_check` requires the
transaction to spend a coin of that asset from the script the attestation
names. The oracle moves every such coin to a new script when it rotates, so an
attestation signed before a rotation has no coin to point at
(sequentia-oracle `doc/format.md`, "The beacon", defines the script and the
rule).
`crates/sequentia-contracts/src/attestation.rs` is the Rust reader of the same
format, and `vectors/attestations.json` is a copy of the oracle repository's
golden vectors, pinned by `vectors/PIN.json`, which the Rust tests reproduce
byte for byte.

It is proven by harness test `o1` rather than `h1`: one attestation spent
through a Simplicity leaf and through a tapscript leaf of the same output.
`o1` runs on the golden vectors, or on a set a running signer wrote
(`O1_SET=<file>`; the oracle repository's runbook says how to make one).

| `o1`, the contract in `harness/programs/attestation_check.simf` | Accepted spend | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Simplicity leaf: the attestation, `time >= NOT_BEFORE`, `price < STRIKE`, the owner's signature | 373 vB | 590 B | 140 B | 319 WU | 3,386 WU |
| Tapscript leaf (300 B) doing the same | 293 vB | | | | |

| Leaf | Refused, each in the mempool and in a forced block, with an accepted control |
|---|---|
| Simplicity | The witness price or time not the signed one; a genuine attestation dated before `NOT_BEFORE`, or at or above `STRIKE`; the same oracle's attestation of another pair; another key's attestation of the same fields; the oracle's format-1 signature of the same observation; the oracle's key over the same fields with version byte 1. All `Assertion failed inside jet` |
| Tapscript | The same eight: `Invalid Schnorr signature` for the six signature cases, `Script failed an OP_VERIFY operation` for the early and the high one. The whole format-1 record, its 8-byte timestamp with its signature, and a time pushed as 5 bytes (`Arithmetic opcode error`); a price pushed as 9 bytes (`Arithmetic opcodes expect 8 bytes operands`) |

The beacon is proven by harness test `o2`: a contract opened while the beacon
is at B1, the beacon rotated to B2 with the oracle's rotation signature, and the
attestation naming B1 refused afterwards in a forced block against an accepted
control naming B2, by a Simplicity leaf and a tapscript leaf of the same
output. `o2` runs on the golden vectors (key A's beacon in epochs 0 and 1) or on
a set a running signer wrote after a real rotation (`O2_SET=<file>`;
sequentia-oracle's `tools/o2_set.py` makes one). The tapscript leaf does not
take the beacon from the witness: it reads the program of the coin at the
named input with `OP_INSPECTINPUTSCRIPTPUBKEY` and puts it into the message,
after `OP_INSPECTINPUTASSET` has shown that coin is the explicit beacon asset.

| `o2`, the contract in `harness/programs/attestation_fresh.simf` | Accepted spend | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Simplicity leaf: the attestation, its beacon live at input 1, `time >= NOT_BEFORE`, `price < STRIKE`, the owner's signature; the beacon coin recreated at output 2 | 579 vB | 804 B | 176 B | 366 WU | 4,386 WU |
| Tapscript leaf (310 B) doing the same | 440 vB | | | | |
| The beacon's rotation, two coins B1 to B2 and a wallet fee input | 664 vB | | | | |

The beacon script's leaves are 28 B (recreate) and 167 B (rotate); a rotation
input's witness is 333 B.

| Spend | Refused, each in the mempool and in a forced block, with an accepted control |
|---|---|
| Simplicity, before the rotation | A coin of another asset paid to B1; an attestation with a zero beacon (the same observation by the same key); the beacon index pointing at the contract's own coin. All `Assertion failed inside jet` |
| Tapscript, before the rotation | The same three: `Script failed an OP_EQUALVERIFY operation` for the foreign coin and the wrong index, `Invalid Schnorr signature` for the zero beacon |
| Both, after the rotation | The B1 attestation with the live B2 coin (`Assertion failed inside jet`; tapscript `Invalid Schnorr signature`); with a coin of another asset paid to B1 after the rotation (`Assertion failed inside jet`; `Script failed an OP_EQUALVERIFY operation`); with the B1 coin it named, now spent (`bad-txns-inputs-missingorspent`) |
| The beacon script | Recreated to another script, or with another asset at it; two beacon coins with one recreated output (input 1 owns output 2); the rotation signature with the coin paid elsewhere (`Script failed an OP_EQUALVERIFY operation`); with another destination in the witness, by another key, an attestation signature in its place, the old rotation used to move B2's coins back to B1 or on to a third program (`Invalid Schnorr signature`) |

A tapscript leaf that builds the message with `OP_CAT` must fix the width of
each field it takes from the witness; the leaf does it with the 64-bit
comparison, which takes exactly 8 bytes, and `OP_LE32TOLE64`, which takes
exactly 4. It pushes the precision byte as `OP_1` to `OP_16` where it lies in
that range (minimal push), and as the byte `0x00` for precision 0, never as
`OP_0`, which pushes nothing. A second vector, native bitcoin priced in US
dollars at precision 0, is spent through both leaves too.

## Proof and cost

| Helper, as used in its test program | Accepted spend | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| `output_reader`: covenant pays a fixed amount to a fixed script | 284 vB | 409 B | 0 B | 53 WU | 1,974 WU |
| `wide_arith`: pays `floor(x * price / scale)` with a product above 2^64; 128-bit cap | 315 vB | 517 B | 16 B | 74 WU | 2,470 WU |
| `state`: a counter in the data leaf, moved forward by one per spend (two spends) | 472 vB | 509 B | 32 B | 220 WU | 2,630 WU |
| `relative_lock`: 5 blocks | 216 vB | 136 B | 0 B | 8 WU | 874 WU |
| `merkle`: membership in a set of 256, depth 8 | 310 vB | 224 B | 289 B | 376 WU | 2,390 WU |
| `fee_cap`: at most 500 in the covenant's asset | 199 vB | 71 B | 0 B | 5 WU | 614 WU |

The program sizes include each test's parameters, which are compiled in. The
`state` spend has a second, wallet input that pays the fee.

Every refusal below was refused by the mempool with
`mempool-script-verify-flag-failed (…)`, and in a block with
`TestBlockValidity failed: mempool-script-verify-flag-failed (…) (code -25)`,
each with the same detail, which the test asserts. The detail is `Assertion
failed inside jet` where a jet's check failed, and `Assertion failed` where
execution failed outside a jet: an `assert!` on a computed value, an `unwrap`
of nothing, or a branch the valid spend had pruned. Neither says which check
failed, so each refusal has a control: the valid spend it differs from in the
one property it breaks, which the node accepts.

| Helper | Refused |
|---|---|
| `output_reader` | Output one atom short; output to another script; a coin of another asset at the same program; the right output carrying a nonce |
| `wide_arith` | Output one more than the proven quotient; a quotient one too small; one too large; a product over the 128-bit cap |
| `state` | A successor that skips a state; a successor one atom short; a witness naming a state the data leaf does not hold |
| `relative_lock` | This input's sequence below the lock; transaction version 1; this input's lock disabled while another, old input carries one |
| `merkle` | A wrong sibling at level 3; a value that is not a member |
| `fee_cap` | A fee of 600, and of 501, against a cap of 500 |

Not run: an output with a confidential asset or amount against `output_reader`,
and a `wide_add` whose sum overflows 128 bits.
