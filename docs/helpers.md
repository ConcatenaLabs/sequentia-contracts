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
