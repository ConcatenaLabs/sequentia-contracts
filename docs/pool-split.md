# The pool split covenant

A staking pool on Sequentia commits on-chain to how the blocks its signer
produces pay out (`announcepayout`). Its `direct` mode makes every block's
coinbase pay one script the pool names. The pool split covenant is such a
script: every reward paid to it can be claimed by anyone, into a fixed table of
shares the pool chose, exact to the atom and in whatever asset the reward was
paid. Nobody signs a claim, so no payout waits on the operator.

The shares are fixed by the table, not by stake. A pool whose members agreed
how to divide its rewards (an operator and its partners, a pool of named
members) uses this covenant; a pool that pays each delegator in proportion to
the stake it lent uses the node's own `split` mode instead
(`doc/sequentia/split-payouts-design.md` in the node repository).

Two templates carry the same rule:

| Template | Leaves | Rows | Coins per claim |
|---|---|---|---|
| `templates/pool_split` (`sequentia/pool-split`) | a Simplicity claim beside its data leaf, and a tapscript follow leaf | 1 to 63 | up to 255 |
| `templates/pool_split_tap3` (`sequentia/pool-split-tap3`) | a tapscript claim and the same follow leaf | exactly 3 | up to 8 |

```text
pool-split:      P2TR(NUMS, {{claim (Simplicity), params (TABLE, DENOM, WITHHOLD_CAP_BP)}, follow})
pool-split-tap3: P2TR(NUMS, {claim (tapscript, the rows in place), follow})
```

Both use the NUMS internal key, so there is no key path.

## The rule

A pool's table has rows `(script, numerator)` over a denominator `DENOM`. Row 0
is the pool's own row. A claim:

1. spends coins of the pool's script, all in one asset and explicit: input 0 by
   the claim leaf, any others by the follow leaf. The follow leaf requires that it
   is not input 0 and that input 0 is a coin of the same script in the same
   asset; the claim scans every input and sums each one of its own script into
   `collected`. So every coin of the pool in a claim is counted, and no coin can
   be spent beside anything but a claim of its own pool.
2. withholds at most `WITHHOLD_CAP_BP / 10,000` of `collected`, for the network
   fee and for whoever claims: `withheld × 10,000 ≤ collected × WITHHOLD_CAP_BP`.
   The claimer names `withheld` in the witness.
3. pays each row `i` from 1, at output `i`, exactly
   `floor(net × numerator_i / DENOM)` of the asset, where
   `net = collected − withheld`, explicitly and with no nonce;
4. pays row 0, at output 0, what is left of `net`: its own share and every
   rounding remainder.

Outputs after the rows are free. They can only carry value the claimer brought:
the rows and `withheld` account for all that the pool's coins hold, so a claim
that takes anything from them is refused. Whatever `withheld` does not spend on
the fee may go to the claimer, so up to the cap of every claim goes to whoever
claims first, a block producer included: the cap is what the members agree to
give up for a claim to happen without them. A claim that keeps nothing back pays its fee from
a coin the claimer brings, in any asset the network accepts; the covenant
allows it, and the claim builder in `tools/pool-claim` does not build it.

`floor(net × n / DENOM)` is computed without overflow as
`q × n + floor(r × n / DENOM)` with `(q, r) = divmod(net, DENOM)`; the twin's
64-bit opcodes are signed, which is why its denominator and numerators are below
2^31 and its amounts below 2^63.

The table's numerators are positive and sum to `DENOM`, which is from 1 to
2^31 − 1, and `WITHHOLD_CAP_BP` is at most 10,000. The claim builder refuses a
record that breaks any of these; the covenant itself only refuses a claim whose
rows from 1 would be owed more than `net`, so a table summing above `DENOM`
could never be claimed.

### The table

`TABLE` is SHA256 over the rows in order, each the SHA256 of its scriptPubKey
followed by its numerator as 4 big-endian bytes. The Simplicity claim takes the
rows in its witness, hashes them and checks the hash, with `DENOM` and
`WITHHOLD_CAP_BP`, against the data leaf. Any script can be a row: a witness
program of version 0 or 1, or any other script, which the twin compares by its
hash. The twin holds its three rows in the script itself: `ROW0_SCRIPT`,
`ROW1_SCRIPT`, `ROW1_NUM`, `ROW2_SCRIPT`, `ROW2_NUM`, with row 0's numerator
being what rows 1 and 2 leave of `DENOM`.

`templates/pool_split/tables.json` holds golden vectors for the table hash and
for the payouts a claim must make, including the claims the rule refuses. The
Rust crate (`sequentia_contracts::pool`) and the three mirrors
(`pool_split_table` and `pool_split_payouts` in Python, `poolSplitTable` and
`poolSplitPayouts` in JavaScript, `PoolSplitTable` and `PoolSplitPayouts` in Go)
reproduce every one of them.

### What a claim cannot do

- Pay some rows and not others: every claim pays every row. A claim of one row at
  a time would need each coin to remember which rows it has paid.
- Claim a confidential coin. The covenant reads explicit amounts only; a coin
  sent to the address with a blinded amount or asset stays there.
- Spend a coinbase reward before it matures. That is the chain's rule, not the
  covenant's: on the real chains a coinbase output waits 1,000 blocks.

## Measured

On regtest against the node, each claim confirmed (`harness/records/p1.json`):

| Claim | Simplicity | Tapscript twin |
|---|---:|---:|
| one coin, three rows | 931 vB; program 2,216 B, cost 957 WU of a 9,950 WU budget | 490 vB; claim script 633 B |
| two coins, three rows | 988 vB | 553 vB |
| eight coins, three rows | | 931 vB |
| one coin, 10 / 20 / 63 rows | 1,564 / 2,442 / 6,217 vB | |
| 70 coins, three rows | 5,255 vB, with a 49-byte annex: cost and budget both 9,590 WU | |

The rows were a P2WPKH, a P2TR and a P2PKH script. The descriptors' `measured`
fields carry the same figures.

## Tests

`harness/tests/p1_pool_split.py` claims with each template from coins the wallet
paid in, each claim built by `tools/pool-claim/pool_claim.py`, and refuses, in
the mempool and in a block forced with `generateblock`, each against the claim
it was changed from: one atom moved between two rows;
two rows' scripts swapped; a row's output with a nonce; a witness naming another
withheld amount; a withheld amount one atom over the cap; a follower's value left
out of the rows and taken; a coin of the pool in another asset beside the claim;
the follow leaf at input 0, and beside a foreign input 0; nine inputs to the
twin; and a 70-coin claim padded one byte short.
