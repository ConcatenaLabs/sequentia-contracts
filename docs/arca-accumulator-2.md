# Arca's accumulator batch without a sweep

`templates/arca_accumulator_2` (`arca/accumulator-2`) is the program of an Arca
batch output that holds up to 1,024 leaves of one asset as a fixed root of leaf
records and a bitmap of the slots that have left, and that nothing sweeps. Two
actions spend it, and nothing else does:

- **EXIT**: one owner, or the operator, takes one slot out in one transaction,
  paying the leaf's entry and re-creating the batch with the slot's bit set,
  exactly as `arca/accumulator-1` does ([`arca-accumulator.md`](arca-accumulator.md));
- **RELEASE**: the operator takes back, in one transaction, up to 14 slots
  whose owners gave them up, each under its owner's release, and re-creates
  the batch with their bits set.

No path moves a slot its owner has neither taken out nor released, so a slot
whose owner never returns stays in the batch until its owner or the operator
takes it out to the owner's entry. The Arca repository (`ConcatenaLabs/arca`,
`covenant/src/accumulator.rs`) builds the batch, its records, its exits and its
releases and proves every path on a node; this repository holds the program and
its pruned forms.

## The batch output

```
P2TR(NUMS, TapBranch(X, D))
```

| Node | Kind | What |
|---|---|---|
| `X` | Simplicity | This program |
| `D` | data | `H_TapData(ROOT ‖ OPERATOR ‖ BITMAP)`, 192 bytes: the state |

`ROOT`, `OPERATOR`, `BITMAP`, the slot records and the Merkle-sum tree are
`arca/accumulator-1`'s:

```
rec_j = SHA256(0x00 ‖ j ‖ OWNER ‖ SPK ‖ VALUE ‖ RESERVE)     weight VALUE + RESERVE
node  = SHA256(0x01 ‖ h_l ‖ w_l ‖ h_r ‖ w_r)                 weight w_l + w_r
empty = 32 zero bytes                                        weight 0
```

Slot `j`'s bit is bit `63 − j mod 64` of word `j / 64` of `BITMAP`; a set bit
is a slot that has left, by its exit or by its release.

## What every spend requires

With the batch output at input `k`, the witness carries the state (`ROOT`,
`OPERATOR`, `BITMAP`) and `ACTION`, `Left` for an exit and `Right` for a
release. Either way:

| Check | Refuses |
|---|---|
| `H_TapData(ROOT ‖ OPERATOR ‖ BITMAP)` is the only hash of the control block's path, and every bit the action sets is clear in `BITMAP` | A slot that has left; a state the coin does not hold |
| No annex on the batch input | An annex of any size, on an exit and on a release |
| Output `2k+1`, unless nothing is left: exactly the input less what the action takes out, explicit, no nonce, at this output with the bits of the slots that left set and nothing else changed (the same program, internal key, `ROOT` and `OPERATOR`) | One atom short or more; the old state; a bit missing; another slot's bit; a bit more; another `ROOT`; another `OPERATOR`; another program; a nonce; no rest |

## An exit

`ACTION` is `Left((INDEX, OWNER, SPK, VALUE, RESERVE, PATH, TIME, BY_OPERATOR,
SIG))`. As in `arca/accumulator-1`: the record is on its path to `ROOT` with
every weight the sum of its children; `KEY` (`OWNER`, or `OPERATOR` when
`BY_OPERATOR`) signs `SHA256(SHA256("Arca/accumulator-exit") ‖ genesis ‖ ROOT ‖
rec_j ‖ TIME)` with the lock time at or after `TIME`; output `2k` pays exactly
`VALUE` to the script whose SHA256 is `SPK`; the rest is the input less `VALUE`
less `RESERVE`. An exit authorisation of `arca/accumulator-1` is the same
message, so a wallet signs one exit for either program.

## A release

`ACTION` is `Right((PLACES, OPERATOR_SIG))`. `PLACES` holds the slots
`j_1 < … < j_n`, `n` from 1 to 14, each as `(INDEX, OWNER, SPK, VALUE, RESERVE,
PATH, M_AT, SIG)`, nested so that a release of `n` slots holds `n` of them:

```
PLACES = P14,  P1 = Option<slot>,  P_i = Option<(slot, P_{i-1})>
```

The program requires:

| Check | Refuses |
|---|---|
| At least one slot, each after the one before it (`j_i ≥ j_{i-1} + 1`) | No slot; one slot twice; two slots out of order |
| For each, `INDEX` below 1,024 and `rec_j` on its path to `ROOT` with every weight the sum of its children, with no overflow | A weight one more or one less on a path; a record claiming one atom more; an index of 1,024 or more |
| For each, `OWNER` signs, BIP340, `SHA256(SHA256("Arca/accumulator-release") ‖ genesis ‖ ROOT ‖ rec_j ‖ M)`, `M` the explicit asset of input `M_AT` | A stranger's signature; another slot's owner; the operator's signature for the owner's; the owner's release under another batch's `ROOT`; a release signed for another round's `M`; naming another round's input, the batch input, an input that does not exist, or a blinded input |
| `OPERATOR` signs, BIP340, `SHA256(SHA256("Arca/accumulator-release-outputs") ‖ genesis ‖ D ‖ k ‖ outputs_hash)`, `D` the state the coin holds, `k` four bytes big-endian and `outputs_hash` the chain's commitment to every output of the transaction | No operator's signature; a stranger's or an owner's for it; the operator's signature over another payout, with the connector's atom sent elsewhere, with the fee one atom more, for the coin at another index, for another state |
| The rest is the input less every `VALUE` and `RESERVE` released | The operator taking one atom more |

`M` is the connector asset of the round that made the owner's new coin. It is
issued by that round's transaction, so an input holding it exists only while
that round is in the chain: a release is void with the round it names, and a
release that confirmed is disconnected with that round. Owners who moved on in
one round share one input of its `M`; the operator pays that atom back to
itself and reuses it. Output `2k` is not pinned: what the released slots held
is the operator's, and its signature over every output decides where it goes
and what pays the fee. `outputs_hash` is the SHA256 of four hashes, each over
every output in order: of its asset and amount, of its nonce, of its script's
SHA256, and of its range proof's SHA256 (of nothing for an explicit amount),
each field as the transaction encodes it.

A release signature names one slot (`rec_j` names `j`, the owner and the
entry) of one batch (`ROOT`) for one round (`M`) on one chain (genesis). It
names no outpoint and no bitmap, so releases signed at different times ride one
transaction, and it holds for every state of the batch until the slot's bit is
set. It cannot release another slot or another batch's slot, and it cannot
release a slot twice. Its message is not an exit's, so it never takes a slot
out to anyone.

## Why 14

Simplicity's static cost bound counts every branch a pruned program keeps, and
a spend's budget on Sequentia is four weight units for each byte of the input's
witness, plus 50. Because the places nest, a release of `n` slots prunes to the
`n` places it holds, and its cost bound grows with `n`: each slot adds 550
witness bytes, so 2,200 units of budget, and from 2,700 units of cost, a little
more for each slot after it. Fourteen is the most a release takes with no
annex, with a rest and taking the last of the batch:

| Release | Program | Witness | Cost bound | Budget | Bit Machine cells |
|---|---|---|---|---|---|
| 1 slot, a rest | 2,772 B | 807 B | 3,819 WU | 14,790 WU | 283,546 |
| 1 slot, the last | 2,478 B | 807 B | 3,626 WU | 13,614 WU | 283,546 |
| 8 slots, a rest | 3,005 B | 4,658 B | 24,060 WU | 31,126 WU | 1,637,171 |
| 14 slots, a rest | 3,148 B | 7,958 B | 43,432 WU | 44,898 WU | 3,811,204 |
| 14 slots, the last | 2,854 B | 7,958 B | 43,125 WU | 43,722 WU | 3,811,204 |
| 15 slots, the last, in a program of 15 places | | | 46,536 WU | 46,058 WU | refused |
| 16 slots, a rest, in a program of 16 places | | | 50,325 WU | 49,578 WU | refused |

The cells stay below the node's limit of 5,242,880. An exit is 2,420 bytes
(2,300 with no rest), its witness 743, its cost bound 3,513 weight units
against a budget of 13,126.

## Building a spend with no compiler

The witness stack is `[witness, program, cmr, control block]`, with no annex:

- `cmr` is `8789ee3de6ad72d2ba5f02f3c4197af20a95d70289dc434e5177883ce413384e`;
- `program` is one of the 30 constants in
  `templates/arca_accumulator_2/paths.json`: `exit` when a rest is left,
  `exit_last` when the exit takes the last of the batch, `release_n` for a
  release of `n` slots that leaves a rest and `release_n_last` for one that
  takes the last of the batch;
- `witness` is the bits of `ROOT`, `OPERATOR` and the 16 words of `BITMAP`
  (192 bytes), then the action's tag bit, then
  - for an exit: `INDEX`, `OWNER`, `SPK`, `VALUE`, `RESERVE`, each sibling and
    its weight, `TIME`, `BY_OPERATOR` as one bit, the 64-byte signature;
  - for a release: for each slot a set bit followed by `INDEX`, `OWNER`, `SPK`,
    `VALUE`, `RESERVE`, each sibling and its weight, `M_AT` and the 64-byte
    signature; then a clear bit, unless the release fills all 14 places; then
    the operator's 64-byte signature;

  padded with zero bits to a whole byte. Integers are big-endian;
- the control block is `0xbe` (with the output key's parity), the NUMS key and
  `D`.

No branch depends on a witness value but the action, how many slots a release
holds and whether a rest is left, and each witness value is read in a statement
of its own. `crates/sequentia-contracts/tests/arca_accumulator_2.rs` builds
batches, records, paths and states independently of the program, runs every
exit and release on the Bit Machine, refuses the cases above there, prunes the
program for every count of slots from 1 to 14 at the corner slots, across words
and in one word, at `k` = 0, 1 and 3, and requires `paths.json` each time, every
spend within the node's budget and cells. Its ignored test `places_that_fit`
builds the program with other numbers of places and shows that 15 slots do not
fit.

## On the chain

A negative case proves nothing until a block refuses it. The Arca repository's
`covenant/tests/accumulator.rs` builds batches of this program on a regtest
chain and forces each refusal into a block on a node checking scripts inline,
beside an accepted control.
