# Arca's accumulator batch

`templates/arca_accumulator` (`arca/accumulator-1`) is the program of an Arca
batch output that holds up to 1,024 leaves of one asset as a fixed root of leaf
records and a bitmap of the leaves that have left. One owner leaves it in one
transaction whose size does not depend on how many leaves it holds, and nothing
any other owner holds changes: the root is fixed, so every other owner's path
stays valid, and the authorisation an owner signs names no state of the batch.
The Arca repository (`ConcatenaLabs/arca`, `covenant/src/accumulator.rs`)
builds the batch, its records and its exits and proves every path on a node;
this repository holds the program and its pruned forms.

## The batch output

```
P2TR(NUMS, TapBranch( TapBranch(X, D), SWEEP ))
```

| Node | Kind | What |
|---|---|---|
| `X` | Simplicity | This program |
| `D` | data | `H_TapData(ROOT ‖ OPERATOR ‖ BITMAP)`, 192 bytes: the state |
| `SWEEP` | tapscript | The sweep a tree's batch output carries: the sweep token at Arca's release script in the input the witness names, and the operator's signature |

| Field | Type | What |
|---|---|---|
| `ROOT` | u256 | The root of a Merkle-sum tree of depth 10 over the leaf records; fixed for the batch's life |
| `OPERATOR` | u256 | The operator's key `S` |
| `BITMAP` | 16 × u64 | Big-endian words; slot `j`'s bit is bit `63 − j mod 64` of word `j / 64`, so slot 0 is the first bit of the first byte. A set bit is a leaf that has left |

A slot's record, and the tree above it:

```
rec_j = SHA256(0x00 ‖ j ‖ OWNER ‖ SPK ‖ VALUE ‖ RESERVE)     weight VALUE + RESERVE
node  = SHA256(0x01 ‖ h_l ‖ w_l ‖ h_r ‖ w_r)                 weight w_l + w_r
empty = 32 zero bytes                                        weight 0
```

Integers are big-endian at their width: `j` two bytes, weights and amounts
eight. `OWNER` is the key that may take the slot out, `SPK` the SHA256 of the
scriptPubKey its exit pays (in Arca, the leaf's hash-locked entry), `VALUE`
what that output holds, and `RESERVE` what the exit leaves for its fee. The
path runs from the record up, and its directions are the bits of `j`, the
lowest first: a record sits only at its own slot, and no two records share a
bit. No record hashes to the empty value.

## An exit

With the batch output at input `k`, the witness carries the state (`ROOT`,
`OPERATOR`, `BITMAP`), the slot (`INDEX`, `OWNER`, `SPK`, `VALUE`, `RESERVE`),
`PATH` (ten `(sibling, weight)` pairs, leaf first), `TIME`, `BY_OPERATOR` and
`SIG`. The program requires:

| Check | Refuses |
|---|---|
| `INDEX` below 1,024; `rec_j` on the path `j` names hashes to `ROOT`; every node on it weighs the sum of its children, with no overflow | A forged sibling; a sibling's weight changed; the neighbour's path; a record claiming one atom more; a weight that overflows; an index of 1,024 or more |
| `H_TapData(ROOT ‖ OPERATOR ‖ BITMAP)` is the first hash of the control block's path, which is two hashes long, and `j`'s bit is clear in `BITMAP` | A slot that has left; a state the coin does not hold |
| `KEY` signs, BIP340, `SHA256(SHA256("Arca/accumulator-exit") ‖ genesis ‖ ROOT ‖ rec_j ‖ TIME)`, `KEY` being `OWNER`, or `OPERATOR` when `BY_OPERATOR` | A stranger's signature; another slot's owner; the owner's signature under the operator's flag, and the operator's without it |
| The transaction's lock time is a time at or after `TIME`, with a non-final input | A lock time one second early; a lock time that is a height; final inputs |
| No annex on the batch input: the signature names none, and the exit's cost never needs the budget one would add | An annex of any size, on the owner's exit, the operator's and the last leaf's |
| Output `2k`: exactly `VALUE` of the coin's asset, explicit, no nonce, to the script whose SHA256 is `SPK` | One atom short; another script; another asset; a nonce; a coin of another asset |
| Output `2k+1`, unless nothing is left: exactly the input less `VALUE` less `RESERVE`, explicit, no nonce, at this output with `j`'s bit set and nothing else changed (the same program, internal key and `SWEEP`) | One atom short; the old state; another slot's bit; a second bit as well; another sweep leaf; a nonce; no rest |

The authorisation names no outpoint and no bitmap, so it is good for every
state of the batch: it can be signed when a leaf is created and held by a
watcher or a receiver, and it becomes good at `TIME`. It names the chain, the
root and the record, so it takes out this slot of this batch only. Because the
program checks every weight on the path, a record under a node whose weight is
not the sum of its children can never leave, and the batch always holds enough
for every record that can; a holder checks that the root's weight is the value
the batch output was created with.

## Building a spend with no compiler

The witness stack is `[witness, program, cmr, control block]`, with no annex:

- `cmr` is `9b6467a1f9d787f6e93ac2422194e61fc56638db63735c6f24ba2c7a86bc0b96`;
- `program` is one of the two constants in `templates/arca_accumulator/exits.json`:
  `exit` (2,018 bytes) when a rest is left, `exit_last` (1,891) when the exit
  takes the last of the batch;
- `witness` is 743 bytes: `ROOT`, `OPERATOR`, the 16 words of `BITMAP`, `INDEX`,
  `OWNER`, `SPK`, `VALUE`, `RESERVE`, each sibling and its weight, `TIME`, then
  `BY_OPERATOR` as one bit followed by the 64-byte signature, padded with zero
  bits to a whole byte;
- the control block is `0xbe` (with the output key's parity), the NUMS key,
  `D` and the hash of `SWEEP`.

No branch depends on a witness value but whether a rest is left: the side of
each Merkle step and the key are chosen with masks, the bitmap word with a mask,
and each witness value is read in a statement of its own. So the pruned program
is one of two constants whatever the batch, the slot, `k` or the key.
`crates/sequentia-contracts/tests/arca_accumulator.rs` builds batches, records,
paths and states independently of the program, runs every exit on the Bit
Machine, refuses the cases above there, prunes the program at the corner slots
0, 1, 1022 and 1023 and in between, at `k` = 0, 1 and 3, by both keys, for a
batch whose slots hold equal values, and after earlier exits, and requires
`exits.json` each time.

## On the chain

A negative case proves nothing until a block refuses it. The Arca repository's
`covenant/tests/accumulator.rs` builds a 1,024-leaf batch on an anchored
regtest chain, takes owners out one after another, and forces each refusal
into a block on a node checking scripts inline, beside an accepted control;
an annex on the exit's witness, of 3 or 1,000 bytes, is one of them.
Measured there, with 1,024 leaves:

| Spend | Size |
|---|---|
| An exit, its fee from the slot's reserve | 979 vB |
| An exit by the operator, a coin of the batch's asset attached for the fee | 1,187 vB |
| The exit of the last leaf, with no rest (`exit_last`) | 869 vB |
| The five node transactions that take one leaf out of a 1,024-leaf radix-4 tree, for comparison | 2,854 vB |

The leaf's entry (234 vB) and its exit (219 vB) follow in both. The cost bound
is 4,097 weight units for `exit` and 3,898 for `exit_last`, against a budget
of 11,646 and 11,138: four weight units for each of the 2,899 and 2,772
bytes of the input's witness, plus 50.
