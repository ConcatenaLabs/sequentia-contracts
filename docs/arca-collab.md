# Arca's collaborative path

`templates/arca_collab` (`arca/collab-2`) is the path by which an owner and the
Arca operator spend a `vtxo-2` leaf, or its checkpoint, together. Like the
tapscript path of `vtxo-1` it names no outpoint, so a pair of signatures made
while the tree is off the chain holds whatever outpoint an unroll gives the
coin. Unlike it, it binds the coin's own index and every input the signers
name, so a pair fits one place in one shape of transaction. One program serves
every leaf and every checkpoint of the template: its commitment root is a
constant, and its parameters sit in a data leaf beside it. The Arca repository
(`ConcatenaLabs/arca`, `covenant/src/collab.rs`) builds the outputs and their
spends and proves every path on a node; this repository holds the program and
its pruned form.

## The output

```
leaf:        P2TR(NUMS, TapBranch( TapBranch(F, D), E ))
checkpoint:  P2TR(NUMS, TapBranch( TapBranch(F, D), SWEEP ))
```

| Leaf | Kind | What |
|---|---|---|
| `F` | Simplicity | This program |
| `D` | data | `H_TapData(OWNER ‖ OPERATOR ‖ SALT)`, 96 bytes |
| `E` | tapscript | The leaf's exit, `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <OWNER> OP_CHECKSIG`, the same script as a `vtxo-1` leaf's exit |
| `SWEEP` | tapscript | A checkpoint's sweep with notice, the same as a `vtxo-1` checkpoint's |

`OWNER` is the leaf's owner key, `OPERATOR` the operator's key `S`, and `SALT`
the coin's salt (a checkpoint has a salt of its own). The tree holds scripts the
program does not read, so it is not a descriptor tree: there is no
`descriptor.json`, and the address is derived by the Arca rules.

## A spend

With the coin at input `k`, the witness carries the 96 bytes of `D`, `n`, `m`,
the owner's signature and the operator's. The program requires:

| Check | Refuses |
|---|---|
| `H_TapData(OWNER ‖ OPERATOR ‖ SALT)` is the first hash of the control block's path | Parameters the coin does not commit to |
| `1 ≤ n ≤ 16`, `1 ≤ m ≤ 4`, `k < n`, and inputs `0..n-1` and outputs `0..m-1` exist | A spend that names no input, or this coin outside what it names |
| `OWNER` and then `OPERATOR` sign, BIP340, `SHA256(K ‖ k ‖ n ‖ I ‖ m ‖ O)` | Any spend the pair was not made for: the coin at another index, beside another coin than the ones named, a coin of another asset or amount, other outputs or outputs in another order, another salt, another chain |

where, in the bytes signed:

| Part | Bytes | What |
|---|---|---|
| `K` | 32 | `SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ SALT)`, the constant a `vtxo-1` path pushes for the same salt |
| `k` | 4 | This input's index, big-endian |
| `n` | 1 | How many inputs the signers name |
| `I` | 32 | `SHA256(input_utxo_hash(0) ‖ … ‖ input_utxo_hash(n-1))`: each named input's asset, amount and script, `SHA256(01 ‖ asset ‖ 01 ‖ amount (8, big-endian) ‖ SHA256(scriptPubKey))` for an explicit coin, never its outpoint |
| `m` | 1 | How many outputs the signers commit to |
| `O` | 32 | `SHA256(output_hash(0) ‖ … ‖ output_hash(m-1))`: each whole output, nonce and range proof included |

Inputs after `n` and outputs after `m` are free, as are sequences, the lock
time and the annex, so whoever broadcasts can attach a fee coin and its change
in any asset a producer accepts.

What this binds beyond `vtxo-1`'s tapscript path:

- **The index.** A pair made for a coin at input 0 does not hold at input 1.
  So one pair never spends two coins of one script in one transaction, and two
  pairs that commit to the same outputs, each made for a coin spent alone, can
  never both be satisfied by one transaction.
- **The named inputs.** A pair holds only beside coins of the named assets,
  amounts and scripts. Every Arca leaf script is unique, so in a swap one leg is
  spent only where the other is.
- **The coin's own script**, inside `input_utxo_hash(k)`.
- **Whole outputs**, so a broadcaster cannot add a nonce to a committed output.

What it does not bind: the outpoint. A coin funded twice under one script can
be spent alone, a second time, by the same pair; it then pays the same outputs
again. Arca's rule that a leaf script is never funded twice stands.

`K ‖ k ‖ n ‖ I ‖ m ‖ O` is `K` followed by 70 bytes. An Arca operator's
equivocation bond computes `K` from a salt and slashes on two different
messages `SHA256(K ‖ rest)` with a rest of at most 240 bytes, so it slashes a
double-sign under this program as it does under `vtxo-1`'s path. A `vtxo-1`
rest is 43 + 32m bytes, never 70, so no `vtxo-1` signature is a signature here.

## Building a spend with no compiler

The witness stack is `[witness, program, cmr, control block]`:

- `cmr` is `83bd261c1cafb63fda7cc7cdc00cca55f25b4bbd9e768ae46b71af64349927a0`;
- `program` is the one constant in `templates/arca_collab/collab.json`, 1,107
  bytes;
- `witness` is the 96 bytes of `D`, `n` and `m` one byte each, then the
  owner's 64-byte signature and the operator's, 226 bytes;
- the control block is the leaf version `0xbe` with the output key's parity,
  the NUMS key, `D` and the hash of `E` or `SWEEP`.

Both loops, over the inputs and over the outputs, run to a fixed index past
the largest `n` and `m` (inputs 16 and 17, output 4), so every spend runs the
same branches and the pruned program is one constant whatever `n`, `m`, `k` and
the keys. Its cost bound is 1,823 weight units; a spend's budget, four times
its witness bytes, is above 5,500.

`crates/sequentia-contracts/tests/arca_collab.rs` builds the output and the
digest independently of the program, runs accepted spends of every shape on the
Bit Machine, refuses each case above there, and prunes the program for 384
shapes (`n` from 1 to 16, `m` from 1 to 4, the coin first, last and between,
owner and operator keys equal and different), requiring `collab.json` each
time.

## On the chain

A negative case proves nothing until a block refuses it. The Arca repository's
`covenant/tests/vtxo2.rs` spends this program in blocks on a node checking
scripts inline, and forces each attack that a `vtxo-1` pair allows into a block
twice: against a `vtxo-1` leaf, where it is mined, and against a `vtxo-2` leaf,
where the block is refused. Measured there: a coin spent alone into one output,
or into its checkpoint, is 543 vB where the tapscript path's is 280; a swap
reassignment naming a `vtxo-2` and a `vtxo-1` checkpoint 768 vB; the exit 219 vB,
the same as `vtxo-1`'s.
