# Arca's resting order

`templates/arca_order_3` (`arca/order-3`) is the fill program of an order that
rests as a leaf in an Arca tree. The Arca operator fills it while the maker is
offline; nobody fills it without the operator, the maker included; each fill
pays the maker's credit to a leaf of its own; and one exit delay after the leaf
reaches the chain, anyone may land it as SeqDEX's own order
([`seqdex-order.md`](seqdex-order.md)) for the same terms. The Arca
repository (`ConcatenaLabs/arca`, `covenant/src/order.rs`) builds the leaf and
its spends and proves every path on a node; this repository holds the program
and its pruned forms.

## Versions

| Program | Template | Root | Lands as |
|---|---|---|---|
| `arca/order-3` | `templates/arca_order_3` | `2d352aa6b8d2708e3ea867baa35dc3e855a6ffda2d951268ff98fdf959f5f337` | `seqdex/order` version 2 |
| `arca/order-2` | `templates/arca_order` | `fac4e5ebe8c377159c28f5fc74e6c492132983859d500081e46c727641b9e164` | `seqdex/order` version 1 |

`order-3` is `order-2` with one more rule: a fill carries no annex. The
operator's signature covers the coin and the outputs, not an annex, and the
node relays an annex of up to 100,000 bytes on a Simplicity leaf spend. On
`order-2`, whoever holds a signed fill (the operator, or anyone a fill reached
on its way to the chain) can therefore attach one: a fill grows from about
1,400 to some 26,000 vB, its fee rate falls to the relay floor, and the mempool
keeps that copy when the honest one arrives. `order-3` refuses it; its cost is
far inside the budget its own witness buys, so it never needs one. The program
does not choose where its leaf lands (`LAND_LEAF` is a parameter); the Arca
repository builds an `order-3` leaf's landing as `seqdex/order` version 2,
which refuses an annex too, and an `order-2` leaf's as version 1.

Every new order rests as `order-3`. An `order-2` leaf already resting is filled
and landed as before until it is gone. Everything below holds for both
programs.

## The leaf

```
P2TR(NUMS, TapBranch( TapBranch(C, L), TapBranch(F, D) ))
```

| Leaf | Kind | What |
|---|---|---|
| `C` | tapscript | The standard rebindable collaborative path of an Arca leaf: the maker's key and the operator's, over a message bound to the coin's salt and the chain |
| `L` | tapscript | The landing: after the exit delay, output 0 is the `seqdex/order` output for the same terms, in the order's asset, explicit, with no nonce, worth at least the coin. No signature |
| `F` | Simplicity | This program |
| `D` | data | `H_TapData(P)`, the parameters |

The parameters `P`, 346 bytes, each big-endian at its width, asset ids in
internal byte order:

| Field | Type | What |
|---|---|---|
| `ASSET_A` | u256 | The asset the order sells, which the coin holds |
| `ASSET_B` | u256 | The asset a fill pays in |
| `RATE_NUM` | u64 | The price: `RATE_NUM` atoms of `ASSET_B` ... |
| `RATE_DEN` | u64 | ... for every `RATE_DEN` atoms of `ASSET_A` |
| `MIN_LOT` | u64 | The least a fill takes, and the least a remainder holds |
| `OWNER` | u256 | The maker's leaf key, in `C` |
| `OPERATOR` | u256 | The operator's key `S` |
| `SALT` | u256 | This coin's salt |
| `EXIT_UNITS` | u16 | The exit delay, in 512-second units |
| `LAND_LEAF` | u256 | The tapleaf hash of `L` |
| `CREDIT_0` to `CREDIT_3` | u256 | The keys of the next four credits, the next one first; zero once used |

The tree holds values the program derives (`C` holds `K`, a hash of the salt and
the chain, and `L` the landed order's scriptPubKey), so it is not a descriptor
tree: there is no `descriptor.json`, and the address is derived by the Arca
rules. `regtest/order.py` in the Arca repository derives it independently and
exports golden vectors that the Rust builder there reproduces byte for byte.

## A fill

With the coin at input `k`, the witness carries `P`, the operator's signature,
`m` and `PATH` (true for a partial fill, false for a whole one). The program
requires:

| Check | Refuses |
|---|---|
| `H_TapData(P)` is the first hash of the control block's path, and the path is two hashes long | Parameters the coin does not commit to |
| The coin holds `ASSET_A`, explicitly | Another asset at the address, or a confidential coin |
| `S` signs, BIP340, `SHA256(T ‖ SALT ‖ ASSET_A ‖ value_in ‖ m ‖ output_hash(0) ‖ … ‖ output_hash(m−1))`, `T = SHA256(SHA256("Arca/order-fill") ‖ genesis)`, `m` from 2 to 4 | A fill without the operator, the maker's own included; a fill the operator signed for other outputs, another taker's leaf among them; a signature made for another coin of the order, or on another chain |
| Output `2k`, the credit: `ASSET_B`, explicit, no nonce, at least `ceil(fill × RATE_NUM / RATE_DEN)` (checked on 128-bit products), paid to the `vtxo-1` leaf `[collab(CREDIT_0, S, K_c), exit(EXIT_UNITS, CREDIT_0)]` under the salt `SHA256(SHA256("Arca/order-credit") ‖ SALT)` | Underpaying by one atom; another asset; a confidential credit; any other script, the credit key's plain script and a later credit's leaf included |
| `CREDIT_0` is not zero | A fifth fill along one lineage |
| A partial fill: output `2k+1`, the remainder: `ASSET_A`, explicit, no nonce, at least `MIN_LOT`, at the leaf of `P` with `SALT' = SHA256(SHA256("Arca/order-rest") ‖ SALT)` and the credit keys moved up one | A remainder under the coin's own script, with the keys not moved, landed at once, or anywhere else; one below the lot |
| The fill is at least `MIN_LOT` and at least one atom | Dust fills |

The operator's signature names the coin by its salt, asset and value, never by
its outpoint, so a fill signed while the tree is off the chain holds whatever
outpoint an unroll gives the coin. Each coin of an order has its own salt, so a
signature for one never fills another, and each credit has its own salt and
key, so a pair the maker signs over one credit never spends another of the same
value.

## Building a spend with no compiler

The witness stack is `[witness, program, cmr, control block]`, with no annex:

- `cmr` is the program's root (above);
- `program` is one of six constants in the program's `fills.json`, by `PATH`
  and `m`: `fill_m2`, `fill_m3`, `fill_m4` and `fill_whole_m2`,
  `fill_whole_m3`, `fill_whole_m4`; `order-3`'s are 2,785 to 2,860 bytes and
  2,467 to 2,541, `order-2`'s 2,771 to 2,846 and 2,453 to 2,528;
- `witness` is the 346 bytes of `P`, the 64-byte signature, `m` as one byte,
  then `PATH` as one bit, padded with zero bits to a whole byte.

No branch of a fill depends on a value but `PATH` and `m`, and each witness
value is read in a statement of its own, so the pruned program is one constant
per `PATH` and `m` whatever the order and whatever `k`.
`crates/sequentia-contracts/tests/arca_order.rs` builds orders, credit leaves
and remainders independently of the program, runs every fill on the Bit
Machine, refuses the cases above there, prunes the program for orders holding
equal values (a 1:1 price, one asset on both sides, two equal credit keys, a
remainder three fills down) at `k` = 0, 1 and 3, and requires `fills.json` each
time, for both programs. It also runs signed part and whole fills at `k` = 0
and 1 with an annex of 3 and of 1,000 bytes beside the same fills without one:
`order-3` refuses each, `order-2` takes each.

## On the chain

A negative case proves nothing until a block refuses it. The Arca repository's
`covenant/tests/order_resting.rs` spends every one of the six programs of each
version in blocks and forces each refusal above into a block on a node checking scripts
inline, each beside an accepted control, along with every way an earlier
design's in-tree fill could be reversed. Measured there, on a fill with one
payment coin and one fee coin: a partial fill is 1,441 vB with change and
1,344 vB at `m` = 2; a whole fill 1,186 to 1,362 vB; a fill made in the tree
and published with the taker's checkpoint 1,614 vB.
