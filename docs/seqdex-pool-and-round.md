# The SeqDEX pool and the clearing round

Two templates for SeqDEX's on-chain book beside the resting order of
[`seqdex-order.md`](seqdex-order.md):

- `templates/seqdex_pool` (`seqdex/pool`): a maker's two coins, one of each
  asset of a pair, that anyone fills from either side at the pool's bid and ask,
  never below the reserve the maker states, and that only the maker withdraws;
- `templates/seqdex_round_order` (`seqdex/round-order`): an order that fills
  only in a clearing round its clearer signs, at the one price the round
  publishes in its last output, never below its limit.

Both put their terms in a data leaf beside one program, as `seqdex/order` does,
so an instance's address is the program's root plus its terms and any language
derives it with no compiler. Every product is compared at 128 bits, so every
64-bit amount and price works. `crates/sequentia-contracts/src/round.rs` builds
the clearing output and the digest a clearer signs.

## The pool

```
P2TR(NUMS, TapBranch(TapLeaf_0xbe(pool), H_TapData(terms)))
```

The data leaf, 152 bytes, each term big-endian at its width:

| Term | Type | What |
|---|---|---|
| `BASE` | u256 | One asset of the pair, internal byte order |
| `QUOTE` | u256 | The other |
| `BID_NUM`, `BID_DEN` | u64 | The pool buys `BASE` paying at most `BID_NUM` of `QUOTE` for every `BID_DEN` of `BASE` |
| `ASK_NUM`, `ASK_DEN` | u64 | The pool sells `BASE` asking at least `ASK_NUM` of `QUOTE` for every `ASK_DEN` of `BASE` |
| `MIN_LOT` | u64 | The least `BASE` a fill moves |
| `RESERVE_BASE` | u64 | The least `BASE` a fill that pays `BASE` out leaves in the pool |
| `RESERVE_QUOTE` | u64 | The least `QUOTE` a fill that pays `QUOTE` out leaves |
| `MAKER_KEY` | Pubkey | The only key that withdraws |

A pool is two coins at this address: the `BASE` coin at input `j` and the
`QUOTE` coin at input `j+1`. The `BASE` coin's program judges every move and owns
outputs `2j` and `2j+1`, which are the pool again. The `QUOTE` coin at `j+1` owns
`2j+2` and `2j+3` under the `2k` rule and reads neither, so a transaction may use
them for anything.

| Path | `PATH` | Who | Requires |
|---|---|---|---|
| sell | `Left(true)` | anyone, at the `BASE` coin | Input `j+1` holds `QUOTE` explicitly at this script; outputs `2j` (`BASE`) and `2j+1` (`QUOTE`) are at this script, explicit, with no nonce. The pool pays out `db = x0 - x1` of `BASE`, at least `MIN_LOT` and one atom, keeps `x1 >= RESERVE_BASE`, and takes in `dq = y1 - y0` with `dq * ASK_DEN >= db * ASK_NUM` |
| buy | `Left(false)` | anyone, at the `BASE` coin | As sell, the pool taking in `db = x1 - x0` of `BASE`, at least `MIN_LOT` and one atom, paying out `dq = y0 - y1` with `dq * BID_DEN <= db * BID_NUM`, and keeping `y1 >= RESERVE_QUOTE` |
| pair | `Right(Left(()))` | anyone, at the `QUOTE` coin | Input `j-1` holds `BASE` explicitly at this script. That coin's program judges the move |
| withdraw | `Right(Right(()))` | `MAKER_KEY` | A BIP340 signature over `jet::sig_all_hash()`: one transaction, one input, this chain. Either coin, alone or together |

No spend of a pool carries an annex. A fill and a pair sign nothing, so nothing
would bind an annex: anyone relaying a fill could attach one of up to 100,000
bytes, and the copy that reaches a mempool first, at the relay's lowest fee rate
under the same txid, would keep the honest one out. The withdrawal refuses one
too. No path needs an annex for its budget.

Each side rounds in the pool's favour, so no sequence of fills draws value out
by rounding. A coin at the address with no partner, or with a partner of the
wrong asset, can only be withdrawn; a stray coin that someone pairs with the
pool's own coin becomes part of the pool. To change its quotes the maker
withdraws both coins into the address of the new terms in one transaction.

Choose `BID <= ASK`: a pool that bids above its ask can be bought from and sold
back to at a profit until each side reaches its reserve. A reserve of at least
one atom keeps both coins in existence.

## The round order

The data leaf, 188 bytes:

| Term | Type | What |
|---|---|---|
| `ASSET_A` | u256 | The asset the order sells, which the coin holds |
| `ASSET_B` | u256 | The asset a fill pays in |
| `LIMIT_NUM`, `LIMIT_DEN` | u64 | The least the order accepts: `LIMIT_NUM` of `ASSET_B` for every `LIMIT_DEN` of `ASSET_A` |
| `MIN_LOT` | u64 | The least a fill takes, and the least a remainder holds |
| `MAKER` | u256 | SHA256 of the scriptPubKey every credit pays |
| `EXPIRY` | u32 | Refund lock: below 500,000,000 a height, else a median time |
| `REFUND_KEY` | Pubkey | Takes the coin back after `EXPIRY` |
| `CLEARER` | Pubkey | The only key whose rounds fill the order |

### The clearing output

A round publishes its one price in its last output, whose scriptPubKey is
exactly

```
OP_RETURN OP_PUSHDATA1 80 <BASE 32> <QUOTE 32> <N 8> <D 8>
```

meaning `N` atoms of `QUOTE` for every `D` atoms of `BASE`, numbers big-endian,
asset ids in internal byte order. It is 83 bytes, the standard data-carrier size
exactly, and its amount is not read. The last output is unique by position, so a
transaction has one price for everything that reads it.

### A fill

`PATH` = `Left((partial, (flip, (N, D))))`, the order at input `k`:

1. The coin holds `ASSET_A` explicitly. A partial fill leaves at `2k+1` a
   remainder of `ASSET_A` at this script, explicit, with no nonce, of at least
   `MIN_LOT`; a whole fill leaves nothing and `2k+1` is the round's. The fill is
   at least `MIN_LOT` and one atom.
2. The last output's script hash is that of the clearing output for
   `(BASE, QUOTE) = (ASSET_A, ASSET_B)`, or `(ASSET_B, ASSET_A)` when `flip`.
   The order's rate `n/d` of `ASSET_B` per `ASSET_A` is `N/D`, or `D/N` when
   `flip`, and `d` is at least one.
3. The rate is at least the limit: `n * LIMIT_DEN >= LIMIT_NUM * d`.
4. Output `2k` pays `MAKER` exactly `ceil(fill * n / d)` of `ASSET_B`, explicit,
   with no nonce: `fill * n <= paid * d < fill * n + d`.
5. `CLEARER` signs (BIP340) `SHA256(T || T || genesis || jet::tx_hash())`, with
   `T = SHA256("SeqDEX/clearing")` and the genesis hash in internal byte order.

`tx_hash` commits to the version, the lock time, every input's outpoint,
sequence and annex, every spent coin's asset, amount and script, every output and
the issuances, so the clearer's signature authorises exactly one transaction on
one chain, and the tag keeps it from being read as any other message the key
signs. It moves nothing by itself: each order still checks its own credit, limit
and remainder. Witnesses are outside `tx_hash`, so the clearer signs once, after
the transaction is final, and the same signature goes into every round order of
that clearer in it.

What this gives a maker: a fill only in a transaction the clearer signed, only at
the price that transaction publishes, exactly (rounded in the maker's favour by
under one atom), at the price every other round order in the transaction reads,
and never below the limit. Without the clearer's signature anybody could clear a
round of one order at that order's own limit. What it does not give: the clearer
chooses which orders a round takes and which price within their limits it
publishes, and it can leave an order out; the refund after `EXPIRY` bounds that
(an `EXPIRY` of zero refunds at any time).

### The refund

`PATH` = `Right(())`: `REFUND_KEY` signs `jet::sig_all_hash()` once the
transaction's lock time reaches `EXPIRY`, exactly as in `seqdex/order`.

No spend of a round order carries an annex. The clearer's digest and the refund
key's `sig_all_hash` already cover every input's annex; the rule keeps the order
safe on its own terms, and no path needs an annex for its budget.

## A round

The round orders sit at inputs `0..n-1`, each crediting its maker at `2k` and
leaving any remainder at `2k+1`. A pool can take part like any order: its `BASE`
coin at an input `j` after the orders and its `QUOTE` coin at `j+1`, filled
through its own sell or buy path, so the pool gets its quote or better. The
clearer's own coins come next: a fee coin in any asset the chain accepts for
fees, and, because every participant is rounded in its own favour, a coin of
each asset that covers the round's shortfall of at most one atom per
participant. The clearer's change fills the free slots (a whole fill's `2k+1`),
then the fee, and the clearing output is last.

## Building a spend with no compiler

The witness stack of every spend is `[witness, program, cmr, control block]`.
`program` is one constant per path, held in each template's `fills.json`:

| Template | Path | Program | Witness |
|---|---|---|---|
| `seqdex/pool` | `sell` | 1,353 B | the terms, then `01` |
| | `buy` | 1,355 B | the terms, then `00` |
| | `pair` | 791 B | the terms, then `10` |
| | `withdraw` | 569 B | the terms, `11`, the 64-byte signature |
| `seqdex/round-order` | `fill`, `fill_flip` | 1,714, 1,718 B | the terms, `0`, `partial`, `flip`, `N` and `D` (64 bits each), the clearer's 64-byte signature |
| | `fill_whole`, `fill_whole_flip` | 1,602, 1,606 B | the same |
| | `refund_height`, `refund_time` | 561 B each | the terms, `1`, the 64-byte signature |

Each witness is padded with zero bits to a whole byte. The program is one
constant per path because no branch depends on a value and each term is read in
a statement of its own. `crates/sequentia-contracts/tests/seqdex_pool_round.rs`
prunes each program for every vector's terms, for terms holding equal values
(and a round order whose clearer key is its refund key), at input indices 0, 1
and 3, and requires `fills.json` each time; every fill it builds executes only
because the clearer signed `round::clearing_digest`, which holds that function to
the program's own jet. It also runs every path with an annex of 3 and of 1,000
bytes, the signatures covering it, and requires each refused. `seqc run` prints
`tx_hash` and `clearing_digest` for any transaction it is given, reading an annex
as the node does: the last item of a witness stack of at least two, after its
`0x50` tag.

## Measured

`harness/tests/x4_seqdex_pool_round.py`, on an anchored chain (a parent node
standing in for Bitcoin, `-con_bitcoin_anchor=1 -validateanchor=1`), recorded in
`harness/records/x4.json`. Every transaction pays its fee in an issued asset.

| Spend | vsize | Covenant inputs: program, witness, cost bound, budget |
|---|---|---|
| Pool sell: the pool's two coins, a payment coin, a fee coin; six outputs | 1,297 vB | base 1,353 B, 153 B, 499 WU, 6,490 WU; quote 791 B, 153 B, 317 WU, 4,242 WU |
| Pool buy, the same layout | 1,298 vB | the same, 1,355 B and 500 WU for the base coin |
| Withdrawal of both coins by the maker | 852 vB | 569 B, 217 B, 314 WU, 3,610 WU each |
| A round of four orders (two asks, two bids, one filled in part), the clearer's two gap coins and a fee coin; twelve outputs with the clearing output | 3,107 vB | 1,602 to 1,718 B, 269 B, 651 to 697 WU, 7,958 to 8,422 WU each |
| A round order's refund by height | 529 vB | 561 B, 253 B, 295 WU, 3,730 WU |

No spend needs an annex. A round order's input carries about 2 KB of witness
(about 510 vB), and a pool fill's two inputs about 2.4 KB.
