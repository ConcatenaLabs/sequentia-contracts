# The SeqDEX order

`templates/seqdex_order_2` (`seqdex/order` version 2) is a resting order on the SeqDEX book:
a maker's coin of one asset that any taker fills, in part or in whole, by paying
the maker in another asset at the order's price, and that the maker takes back
after the order expires. Nobody but the taker has to be online for a fill.

One program serves every order. The order's terms sit in a data leaf beside it,
so the program's commitment root is one constant and an order's address is that
root plus its terms: any language derives it with one hash per leaf and one curve
tweak, and needs no compiler. The price is checked on 128-bit products, so every
64-bit amount and price fills; nothing has to be kept under 2^63.

## Versions

| Version | Template | Root | Template hash |
|---|---|---|---|
| 2 | `templates/seqdex_order_2` | `5f0819996f39cf22adfaa0da711a99dd0e06379e901c585c0db56ecd3d1f1cca` | `5e5a45fe64b85134c8f3706f0f21abfacb871c40cae4f449406ba6f86fa03cdd` |
| 1 | `templates/seqdex_order` | `f9b42b838b6295f4f376760fbb02eed9cb20f872f07ee4b9df7273d26822ee44` | `322c0e596e9552a4c20f6a7f9ed518013a50076ec8b2b9005fd032077ebcd157` |

Version 2 is version 1 with one more rule: no spend carries an annex. A fill
signs nothing, so nothing binds an annex on it, and the node relays an annex of
up to 100,000 bytes on a Simplicity leaf spend. On version 1, whoever relays a
fill can therefore attach one: the fill grows to some 26,000 vB, its fee rate
falls to the relay floor, and the mempool keeps that copy when the honest one
arrives, since both have the same txid. Version 2 refuses it. No path needs an
annex for its budget: each path's own witness buys far more than it costs.

Every new order uses version 2. A version 1 coin already resting fills, and is
refunded, exactly as before until it is gone; an offer names its version by
its template hash. Everything below holds for both versions except where it
names one.

## The output

```
P2TR(NUMS, TapBranch(TapLeaf_0xbe(order), H_TapData(terms)))
```

The internal key is NUMS, so there is no key path. The data leaf holds the terms
in this order, each big-endian at its width:

| Term | Type | What |
|---|---|---|
| `ASSET_A` | u256 | The asset the order sells, which the coin holds. Internal byte order |
| `ASSET_B` | u256 | The asset a fill pays in. Internal byte order |
| `RATE_NUM` | u64 | The price: `RATE_NUM` atoms of `ASSET_B` ... |
| `RATE_DEN` | u64 | ... for every `RATE_DEN` atoms of `ASSET_A` |
| `MIN_LOT` | u64 | The least a fill takes, and the least a remainder holds, in `ASSET_A` |
| `MAKER` | u256 | SHA256 of the scriptPubKey every fill pays |
| `EXPIRY` | u32 | A lock time: below 500,000,000 a block height, else a Unix time, which consensus compares with the median time past |
| `REFUND_KEY` | Pubkey | The x-only key that takes the coin back after `EXPIRY` |

The data leaf is 156 bytes. Either asset may be any asset. `MAKER` names a whole
scriptPubKey by its hash, so the maker may be paid at any script.

## A fill

The spender chooses the path in the witness value `PATH`: `Left(true)` for a
partial fill, `Left(false)` for a whole one. With the order at input `k`, for
any `k`, the program requires:

| Check | Refuses |
|---|---|
| The terms are the data leaf's, and the tree is this leaf and the data leaf alone | Terms the address does not commit to |
| The coin holds `ASSET_A`, explicitly | Anything else at an order's address: a coin of another asset, or a confidential coin, is never sold, and only the refund key moves it |
| A partial fill: output `2k+1` holds `ASSET_A`, explicitly and with no nonce, at the coin's own scriptPubKey, and at least `MIN_LOT` | A remainder sent elsewhere, under another program, under other terms (another price, another refund key, another expiry), in another asset, confidential, or too small to fill again |
| The fill, the coin less the remainder (the whole coin in a whole fill), is at least `MIN_LOT` and at least one atom | Dust fills, and a fill of nothing that only moves the order |
| Output `2k` pays `MAKER` at least `ceil(fill × RATE_NUM / RATE_DEN)` of `ASSET_B`, explicitly and with no nonce | Underpaying by one atom, paying in another asset, confidentially, or to another script |

The price is checked as `fill × RATE_NUM ≤ paid × RATE_DEN` on 128-bit products,
which is exactly `paid ≥ ceil(fill × RATE_NUM / RATE_DEN)` and holds for every
pair of 64-bit values. A price need not be reduced to lowest terms.

A fill signs nothing and needs nothing from the maker. Outputs other than `2k`
and `2k+1` are the taker's to arrange: where the asset goes, the change, the
fee and the fee's asset, which can be any asset the chain accepts for fees. In a
whole fill, output `2k+1` is unconstrained and is usually the taker's own receipt
of `ASSET_A`.

Covenant input `k` owns outputs `2k` and `2k+1`, so several orders fill in one
transaction without ever sharing a payment: two coins of one order at inputs 0
and 1, paid once at output 0 for both, are refused, because the coin at input 1
reads its own credit at output 2. The rule is the same as the capped sale's and
the Pignus offer's, so a round that batches covenant fills spends an order like
any other.

## The refund

`PATH` = `Right(())`. The refund key signs the whole transaction (`REFUND_SIG`,
BIP340 over `jet::sig_all_hash()`), once the transaction's lock time reaches
`EXPIRY`:

- a height `EXPIRY` requires a height lock time of at least `EXPIRY`
  (`jet::check_lock_height`), and a time `EXPIRY` a time lock time of at least
  `EXPIRY` (`jet::check_lock_time`); a lock time of the other kind is refused;
- either jet reads no lock time when every input's sequence is final, so the
  refund's inputs must leave a non-final sequence (`0xfffffffe` does), and then
  consensus holds the transaction until the chain's height, or its median time
  past, reaches the lock time.

A time lock follows the clock, which keeps moving whatever happens to the chain's
height; a height lock that has been reached can be undone when the chain reorgs
with its Bitcoin anchor. A maker who wants the order to end at a moment chooses a
time.

`sig_all_hash` commits to the chain's genesis, every input and output, this leaf
and the input's index, so a refund signature authorises exactly one transaction:
it moves no other coin of the same order, and no coin on another chain. An
`EXPIRY` of zero makes an order the maker can take back at any time; a taker sees
that in the terms.

## Building a spend with no compiler

The witness stack of every spend is `[witness, program, cmr, control block]`,
with no annex:

- `cmr` is the version's root (above);
- the control block is the one the address mirrors derive for the leaf `order`;
- `program` is one of four constants, the pruned program of each path, held in
  the version's `fills.json`: `fill`, `fill_whole`, and `refund_height` and
  `refund_time`, chosen by whether `EXPIRY` is below 500,000,000. Version 2's
  are 1,105, 994 and 516 bytes (`templates/seqdex_order_2/fills.json`),
  version 1's 1,092, 981 and 505 (`templates/seqdex_order/fills.json`);
- `witness` is the bit string of the 156 data-leaf bytes, then `PATH` (`01` for a
  partial fill, `00` for a whole one, `1` for the refund), then for the refund the
  64-byte signature, padded with zero bits to a whole byte. A fill's witness is
  therefore the data leaf's bytes followed by `0x40` or `0x00`.

The program is one constant per path because no branch of a fill depends on a
value, and because each term is read in a statement of its own: two equal values
read side by side, such as a 1:1 price, would otherwise be one shared node, and
the program would depend on the terms. `crates/sequentia-contracts/tests/seqdex_order.rs`
prunes each version's program for every vector's terms, for terms holding equal
values, and at `k` = 0, 1 and 3, and requires its `fills.json` each time; the
regtest tests `x3` (version 2) and `x1` (version 1) require it of every spend
they mine. The same test runs part and whole fills at `k` = 0 and 1 with an
annex of 3 and of 1,000 bytes on the order's input, beside the same fills
without one: version 2 refuses each, version 1 takes each. A refund still needs the chain's
`sig_all_hash` of the transaction, which `seqc run` prints.

## Choosing terms

- `MAKER` is SHA256 of the maker's whole scriptPubKey. Pay a plain key's script.
  A script whose coins the maker spends as a set under one signature, such as an
  Arca leaf, would let two fills of the same size produce two equal credits that
  one signature spends, so it is not a payout for an order.
- `MIN_LOT` floors every fill and every remainder. A coin at an order's address
  holding less than `MIN_LOT` can only be refunded.
- Asset ids are in internal byte order, the reverse of the hex an RPC prints.

## Measured

`harness/tests/x3_seqdex_order_2.py` (version 2) and `x1_seqdex_order.py`
(version 1), recorded in `harness/records/x3.json` and `x1.json` and in each
descriptor's `measured`. Each transaction pays its fee in a third issued asset;
none touches the policy asset. X3 runs every spend and refusal of X1 again under
version 2's root, and refuses a fill with an annex of 3 and of 1,000 bytes, and
a zero annex of 1,000 bytes, in a block (`Assertion failed`), beside the same
fill without one. The mempool refuses each too: for the program's failure on a
node before Sequentia 25.2.4, and for the annex itself on a node from it, which
relays an annex on a Simplicity leaf only when it is zeros and as large as the
program's cost needs. X1 offers the same annexed fills to version 1, whose
mempool takes them before 25.2.4 and from it refuses them for the annex alone;
the program itself takes them, so a block producer can still pad a version 1
fill.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Partial fill: the order, a payment coin, a fee coin; six outputs | 921 vB (v1: 917) | 1,105 B (1,092) | 157 B | 359 WU (356) | 5,514 WU (5,462) |
| Whole fill: five outputs | 814 vB (811) | 994 B (981) | 157 B | 316 WU (313) | 5,070 WU (5,018) |
| Two orders in one transaction, at inputs 0 and 1 | 1,409 vB (1,403) | 1,105 + 994 B | 157 + 157 B | 359 + 316 WU | 5,514 + 5,070 WU |
| Refund, by height or by time | 509 vB (507) | 516 B (505) | 221 B | 257 WU (254) | 3,414 WU (3,370) |

The witness's own size earns far more budget than the program costs, so no spend
needs an annex. The order's input carries about 1,350 witness bytes (338 vB) in a
fill.
