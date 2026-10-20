# The SeqDEX order

`templates/seqdex_order` (`seqdex/order`) is a resting order on the SeqDEX book:
a maker's coin of one asset that any taker fills, in part or in whole, by paying
the maker in another asset at the order's price, and that the maker takes back
after the order expires. Nobody but the taker has to be online for a fill.

One program serves every order. The order's terms sit in a data leaf beside it,
so the program's commitment root is one constant and an order's address is that
root plus its terms: any language derives it with one hash per leaf and one curve
tweak, and needs no compiler. The price is checked on 128-bit products, so every
64-bit amount and price fills; nothing has to be kept under 2^63.

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

The witness stack of every spend is `[witness, program, cmr, control block]`:

- `cmr` is the template's root, `f9b42b838b6295f4f376760fbb02eed9cb20f872f07ee4b9df7273d26822ee44`;
- the control block is the one the address mirrors derive for the leaf `order`;
- `program` is one of four constants, the pruned program of each path, held in
  `templates/seqdex_order/fills.json`: `fill` (1,092 bytes), `fill_whole` (981),
  and `refund_height` and `refund_time` (505 each), chosen by whether `EXPIRY` is
  below 500,000,000;
- `witness` is the bit string of the 156 data-leaf bytes, then `PATH` (`01` for a
  partial fill, `00` for a whole one, `1` for the refund), then for the refund the
  64-byte signature, padded with zero bits to a whole byte. A fill's witness is
  therefore the data leaf's bytes followed by `0x40` or `0x00`.

The program is one constant per path because no branch of a fill depends on a
value, and because each term is read in a statement of its own: two equal values
read side by side, such as a 1:1 price, would otherwise be one shared node, and
the program would depend on the terms. `crates/sequentia-contracts/tests/seqdex_order.rs`
prunes the program for every vector's terms, for terms holding equal values, and
at `k` = 0, 1 and 3, and requires `fills.json` each time; the regtest test `x1`
requires it of every spend it mines. A refund still needs the chain's
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

`harness/tests/x1_seqdex_order.py`, recorded in `harness/records/x1.json` and in
the descriptor's `measured`. Each transaction pays its fee in a third issued
asset; none touches the policy asset.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Partial fill: the order, a payment coin, a fee coin; six outputs | 917 vB | 1,092 B | 157 B | 356 WU | 5,462 WU |
| Whole fill: five outputs | 811 vB | 981 B | 157 B | 313 WU | 5,018 WU |
| Two orders in one transaction, at inputs 0 and 1 | 1,403 vB | 1,092 + 981 B | 157 + 157 B | 356 + 313 WU | 5,462 + 5,018 WU |
| Refund, by height or by time | 507 vB | 505 B | 221 B | 254 WU | 3,370 WU |

The witness's own size earns far more budget than the program costs, so no spend
needs an annex. The order's input carries about 1,350 witness bytes (338 vB) in a
fill.
