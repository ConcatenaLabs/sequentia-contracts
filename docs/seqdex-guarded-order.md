# The guarded SeqDEX order

`templates/seqdex_guarded_order` (`seqdex/guarded-order`) is the SeqDEX order of
[`seqdex-order.md`](seqdex-order.md) with a guard: every spend, each fill and the
refund, needs a coin of a named asset in a named amount at input 0. Everything
else is the order's: the price, the minimum lot, the remainder at the same
script, the refund after expiry, one program for every order with the terms as
data, and spends built with no compiler.

## What the guard is for

Some assets have their rules enforced by a covenant that every transfer must
spend at input 0. An OpenDAMP asset is one: its verifier covenant holds `q` units
of a verifier asset `V`, and each transfer spends the verifier at input 0 so that
the verifier can check every output of the regulated asset.

A plain order cannot hold such an asset. Consensus runs only the scripts of the
coins a transaction spends, and a plain order's fill constrains only the payment
and the remainder: the taker's output of the sold asset can go anywhere, in a
transaction with no verifier in it. A guarded order with `GUARD_ASSET = V` and
`GUARD_AMOUNT = q` can be filled or refunded only beside the verifier, which then
scans everything the order's coin pays out. That is what lets OpenDAMP's
verifier put the order on an asset's list of contract templates. The opendamp
repository states what the verifier then checks.

The guard itself is not tied to OpenDAMP. Any covenant that sits at input 0 of
the transactions it polices can guard an order this way.

## The output

```
P2TR(NUMS, TapBranch(TapLeaf_0xbe(order), H_TapData(terms)))
```

The data leaf holds ten terms, the order's eight followed by the guard's two,
each big-endian at its width:

| Term | Type | What |
|---|---|---|
| `ASSET_A` | u256 | The asset the order sells, which the coin holds. Internal byte order |
| `ASSET_B` | u256 | The asset a fill pays in. Internal byte order |
| `RATE_NUM` | u64 | The price: `RATE_NUM` atoms of `ASSET_B` ... |
| `RATE_DEN` | u64 | ... for every `RATE_DEN` atoms of `ASSET_A` |
| `MIN_LOT` | u64 | The least a fill takes, and the least a remainder holds, in `ASSET_A` |
| `MAKER` | u256 | SHA256 of the scriptPubKey every fill pays |
| `EXPIRY` | u32 | A lock time: below 500,000,000 a block height, else a Unix time compared with the median time past |
| `REFUND_KEY` | Pubkey | The x-only key that takes the coin back after `EXPIRY` |
| `GUARD_ASSET` | u256 | The asset input 0 of every spend must hold. Internal byte order |
| `GUARD_AMOUNT` | u64 | How much of it, exactly |

The data leaf is 196 bytes.

## The guard

On every path, before anything else, the program requires:

| Check | Refuses |
|---|---|
| The coin is not input 0 | An order that would be its own guard |
| Input 0 holds `GUARD_ASSET`, its asset id explicit | No guard coin, a guard coin at another input, a coin of another asset at input 0, a confidential guard coin |
| Input 0 holds exactly `GUARD_AMOUNT`, explicitly | One atom short, one atom over |

With the guard at input 0 and the order at input `k`, for any `k` of at least 1,
the order owns outputs `2k` and `2k+1` exactly as `seqdex/order` does, so its
outputs never include output 0. Output 0 is the guard coin's to arrange. For an
OpenDAMP verifier it is the verifier's recreation.

## A fill and the refund

These are `seqdex/order`'s, unchanged: see
[`seqdex-order.md`](seqdex-order.md#a-fill) for the fill's checks and
[the refund](seqdex-order.md#the-refund) for the refund's. In a fill at `k = 1`
the layout is the guard coin, the order, the payment coin and a fee coin in, and
the guard's output, the taker's asset, the payment to `MAKER` (output 2), the
remainder (output 3), the payment change, the fee change and the fee out.

## Building a spend with no compiler

The witness stack of every spend is `[witness, program, cmr, control block]`:

- `cmr` is the template's root,
  `c676964fbb78174782e24f18b5fb3fdd65a844d7317ca43b84547807461ca659`;
- the control block is the one the address mirrors derive for the leaf `order`;
- `program` is one of four constants in `templates/seqdex_guarded_order/fills.json`:
  `fill` (1,286 bytes), `fill_whole` (1,177), and `refund_height` and
  `refund_time` (731 each);
- `witness` is the bit string of the 196 data-leaf bytes, then `PATH` (`01` for
  a partial fill, `00` for a whole one, `1` for the refund), then for the refund
  the 64-byte signature, padded with zero bits to a whole byte. A fill's witness
  is therefore the data leaf's bytes followed by `0x40` or `0x00`.

`crates/sequentia-contracts/tests/seqdex_guarded_order.rs` prunes the program for
every vector's terms, for terms holding equal values (including a guard asset
equal to either order asset), and at `k` = 1, 2 and 4, and requires `fills.json`
each time. The regtest test `x2` requires it of every spend it mines.

## Measured

`harness/tests/x2_seqdex_guarded_order.py`, recorded in `harness/records/x2.json`
and in the descriptor's `measured`. The guard coin is a wallet coin of an issued
asset, and each transaction pays its fee in a third issued asset.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Partial fill at input 1: the guard, the order, a payment coin, a fee coin; seven outputs | 1,111 vB | 1,286 B | 197 B | 469 WU | 6,398 WU |
| Whole fill at input 1: six outputs | 1,005 vB | 1,177 B | 197 B | 425 WU | 5,962 WU |
| Refund by height at input 1 | 709 vB | 731 B | 261 B | 366 WU | 4,442 WU |

No spend needs an annex.
