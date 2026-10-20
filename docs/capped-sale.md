# The capped sale

`templates/capped_sale` (`sequentia/capped-sale`) sells a token at a fixed
price to the buyers on an allocation list, each up to the cap the list gives
them. The cap is enforced by consensus: a purchase over a buyer's cap, by a key
that is not on the list, or that leaves the running totals wrong cannot be
mined. Nobody has to be online for a sale to settle but the buyer.

## The output

```
P2TR(NUMS, TapBranch(TapBranch(TapLeaf_0xbe(sale), H_TapData(params ‖ state)), reclaim))
```

- `sale`, a Simplicity leaf (`templates/capped_sale/capped_sale.simf`): the
  purchase.
- The data leaf: `TOKEN`, `PAY_ASSET`, `PRICE_NUM`, `PRICE_DEN`, `TREASURY`
  (SHA256 of the treasury's scriptPubKey), `MIN_LOT` and the state slot
  `ALLOCATIONS`, in that order.
- `reclaim`, a tapscript leaf: `<CLOSE> OP_CHECKLOCKTIMEVERIFY OP_DROP
  <PROJECT_KEY> OP_CHECKSIG`.

The internal key is NUMS, so there is no key path. A sale's address changes
with every purchase, because its state does; everything else stays.

## The allocation tree

`ALLOCATIONS` is the root of a Merkle tree of 16 levels, room for 65,536
buyers. Leaf `i` is buyer `i` of the list:

```
leaf = SHA256(0x00 ‖ SHA256(key ‖ cap ‖ bought))      key: 32-byte x-only key
node = SHA256(0x01 ‖ left ‖ right)                     cap, bought: 8-byte big-endian
```

Every position past the list holds the leaf of a zero key with a zero cap,
which nothing can buy through. A sale starts with every `bought` at zero, so
its first state is the root of the allocation list itself, and that root is
what a project publishes beside the list. A key may appear once.

The mirrors compute the tree with no compiler: `capped_sale_root`,
`capped_sale_proof`, `capped_sale_leaf` and `capped_sale_payment` in Python,
`cappedSaleRoot` and its siblings in JavaScript, `CappedSaleRoot` in Go, and
`sale::root` in the Rust crate. `templates/capped_sale/allocations.json` holds
the vectors all four reproduce.

## A purchase

The buyer shows their leaf (`BUYER_KEY`, `CAP`, `BOUGHT`), its proof (`PROOF`,
one `(sibling, sibling_is_left)` per level, leaf first) and the amount bought
(`AMOUNT`), and signs. With the coin at input `k`, the program requires:

| Check | Refuses |
|---|---|
| The data leaf is the coin's, and the tree is the template's | Parameters or a state the address does not commit to |
| The coin holds `TOKEN`, explicitly | Anything else resting at a sale address: it is never sold |
| `MIN_LOT ≤ AMOUNT` and `BOUGHT + AMOUNT ≤ CAP` | A purchase over the cap, in one purchase or across several |
| The proof folds the buyer's leaf to `ALLOCATIONS` | A key not on the list, a cap larger than the list's, a running total other than the state's |
| Output `2k` pays `TREASURY` at least `ceil(AMOUNT × PRICE_NUM / PRICE_DEN)` of `PAY_ASSET`, explicitly, with no nonce | Underpaying, paying in another asset or to another script |
| Unless `AMOUNT` is the whole coin, output `2k+1` holds exactly the rest of `TOKEN`, at least `MIN_LOT`, explicitly and with no nonce, at the sale's script in the next state | A rest kept back, sent elsewhere, or in a state that does not follow |
| `BUYER_SIG` is `BUYER_KEY`'s BIP340 signature over `jet::sig_all_hash()` | A purchase the buyer did not sign |

The next state is computed in the program from the same proof: the tree with
only this buyer's `bought` raised by `AMOUNT`. One proof folds both roots, so no
other buyer's leaf and no cap can change. The price is compared at 128 bits
(`paid × PRICE_DEN ≥ AMOUNT × PRICE_NUM`), so no price or amount overflows and
a price need not be reduced first.

`sig_all_hash` commits to the chain's genesis, every input and output, this
leaf and the input's index. A buyer's signature therefore authorises exactly
one purchase in one transaction; it cannot be moved to another coin, another
amount or another chain. Outputs other than `2k` and `2k+1` are the buyer's to
arrange: where the tokens go, the change, the fee and the fee's asset.

Any input index works, and covenant input `k` owns outputs `2k` and `2k+1`, so
several sales can settle in one transaction without sharing a payment, and a
round that batches covenant fills can spend a sale like any other.

When no rest is left there is no successor, and output `2k+1` is unconstrained;
put anything there but the token.

## The close and the reclaim

`CLOSE` is a block height below 500,000,000, or a unix time at or above it. The
reclaim leaf lets `PROJECT_KEY` take a coin into any transaction it signs once
the close has passed, judged against the transaction's locktime as
`OP_CHECKLOCKTIMEVERIFY` does. A Simplicity program cannot read the time, so
the close does not stop purchases: until the project reclaims, a buyer within
their cap can still buy at the price.

## What the cap means

The running totals live in the coin. A cap therefore holds for the coin the
project funds and the coins that descend from it. A second coin funded at the
first state's address starts its own totals from zero, so a sale is funded with
one coin, and a launchpad shows any other coin at a sale's addresses as not
part of the sale. Tokens that someone else sends there can be bought, within
each buyer's cap, at the sale's price, which takes nothing from the project.

The list itself is the project's decision, made before the sale is funded:
whoever builds the list chooses who may buy and how much. What the chain
guarantees is that the list, once its root is in the address, is the one that
binds.

## Measured

`harness/tests/c1_capped_sale.py`, recorded in `harness/records/c1.json` and in
the descriptor's `measured`: a purchase with a payment coin and a fee coin in a
third asset is 1,233 vB (program 1,692 B, witness 786 B, cost bound 2,225 WU
against a budget of 10,514 WU). The witness's own size earns far more budget
than the program costs, so a purchase never needs an annex. A full buy is
1,076 vB and the reclaim 342 vB.
