# The Pignus vault and offer, version 2

Two templates hold a Pignus loan on Sequentia: `templates/pignus_vault`, the
loan itself, and `templates/pignus_offer`, a lender's principal waiting to be
lent. Both are one Simplicity program beside a data leaf, so each program has
one commitment root for every loan and every offer, and an address is one hash
per leaf and one curve tweak from its values. The descriptor of each is the
template; this page says what the programs enforce and why.

The vault keeps its terms and its state in the data leaf beside the program
and reads the collateral from the coin itself. Its health is computed from the
live collateral and the debt outstanding at a fresh oracle price, with
products of three 64-bit numbers compared at 192 bits, so no loan is too large
for it. Anyone can repay part or all of the debt, anyone can add collateral in
place, and a liquidation takes only as much as brings an unhealthy vault back
to its target, under an attestation whose beacon is still live and that is
newer than the last one the vault used.

## The vault

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(vault program), H_TapData(terms || state)))
```

The internal key is BIP341's point with no known discrete logarithm, so there
is no key path: the program is the only way to spend the coin.

| Terms | Type | What |
|---|---|---|
| `COLL`, `DEBT_ASSET` | asset ids | The collateral and the debt asset, in internal byte order. Any accepted asset may be either |
| `ORACLE` | key | The key whose format-2 attestations price `COLL` in `DEBT_ASSET` |
| `BEACON_ASSET` | asset id | That oracle's beacon asset |
| `PRECISION` | 0 to 18 | The attestations' precision: a price is `price / 10^PRECISION` debt atoms per collateral atom |
| `LIQ_BP` | basis points | The liquidation threshold: below this collateral ratio the vault is unhealthy |
| `TARGET_BP` | basis points | A liquidation brings the vault back at most to this ratio |
| `BONUS_BP` | basis points | A liquidator keeps collateral worth at most this share of what it repays |
| `MATURITY`, `RECOVER_AFTER` | Unix times | When anyone may call the loan; when anyone may pay the whole collateral to the lender |
| `LENDER`, `BORROWER` | script hashes | SHA-256 of each party's payout scriptPubKey, so any script can be paid |

| State | Type | What |
|---|---|---|
| `DEBT_OUT` | amount | The debt outstanding, in the debt asset |
| `LAST_TIME` | Unix time | The time of the newest attestation a liquidation used, or of the loan's start |

The data leaf is the terms in that order, then the state, each value at its
width, big-endian. The collateral is the coin's own amount and is kept nowhere
else, so nothing can disagree with it. The spender gives the terms and the
state in the witness, and the program checks them against the data leaf, which
consensus has bound to the output through the control block.

### The output map

The vault coin at input `k` owns outputs `2k` and `2k+1`. Output `2k` is the
vault's successor, or the collateral's payout when the vault closes; output
`2k+1` pays the lender. Two vaults spent in one transaction therefore never
share an output, and one payment never settles two loans (`l1` refuses a
transaction that tries). Every output the program reads must be explicit.

The successor is this program with the same terms and the next state: the
program builds its script from its own leaf hash, its own internal key and the
data leaf it computes, so no constant names the program. Anyone who knows the
terms can follow a vault from coin to coin with the transactions alone: a
successor's debt is the old debt less what output `2k+1` pays the lender, and
its `LAST_TIME` is unchanged, or, after a liquidation, the lock time.

### The paths

**Repay** (anyone). Output `2k+1` pays the lender `P >= 1` of `DEBT_ASSET`. Below
the debt, output `2k` is the successor holding the same collateral and owing
`DEBT_OUT - P`; at or above it, output `2k` pays the borrower at least the whole
collateral and the vault closes. No oracle, no signature and no time is
involved, so a borrower can always leave, and a third party who repays can only
make the borrower better off.

**Top-up** (anyone). Output `2k` is this same script, its state unchanged,
holding more collateral than the coin. The address does not change.

**Liquidate** (anyone). The witness gives an attestation, where its beacon is
spent, and whether the loan is being called after maturity. The program
requires, in this order:

1. The attestation is `ORACLE`'s format-2 signature over the price of `COLL` in
   `DEBT_ASSET` at `PRECISION`, and its beacon is live: the input it names spends
   a coin of `BEACON_ASSET` from the script the attestation names
   (`helpers/attestation.simf`, `att_verify_fresh`).
2. Its time is after `LAST_TIME` and is the transaction's lock time, which the
   chain's median time must pass: the attestation is judged against the chain's
   clock, and the successor's `LAST_TIME` can be read off the transaction.
3. Output `2k+1` pays the lender `P >= 1`; the debt repaid is
   `r = min(P, DEBT_OUT)`.
4. Before maturity, the vault is unhealthy at that price, and `r` is no more
   than brings it to `TARGET_BP`. When called, the lock time reaches `MATURITY`,
   so the attestation is from after maturity, and any `r` is allowed.
5. The liquidator keeps a seizure `s` worth at most `r * BONUS_BP / 10000` at
   that price.
6. Below the debt, output `2k` is the successor with the rest of the
   collateral, owing `DEBT_OUT - r`, with `LAST_TIME` the attestation's time, and
   it is healthy at that price. At the debt, the vault closes: output `2k` must
   exist, and what it pays the borrower in `COLL` is the surplus returned.

**Recover** (anyone). Once the lock time reaches `RECOVER_AFTER`, output `2k`
pays the lender at least the whole collateral. It is the backstop for an oracle
that has stopped: the borrower has had the whole term to repay without one.

### The arithmetic

With `u = 10^PRECISION`, `c` the collateral, `d` the debt and `p` the price,
every rule compares two products of three 64-bit numbers:

| Rule | Comparison |
|---|---|
| healthy | `c * p * 10000 >= LIQ_BP * d * u` |
| the seizure | `s * p * 10000 <= r * BONUS_BP * u` |
| no further than the target | `c*p*10000 + (r-1)*TARGET_BP*u < TARGET_BP*d*u + (r-1)*BONUS_BP*u` |
| healthy afterwards | `(d - r) * LIQ_BP * u <= (c - s) * p * 10000` |

The target rule says that repaying one atom less, at the most the liquidator
may seize for it, would leave the vault below `TARGET_BP`: a liquidator repays
at most what brings the vault back, rounded up by an atom. When a vault cannot
be brought back (its collateral is worth less than the debt plus the bonus),
every `r` up to the whole debt passes.

The products are at most 2^156, and the program forms them at 192 bits
(`helpers/wide_arith192.simf`), so no amount, price or ratio makes it fail.
The comparisons take no branch on the values. Division is never needed.

`crates/sequentia-contracts/src/vault.rs` writes the rule out, and the mirrors
in Python, JavaScript and Go do the same (`pignus_vault_healthy`,
`pignus_vault_max_seizure`, `pignus_vault_max_repay`,
`pignus_vault_liquidation`, and their spellings in each language), so a
wallet, a liquidator, the explorer or the registry can show a vault's health
and check a liquidation without running the program.
`templates/pignus_vault/rules.json` holds the golden vectors all four
reproduce, and harness test `l1` runs every liquidation vector through the
program itself on the abstract machine, at amounts up to 2^64 - 1.

### What each party can do

| Party | Can | Cannot |
|---|---|---|
| The borrower | Repay in part or in whole at any time, add collateral | Take collateral out while a debt is owed |
| Anyone | Repay, top up, liquidate an unhealthy vault, call a matured loan, recover after `RECOVER_AFTER` | Pay anyone but the pinned lender and borrower what the program reserves for them |
| A liquidator | Repay up to the target and keep a seizure worth the bonus | Liquidate a healthy vault, seize more than the price allows, keep the surplus, leave the vault unhealthy, use an attestation no newer than the last or one whose beacon has moved |
| The oracle | Sign a price low enough to make a vault unhealthy | Move any coin, choose a recipient, stop a repayment, call a loan before maturity, or leave the lender short: a partial liquidation must leave the vault healthy at the price it signed, so at a false low price a liquidator must repay nearly the whole debt, and a close repays all of it |

A coin is spent and re-created by every repayment, top-up and liquidation, so
anyone who pays a fee and one atom can make a pending transaction on the vault
invalid by spending it first. That costs its maker, not the vault; a
liquidator rebuilds against the new coin, since nothing it signs names the
coin.

### What a builder must check

The program enforces what a spend may do. These hold for a vault that behaves
as described, and the vault's builder and every party's wallet check them
before funding one:

- `BONUS_BP >= 10000` and `BONUS_BP < LIQ_BP <= TARGET_BP`. A threshold at or
  under the bonus makes every liquidation a loss to the vault.
- `PRECISION <= 18`, as format 2 requires. A larger one makes the
  liquidation path unusable.
- `MATURITY` and `RECOVER_AFTER` are times (at least 500,000,000), and
  `RECOVER_AFTER` is far enough after `MATURITY` that an oracle outage cannot
  reach it.
- `LAST_TIME` is not in the future; the offer sets it from the lock time.
- The oracle publishes the pair `COLL`/`DEBT_ASSET` at `PRECISION` with a beacon.

## The offer

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(offer program), H_TapData(terms)))
```

Its terms are the vault's terms but the borrower's payout, then `LOT` (the
principal one take draws), `DEBT` (what a vault opened for one lot owes),
`COLLATERAL` (the least collateral that vault holds) and `EXPIRY`. The offer at
input `k` owns outputs `2k` and `2k+1`.

**Take** (anyone). Output `2k` is a vault of `templates/pignus_vault` on these
terms, its borrower's payout script hash given in the witness, owing `DEBT`,
its `LAST_TIME` the transaction's lock time, holding at least `COLLATERAL` of
`COLL`. Exactly `LOT` leaves the coin: whatever it holds beyond a lot goes to
output `2k+1` at this same script. Where the principal goes is the taker's
business. The vault's program is named by its commitment root, a constant in
the offer's program, so an offer of this template opens vaults of exactly one
template.

**Refund** (anyone). Once the lock time reaches `EXPIRY`, output `2k` pays the
lender at least the whole coin.

## Signing

Neither program checks a signature but the oracle's. A wallet that takes part
signs only its own inputs: the debt asset it repays with, the collateral it
adds, the collateral a borrower locks at a take. The five-point rule of
[`descriptor.md`](descriptor.md) still applies to that approval: the template
hash is on the wallet's list, the wallet recomputes the vault's script and the
successor's, runs the program against the final transaction, shows the
template, the path, the terms by role and its own balance changes, and signs
no contract key, because these paths need none.

## Proof

Harness test `l1` runs both templates on a regtest chain from their
descriptors: a loan of 2,000,000 units at 8 decimal places, which the version
1 vault's builder refuses to build at any price scale, taken from an offer,
topped up, repaid in part, liquidated in part under a fresh attestation, the
beacon rotated and liquidated again, called at maturity with the surplus
returned, repaid in full, recovered after its time, and an offer refunded
after its expiry. Every refusal is forced into a block with `generateblock`
and refused there for its reason, against an accepted control that differs
only in the property it breaks; a negative runs its control's pruned program,
so it fails at the check it breaks. `harness/records/l1.json` holds every
figure.

| Spend, from `harness/records/l1.json` | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Take: the offer, a collateral coin; the vault, the rest, the principal | 894 | 1,670 B | 242 B | 1,216 WU | 8,114 WU |
| Top-up in place | 565 | 952 B | 226 B | 501 WU | 5,178 WU |
| Partial repay | 730 | 1,347 B | 226 B | 751 WU | 6,758 WU |
| Partial liquidation: the vault, a beacon coin, the liquidator's coin | 1,427 | 2,910 B | 338 B | 1,653 WU | 13,466 WU |
| Full repay | 668 | 1,146 B | 226 B | 591 WU | 5,954 WU |
| Call at maturity, surplus returned | 1,338 | 2,602 B | 338 B | 1,268 WU | 12,234 WU |
| Recovery | 561 | 983 B | 226 B | 504 WU | 5,302 WU |
| Offer refund | 520 | 850 B | 194 B | 590 WU | 4,642 WU |

| Refused in a block, each against an accepted control | Error |
|---|---|
| Take: a vault one atom short of the collateral, owing less than the debt, with a start time other than the lock time, under another oracle; one atom more than a lot drawn; no lock time | `Assertion failed inside jet` |
| Top-up adding nothing; a successor with another state | `Assertion failed inside jet` |
| Repay: a successor keeping the old debt, owing less than repaid, one atom short; the lender paid at another script; two vaults and one payment; a close one atom short | `Assertion failed inside jet` |
| Liquidation: a healthy vault; a seizure one atom over; one atom beyond the target; a repayment that leaves the vault unhealthy; a successor whose debt or last time does not follow; a lock time before or after the attestation's time; the beacon index at another input; the lender paid elsewhere; another key's attestation; the reversed pair; an attestation no newer than the last; an attestation whose beacon has rotated | `Assertion failed inside jet` |
| The rotated beacon's own coin, spent by the rotation | `bad-txns-inputs-missingorspent` |
| Call: before maturity; the surplus paid to the liquidator; the surplus one atom short | `Assertion failed inside jet` |
| Recovery before its time, or paid to the borrower; a refund before expiry, or 1,000 atoms short | `Assertion failed inside jet` |
