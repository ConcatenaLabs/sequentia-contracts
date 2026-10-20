# The subscription escrow

`templates/subscription_escrow` (`sequentia/subscription-escrow`) holds one
subscription's payment to an offering until the offering settles. The
subscriber pays straight into it from their own wallet, so the money never
passes through a platform's wallet, and only three things can happen to it:

| Path | Who | When | Where the money goes |
|---|---|---|---|
| `release` | the issuer's key | once the offering has closed | into one transaction whose output 0 pays the issuer at least the minimum |
| `cancel` | the issuer's key | at any time | back to the subscriber |
| `refund` | anyone, no signature | once the deadline has passed | back to the subscriber |

All three leaves are tapscript; `tools/subscription-escrow/escrow_leaves.py`
wrote them, and `--asm` prints them as opcodes.

## The output

```
P2TR(NUMS, {{release, cancel}, {refund, H_TapData(SUBSCRIPTION)}})
```

| Parameter | Meaning |
|---|---|
| `PAY_ASSET` | The asset the subscription is paid in, in internal byte order |
| `ISSUER_KEY` | The issuer's x-only key |
| `ISSUER_SCRIPT` | SHA256 of the scriptPubKey the raise is released to |
| `MINIMUM` | The least the release pays the issuer: the offering's minimum |
| `CLOSE` | A block height below 500,000,000, or a unix time at or above it, from which the issuer may release |
| `REFUND_SCRIPT` | SHA256 of the subscriber's refund scriptPubKey |
| `DEADLINE` | A height or a time, as `CLOSE` is, from which anyone may refund |
| `FEE_CAP` | The most a refund or a cancel may keep back from the coin, for its fee |
| `SUBSCRIPTION` | An identifier of the subscription, in a data leaf: it gives every subscription its own address, so a platform tells them apart on the chain |

Every subscription to one offering shares every parameter but
`REFUND_SCRIPT` and `SUBSCRIPTION`. The internal key is NUMS, so there is no
key path.

## Release

`<CLOSE> OP_CHECKLOCKTIMEVERIFY OP_DROP`, then output 0 must be `PAY_ASSET`,
explicitly, to `ISSUER_SCRIPT`, with no nonce, holding at least `MINIMUM`, and
`ISSUER_KEY` signs. Every subscription's coin checks the same output 0, so one
release spends them all and output 0 carries the raise. The issuer's signature
covers the whole transaction and the leaf, so it authorises that release alone;
it cannot be replayed onto the cancel leaf, another coin or another chain.

The chain cannot tell the issuer's own money from a subscriber's. An issuer who
adds a coin of its own to the release meets the minimum with it, exactly as it
could by subscribing to its own offering, and the release shows it: every
escrow input and the issuer's output are on the chain. What the covenant
guarantees is that no subscriber's money reaches the issuer before the close,
or in a release that pays the issuer less than the minimum.

## Cancel and refund

Both require, for the coin at input `k`, that output `k` returns the coin's
own asset to `REFUND_SCRIPT`, explicitly and with no nonce, holding at least
the coin's value less `FEE_CAP`. A transaction can therefore refund many
subscriptions at once, input `k` to output `k`. The fee comes from the coin,
capped, or from another input in any asset the node accepts, in which case the
subscriber gets the whole coin.

`cancel` is signed by the issuer and has no time lock: it is how a platform
returns a subscription when an offering fails or a delivery cannot be made.
`refund` needs no signature and opens at `DEADLINE`, so a subscriber is repaid
even if the issuer and the platform both disappear.

## Confidential coins

Pay a subscription escrow with a transparent transfer. A confidential coin at
an escrow address can only be released, never cancelled or refunded: `cancel`
and `refund` read the coin's own asset and amount at its input
(`OP_INSPECTINPUTASSET`, `OP_INSPECTINPUTVALUE`) and require them explicit, so
neither leaf can spend a coin that hides them, while `release` reads only its
output 0 and the issuer's signature. A subscriber who pays confidentially
therefore loses the refund the deadline promises, and the release that can
spend the coin also needs its blinding factors to balance. A platform built on
this escrow refuses a confidential subscription before it is paid, and credits
only explicit coins of `PAY_ASSET`.

## Timing

`OP_CHECKLOCKTIMEVERIFY` sets a floor and no ceiling, so after the deadline
both the release and the refund are possible, and whichever is mined first
wins. A platform releases between the close and the deadline and refunds
promptly after it; the deadline is set with room for the close to settle.

## Measured

`harness/tests/e1_subscription_escrow.py`, recorded in
`harness/records/e1.json` and in the descriptor's `measured`: a release of two
subscriptions with a fee coin is 533 vB, a cancel 388 vB, and a refund of two
subscriptions by anyone after the deadline 404 vB. The leaves are 219, 191 and
163 bytes.
