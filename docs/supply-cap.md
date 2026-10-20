# The supply cap

`templates/supply_cap` is a covenant that holds an asset's reissuance token.
Whoever holds a reissuance token can mint any amount of its asset, so an
issuer whose server keeps the token in a wallet trusts that wallet's key with
the whole supply. The supply cap takes the token out of the wallet: an
operator key mints, and the covenant counts every mint against a cap fixed
when the covenant is made.

| Path | Who | What it does |
|---|---|---|
| `mint` | the operator key | Reissues the asset on the covenant's input and re-creates the covenant with the count raised by the amount. Refused once the count would pass the cap |
| `rekey` | the cold key | Re-creates the covenant under new operator and cold keys, with the count and the cap unchanged |

No path releases the token, lowers the count or raises the cap. Burning the
asset is unaffected: units are burned from whichever output holds them, and a
burn gives no room back, since the count is of what was minted.

## The output

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(cap), H_TapData(params ‖ state)))
```

One Simplicity leaf and one data leaf. The data leaf holds the parameters,
fixed for the instance, and the count, which changes with every mint, so each
count has its own address:

| Value | Kind | Meaning |
|---|---|---|
| `ASSET` | parameter | The asset the token reissues |
| `TOKEN` | parameter | The reissuance token, the coin's own asset |
| `OPERATOR_KEY` | parameter | Signs mints |
| `COLD_KEY` | parameter | Signs a rekey |
| `CAP` | parameter | The most ever minted through the covenant, in atoms of the asset |
| `MINTED` | state | The total minted through the covenant so far |

Both paths re-create the coin at output 0: the same program, the same `ASSET`,
`TOKEN` and `CAP`, the token's whole amount, explicitly and with no nonce. The
coin must be input 0 of its transaction, so two coins of one instance can
never share a successor. A coin holds the token explicitly; a confidential
coin at the address cannot be spent by any path, and a successor whose amount
or asset is confidential is refused.

A mint's amount is the issuance amount on the covenant's own input, which must
be explicit: the covenant counts what it reads there. The minted units may go
to any output the operator signs for; the count is of the issuance, not of
where it lands.

A rekey moves the coin to the same template under other keys, so the coin's
instance changes with it: an instance is its parameters, and the keys are
parameters. The count and the cap travel unchanged.

## What the cap holds, and what the keys can still do

The count only grows, the cap is fixed, and every path re-creates the coin
with the whole token. So, whichever key is stolen, at most `CAP` is ever
minted through the covenant, counted from the instance the token was moved
into.

| A key held by | Can | Cannot |
|---|---|---|
| The operator | Mint up to the room left, `CAP − MINTED`, into any output it signs for, at once | Mint past the cap, move the token, change the keys |
| The cold key | Replace both keys, the operator's and its own, and through a new operator key mint the room left | Raise the cap, reset the count, take the token out |

The asset's maximum supply is therefore what was issued before the token moved
in, plus `CAP`. The cap bounds issuance through the covenant and nothing else:
it does not bound where minted units go, which the operator decides, nor any
rule the asset's issuer enforces elsewhere.

## Recovery: a rekey, with no brake and no delay

A lost operator key would otherwise end issuance for good, so the cold key
can replace it. The mint limiter (`docs/mint-limiter.md`) answers the same
question with two phases, a brake applied by a signature made in advance and a
recovery after a long delay, because its recovery hands the token to the cold
key outright: the delay is the time to notice a stolen cold key before it
takes everything.

The supply cap needs neither. Its rekey cannot release the token or touch the
count, so a stolen cold key gains exactly what a stolen operator key gains,
the room left under the cap, which the cap already bounds. A delay would only
hold back the honest rekey that replaces a stolen operator key, and the thief
of an operator key mints the room left in one transaction anyway. A rekey is
therefore immediate, signed by the cold key over the whole transaction.

An instance whose keys are both the NUMS point (the template's internal key,
`50929b74…3ac0`, which no one can sign for) is retired: no mint and no rekey is
possible again, and the asset's supply is final. A rekey to that point is how
an issuer closes issuance.

The two keys of an instance must differ, or the cold key could not replace a
lost operator key; `tools/token-covenants` refuses an instance or a rekey that
names one key twice, other than the retirement.

## What each signature authorises

| Signature | Over | It authorises |
|---|---|---|
| Operator, mint | `sig_all_hash` | That transaction: its coin, its every input and output, this leaf, this chain |
| Cold key, rekey | `sig_all_hash` | That transaction |

`sig_all_hash` names the input it signs, the leaf it runs and the chain's
genesis, so neither signature applies to another coin, another instance or
another chain. It covers every input's issuance except Sequentia's
denomination byte, which is not in the Simplicity environment; a mint always
spends a fee coin from a wallet whose own signature covers the whole issuance,
so nobody can alter that byte, and with it the transaction's id, in flight.

## Moving a token in

A token moves into the supply cap by an ordinary transfer of its whole amount
to the instance's address with `MINTED` at zero. The covenant cannot see its
own creation, so check it: the coin must carry every unit of the token the
asset's issuance created. A second coin holding part of the token at the same
address would count its own mints separately, and each coin's count would be
held to the cap on its own. The best move-in is the issuance itself, paying
the token straight to the instance in the transaction that creates it, which
anyone can check from that one transaction.

## Measured

`harness/tests/u1_supply_cap.py` (record `harness/records/u1.json`) runs every
path on regtest and forces 28 violations into blocks, each refused for its
reason against a control the node accepts. Each spend below has the covenant
at input 0 and one wallet coin paying the fee in an issued asset.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Mint | 765 vB | 935 B | 209 B | 525 WU | 5,042 WU |
| Rekey | 610 vB | 817 B | 273 B | 495 WU | 4,834 WU |
| Retire (a rekey to the NUMS point) | 601 vB | 816 B | 241 B | 495 WU | 4,694 WU |

No spend needs padding. `harness/tests/u2_supply_cap_tool.py` builds every
path with `tools/token-covenants` and mines it at the same sizes.

## Building spends

`tools/token-covenants` builds and signs every path (`supply-cap build`) and
reads back what a spend did (`supply-cap follow`). It reaches no node and holds
no credential: the service reads the chain and its wallet, hands the tool the
coins, has its wallet sign the fee coin and broadcasts. Its `README.md` gives
the commands and the request format.
