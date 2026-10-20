# The verifier token

`templates/verifier_token` is a covenant that holds the reissuance token of an
[OpenDAMP](https://github.com/ConcatenaLabs/opendamp) asset's verifier asset.

An OpenDAMP asset A lives in user covenants, and every transfer of it spends
the asset's verifier covenant `C_V(pi)` at input 0, which enforces the policy
`pi`. A user covenant can only check that input 0 holds the verifier amount
`q` of the verifier asset V, not that input 0 is a verifier covenant, so
OpenDAMP's confinement rests on one invariant no covenant of the asset can
check: `q` of V never exists outside a verifier covenant. Whoever holds `q` of
V at an ordinary address can let any holder spend with no policy at all.

A halt burns V. V's reissuance token is what resumes the asset afterwards, by
minting V again, and held in a wallet it can just as well mint V to any
address: as sensitive as the issuer key itself. Held in this covenant, the
token mints V only in the verifier amount and only into a script the chain has
already shown holding the verifier amount.

| Path | Who | What it does |
|---|---|---|
| `record` | the issuer key | In a transaction that spends a coin holding exactly `q` of V at input 0, such as the halt that burns it, records that coin's script |
| `resume` | the issuer key | Reissues exactly `q` of V, into the script last recorded, and nothing else |

## Why the covenant records instead of recognising

A verifier covenant's address is not one formula of the policy: `pi` is a
compile-time parameter of OpenDAMP's verifier programs, so each policy is a
different program with a different commitment root, and recomputing that root
from `pi` inside a covenant would mean re-deriving the whole compiled program.
What the covenant can check cheaply is a coin: input 0 holding exactly `q` of
V, explicitly. By the invariant, that coin is a verifier covenant, so its
script is one V may go back to. The token covenant keeps that script's
SHA-256 as its state, `VERIFIER`, and a resume pays only to it.

So the token never creates a new place for V to live. By induction from an
honest issuance, every script it can mint into is one that held the verifier
amount on chain, which every resume and every record re-establishes.

## The output

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(token), H_TapData(params ‖ state)))
```

| Value | Kind | Meaning |
|---|---|---|
| `VERIFIER_ASSET` | parameter | V, the asset the token reissues |
| `TOKEN` | parameter | V's reissuance token, the coin's own asset |
| `AMOUNT` | parameter | `q`, the amount of V a verifier covenant holds |
| `ISSUER_KEY` | parameter | The asset's issuer update key `I`, which signs every spend |
| `VERIFIER` | state | SHA-256 of the scriptPubKey a resume mints into |

Every path re-creates the coin at the output whose index is the coin's own
input index: the same program, the same parameters, the token's whole amount,
explicitly and with no nonce.

**Resume.** The coin is input 0 and reissues exactly `AMOUNT` of V on its own
input, explicitly. The successor is output 0, with `VERIFIER` unchanged.
Output 1 pays exactly `AMOUNT` of V, explicitly and with no nonce, to the
script `VERIFIER` names. The transaction has at most six outputs, every one
of them with an explicit asset, and none but output 1 carries V: no fee in V,
no second output of V beside the verifier's, and nothing confidential that
could hide one. Signed by `ISSUER_KEY` over the whole transaction.

**Record.** The coin is input 1, with no issuance on it. Input 0 holds
exactly `AMOUNT` of V, explicitly. The successor is output 1, with `VERIFIER`
set to the SHA-256 of input 0's script. Signed by `ISSUER_KEY` over the whole
transaction. Input 0 is spent by its own covenant's rules alongside: in a halt,
by the verifier's issuer path burning V.

## How OpenDAMP uses it

- **Issuance.** The issuance that locks `q` of V into the genesis verifier
  `C_V(pi_0)` pays V's token, in the same transaction, to this covenant with
  `VERIFIER` naming `C_V(pi_0)`. Anyone checks the move-in from that one
  transaction: the token coin carries every unit of the token the issuance
  created, and records the verifier the issuance funded.
- **Halt.** The halt burns V from the current verifier `C_V(pi)` at input 0
  and records `C_V(pi)` with the token covenant at input 1, in one
  transaction.
- **Resume.** The resume mints `q` of V back into `C_V(pi)`: the asset resumes
  under the policy it was halted at. Moving to another policy is then an
  ordinary update through the issuer path.

A resume restores the verifier last recorded. A halt made without the token
covenant beside it leaves the record where it was, and a resume then restores
that older policy, which the issuer moves on from with an update; OpenDAMP's
halt always records. An update may record too, in which case it records the
verifier it leaves.

A resume while a verifier coin is still live at the recorded script makes a
second, parallel verifier under the same policy. OpenDAMP's design allows
parallel verifiers, and each one enforces the policy; but a halt then has to
burn every one of them, so the issuer resumes only a halted asset unless it
means to run them in parallel.

## What the covenant stops, and what the issuer key can still do

| Holder | Can | Cannot |
|---|---|---|
| A wallet or server that held the token before | Nothing: the token has left it | Mint V anywhere |
| The issuer key `I`, through this covenant | Record a coin holding `q` of V; mint `q` of V into the recorded script | Mint V in another amount, into another script, beside another output of V, or confidentially |
| The issuer key `I`, through the verifier's own issuer path | Everything that path allows: update the policy, halt, or send a verifier's V to any script it signs for | (unchanged by this covenant) |

The covenant takes V's minting out of every wallet and binds it to the issuer
key and to scripts that held the verifier amount. It does not narrow the
issuer key's power over a live verifier, which OpenDAMP's issuer path gives
it: a stolen issuer key can already move a verifier's V to an ordinary
address, and after that, record it there. The issuer key is the asset's root
of trust, a FROST group key in production, and the token is now no more
sensitive than it.

## What each signature authorises

| Signature | Over | It authorises |
|---|---|---|
| Issuer key, resume | `sig_all_hash` | That transaction: its coin, its every input and output, this leaf, this chain |
| Issuer key, record | `sig_all_hash` | That transaction, including the verifier coin at input 0 and what becomes of it |

`sig_all_hash` names the input it signs, so the issuer key's signature on the
token covenant and its signature on the verifier's issuer path in the same
halt are signatures over different messages; neither stands in for the other.
It covers every input's issuance except Sequentia's denomination byte, which
is not in the Simplicity environment; a resume always spends a fee coin whose
wallet signature covers the whole issuance.

## Measured

`harness/tests/v1_verifier_token.py` (record `harness/records/v1.json`) runs
an issuance's move-in, an update, a halt that records and a resume, with two
stand-ins for the verifier covenant: the one-key program OpenDAMP's issuer path
is, under two data leaves. It forces 23 violations into blocks, each refused
for its reason against a control the node accepts: V resumed to the old
verifier or an ordinary address, one atom more or less, twice the amount with
half elsewhere, beside another output of V or a fee in V, by another key,
seven outputs, a confidential output, a nonce on the verifier output, the
successor changing the record or sending the token elsewhere, no reissuance,
the coin at input 1; and a record by another key, of a coin one atom short or
of another asset, keeping the old record or recording another script, sending
the token elsewhere, minting at once, or with the coin at input 2.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Halt that records (the verifier's issuer path at input 0, the record at input 1, a fee coin) | 743 vB | 864 B | 201 B | 462 WU | 4,726 WU |
| Resume | 792 vB | 1,003 B | 201 B | 528 WU | 5,282 WU |

No spend needs padding. `harness/tests/v2_verifier_token_tool.py` signs the
record into a halt and builds the resume with `tools/token-covenants`, and
mines both.

## Building spends

`tools/token-covenants verifier-token` makes an instance, builds a resume
(`build`), signs the record into a transaction the issuer's tooling laid out
(`record`), and reads back what a spend did (`follow`). Its `README.md` gives
the requests.
