# The mint limiter

`templates/mint_limiter` is a covenant that holds an asset's reissuance token.
Whoever holds a reissuance token can mint any amount of its asset, so a bridge
that keeps the token in its hot wallet trusts that wallet's key with the whole
supply. The limiter takes the token out of the wallet: the operator's hot key
can mint at most an allowance per window of blocks, and a cold key can stop it.

| Path | Who | What it does |
|---|---|---|
| `mint` | the operator key | Reissues the asset on the covenant's input and re-creates the covenant with the window's count raised by the amount. Refused above the allowance |
| `arm` | anyone holding the cold key's arm signature | Applies the brake: no mint is possible until it is lifted |
| `disarm` | the cold key | Lifts the brake |
| `recover` | the cold key | Takes the token anywhere, once the brake has held for the recovery delay |

Burning the asset is unaffected: units are burned from whichever wallet holds
them, and the covenant never sees it. A burn does not give room back in the
window, since the count is of what was minted.

## The output

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(limiter), H_TapData(params ‖ state)))
```

One Simplicity leaf and one data leaf. The data leaf holds the parameters,
fixed for the instance, and the state, which changes with every spend, so each
state of an instance has its own address:

| Value | Kind | Meaning |
|---|---|---|
| `ASSET` | parameter | The asset the token reissues |
| `TOKEN` | parameter | The reissuance token, the coin's own asset |
| `OPERATOR_KEY` | parameter | Signs mints |
| `COLD_KEY` | parameter | Signs the arm message, the disarm and the recovery |
| `WINDOW` | parameter | The window, in blocks |
| `ALLOWANCE` | parameter | The most minted in one window, in atoms of the asset |
| `RECOVERY_DELAY` | parameter | How long the brake holds before a recovery, in units of 512 seconds |
| `MINTED` | state | The amount minted in the current window |
| `ELAPSED` | state | Blocks of the current window behind this coin |
| `ARMED` | state | 1 while the brake is on, else 0 |

Every path but the recovery re-creates the coin at output 0: the same program,
the same parameters, the next state, the token's whole amount, explicitly and
with no nonce. The coin must be input 0 of its transaction, so two coins of one
instance can never share a successor. A coin holds the token explicitly; a
confidential coin at the address cannot be spent by any path.

## The window

A mint declares its coin's age in blocks as a relative lock on its own input,
which consensus enforces (BIP68: transaction version 2 or more, the disable bit
clear). The age is added to `ELAPSED`. Once `ELAPSED` and the age reach
`WINDOW`, that mint opens a new window: `MINTED` restarts from its own amount
and `ELAPSED` from zero. Otherwise `MINTED` grows by the amount. `MINTED` may
never exceed `ALLOWANCE`, and no other path changes `MINTED` or `ELAPSED`.

So the window's start is the coin's height less `ELAPSED`, and every block of a
window has been vouched for by the chain once. A start stored as a number
would be the spender's claim: a claimed start far in the past, after a quiet
period, would let several windows open in succession at once, each with a full
allowance. A coin's age cannot be claimed twice, because each mint spends the
coin it was measured on.

What this gives:

- at most `ALLOWANCE` is minted in one window, and windows are at least
  `WINDOW` blocks apart, so at most twice `ALLOWANCE` in any `WINDOW`
  consecutive blocks (the end of one window and the start of the next). That
  is the same bound the Ethereum vault's token bucket gives over its refill
  period, a full bucket and its refill;
- a declared age is a lower bound: a mint that is mined later than planned
  loses the difference, which only delays the next window. It never brings it
  forward.

The window is counted in blocks rather than in median time past. A relative lock
in time counts in units of 512 seconds, and each mint's age would be rounded
down to whole units: a bridge minting every few minutes would declare ages of
zero and its window would never end. Block heights count exactly. On the
testnet and on the mainnet parameters the chain cannot outrun the clock:
consensus spaces blocks at least 60 seconds apart by their timestamps
(`pos_block_spacing`), and no timestamp may run more than two hours ahead, so
`WINDOW` blocks span at least `WINDOW × 60` seconds less those two hours. A
stall stretches a window, which only slows minting. Bitcoin anchoring is
unaffected: the covenant's state lives in its coin, so when an anchor reorg
replaces blocks, the mints in them go with them and the replacing chain's own
mints are counted on it. A fork that shortened the block spacing would shorten
every window in time; such an instance should then be recovered into one with
a longer `WINDOW`.

`WINDOW` is at most 65,535 blocks, the largest relative lock. A mint spends a
coin at least two blocks old (see the brake).

## The brake and the recovery

The cold key signs one message, which names the chain (its genesis hash), this
program's leaf and the instance's parameters, and no coin and no state:

```text
SHA256(T ‖ T ‖ genesis ‖ leaf hash ‖ ASSET ‖ TOKEN ‖ OPERATOR_KEY ‖ COLD_KEY ‖ WINDOW ‖ ALLOWANCE ‖ RECOVERY_DELAY)
T = SHA256("sequentia/mint-limiter/arm")
```

with each value as the data leaf holds it. The signature is made once, offline,
and applies to whichever coin of the instance is current. Anyone holding it
can apply the brake, paying the fee from a coin of their own: the arm path
re-creates the covenant with `ARMED` set and refuses an issuance on its input.
A watcher can hold it and pull the brake the moment something looks wrong,
without the cold key being online. A leaked arm signature lets its holder stop
minting, and nothing more; the cold key then lifts the brake each time, or
recovers the token into a new instance with a new signature.

Because a mint spends a coin at least two blocks old, after any mint there is a
block in which only the brake can spend the new coin. A thief holding the
operator key can mint at most once more after the brake is broadcast, within
the allowance: the next block takes the brake.

The recovery spends the token into any transaction the cold key signs, once the
brake has held for `RECOVERY_DELAY`, by the braked coin's own sequence. Only the
cold key can spend a braked coin, so nothing can restart the delay but the cold
key itself. A recovery moves the token to a new instance (a new operator key,
other limits) or to a key.

A stolen cold key can brake and, after the delay, take the token. The delay is
the time to notice: the holder of the real cold key lifts the brake, which
restarts the thief's delay, and the bridge's other halves (the Ethereum vault's
guardian, the bridge's own halts) stop paying out against new supply.

## What each signature authorises

| Signature | Over | It authorises |
|---|---|---|
| Operator, mint | `sig_all_hash` | That transaction: its coin, its every input and output, this leaf, this chain |
| Cold key, arm | the arm message | The brake on any coin of this instance on this chain, and nothing else. Not a disarm or a recovery, which check a signature over the transaction |
| Cold key, disarm and recover | `sig_all_hash` | That transaction |

`sig_all_hash` covers every input's issuance except Sequentia's denomination
byte, which is not in the Simplicity environment. A mint transaction always
spends a fee coin from the operator's wallet, whose own signature covers the
whole issuance, so nobody can alter the denomination byte, and with it the
transaction's id, in flight.

The operator key and the cold key must differ: the operator could otherwise
lift its own brake. `tools/mint-limiter` refuses such an instance.

## Why there is no tapscript twin

The limiter is Simplicity only. A tapscript leaf on Sequentia could carry the
same state in principle: it can rebuild its own output key from the state with
`OP_SHA256` and `OP_CAT` and check it against `OP_INSPECTINPUTSCRIPTPUBKEY`
with `OP_TWEAKVERIFY`, do the same for the successor at output 0, read the
reissuance with `OP_INSPECTINPUTISSUANCE` and check a declared age with
`OP_CHECKSEQUENCEVERIFY`. Three things make it a large, fragile script with
nothing gained over the Simplicity leaf:

- a taproot branch hashes its two children in byte order, and tapscript has
  no comparison of 32-byte strings, so every spend would prove the order of
  the state's leaf against the code's leaf from a witness hint, byte by byte
  with `OP_SUBSTR`, for the coin and again for its successor;
- the descriptor's values are big-endian and Elements' 64-bit arithmetic is
  little-endian, so the count and the allowance would be reversed byte by
  byte in script on every spend;
- the brake's message names the chain, and no opcode reads the genesis hash,
  so the twin's message would bind the chain only through a parameter.

The plan's measurement of state carried across a spend found the same: not
practical in tapscript, 448 vB with a 363-byte program in Simplicity. The
limiter's Simplicity leaf is 857 to 867 vB a mint, well inside its budget.

## Measured

`harness/tests/m1_mint_limiter.py` (record `harness/records/m1.json`) runs
every path on regtest and forces 47 violations into blocks, each refused for
its reason against a control the node accepts. Each spend below has the
covenant at input 0 and one wallet coin paying the fee in an issued asset.

| Spend | vsize | Program | Witness | Cost bound | Budget |
|---|---|---|---|---|---|
| Mint within a window | 867 vB | 1,339 B | 216 B | 797 WU | 6,686 WU |
| Mint opening a window | 857 vB | 1,296 B | 216 B | 792 WU | 6,514 WU |
| Arm | 719 vB | 1,310 B | 216 B | 959 WU | 6,570 WU |
| Disarm | 661 vB | 1,080 B | 216 B | 725 WU | 5,650 WU |
| Recover | 563 vB | 734 B | 216 B | 337 WU | 4,266 WU |

No spend needs padding. `harness/tests/m2_mint_limiter_tool.py` builds each
path with `tools/mint-limiter` and mines it at the same sizes.

## Building spends

`tools/mint-limiter` builds and signs every path. It reaches no node and holds no
credential: a bridge reads the chain and its wallet, hands the tool the coins,
has its wallet sign the fee coin and broadcasts. A program that builds its own
transactions mints into them instead with `sign`: it puts the covenant at
input 0 with the reissuance and the successor at output 0, and the tool checks,
signs and satisfies that input in place. Its `README.md` gives the commands and
the request format.

## Moving a token in

A token moves into the limiter by an ordinary transfer of its whole amount to
the instance's address with `MINTED`, `ELAPSED` and `ARMED` at zero. Before
moving one, check the issuance: the coin must carry every unit of the token the
issuance created, or a coin outside the covenant can still mint. The watcher of
a bridge that mints through the limiter checks the same thing on chain.
