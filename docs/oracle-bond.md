# The oracle bond

`templates/oracle_bond` holds coins an oracle puts behind its price
attestations. Its key can take them back only after giving notice and waiting
it out, and anyone who shows two of its attestations of one pair, at one
precision and one time, with different prices, slashes them at once: at least
half is burned and the rest goes to whoever presented the pair. The descriptor
is the template; this page says what the program enforces, why, and what a
bond can and cannot tell a user about an oracle.

Attestations are format 2, defined in
[`sequentia-oracle`](https://github.com/ConcatenaLabs/sequentia-oracle)
(`doc/format.md`). The program rebuilds each message with
`helpers/attestation.simf` and checks its BIP340 signature.

## The output

```text
P2TR(NUMS, TapBranch(TapLeaf_0xbe(bond program), H_TapData(ORACLE || BOND_ASSET || NOTICE || STATE)))
```

There is no key path. Every value is at its width, big-endian.

| Value | Type | What |
|---|---|---|
| `ORACLE` | key | The key whose format-2 attestations the bond stands behind |
| `BOND_ASSET` | asset id | The asset the bond is held in, in internal byte order. Any asset can bond an oracle; a coin of another asset at the address can be spent by no path |
| `NOTICE` | sequence | The notice, a BIP68 relative lock written as its `nSequence` value: the type flag (bit 22) and a count of 512-second units. It must be a time; a count of blocks leaves the withdrawal unusable, and the tools refuse one |
| `STATE` | slot | `0` while bonded, `1` once notice is given. The two states are two addresses |

Every coin at the address is a bond on its own. Topping a bond up is paying
another coin there, and a reader sums the coins at both addresses. The coin at
input `k` owns output `2k`, so two bond coins spent in one transaction never
share an output.

## The paths

| Path | Who | What it requires |
|---|---|---|
| `notice` | the oracle key | `STATE` is 0. Output `2k` is this bond with `STATE` 1, holding at least the whole coin in `BOND_ASSET`, explicitly. The key signs the notice digest of this coin |
| `withdraw` | the oracle key | `STATE` is 1, and the coin has waited `NOTICE` by its own sequence (version 2 or later, the sequence a time of at least `NOTICE`). Output `2k` pays the script whose SHA-256 is `DEST` at least the whole coin in `BOND_ASSET`, explicitly. The key signs the withdrawal digest of this coin and `DEST` |
| `slash` | anyone | In either state, two format-2 attestations by `ORACLE` of one base, quote, precision and time, at two different prices, each under a valid signature. Output `2k` burns at least half the coin, rounded up, in `BOND_ASSET` to the script `OP_RETURN` (`6a`), explicitly. Everything else in the transaction is the presenter's |

### What the key signs for its bond

```text
notice    = tagged("Sequentia/oracle/bond", 0x01 || genesis || txid || vout)
withdraw  = tagged("Sequentia/oracle/bond", 0x02 || genesis || txid || vout || DEST)
```

`genesis` is the chain's genesis block hash and `txid` the coin's
transaction id, both in internal byte order; `vout` is four bytes,
big-endian; `DEST` is the SHA-256 of the destination's scriptPubKey. Each
signature therefore moves one coin, on one chain, to the one place the
program or the signature names:

- **Another coin**, a top-up beside it, or the same output on another chain:
  another digest.
- **Another destination**: the withdrawal digest holds `DEST`, and the
  program pays exactly the `DEST` it hashed.
- **A notice as a withdrawal, or the reverse**: the kind byte differs.
- **A price**: an attestation digest is tagged `Sequentia/oracle/price`, a
  beacon rotation `Sequentia/oracle/beacon`; the tags differ, so no
  attestation is a notice and no notice is an attestation.

Neither signature binds the transaction around the coin, so anyone holding
one can submit it; the fee comes from another input. It can only do what the
key signed.

### The conflict

Two signed messages `m1`, `m2` are a conflict for a bond of `ORACLE` when, in
this order of checks:

1. both are 142 bytes,
2. of version 2,
3. name `ORACLE` as their key,
4. carry valid signatures by it,
5. name one base and one quote,
6. one precision,
7. one time,
8. and two prices.

The beacons are not compared. An honest signer that rotates its beacon signs
the newest observation again under the new beacon at the same price, which is
no conflict; two prices are a conflict whatever the beacons say.

`crate::bond::conflict` (Rust), `oracle_bond_conflict` (Python),
`oracleBondConflict` (JavaScript) and `OracleBondConflict` (Go) apply the rule
and name the first check that fails. `rules.json` holds a case for each, the
digests and the burn, and all four reproduce them; harness test `b1` refuses
in a block every non-conflict it can express and mines the conflicts.

## Why half is burned

The oracle can present its own conflict. Whatever a slash pays out, the
oracle could take back itself by racing anyone who found the pair, so the
burned half is the least a conflict costs it, and the paid half is what
pays a third party to watch. Burning all of it would leave a watcher nothing
for its fee and its work; paying all of it out would let a conflicting oracle
lose nothing by presenting the pair itself, and would turn a slash into a
withdrawal that needs no notice.

A slash in the mempool shows the pair, so anyone, a block producer included,
can copy it and redirect the presenter's half. The burn happens whoever
submits it.

## What a bond deters, and what it does not

A bond turns one kind of misbehaviour into a loss: **two prices for one pair,
precision and time**. That is what an oracle does when it publishes one price
and hands a contract another for the same observation, and every attestation
it signs is meant to be on its public log, so a watcher that compares the log
with what contracts settle on finds the pair.

It does not deter:

- **A single consistent lie.** A false price that is the only attestation for
  its time conflicts with nothing. Neither does a false price published on
  the log as the oracle's only word.
- **A lie at a time the oracle published nothing for.** A contract cannot
  tell which times an oracle should have signed, so an attestation at a fresh
  time has no counterpart to conflict with. A public log makes such an
  attestation visible as off the record, but no script can prove an absence.
- **A lie at another precision or for another pair.** Prices at two
  precisions are two feeds, since an honest signer rounds differently at
  each.
- **Format 1.** Its 48-byte message cannot be checked by a Simplicity
  signature jet, so a format-1 conflict cannot be slashed.
- **More than the bond.** A conflict that earns more than the burned half is
  still worth making.

Two things follow for the oracle that holds a bond. One key belongs to one
signer: two signers sharing a key sign two prices for one observation the
first time their feeds disagree, and a unit pair (BTC in USD) is the same fact
on every chain, so one key signing it on two chains is one key. And a stolen
key costs the bond at once: the thief can present a conflict of its own and
take half.

A bond with notice given (`STATE` 1) is still slashable until the coin is
withdrawn, so attestations signed during the notice are still covered. A
reader shows a coin in notice as leaving, and the earliest time it can be
withdrawn: its confirmation's median time plus `NOTICE`.

## Measured

On a regtest chain with Simplicity active, from `harness/records/b1.json`:

| Spend | vsize | program bytes | witness bytes | cost bound | budget |
|---|---:|---:|---:|---:|---:|
| `slash`, one coin, fee from the bond | 598 | 1,101 | 347 | 749 WU | 6,266 WU |
| `slash`, two coins in one transaction | 1,140 | 1,101 each | 347 each | 749 WU each | 6,266 WU each |
| `notice`, with a wallet fee input | 598 | 909 | 134 | 433 WU | 4,638 WU |
| `withdraw`, with a wallet fee input | 608 | 964 | 166 | 294 WU | 4,986 WU |

The program's cost bound with every branch kept is 749 weight units, the
slash's: two signature checks over four SHA-256 blocks each.
