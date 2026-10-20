# mint-limiter

Builds and signs spends of the `sequentia/mint-limiter` covenant
(`templates/mint_limiter`, described in `docs/mint-limiter.md`): the output
that holds an asset's reissuance token and lets an operator mint at most an
allowance per window of blocks.

The tool reaches no node and holds no credential. The program that uses it, a
bridge, reads the chain and its own wallet, hands the tool the coins as the
transactions that made them, has its wallet sign the fee coins
(`signrawtransactionwithwallet`) and broadcasts. The covenant's signature
covers every input and output, so the wallet's signatures, added after, change
nothing it signed, and the transaction id `build` returns is the one the chain
will show. A spend the covenant would refuse is never returned: the program is
run and pruned against the final transaction first, and its cost is checked
against the budget its witness earns.

## Build

```sh
cargo build --release --manifest-path tools/mint-limiter/Cargo.toml
```

or install it from a commit, with no checkout:

```sh
cargo install --locked --git https://github.com/ConcatenaLabs/sequentia-contracts --rev COMMIT mint-limiter
```

The template (`templates/mint_limiter` and the helper its source includes) is
built into the binary, so the tool reads no file of the checkout it was built
from, which may be moved or deleted. Each run compiles the template with the
pinned compiler and checks it against its descriptor. `--template DIR` reads a
directory's copy instead, and the tool refuses any template but the one it
pins.

## Commands

Each prints one JSON object on success; on failure it prints the reason on
stderr and exits 1.

```text
mint-limiter key [--new] --mnemonic-file F
```

The contract key (`m/8383h/1h/0h/0/0`) of a twelve-word mnemonic. With
`--new`, a new mnemonic from the operating system's randomness, written once to
a new file readable by its owner alone, never over an existing file; without
`--mnemonic-file` it is printed once instead, for writing down offline. The
operator's mnemonic lives on the bridge's host; the cold key's never does.

```text
mint-limiter instance --asset A --token T --entropy E --operator-key K --cold-key K \
    --window BLOCKS --allowance ATOMS --recovery-delay UNITS --genesis HASH
```

An instance: the asset, its reissuance token and its issuance entropy as an RPC
prints them, the two keys, the window in blocks, the allowance in atoms, the
recovery delay in units of 512 seconds and the chain's genesis hash. The token
must be the asset's explicit reissuance token, the two keys must differ, the
window must be at least two blocks and the delay at least one unit. The output
is the instance file (drop its `address` field, which is printed for
convenience) and the address of the instance with nothing minted, which is
where the token moves in.

```text
mint-limiter address --instance I [--state MINTED,ELAPSED,ARMED]
mint-limiter arm-signature --instance I --mnemonic-file COLD
```

The address of the instance in a state, and the brake: the cold key's signature
over the instance's arm message, which names no coin, so it is made once and
applies to whichever coin is current. Keep it where the brake should be pulled
from (the bridge's watcher), apart from the operator's mnemonic.

```text
mint-limiter build --instance I [--mnemonic-file F] < request.json
```

A spend, from a request:

```json
{
  "path": "mint",
  "coin": {"tx": "<hex of the transaction that made the covenant coin>", "vout": 0},
  "state": {"minted": "0", "elapsed": 0, "armed": 0},
  "entropy": "<the asset's issuance entropy>",
  "age": 2,
  "amount": "100000000",
  "mint_to": "<scriptPubKey hex that receives the minted units>",
  "fee": {"coins": [{"tx": "<hex>", "vout": 1}], "atoms": "300", "change_to": "<scriptPubKey hex>"}
}
```

Amounts of atoms (`amount`, `fee.atoms`, the state's `minted`) are decimal
strings, as the tool writes them back, because a JSON number above 2^53 is not
read exactly by every reader; a JSON number is accepted only up to 2^53.

| `path` | Takes | Signed by |
|---|---|---|
| `mint` | `entropy`, `age` (the coin's age as the next block finds it, at least 2), `amount`, `mint_to` | the operator's mnemonic |
| `arm` | `arm_signature` | no mnemonic: the signature made in advance |
| `disarm` | | the cold key's mnemonic |
| `recover` | `recover_to`, the scriptPubKey the token goes to | the cold key's mnemonic |

The fee coins are wallet coins of one asset, which pays the fee; `atoms` is the
fee in that asset's atoms and the rest returns to `change_to`. The reply holds
the transaction (`hex`, with the fee coins still to sign), its `txid`, the
`next_state` and the `successor` coin (`txid`, vout 0, its address), the
weight before the wallet's signatures, and the program's size, cost bound and
budget. A mint the covenant would refuse is refused here first, with the
reason: a count over the allowance, a coin younger than two blocks, the brake
on, a mnemonic that is not the path's key, or a coin that is not the instance
in the state given.

```text
mint-limiter follow --instance I < request.json
```

What a transaction that spent the covenant coin did to it, from
`{"coin": {...}, "state": {...}, "tx": "<hex of the spending transaction>"}`:
the path, the next state and the successor, or for a recovery where the token
went. A bridge or its watcher uses it to follow the coin through spends it did
not make, such as the brake.

## Tests

`cargo test --release --manifest-path tools/mint-limiter/Cargo.toml` runs the
unit tests. `harness/run.py m2` runs the tool against a regtest node: every
path is built, signed by the wallet, mined, and read back with `follow`.
