# token-covenants

Builds and signs spends of the covenants that hold an asset's reissuance
token, for the services that mint through them: the supply cap,
`sequentia/supply-cap` (`templates/supply_cap`, described in
`docs/supply-cap.md`), which lets an operator mint only while the total minted
through it stays at or under a cap fixed when it is made.

The tool reaches no node and holds no credential. The service that uses it
reads the chain and its own wallet, hands the tool the coins as the
transactions that made them, has its wallet sign the fee coins
(`signrawtransactionwithwallet`) and broadcasts. The covenant's signature
covers every input and output, so the wallet's signatures, added after, change
nothing it signed, and the transaction id `build` returns is the one the chain
will show. A spend the covenant would refuse is never returned: the program is
run and pruned against the final transaction first, and its cost is checked
against the budget its witness earns.

## Build

```sh
cargo build --release --manifest-path tools/token-covenants/Cargo.toml
```

or install it from a commit, with no checkout:

```sh
cargo install --locked --git https://github.com/ConcatenaLabs/sequentia-contracts --rev COMMIT token-covenants
```

The templates and the helper their sources include are built into the binary,
so the tool reads no file of the checkout it was built from. Each run compiles
the template with the pinned compiler and checks it against its descriptor.
`--template DIR` reads a directory's copy instead, and the tool refuses any
template but the one it pins.

## Commands

Each prints one JSON object on success; on failure it prints the reason on
stderr and exits 1. Amounts of atoms are decimal strings, as the tool writes
them back, because a JSON number above 2^53 is not read exactly by every
reader; a JSON number is accepted only up to 2^53.

### Keys

```text
token-covenants key [--new] (--mnemonic-file F | --key-file F)
```

A covenant key is either the contract key (`m/8383h/1h/0h/0/0`) of a
twelve-word mnemonic, or a raw secret key: 64 hex characters in a file, for a
service that keeps its key in a file of its own. Without `--new` the command
prints the key's x-only public key. With `--new` it makes one from the
operating system's randomness and writes it once to a new file readable by its
owner alone, never over an existing file; `key --new` with no file prints a
new mnemonic once instead, for writing down offline. A cold key's mnemonic
never lives on the service's host.

### The supply cap

```text
token-covenants supply-cap instance --asset A --token T --entropy E --operator-key K \
    --cold-key K --cap ATOMS --genesis HASH
```

An instance: the asset, its reissuance token and its issuance entropy as an
RPC prints them, the two keys, the cap in atoms of the asset and the chain's
genesis hash. The token must be the asset's explicit reissuance token and the
two keys must differ. The output is the instance file (its `address` field is
for convenience) with nothing minted, which is where the token moves in.

```text
token-covenants supply-cap address --instance I [--minted ATOMS]
```

The address of the instance holding a count.

```text
token-covenants supply-cap build --instance I (--mnemonic-file F | --key-file F) < request.json
```

A spend, from a request:

```json
{
  "path": "mint",
  "coin": {"tx": "<hex of the transaction that made the covenant coin>", "vout": 0},
  "minted": "0",
  "entropy": "<the asset's issuance entropy>",
  "amount": "100000000",
  "mint_to": "<scriptPubKey hex that receives the minted units>",
  "fee": {"coins": [{"tx": "<hex>", "vout": 1}], "atoms": "300", "change_to": "<scriptPubKey hex>"}
}
```

| `path` | Takes | Signed by |
|---|---|---|
| `mint` | `entropy`, `amount`, `mint_to` | the operator key |
| `rekey` | `new_operator_key`, `new_cold_key` | the cold key |

The fee coins are explicit wallet coins of one asset, which pays the fee;
`atoms` is the fee in that asset's atoms and the rest returns to `change_to`.
No asset is assumed. The reply holds the transaction (`hex`, with the fee
coins still to sign), its `txid`, the count before and after
(`minted`, `next_minted`), the `successor` coin (`txid`, vout 0, its address),
for a rekey the `next_instance` file, the weight before the wallet's
signatures, and the program's size, cost bound and budget. A spend the
covenant would refuse is refused here first, with the reason: a count over the
cap, a key that is not the path's, a coin that is not the instance holding the
count given, a rekey naming one key twice.

```text
token-covenants supply-cap follow --instance I < request.json
```

What a transaction that spent the covenant coin did to it, from
`{"coin": {...}, "minted": "...", "tx": "<hex of the spending transaction>"}`:
for a mint, the amount and the next count and successor; for a rekey, the
successor's script, and with `new_operator_key` and `new_cold_key` in the
request, checked against them, the `next_instance`.

## Tests

`cargo test --release --manifest-path tools/token-covenants/Cargo.toml` runs
the unit tests. `harness/run.py u2` runs the tool against a regtest node: every
path is built, signed by the wallet, mined, and read back with `follow`.
