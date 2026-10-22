# sequentia-contracts

The place where Simplicity contracts for [Sequentia](https://github.com/ConcatenaLabs/Sequentia)
are compiled, linted, tested and recorded.

Simplicity is active on Sequentia: a taproot leaf of version `0xbe` holds a
Simplicity program, and the node runs it with the full upstream jet set. A
program's commitment Merkle root, and so its address, depends on the compiler
that built it. This repository therefore pins one compiler, checks that its C
library matches the node's, and refuses the jets that are wrong on this chain,
so that a contract built here behaves on the chain exactly as it did in its
tests.

## What is here

| Path | What |
|---|---|
| `crates/sequentia-contracts/` | The Rust crate. It pins SimplicityHL exactly (see `Cargo.toml`) and re-exports it, together with `simplicity` and `elements`, so no other repository names the compiler itself. It holds the lints and the `seqc` command line |
| `lints/fixtures/` | Programs the lints must refuse (`reject/`) and pass (`accept/`), each with a Simplex project that imports a dependency |
| `parity/` | The parity gate between the Simplicity libraries a project builds with (the C library and the Rust jet table) and the node's |
| `helpers/` | Shared SimplicityHL helpers, included as source: output reader, wide arithmetic at 128 and 192 bits, state, relative lock, Merkle fold and update, fee cap, price attestation, a threshold of price attestations |
| `vectors/` | `attestations.json`, the price-attestation golden vectors of [`sequentia-oracle`](https://github.com/ConcatenaLabs/sequentia-oracle), pinned by `PIN.json`; the crate's `attestation` module reproduces them byte for byte |
| `templates/` | Contract templates: each its programs and, where its tree is a descriptor tree, its descriptor (`descriptor.json`) and its golden vectors (`vectors.json`) |
| `mirrors/` | Address derivation for a descriptor's instance in Python, JavaScript and Go, with no compiler, and in `mirrors/fixtures/` the files every reader is checked against |
| `harness/` | The regtest harness: a Sequentia node with Simplicity active, the tests that run programs on it, and their records |
| `docs/` | `descriptor.md` specifies contract descriptors and golden vectors; `helpers.md` documents the helpers and their measured costs; `pool-split.md` specifies the pool split covenant and how a pool uses and claims it; `mint-limiter.md` describes the mint limiter; `supply-cap.md` specifies the supply cap and states what the cap holds and what its keys can still do; `verifier-token.md` specifies the covenant that holds an OpenDAMP verifier asset's token and states what it stops and what the issuer key can still do; `pignus-vault.md` specifies the Pignus loan vault and offer; `capped-sale.md` specifies the capped sale; `subscription-escrow.md` specifies the subscription escrow; `oracle-bond.md` specifies the oracle bond and states what it deters and what it does not. `seqdex-order.md` specifies the SeqDEX order and how a caller with no compiler builds its spends; `seqdex-guarded-order.md` specifies the order that moves only beside a guard coin at input 0, which is how an asset under OpenDAMP's verifier rests in an order; `arca-order.md` specifies the fill program of an order resting as a leaf in an Arca tree; `arca-accumulator.md` specifies the program of an Arca batch from which one owner leaves in one transaction; `arca-collab.md` specifies the collaborative path of an Arca `vtxo-2` leaf and its checkpoint, and what it binds beyond the tapscript path; `seqdex-pool-and-round.md` specifies the maker's two-sided pool and the round order, the clearing output a round publishes its one price in, and what the clearer signs. Measured results: `harness-sizes.md` compares every harness figure with a run under SimplicityHL 0.4.1; `compiler-roots.md` compares the roots of the programs other repositories ship |
| `tools/pool-claim/` | `pool_claim.py`, which derives a pool split covenant's address from a pool's record and claims, or checks a claim of, the pool's rewards; `twin_script.py`, which wrote the tapscript twin's claim leaf |
| `tools/compiler-roots/` | Compiles a set of programs under SimplicityHL 0.4.1 and the pinned compiler in one binary and compares their roots |
| `tools/mint-limiter/` | Builds and signs spends of the mint limiter for the bridges that mint through it, with no node access and no credential (its `README.md`) |
| `tools/token-covenants/` | Builds and signs spends of the supply cap and the verifier token for the services that mint through them, with no node access and no credential (its `README.md`) |
| `tools/subscription-escrow/` | `escrow_leaves.py`, which wrote the subscription escrow's three tapscript leaves |
| `.github/workflows/ci.yml` | Unit tests, lints, descriptor checks, the three address mirrors and the parity gate on every pull request |

## Using the pinned compiler

Depend on this crate, not on `simplicityhl`:

```toml
[dependencies]
sequentia-contracts = { git = "https://github.com/ConcatenaLabs/sequentia-contracts" }
```

```rust
use sequentia_contracts::{compile, cmr_hex, simplicityhl::Arguments};

let program = compile(source, Arguments::default())?;
println!("{}", cmr_hex(&program));
```

`sequentia_contracts::COMPILER_VERSION` names the version, and a unit test fails
if it ever differs from the one `Cargo.toml` pins.

## Helpers

A program includes a shared helper with a line `// include <name>`, which `seqc`
replaces with `helpers/<name>.simf` before compiling or linting (the compiler's
own imports are still behind an unstable flag). [`docs/helpers.md`](docs/helpers.md)
lists the helpers, what each checks, and what each costs on regtest.

```sh
cargo run --bin seqc -- expand path/to/program.simf   # the source as compiled
```

## Contract descriptors

A descriptor names a contract template so that a wallet, an operator, the
explorer and the registry can each tell what an output is and what spending it
does, by recomputing its script rather than parsing a program.
[`docs/descriptor.md`](docs/descriptor.md) is the specification.

A descriptor describes the output's taproot tree: Simplicity leaves, tapscript
leaves and hidden data leaves, each named, and each way to spend it. A program
takes no compile-time parameter, so its commitment root is one constant, and its
parameters sit in a data leaf beside it; a tapscript leaf is a script with the
parameters put in place. Storage slots, values that change from coin to coin,
sit in data leaves too. An instance's address is then one hash per leaf and one
curve tweak away from its values, which is all the mirrors in `mirrors/` need:

```python
import sequentia_address                  # mirrors/python
d = sequentia_address.loads(open("templates/one_key_exit/descriptor.json").read())
x = sequentia_address.derive(d, {"PK": "<hex>", "EXIT_KEY": "<hex>", "EXIT_DELAY": "00400002"})
x["address"]["sequentia-testnet"], x["leaves"]["exit"]["control_block"]
```

```js
import { parseDescriptor, derive } from './mirrors/js/sequentia-address.mjs';
const descriptor = parseDescriptor(text);
derive(descriptor, { PK: '<hex>', EXIT_KEY: '<hex>', EXIT_DELAY: '00400002' }).address['sequentia-testnet'];
```

```go
import sequentiaaddress "github.com/ConcatenaLabs/sequentia-contracts/mirrors/go"
descriptor, err := sequentiaaddress.ParseDescriptor(raw)
derived, err := sequentiaaddress.DeriveTree(descriptor, params, slots)
```

Each derivation gives every leaf's hash, the control block that spends each
Simplicity and tapscript leaf, each tapscript with its values in place, and the
output key, script and address, so a spend can be built from the descriptor
alone. A descriptor of the single-program layout (`"descriptor": 1`,
`templates/one_key`) is read as the two-leaf tree it is.

Each reader refuses a descriptor with a field the specification does not list or
a field named twice, a number that is not an integer below 2^53, hex that is not
exactly its width, text that is not printable ASCII, a tree that breaks a rule of
the specification, or a key path or leaf that no path declares, so that no two
readers take one file for two templates. `mirrors/fixtures/refusals.json` holds a
case for each rule, and the Rust crate and all three mirrors must refuse every
case for its reason.

Each template directory holds its programs, `descriptor.json` and
`vectors.json`. The Rust crate, the three mirrors and CI all check every
template's vectors, so the four implementations agree on every address and
control block.

```sh
cargo run --bin seqc -- descriptor seal templates/<t>      # after editing a template
cargo run --bin seqc -- descriptor vectors templates/<t>   # after adding a vector
cargo run --bin seqc -- descriptor check templates/<t>
```

| Template | What |
|---|---|
| `templates/one_key` | One key, held in the data leaf beside the program (the single-program layout) |
| `templates/one_key_exit` | The one-key program and its data leaf, beside a tapscript exit leaf that a second key spends after a relative delay |
| `templates/faucet_drip` | A faucet's reserve: the faucet key drips at most one tier per interval, the reserve re-created with the rest and its fee capped in its own asset; a tapscript leaf lets the treasury key take everything once drips have stopped for a long delay |
| `templates/pool_split` | A staking pool's payout script: anyone claims its coins into a table of up to 63 fixed shares, exact to the atom, in whatever asset they hold, withholding at most a capped part for the fee; row 0, the pool, takes the rounding. A tapscript follow leaf lets one claim spend many coins. `tables.json` holds the table-hash and payout vectors ([`docs/pool-split.md`](docs/pool-split.md)) |
| `templates/pool_split_tap3` | The same rule for a table of three rows, all in tapscript |
| `templates/mint_limiter` | An asset's reissuance token: the operator key mints at most an allowance per window of blocks, the window and the count carried in the coin's state; a cold key's signature made in advance applies a brake that stops every mint, the cold key lifts it, and takes the token once the brake has held a long delay (`docs/mint-limiter.md`) |
| `templates/supply_cap` | An asset's reissuance token: the operator key mints only while the total minted through the covenant stays at or under a cap fixed when it is made, the count carried in the coin's state; the cold key moves the covenant to new keys, and nothing takes the token out or raises the cap (`docs/supply-cap.md`) |
| `templates/verifier_token` | An OpenDAMP asset's verifier-asset reissuance token: the issuer key records the script of a coin that holds the verifier amount, as a halt that burns the verifier does, and resumes by minting exactly the verifier amount into the script it last recorded and nowhere else (`docs/verifier-token.md`) |
| `templates/pignus_vault` | A Pignus loan: the collateral in one coin, the terms and the debt outstanding beside the program. Anyone repays in part or whole or adds collateral; a liquidation under a fresh oracle price, its beacon live, takes only what brings an unhealthy vault back to its target and forces the rest back; the loan is called at maturity and recovered to the lender long after. Health is compared at 192 bits, so no loan is too large. `rules.json` holds the liquidation rule's vectors ([`docs/pignus-vault.md`](docs/pignus-vault.md)) |
| `templates/pignus_offer` | A lender's principal at rest: anyone takes one lot by opening a `pignus_vault` on the offer's terms with enough collateral, the rest resting again; after expiry anyone returns it to the lender |
| `templates/pignus_vault_threshold` | The Pignus vault under three oracles: liquidated under a price record that at least `THRESHOLD` of three distinct oracle keys attest, each with its own beacon live; every other path as `pignus_vault` ([`docs/pignus-vault.md`](docs/pignus-vault.md), "Several oracles") |
| `templates/pignus_offer_threshold` | A lender's principal at rest that opens `pignus_vault_threshold` vaults on its terms, as `pignus_offer` does for `pignus_vault` |
| `templates/capped_sale` | A token sale capped per buyer by consensus: an allocation list's Merkle root in the coin's state, each purchase signed by a listed buyer, paid at output `2k` for the coin at input `k`, and the rest re-created at `2k+1` with that buyer's running total raised; the project reclaims after the close. `allocations.json` holds the tree's vectors ([`docs/capped-sale.md`](docs/capped-sale.md)) |
| `templates/subscription_escrow` | One subscription's payment to an offering, paid in by the subscriber: the issuer's key releases every subscription together once the offering has closed, into a transaction whose output 0 pays the issuer at least the minimum; the issuer cancels it back to the subscriber at any time; after a deadline anyone refunds it to the subscriber. All three leaves tapscript ([`docs/subscription-escrow.md`](docs/subscription-escrow.md)) |
| `templates/oracle_bond` | Coins an oracle puts behind its format-2 price attestations: its key gives notice on a coin and withdraws it once the coin has waited the notice, and anyone who shows two of its attestations of one pair, precision and time at different prices slashes it, burning at least half and keeping the rest. `rules.json` holds the conflict rule's, the signed digests' and the burn's vectors ([`docs/oracle-bond.md`](docs/oracle-bond.md)) |
| `templates/seqdex_order` | A SeqDEX resting order with its terms in a data leaf beside one program for every order: anyone fills it at input `k`, paying the maker at output `2k` at least the price on 128-bit products, so every 64-bit amount and price fills, the rest resting again at `2k+1` under the same script; the refund key takes it back after a height or a median time. `fills.json` holds the pruned program of each path, so a spend is built with no compiler ([`docs/seqdex-order.md`](docs/seqdex-order.md)) |
| `templates/seqdex_guarded_order` | The SeqDEX order with a guard: every fill and the refund need exactly `GUARD_AMOUNT` of `GUARD_ASSET` at input 0, and the order is never input 0. Guarded by an OpenDAMP verifier asset, it is an order a network-enforced asset can rest in, because it moves only beside the verifier. `fills.json` holds the pruned program of each path ([`docs/seqdex-guarded-order.md`](docs/seqdex-guarded-order.md)) |
| `templates/seqdex_pool` | A SeqDEX pool: a maker's two coins, one of each asset, at one address under one program with the terms in a data leaf. Anyone fills it from either side at its bid and ask on 128-bit products, the `BASE` coin at input `j` judging the move and the pool again at outputs `2j` and `2j+1`, never below the reserve the maker states; only the maker's key withdraws. `fills.json` holds the pruned program of each path ([`docs/seqdex-pool-and-round.md`](docs/seqdex-pool-and-round.md)) |
| `templates/seqdex_round_order` | A SeqDEX round order: filled, in part or in whole, only in a round its clearer signs, at the one price the round publishes in its last output, credited exactly at that price and never below its limit; the refund key takes it back after a height or a median time. `fills.json` holds the pruned program of each path ([`docs/seqdex-pool-and-round.md`](docs/seqdex-pool-and-round.md)) |
| `templates/arca_order` | The fill of an order resting as a leaf in an Arca tree (`arca/order-2`): the operator's signature over the fill's outputs, the maker's credit to a leaf of its own, the remainder under the next salt, at most four fills along one lineage. The leaf around it, and its landing as `seqdex/order`, are built by the Arca repository, so the template has no descriptor; `fills.json` holds its six pruned programs ([`docs/arca-order.md`](docs/arca-order.md)) |
| `templates/arca_accumulator` | An Arca batch of up to 1,024 leaves held as a fixed Merkle-sum root of leaf records and a bitmap of the leaves that have left (`arca/accumulator-1`): one owner, or the operator, takes one leaf out in one transaction under a signature that names no state, paying the leaf's entry and re-creating the batch with its bit set. The batch around it is built by the Arca repository, so the template has no descriptor; `exits.json` holds its two pruned programs ([`docs/arca-accumulator.md`](docs/arca-accumulator.md)) |
| `templates/arca_collab` | The collaborative path of an Arca `vtxo-2` leaf and its checkpoint (`arca/collab-2`): the owner's and the operator's signatures over the coin's index, the inputs they name by asset, amount and script, and the outputs, never the outpoint. One program for every leaf, its parameters in a data leaf; the Arca repository builds the outputs, so the template has no descriptor; `collab.json` holds its one pruned program ([`docs/arca-collab.md`](docs/arca-collab.md)) |

## Lints

Two kinds of jet compile without a warning and are wrong on Sequentia. The lints
refuse any program that uses them:

- `lbtc_asset` returns a constant, Liquid's L-BTC asset id. On Sequentia it
  names no asset.
- The four relative-timelock jets, `check_lock_distance`, `check_lock_duration`,
  `tx_lock_distance` and `tx_lock_duration` (spelled `broken_do_not_use_*` by the
  pinned compiler). They read the largest relative lock over every input of the
  transaction, not the input being spent, so a spender defeats them by adding an
  old coin of their own. A correct relative lock requires `jet::version()` of at
  least 2 and reads `jet::parse_sequence(jet::current_sequence())`;
  `lints/fixtures/accept/safe_distance.simf` is the pattern.

Each program is checked in two layers: the source, with comments removed, for
any spelling of these jets; and the compiled program for the jets themselves,
which catches a use however the source names it or wherever it comes from. The
compiled layer is the one that cannot be fooled, so a program passes only when
it compiles: `seqc lint` fails on a source it cannot compile, and says why.

```sh
cargo run --bin seqc -- lint path/to/program.simf
```

A program that imports other files with `use` compiles only against the
dependencies it is built with. Lint it as Simplex builds it, with the same
dependency map and every unstable compiler feature enabled; the lint then scans
the flattened program, the single source Simplex embeds and compiles at run
time, and the program compiled from it:

```sh
seqc lint --project path/to/simplex-project          # every program of a Simplex project
seqc lint --dep vendor=path/to/vendor/simf program.simf   # one program, dependencies by hand
```

`--project` reads the project's `Simplex.toml`: its source directory, and its
dependencies by path or by git (installed by `simplex install` under `deps/`),
followed transitively. It lints every `.simf` file under the source directory
that declares `fn main`. The library form is `lint::lint_with_deps`, for a
build that already holds the dependency map, and `lint::lint_expanded` for a
source whose helper includes are already resolved (`seqc expand`'s output),
which reads no file and so also runs in a browser.

A fragment that is not a program on its own, such as a helper or a template
with placeholders, cannot compile alone; `--source-only` accepts it on the
source scan, and is meant for those alone.

`cargo test` lints every `.simf` and `.simf.in` file in the repository outside
`lints/fixtures/reject/`: every program must compile and pass both layers, the
helpers and templates must pass the source scan, and every Simplex project
under `lints/fixtures/accept/` must pass as Simplex builds it. Every reject
fixture, including the project in `lints/fixtures/reject/import/` whose
programs reach `lbtc_asset` and a broken lock jet only through a dependency,
must fail. So a program using a banned jet fails the build.

## Parity gate

```sh
python3 parity/parity_gate.py --node /path/to/Sequentia/src/simplicity
python3 parity/parity_gate.py --node ... --manifest-path /path/to/project/Cargo.toml
```

It locates the Simplicity crates that a project's `Cargo.lock` resolves (this
repository's by default, any Rust project's with `--manifest-path`) and compares
them with the node's `src/simplicity` in two ways:

- **The C library.** Every file of `simplicity-sys`'s bundled C sources, after
  normalising the crate's versioned symbol prefix, against the node's copy. It
  fails on a file present on one side only, or on any difference not listed in
  `parity/allowlist.txt`. Each allow-list entry pins the content hash of both
  sides and says why the difference is harmless, so a later change to either
  side fails the gate again until it is reviewed.
- **The Rust jet table.** `simplicity-lang` keeps its own table of the Elements
  jets, and that table, not the C library, is what costs a program and sizes the
  padding that buys its budget. The gate compares it with the node's
  `elements/primitiveJetNode.inc`: the same jet names, the same cost and the same
  commitment root for each. Any difference fails; none can be allow-listed.
  `parity/test_parity_gate.py` shows that a changed cost, a changed root, and a
  missing or renamed jet each fail it.

Run it whenever the pinned compiler changes and whenever the node updates its
Simplicity subtree. In CI it compares against the tip of the node's default
branch: the workflow checks out only `src/simplicity` from the public
`ConcatenaLabs/Sequentia` repository.

Another Rust project that builds Simplicity programs gates its own lock file
the same way. Its CI checks out this repository and the node's
`src/simplicity`, fetches its crates, and runs the gate on its own manifest:

```yaml
- uses: actions/checkout@v4
- uses: actions/checkout@v4
  with: { repository: ConcatenaLabs/sequentia-contracts, path: contracts }
- uses: actions/checkout@v4
  with:
    repository: ConcatenaLabs/Sequentia
    path: node
    sparse-checkout: src/simplicity
- run: cargo fetch --locked
- run: python3 contracts/parity/parity_gate.py --node node/src/simplicity --manifest-path Cargo.toml
```

The gate needs exactly one `simplicity-sys` and one `simplicity-lang` in the
lock file, and Python 3 with nothing beyond its standard library.

## Regtest harness

The harness runs programs on a real Sequentia node. Each test starts its own
`sequentiad` on a custom chain (`elementsregtest`) with Simplicity active from
genesis (`-evbparams=simplicity:-1:::`) and transparent defaults
(`-con_default_blinded_addresses=0`, `-blindedaddresses=0`), issues test assets
and puts them on the fee whitelist. It then pays to program addresses, builds
and broadcasts spends, and refuses every negative case twice: in the mempool,
and by forcing the same transaction into a block with the hidden
`generateblock` RPC. A rejection counts only when the block refuses it too,
because the mempool runs Simplicity as policy even where consensus does not.

Each refusal asserts its reason, in the mempool and in the block. Nodes run
with `-par=1`, which checks scripts on the validating thread, so a block's
error names the script failure instead of only `block-validation-failed`. Where
that failure is a failed assertion, which does not say which check failed,
the negative names a control: a transaction that differs from it only in the
property the negative breaks, spends the same program, and is accepted. Then
the refusal is that property's and no other check's.

```sh
harness/run.py                                   # every test but the ceilings
harness/run.py s3 s6                             # some of them
harness/run.py --ceilings                        # also the slow S1 ceiling runs
harness/run.py --node-repo /path/to/Sequentia --sequentiad /path/to/sequentiad
```

It needs a Sequentia checkout for the node's functional test framework
(`test/functional`, imported read-only) and a `sequentiad` and `sequentia-cli`
built from it. `--node-repo` defaults to `$SEQUENTIA_REPO`, else to a `Sequentia`
checkout beside this repository, and `--sequentiad` to `src/sequentiad` in it. Node data
directories go under `harness/tmp/` and are removed when a test passes.

| Test | What it proves |
|---|---|
| `s0` | On a chain where Simplicity is not active, a keyless spend of a `0xbe` output is refused by the mempool and accepted in a block |
| `s1` | A one-key program; wrong key, a flipped program bit and a key-path attempt refused; a `sig_all_hash` signature with an annex, refused when the signed hash omits the annex and accepted when it commits to it |
| `s2` | A covenant tree node at radix 2, 4 and 8 in three encodings, with the tapscript node's violations refused, and a child carrying a nonce refused by every form |
| `s3` | A custom signature hash that names no outpoint, rebound to a second coin, with and without binding the coin's asset and amount |
| `s4` | State in a taproot data leaf, moved forward by a spend and swept after expiry |
| `s5` | One owner leaves a shared output of 16, 1,024 and about a million leaves |
| `s6` | The broken relative-lock jets bypassed by a second, old input; the safe form refusing the bypass |
| `s7` | An oracle-signed price checked with 128-bit products |
| `h1` | Every helper in a program that uses it: spent, and each violation refused |
| `o1` | One format-2 price attestation accepted by a Simplicity leaf and by a tapscript leaf of the same output; a wrong price, time, pair or key, an attestation too early or above the strike, a version byte of 1, and the format-1 signature of the same observation refused in each, and the whole format-1 record refused by the tapscript leaf |
| `o2` | Fresh attestations through a beacon coin: a contract opened under beacon B1 accepts an attestation naming B1 through a Simplicity leaf and a tapscript leaf; after the oracle rotates its beacon to B2 the B1 attestation is refused by both in a block, against an accepted control naming B2, and with the spent B1 coin or a foreign coin at B1; the beacon script refuses every move but a signed rotation, and every reuse of an old rotation signature |
| `f1` | The faucet drip covenant, from its descriptor: two drips in a row and a drip in the second tier, the recovery after its delay, and every violation refused: early, a short or disabled lock and the lock moved to another input, above the tier or a forged larger tier, the drip in another asset or back into the covenant, the successor to another script, key or asset or short by 1,000 atoms, a fee over the cap, another key's or another drip's signature, a reserve of another asset, two reserves sharing one successor, and the recovery early, with a short lock or signed by the faucet key |
| `m1` | The mint limiter, from its descriptor: mints within a window up to exactly its allowance, a new window restarting it, the brake applied by a third party with a signature made before the coin existed, lifted and applied again, and the recovery accepted at its delay and refused one second before; every violation refused: a count one atom over the allowance, a coin under two blocks old, an age declared beyond the coin's, a disabled or time lock, version 1, another key's or another mint's signature, no reissuance, a successor that forgets the count, restarts the window early, is braked or holds less than the whole token, the coin at input 1, two coins sharing a successor, a mint from a braked coin, the brake with the operator's signature or another instance's or chain's, the brake or its release with an issuance, the release by the operator or of a coin not braked, and the recovery with a short, disabled or block lock, in version 1, by the operator or of a coin not braked |
| `m2` | `tools/mint-limiter` against the node: every path it builds is signed by the wallet and mined, `follow` reads each back, and the tool refuses a mint over the allowance, a coin under two blocks old, the wrong key, a coin in another state and a broken arm signature |
| `m3` | `tools/mint-limiter sign` on a transaction shaped as an Arca round (the covenant reissuing at input 0 beside an input that issues a new asset and a fee coin, the minted units in a batch output): the whole allowance minted and mined, a whole allowance again in the next window, `sighash` equal to the harness's own; the tool refuses a mint over the allowance, output 0 not the successor, an age in time or of one block, version 1, a new issuance, another entropy, a missing spent output, a denomination other than 8, another key and a coin in another state; the same round minting one atom over the allowance, re-signed by the operator key, refused in a block beside the tool's mint as control |
| `u1` | The supply cap, from its descriptor: mints up to exactly the cap on each side of a rekey to a new operator key, and the retirement to keys nobody holds; every violation refused: one atom over the cap, at the cap and after the rekey, another key's, the cold key's or another mint's signature, no reissuance or a new issuance, a successor that counts less, raises the cap, changes the keys, holds less than the whole token, carries a nonce or is confidential, the coin at input 1, two coins sharing a successor, a 64-bit overflow, and a rekey by the operator or another key, with a mint, forgetting the count, raising the cap, to keys other than those named, or sending the token elsewhere |
| `u2` | `tools/token-covenants` against the node for the supply cap: a mint from a mnemonic, a rekey to a raw key file, a mint to exactly the cap and the retirement, each signed by the wallet, mined and read back with `follow`; the tool refuses a mint over the cap, the wrong key, a coin holding another count and one key named twice |
| `v1` | The verifier token, from its descriptor, with two stand-ins for an OpenDAMP verifier: the token moved in recording the first, an update, a halt that burns the verifier and records it, the resume into it; every violation refused: the resume to the old verifier or an ordinary address, one atom more or less, twice the amount with half elsewhere, beside another output of the verifier asset or a fee in it, by another key, with seven outputs, a confidential output or a nonce, a successor that changes the record or sends the token elsewhere, no reissuance, the coin at input 1; and a record by another key, of a coin one atom short or of another asset, keeping the old record or recording another script, sending the token elsewhere, minting at once, or with the coin at input 2 |
| `v2` | `tools/token-covenants` against the node for the verifier token: the record signed into a halt laid out by the issuer's tooling and the resume built whole, both mined and read back, the resumed verifier spent again; the tool refuses another key, a coin recording another verifier, an output 1 recording another script and an input 0 short of the verifier amount |
| `d1` | The one-key template, paid at the address the Python mirror derives from its descriptor, and spent; another key and another key's signature refused |
| `d2` | The `one_key_exit` tree, paid at a golden vector's address and spent by each leaf from its descriptor alone: the wrong key or chain and the wrong control block refused on the Simplicity leaf; the exit refused before its delay, with a short or disabled lock, in version 1 and with the other key; each leaf's signature refused on the other under one key |
| `p1` | The pool split covenant, Simplicity and tapscript, claimed by `tools/pool-claim`: one coin, two, eight, 70 (padded) and an issued asset, tables of 3 to 63 rows; a wrong share, swapped rows, a nonce, another withheld amount, one atom over the cap, a follower's value taken, a coin in another asset, the follow leaf alone or beside a foreign input, nine inputs to the twin and padding one byte short, all refused |
| `l1` | The Pignus vault and offer from their descriptors: a loan of 2,000,000 units at 8 decimal places, which the version 1 vault cannot be built for, taken from an offer, topped up, repaid in part, liquidated in part under a fresh attestation, liquidated again after the oracle's beacon rotates, called at maturity with its surplus returned, repaid in full and recovered; a liquidation of a healthy vault, a seizure above the price, one beyond the target, one leaving the vault unhealthy, an old or rotated attestation, a surplus kept back and successors whose state does not follow, all refused; every vector of `rules.json` run through the program on the abstract machine |
| `l2` | The threshold vault and offer from their descriptors, with three oracles each with its own beacon: a 2-of-3 offer taken, the vault liquidated in part by oracles 1 and 2 and its successor by oracles 2 and 3, a 1-of-3 and a 3-of-3 vault liquidated with one and three signatures; refused, each against an accepted control: a 2-of-3 with one signature, a 3-of-3 with two, a threshold of 0, a signature by a stranger, one oracle in two slots, a second signature over another price or time, a beacon at another input or not live, the offer opening a vault under another key set or threshold; one key listed twice refused on the abstract machine |
| `c1` | The capped sale from its descriptor: a buyer's two purchases reaching their cap exactly, a purchase at input 1 paying at outputs 2 and 3, a full buy and the reclaim after the close; refused, each against an accepted control: the second purchase one atom past the cap, a key not on the list, a stranger signing a listed leaf, a signature over another purchase, a cap claimed larger, a running total shown as zero, a payment one atom short, in another asset or to another script, a rest short, elsewhere, with a nonce or below the minimum lot, a successor state that counts nothing, one atom less or charges another buyer, a coin of another asset at the sale's address, a purchase below the minimum lot, input 1 paying at outputs 0 and 1; the reclaim before the close or by another key |
| `b1` | The oracle bond from its descriptor: three coins and a top-up bonded; a conflict (one pair and time, two prices under two beacons) slashed with half burned and half to the presenter, a slash during notice, two coins slashed in one transaction; notice given, the wait, the withdrawal; refused, each against an accepted control: two times, the same price twice, another pair, another precision, another key, one of each key, a burn one atom short, to the presenter, in another asset or missing, two coins sharing one burn, a second coin's burn missing; a notice to another script, still bonded, one atom short, signed for another coin, by another key, as a price or a withdrawal, or from notice given; a withdrawal before the notice has run (BIP68), with a sequence below the notice, in blocks or disabled, at version 1, to another script, to a replaced destination, one atom short, signed for another coin, as a notice, by another key, or without notice; the Python mirror's conflict rule agrees on every pair |
| `e1` | The subscription escrow from its descriptor: two subscriptions released together after the close, one cancelled back to its subscriber, two refunded by anyone in one transaction after the deadline; refused: a release or a refund before its time (by its locktime, and as non-final), output 0 one atom under the minimum, subscriptions short of it, output 0 to another script, in another asset or with a nonce, another key's signature, a release signature on the cancel leaf, a refund or cancel to another script, to swapped subscribers, or keeping one atom over the fee cap |
| `x1` | The SeqDEX order from its descriptor: an order whose price times its size is far beyond 2^63 filled in part at input 0, again at input 1 and in whole; an order at the price (2^64-1)/(2^64-2) and one at 1:1 filled together at inputs 0 and 1; the refund by height and by median time, and of a coin of another asset at an order's address. Refused, each against an accepted control: a payment one atom under the price, a rest one atom short, elsewhere, under another program, under other terms (a lower price, another refund key, an earlier expiry), in another asset, with a nonce or confidential, a fill or a rest one atom below the minimum lot, a credit in another asset, confidential, elsewhere or with a nonce, the credit and the rest swapped, input 1 paying at outputs 0 and 1, two coins paid by one credit, a coin of another asset and a confidential coin at the order's address; the refund before its height or its median time, one block or one second below the expiry, with final sequences, a height lock against a time expiry, by another key, or with a signature over another transaction. Every spend's pruned program is the constant `fills.json` holds |
| `x2` | The guarded SeqDEX order from its descriptor: filled in part and in whole at input 1 and refunded by height, each beside a guard coin of exactly the guard amount at input 0. Refused, each against an accepted control: no guard coin (the payment coin at input 0), the guard coin at input 2 instead of 0, the order itself at input 0, a guard coin of another asset, one atom short, one atom over, a confidential guard coin with valid proofs, a payment one atom under the price beside the guard; the refund without the guard and with a guard of another asset. Every spend's pruned program is the constant `fills.json` holds |
| `x3` | The SeqDEX pool and the round order from their descriptors, on an anchored chain: a pool funded by its maker, filled from both sides with products far beyond 2^63 and withdrawn by the maker; four round orders (two asks, two bids, one filled in part) cleared at one price read from the round's last output, that round reorged out with its Bitcoin anchor and mined again, a refund by height. Refused, each against an accepted control: a sell one atom under the ask, a buy one atom over the bid, a sell or a buy that leaves the pool below its reserve, a fill under the minimum lot, the pool's coin not recreated or recreated with a nonce, a partner coin that is not the pool's, the pool's `QUOTE` coin beside a `BASE` coin that is not the pool's, the pool taken through the fill path for nothing, a withdrawal by another key or with a signature over another transaction; a credit at the order's own limit instead of the published price, a credit one atom over it, the clearing output not last, naming another asset or another price, a round signed by another key or a signature over another round, a remainder under another clearer, a bid reading the price unflipped, a price one step below a limit; the refund by another key. Every spend's pruned program is the constant `fills.json` holds |
| `p2` | The same covenants as a pool's payout script on a proof-of-stake chain with coinbase maturity 1,000: every block's reward paid to them, a claim refused at 17 and 999 confirmations and accepted at 1,000, every reward claimed in exact shares in two assets, and a wrong share and a withheld amount over the cap refused in a block |
| `s1c`, `s1d` | The budget to the byte, the annex cap, program size and cost ceilings, budget bought with witness data |

Each test writes `harness/records/<id>.json`: for every spend the program and
witness bytes, the transaction's vsize and weight, the static cost bound and the
budget; for every refusal the mempool and block errors. The committed records are
those of the run that `docs/harness-sizes.md` reports. After a run,
`harness/compare.py` regenerates that page against
`harness/baseline/simplicityhl-0.4.1.json`.

The harness is a Python layer over `seqc run`, which compiles, satisfies, prunes
and costs a program with the pinned compiler and refuses any program the lints
refuse. `harness/run.py` builds `seqc` with the `sequentia-tx` feature, which
reads Sequentia's transaction encoding: an issuance there carries a
denomination byte that the upstream `elements` crate does not read, so without
the feature `seqc run` refuses any transaction that issues or reissues. The only exception is `s6`, which compiles the reject fixtures with
`allow_banned_jets` to prove on-chain why they are refused.

| Helper (`harness/lib/`) | Does |
|---|---|
| `SimProg(source, args, data=..., sibling=...)` | Compiles a program and builds its taproot output: the program leaf alone, beside a hidden data leaf, or beside a tapscript leaf |
| `fund(spk, atoms, asset)` | Pays a program address from the node wallet and mines it |
| `mktx`, `sim_satisfy`, `send` | Builds a spend, satisfies and prunes the program against it, broadcasts, mines and records it |
| `reject(tx, label, expect, mempool=, control=)` | Asserts the mempool refuses the transaction and that `generateblock` refuses it too, each with the expected reason (`mempool` when policy refuses first for another), and that the control, required for a failed assertion, is accepted; records it all. With `other_state=True` the control spends a coin of the same program in another state, for a property that is the coin's state itself |
| `try_block(tx, label, expect)`, `try_mempool(tx, label, expect)` | Mine the transaction directly, or offer it to the mempool, and assert the result: accepted, or refused for the reason given |
| `bit_replace`, `set_sim_wit` | Rewrite a witness at bit granularity for a negative case the compiler would not satisfy |
| `poolsplit.py` | Builds pool split claims with the claim tool through the test node, and changes one property of a claim for a negative |

## Comparing roots across compilers

A commitment root is what an address commits to, so a compiler change must be
shown not to move the roots of programs already in use. `tools/compiler-roots`
links SimplicityHL 0.4.1 and the pinned compiler into one binary (each bundles
its C library under its own symbol prefix) and compiles the same sources with
the same arguments under both. It is its own Cargo workspace, so the second
compiler stays out of the main lock file.

```sh
cargo build --release --manifest-path tools/compiler-roots/Cargo.toml
tools/compiler-roots/compare.py --swk /path/to/SWK --openamp /path/to/openamp
```

It reads the programs from checkouts of `ConcatenaLabs/SWK` and
`ConcatenaLabs/openamp` without changing them and writes
`docs/compiler-roots.md` and `tools/compiler-roots/roots.json`.

## Building

Rust stable and a C compiler (the crate builds the Simplicity C library).

```sh
cargo test
```

## License

MIT
