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
| `helpers/` | Shared SimplicityHL helpers, included as source: output reader, wide arithmetic, state, relative lock, Merkle fold, fee cap |
| `templates/` | Contract templates: each a program, its descriptor (`descriptor.json`) and its golden vectors (`vectors.json`) |
| `mirrors/` | Address derivation for a descriptor's instance in Python, JavaScript and Go, with no compiler |
| `harness/` | The regtest harness: a Sequentia node with Simplicity active, the tests that run programs on it, and their records |
| `docs/` | `descriptor.md` specifies contract descriptors and golden vectors; `helpers.md` documents the helpers and their measured costs. Measured results: `harness-sizes.md` compares every harness figure with a run under SimplicityHL 0.4.1; `compiler-roots.md` compares the roots of the programs other repositories ship |
| `tools/compiler-roots/` | Compiles a set of programs under SimplicityHL 0.4.1 and the pinned compiler in one binary and compares their roots |
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

Templates use the fixed-root layout: the program takes no compile-time
parameter, so its commitment root is one constant, and the parameters sit in a
hidden data leaf beside it. An instance's address is then one hash and one curve
tweak away from its parameters, which is all the mirrors in `mirrors/` need:

```python
import sequentia_address                  # mirrors/python
d = sequentia_address.loads(open("templates/one_key/descriptor.json").read())
sequentia_address.derive(d, {"PK": "<32-byte x-only key, hex>"})["address"]["sequentia-testnet"]
```

```js
import { parseDescriptor, derive } from './mirrors/js/sequentia-address.mjs';
const descriptor = parseDescriptor(text);
derive(descriptor, { PK: '<hex>' }).address['sequentia-testnet'];
```

```go
import sequentiaaddress "github.com/ConcatenaLabs/sequentia-contracts/mirrors/go"
descriptor, err := sequentiaaddress.ParseDescriptor(raw)
derived, err := sequentiaaddress.Derive(descriptor, map[string]string{"PK": "<hex>"})
```

Each reader refuses a descriptor with a field the specification does not list,
a number that is not an integer below 2^53, hex that is not exactly its width,
or a key path the template does not declare, so that no two readers take one
file for two templates.

Each template directory holds the program, `descriptor.json` and `vectors.json`.
The Rust crate, the three mirrors and CI all check every template's vectors, so
the four implementations agree on every address.

```sh
cargo run --bin seqc -- descriptor seal templates/<t>      # after editing a template
cargo run --bin seqc -- descriptor vectors templates/<t>   # after adding a vector
cargo run --bin seqc -- descriptor check templates/<t>
```

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
build that already holds the dependency map.

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
and broadcasts spends, and for every negative case records both the mempool's
error and the error from forcing the same transaction into a block with the
hidden `generateblock` RPC. A rejection counts only when the block refuses it
too, because the mempool runs Simplicity as policy even where consensus does not.

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
| `s2` | A covenant tree node at radix 2, 4 and 8 in three encodings, with the tapscript node's violations refused |
| `s3` | A custom signature hash that names no outpoint, rebound to a second coin, with and without binding the coin's asset and amount |
| `s4` | State in a taproot data leaf, moved forward by a spend and swept after expiry |
| `s5` | One owner leaves a shared output of 16, 1,024 and about a million leaves |
| `s6` | The broken relative-lock jets bypassed by a second, old input; the safe form refusing the bypass |
| `s7` | An oracle-signed price checked with 128-bit products |
| `h1` | Every helper in a program that uses it: spent, and each violation refused |
| `d1` | The one-key template, paid at the address the Python mirror derives from its descriptor, and spent; another key and another key's signature refused |
| `s1c`, `s1d` | The budget to the byte, the annex cap, program size and cost ceilings, budget bought with witness data |

Each test writes `harness/records/<id>.json`: for every spend the program and
witness bytes, the transaction's vsize and weight, the static cost bound and the
budget; for every refusal the mempool and block errors. The committed records are
those of the run that `docs/harness-sizes.md` reports. After a run,
`harness/compare.py` regenerates that page against
`harness/baseline/simplicityhl-0.4.1.json`.

The harness is a Python layer over `seqc run`, which compiles, satisfies, prunes
and costs a program with the pinned compiler and refuses any program the lints
refuse. The only exception is `s6`, which compiles the reject fixtures with
`allow_banned_jets` to prove on-chain why they are refused.

| Helper (`harness/lib/`) | Does |
|---|---|
| `SimProg(source, args, data=..., sibling=...)` | Compiles a program and builds its taproot output: the program leaf alone, beside a hidden data leaf, or beside a tapscript leaf |
| `fund(spk, atoms, asset)` | Pays a program address from the node wallet and mines it |
| `mktx`, `sim_satisfy`, `send` | Builds a spend, satisfies and prunes the program against it, broadcasts, mines and records it |
| `reject(tx, label)` | Asserts the mempool refuses the transaction and that `generateblock` refuses it too, and records both errors |
| `try_block`, `try_mempool` | Record what the block or the mempool says without asserting it |
| `bit_replace`, `set_sim_wit` | Rewrite a witness at bit granularity for a negative case the compiler would not satisfy |

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
