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
| `lints/fixtures/` | Programs the lints must refuse (`reject/`) and pass (`accept/`) |
| `parity/` | The parity gate between the pinned compiler's C library and the node's |
| `harness/` | The regtest harness: a Sequentia node with Simplicity active, the tests that run programs on it, and their records |
| `docs/` | Measured results: `harness-sizes.md` compares every harness figure with a run under SimplicityHL 0.4.1 |
| `.github/workflows/ci.yml` | Unit tests, lints and the parity gate on every pull request |

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

Each program is checked twice: the source, with comments removed, for any
spelling of these jets; and, when it compiles, the compiled program for the jets
themselves, which catches a use however the source names it.

```sh
cargo run --bin seqc -- lint path/to/program.simf
```

`cargo test` lints every `.simf` and `.simf.in` file in the repository outside
`lints/fixtures/reject/`, so a program using a banned jet fails the build.

## Parity gate

```sh
python3 parity/parity_gate.py --node /path/to/Sequentia/src/simplicity
```

It locates the `simplicity-sys` sources that `Cargo.lock` resolves, normalises
the crate's versioned symbol prefix, and compares every file with the node's
`src/simplicity`. It fails on a file present on one side only, or on any
difference not listed in `parity/allowlist.txt`. Each allow-list entry pins the
content hash of both sides and says why the difference is harmless, so a later
change to either side fails the gate again until it is reviewed.

Run it whenever the pinned compiler changes and whenever the node updates its
Simplicity subtree. In CI it compares against the tip of the node's default
branch: the workflow checks out only `src/simplicity` from the public
`ConcatenaLabs/Sequentia` repository.

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
harness/run.py                                   # S0 to S7
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

## Building

Rust stable and a C compiler (the crate builds the Simplicity C library).

```sh
cargo test
```

## License

MIT
