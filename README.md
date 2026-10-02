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

## Building

Rust stable and a C compiler (the crate builds the Simplicity C library).

```sh
cargo test
```

## License

MIT
