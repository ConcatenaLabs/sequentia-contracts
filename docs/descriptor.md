# Contract descriptors, version 1

A wallet, an operator, the explorer and the registry each need to answer two
questions about an output: what is it, and what does spending it do. They answer
them without parsing a program. A **descriptor** names a contract template; an
**instance** is that template with its parameter values; an output is recognised
by recomputing its script from the instance and comparing, never by parsing.

This page is the specification. The reference implementation is
`crates/sequentia-contracts/src/descriptor.rs`. The mirrors in `mirrors/` (Python,
JavaScript and Go) derive an instance's address with no compiler. Every
implementation is checked against the same golden vectors.

## The fixed-root layout

Version 1 has one layout, `fixed-root`. The program takes no compile-time
parameter (no `param::`), so its commitment Merkle root (CMR) is one constant per
template. The parameters sit in a hidden data leaf beside the program:

```text
output = P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
```

The spender supplies the parameters in the witness. The program checks them
against the data leaf with `jet::tappath(0)`, the hash of the program leaf's
sibling, which consensus has already bound to the output key through the control
block:

```rust
fn main() {
    let pk: Pubkey = witness::PK;
    let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(jet::tapdata_init(), pk);
    assert!(jet::eq_256(jet::sha_256_ctx_8_finalize(ctx), unwrap(jet::tappath(0))));
    // ... the template's rules, using pk ...
}
```

So the commitment root can be checked against a constant in any language, and an
address takes one hash and one curve tweak. The check costs a few jets and the
parameters' bytes in every witness. `templates/one_key` is the smallest example:
a one-key spend at 239 vB, cost bound 72 weight units.

A parameter may appear in the data leaf only if the program checks it there. A
value the program reads from the witness without checking it against
`jet::tappath(0)` is the spender's choice, not a parameter.

## Parameter encoding

`param_bytes` is each parameter's value in the template's order, big-endian, at
its type's width, with nothing between them:

| Type | Bytes | Jet that adds it to a hash |
|---|---|---|
| `u8` | 1 | `sha_256_ctx_8_add_1` |
| `u16` | 2 | `sha_256_ctx_8_add_2` |
| `u32` | 4 | `sha_256_ctx_8_add_4` |
| `u64` | 8 | `sha_256_ctx_8_add_8` |
| `u128` | 16 | `sha_256_ctx_8_add_16` |
| `u256`, `Pubkey` | 32 | `sha_256_ctx_8_add_32` |

These are the bytes the program hashes, which is what makes them canonical. In
JSON a value is lowercase hex of exactly its width. An asset id is given as the
program sees it: internal byte order, the reverse of the hex an RPC prints.

## Address derivation

With `tagged(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`:

1. `data_leaf = tagged("TapData", param_bytes)`
2. `program_leaf = tagged("TapLeaf/elements", 0xbe || 0x20 || cmr)`
3. `merkle_root = tagged("TapBranch/elements", min(a, b) || max(a, b))` over the two
   leaf hashes, ordered bytewise
4. `tweak = tagged("TapTweak/elements", internal_key || merkle_root)`
5. `Q = lift_x(internal_key) + int(tweak)·G`; `output_key` is Q's x coordinate and
   `output_key_parity` the parity of its y coordinate
6. `script_pubkey = 0x51 0x20 || output_key`
7. The address on a chain is the bech32m (BIP350) encoding of witness version 1
   and `output_key` under the chain's prefix

The data leaf's tag is the plain `TapData`, which is what `jet::tapdata_init`
starts from; the other three carry Elements' `/elements` suffix. The script does
not depend on the chain; only the address prefix does.

| Chain name | Prefix | Genesis |
|---|---|---|
| `sequentia-testnet` | `tb` | `ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e` |
| `elementsregtest` | `ert` | Depends on how the chain was started |

## The descriptor file

A template directory under `templates/` holds `descriptor.json`, the program
source it names, and `vectors.json`.

```json
{
  "descriptor": 1,
  "template": { ... },
  "template_hash": "<hex>",
  "chains": [{"name": "sequentia-testnet", "genesis": "<hex>", "bech32_hrp": "tb"}],
  "measured": { ... }
}
```

| Field | Meaning |
|---|---|
| `descriptor` | `1` |
| `template` | The template, below. Immutable: any change is a new template |
| `template_hash` | SHA-256 of the template's canonical JSON, hex. The template's identity |
| `chains` | The chains an instance is addressed on: a name, the genesis hash (`null` for a local chain), the bech32 prefix |
| `measured` | Sizes and costs measured by the regtest harness, with the record they came from. Optional |

`chains` and `measured` are outside the hash: adding a chain or a measurement
does not change what the template is.

**Canonical JSON** is the value with every object's keys sorted bytewise and no
whitespace, as `json.dumps(v, sort_keys=True, separators=(",", ":"))` writes it. A
template is printable ASCII, so every language's encoder agrees.

### Reading a descriptor

Every reader refuses, rather than ignores, anything outside this specification,
so that two readers never take one file for two different templates:

- a field this page does not list, at any level, matched with its exact case
  (`measured` alone is free-form, and outside the hash);
- a number that is not an integer in [0, 2^53): no sign, no fraction, no
  exponent. JavaScript reads 9007199254740993 as 9007199254740992 and `1.0` as
  `1`, so a larger or non-integer number would hash differently in different
  languages;
- hex that is not lowercase or not exactly its width, trailing characters
  included;
- a key path that is not declared (above), and a template hash that does not
  match.

The Rust crate (`Descriptor::load`, `validate`), the Python mirror (`loads`,
`derive`), the JavaScript mirror (`parseDescriptor`, `derive`) and the Go mirror
(`ParseDescriptor`, `Derive`) apply these rules.

### The template

| Field | Meaning |
|---|---|
| `name` | `namespace/name`, such as `sequentia/one-key` |
| `version` | An integer; a changed template is a new version |
| `summary` | One sentence a wallet can show |
| `layout` | `fixed-root` |
| `internal_key` | The x-only internal key, hex. `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`, BIP341's point with no known discrete logarithm, gives no key path |
| `key_path` | Present exactly when `internal_key` is any other key: the name of the entry in `paths` that describes spending by that key. Absent with the NUMS key |
| `program.source` | The source file, relative to the descriptor |
| `program.source_sha256` | SHA-256 of the source with its helper includes resolved, exactly the text compiled (`seqc expand` prints it), so a verifier needs that text alone |
| `program.compiler` | `{"name": "simplicityhl", "version": "<the pinned version>"}` |
| `program.cmr` | The commitment root the source compiles to, hex |
| `program.witness` | Each witness value: `name`, `type`, and `source`, which is `param:<NAME>`, `signature:sig_all_hash:<NAME>` (a BIP340 signature by that parameter's key over `jet::sig_all_hash()`), or `spender` |
| `params` | In data-leaf order: `name`, `type` (from the table above), `role` and `label` |
| `paths` | Each way to spend: `name`, `who` can take it, and its `effect` in words |

Any internal key but the NUMS key gives the output a key path: whoever holds
that key spends the output with one signature, and the program never runs. A
template therefore uses the NUMS key, or declares the key path in `key_path` and
describes it in `paths`, so that a wallet shows it like any other way to spend.
A template that does neither is refused.

A parameter's `role` says how to show its value: `pubkey`, `asset`, `amount`,
`script_hash`, `height`, `time`, `hash`, `feed` or `number`. A wallet renders an
`asset` with the registry's ticker and an `amount` in that asset's precision.

## Instances

An instance is the template hash, the parameter values and the chain:

```json
{"instance": 1, "template_hash": "<hex>", "params": {"PK": "<hex>"}, "genesis": "<hex>"}
```

The genesis hash does not change the script. It names the chain whose
`sig_all_hash` the instance's signatures commit to, so an instance on one chain is
never mistaken for one on another.

## Golden vectors

`vectors.json` pins every value derivation produces, for a set of named
instances:

```json
{
  "vectors": 1,
  "template_hash": "<hex>",
  "cmr": "<hex>",
  "addresses": [
    {
      "name": "secret key 1",
      "params": {"PK": "<hex>"},
      "param_bytes": "<hex>",
      "data_leaf": "<hex>",
      "program_leaf": "<hex>",
      "merkle_root": "<hex>",
      "tweak": "<hex>",
      "output_key": "<hex>",
      "output_key_parity": 0,
      "script_pubkey": "<hex>",
      "address": {"elementsregtest": "ert1p…", "sequentia-testnet": "tb1p…"}
    }
  ]
}
```

Each implementation reads `name` and `params` and must reproduce every other
field exactly, and the template hash. A template's vectors include, for each
order of the two leaf hashes (the data leaf below the program leaf, and above
it), instances whose output keys have each parity, so that an implementation
that does not sort the branch, or that drops the parity, fails them.

## Tools

```sh
cargo run --bin seqc -- descriptor seal templates/<t>      # fill in source hash, root, template hash
cargo run --bin seqc -- descriptor vectors templates/<t>   # rewrite the vectors' derived fields
cargo run --bin seqc -- descriptor check templates/<t>     # validate; the vectors must match
```

`check` compiles the source with the pinned compiler, so a descriptor whose
source, compiler or root disagree fails, as does one whose source fails the lints.
`cargo test` runs it over every template; the mirrors run their own checks:

```sh
python3 mirrors/python/test_sequentia_address.py
node --test mirrors/js/sequentia-address.test.mjs
(cd mirrors/go && go test ./...)
```

## Signing for a contract

A wallet signs for a contract only when all of these hold:

1. the template hash is on its list of known templates;
2. it recomputed the output script from the template and the instance's
   parameters, and it equals the coin being spent;
3. it ran the program against the final transaction itself;
4. the approval shows the template's name, the path, the parameters by role, and
   the wallet's own balance changes;
5. the signing key is one reserved for contracts.
