# Contract descriptors

A wallet, an operator, the explorer and the registry each need to answer two
questions about an output: what is it, and what does spending it do. They answer
them without parsing a program. A **descriptor** names a contract template; an
**instance** is that template with its parameter values; an output is recognised
by recomputing its script from the instance and comparing, never by parsing.

This page is the specification. The reference implementation is
`crates/sequentia-contracts/src/descriptor.rs`. The mirrors in `mirrors/` (Python,
JavaScript and Go) derive an instance's address with no compiler. Every
implementation is checked against the same golden vectors and refuses the same
files (`mirrors/fixtures/refusals.json`).

There are two versions. **Version 2** describes any taproot tree: Simplicity
leaves, tapscript leaves and hidden data leaves, each named, with parameters that
are fixed for an instance and storage slots that change from coin to coin.
**Version 1** has one layout, a program beside the data leaf that holds its
parameters; it is the version 2 tree `branch(program, params)`, and every reader
reads it as that tree.

## The output

An output is a taproot output over a tree:

```text
output = P2TR(internal_key, root(tree))
```

A tree is a leaf, or a branch of two trees. A leaf is one of:

| Leaf | Leaf hash |
|---|---|
| Simplicity | `tagged("TapLeaf/elements", 0xbe ‖ 0x20 ‖ cmr)`: the program's commitment root at leaf version `0xbe` |
| Tapscript | `tagged("TapLeaf/elements", 0xc4 ‖ compact_size(len) ‖ script)`: a script, its parameters in place |
| Data | `tagged("TapData", bytes)`: a hidden node committing to parameter and slot values, which a program reads back with `jet::tappath` |

with `tagged(tag, m) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ m)`. A branch's hash is
`tagged("TapBranch/elements", min(a, b) ‖ max(a, b))` over its two children's
hashes, ordered bytewise, and the root is the top node's hash. The data leaf's tag
is the plain `TapData`, which is what `jet::tapdata_init` starts from; the other
three carry Elements' `/elements` suffix.

From the root:

1. `tweak = tagged("TapTweak/elements", internal_key ‖ root)`
2. `Q = lift_x(internal_key) + int(tweak)·G`; `output_key` is Q's x coordinate and
   `output_key_parity` the parity of its y coordinate
3. `script_pubkey = 0x51 0x20 ‖ output_key`
4. The address on a chain is the bech32m (BIP350) encoding of witness version 1
   and `output_key` under the chain's prefix
5. A Simplicity or tapscript leaf is spent with the control block
   `(leaf_version | output_key_parity) ‖ internal_key ‖ path`, where `path` is the
   hash of each sibling from the leaf up to the root

The script does not depend on the chain; only the address prefix does.

| Chain name | Prefix | Genesis |
|---|---|---|
| `sequentia-testnet` | `tb` | `ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e` |
| `elementsregtest` | `ert` | Depends on how the chain was started |

### Parameters in a data leaf

A program takes no compile-time parameter (no `param::`), so its commitment root
is one constant per template, and its parameters sit in a data leaf beside it.
The spender supplies them in the witness, and the program checks them against
the data leaf with `jet::tappath(0)`, the hash of the program leaf's sibling,
which consensus has already bound to the output key through the control block:

```rust
fn main() {
    let pk: Pubkey = witness::PK;
    let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(jet::tapdata_init(), pk);
    assert!(jet::eq_256(jet::sha_256_ctx_8_finalize(ctx), unwrap(jet::tappath(0))));
    // ... the template's rules, using pk ...
}
```

So the commitment root can be checked against a constant in any language, and an
address takes one hash per leaf and one curve tweak. A program reads its own data
leaf as `jet::tappath(0)` when the two share a branch, wherever else that branch
sits in the tree. The check costs a few jets and the parameters' bytes in every
witness. `templates/one_key` is the smallest example: a one-key spend at 239 vB,
cost bound 72 weight units.

A parameter may appear in a data leaf only if the program checks it there. A
value the program reads from the witness without checking it against the data
leaf is the spender's choice, not a parameter.

### Values

A parameter's or slot's value is big-endian at its type's width:

| Type | Bytes | Jet that adds it to a hash |
|---|---|---|
| `u8` | 1 | `sha_256_ctx_8_add_1` |
| `u16` | 2 | `sha_256_ctx_8_add_2` |
| `u32` | 4 | `sha_256_ctx_8_add_4` |
| `u64` | 8 | `sha_256_ctx_8_add_8` |
| `u128` | 16 | `sha_256_ctx_8_add_16` |
| `u256`, `Pubkey` | 32 | `sha_256_ctx_8_add_32` |

A data leaf's bytes are its values in the order it lists them, with nothing
between. These are the bytes the program hashes, which is what makes them
canonical. In JSON a value is lowercase hex of exactly its width. An asset id is
given as the program sees it: internal byte order, the reverse of the hex an RPC
prints.

A tapscript leaf's script is its items in order:

| Item | Bytes |
|---|---|
| `"<hex>"` | Those bytes: opcodes, and pushes of constants |
| `{"push": "P"}` | A push of P's bytes: one length byte, then the value. P is at least 2 bytes wide |
| `{"num": "P"}` | A minimal push of P's value as a script number: `OP_0` for 0, `OP_1` to `OP_16` for 1 to 16, else the shortest little-endian bytes, with a `0x00` added when the top bit of the last is set. P is at most 8 bytes wide |

So `[{"num": "DELAY"}, "b275", {"push": "KEY"}, "ac"]` is
`<DELAY> OP_CHECKSEQUENCEVERIFY OP_DROP <KEY> OP_CHECKSIG`.

A value's role rules out some values, and every reader refuses them when it
derives an instance:

- a `pubkey` that is not the x coordinate of a curve point, which no signature can
  ever satisfy;
- a `sequence`, a BIP68 relative lock given as its `nSequence` value, that sets
  any bit but the type flag (bit 22, which counts units of 512 seconds instead of
  blocks) and the 16-bit lock. Its disable flag, bit 31, would make
  `OP_CHECKSEQUENCEVERIFY` pass at once.

## The descriptor file

A template directory under `templates/` holds `descriptor.json`, the program
sources it names, and `vectors.json`.

```json
{
  "descriptor": 2,
  "template": { ... },
  "template_hash": "<hex>",
  "chains": [{"name": "sequentia-testnet", "genesis": "<hex>", "bech32_hrp": "tb"}],
  "measured": { ... }
}
```

| Field | Meaning |
|---|---|
| `descriptor` | `2`, or `1` for the layout below |
| `template` | The template. Immutable: any change is a new template |
| `template_hash` | SHA-256 of the template's canonical JSON, hex. The template's identity |
| `chains` | The chains an instance is addressed on: a name, the genesis hash (`null` for a local chain), the bech32 prefix |
| `measured` | Sizes and costs measured by the regtest harness, with the record they came from. Optional and free-form |

`chains` and `measured` are outside the hash: adding a chain or a measurement
does not change what the template is.

**Canonical JSON** is the value with every object's keys sorted bytewise and no
whitespace, as `json.dumps(v, sort_keys=True, separators=(",", ":"))` writes it.
Every string and field name in a template is printable ASCII (`0x20` to `0x7e`),
so every language's encoder writes the same bytes.

### The template

| Field | Meaning |
|---|---|
| `name` | `namespace/name`, such as `sequentia/one-key-exit` |
| `version` | An integer; a changed template is a new version |
| `summary` | One sentence a wallet can show |
| `internal_key` | The x-only internal key, hex. `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`, BIP341's point with no known discrete logarithm, gives no key path |
| `key_path` | Present exactly when `internal_key` is any other key: the name of the path that describes spending by that key. Absent with the NUMS key |
| `params` | `name`, `type` (from the table above), `role` and `label` of each parameter: a value fixed for the instance's life |
| `slots` | The same, for each storage slot: a value that changes from coin to coin as the contract moves, so that one instance has an address per state. Empty when the contract keeps no state |
| `budget` | The execution budget rule the Simplicity leaves are costed under: `{"per_witness_byte": 4, "offset": 50, "max": 4000050}`, which is a Sequentia node's: a spend may cost `min(4 × w + 50, 4000050)` weight units, `w` the serialized size of its input's witness stack |
| `tree` | The tree, below |
| `paths` | Each way to spend: `name`, `who` can take it, its `effect` in words, and the `leaf` it spends. The key path names no leaf |

A node of `tree` is one of:

```json
{"branch": [<node>, <node>]}
{"leaf": "<name>", "simplicity": {"source": "...", "source_sha256": "...", "compiler": {...}, "cmr": "...", "witness": [...], "max_cost_wu": 72}}
{"leaf": "<name>", "tapscript": [<item>, ...]}
{"leaf": "<name>", "data": ["<parameter or slot>", ...]}
```

| Simplicity leaf field | Meaning |
|---|---|
| `source` | The source file, a name of the form `<name>.simf` in the descriptor's directory |
| `source_sha256` | SHA-256 of the source with its helper includes resolved, exactly the text compiled (`seqc expand` prints it), so a verifier needs that text alone |
| `compiler` | `{"name": "simplicityhl", "version": "<the pinned version>"}` |
| `cmr` | The commitment root the source compiles to, hex |
| `witness` | Each witness value the program declares: `name`, `type`, and `source`, which is `param:<NAME>`, `slot:<NAME>`, `signature:sig_all_hash:<NAME>` (a BIP340 signature by that `Pubkey` parameter over `jet::sig_all_hash()`), or `spender` |
| `max_cost_wu` | The static cost bound of the program with every branch kept, in weight units rounded up. No spend of the leaf costs more, so a spend whose witness earns less than this under `budget` may need padding |

A parameter's `role` says how to show its value: `pubkey`, `asset`, `amount`,
`script_hash`, `height`, `time`, `hash`, `feed`, `number` or `sequence`. A
`pubkey` is of type `Pubkey` and a `sequence` of type `u32`. A wallet renders an
`asset` with the registry's ticker, an `amount` in that asset's precision, and a
`sequence` as the delay it sets.

Any internal key but the NUMS key gives the output a key path: whoever holds
that key spends the output with one signature, and no leaf runs. A template
therefore uses the NUMS key, or declares the key path in `key_path` and
describes it in `paths`, so that a wallet shows it like any other way to spend.
A template that does neither is refused. For the same reason every Simplicity
and tapscript leaf is named by a path: a leaf no path describes is a way to spend
that a wallet would not show.

### Version 1

A version 1 template has `layout` (`"fixed-root"`) and `program` (a Simplicity
leaf's fields without `max_cost_wu`) in place of `tree`, `slots` and `budget`,
and its paths name no leaf. It is the version 2 template whose tree is

```json
{"branch": [{"leaf": "program", "simplicity": <program>}, {"leaf": "params", "data": [<every parameter, in order>]}]}
```

with no slots, Sequentia's budget, and every path but the key path spending
`program`. Every reader reads it as that tree, so the two derive the same output:
`mirrors/fixtures/one_key_as_v2` is `templates/one_key` written as version 2, and
its vectors hold the same addresses. `seqc descriptor as-v2 <dir>` prints that
form.

### Reading a descriptor

Every reader refuses, rather than ignores, anything outside this specification,
so that two readers never take one file for two different templates:

- JSON that names one field twice in an object, or nests arrays and objects more
  than 300 levels deep (the deepest tree, 128 levels, nests about 262);
- a field this page does not list, at any level, matched with its exact case
  (`measured` alone is free-form, and outside the hash), and a missing one
  (`key_path`, a path's `leaf` and `measured` are the optional fields);
- a number that is not an integer in [0, 2^53): no sign, no fraction, no
  exponent. JavaScript reads 9007199254740993 as 9007199254740992 and `1.0` as
  `1`, so a larger or non-integer number would hash differently in different
  languages;
- hex that is not lowercase or not exactly its width, trailing characters
  included;
- a string or field name in the template that is not printable ASCII;
- a branch of other than two nodes, a leaf of other than one kind, and a leaf
  deeper than 128 levels;
- two leaves, two parameters or slots, two witness values or two paths of one
  name; a type or role this page does not list, or a role of the wrong type;
- a parameter or slot in no leaf, which would not change the output; a data leaf
  naming a value the template does not have, or none; a slot in a tapscript, a
  `push` of a one-byte value, a `num` of a value wider than 8 bytes;
- a witness value whose source names no parameter or slot, has another type than
  the value it names, or is not one of the four forms;
- a source that is not a `<name>.simf` file beside the descriptor;
- a key path that is not declared (above), a path naming no leaf or one that is
  not Simplicity or tapscript, a Simplicity or tapscript leaf no path describes,
  and a template hash that does not match;
- when an instance is derived: values that are not exactly the template's
  parameters and slots, a value its role rules out (above), and two leaves that
  are one script at one leaf version, which no control block tells apart.

`mirrors/fixtures/refusals.json` lists a case for each, and every reader's tests
require each case refused for its reason. The Rust crate (`Descriptor::load`,
`parse`, `validate`, `model`), the Python mirror (`loads`, `derive`), the
JavaScript mirror (`parseDescriptor`, `derive`) and the Go mirror
(`ParseDescriptor`, `DeriveTree`, `Derive`) apply these rules.

The Rust crate's `validate` also compiles each Simplicity leaf's source with the
pinned compiler, and refuses a source hash, compiler, root, witness list or cost
bound that the source does not give, a source that fails the lints, and a budget
other than Sequentia's.

## Instances

An instance is the template hash, the parameter and slot values and the chain:

```json
{"instance": 2, "template_hash": "<hex>", "params": {"PK": "<hex>"}, "slots": {}, "genesis": "<hex>"}
```

The genesis hash does not change the script. It names the chain whose
`sig_all_hash` the instance's signatures commit to, so an instance on one chain is
never mistaken for one on another. A version 1 instance has `"instance": 1` and
no `slots`.

## Golden vectors

`vectors.json` pins every value derivation produces, for a set of named
instances. A version 2 descriptor's vectors:

```json
{
  "vectors": 2,
  "template_hash": "<hex>",
  "addresses": [
    {
      "name": "secret keys 1 and 2, exit after 1,024 seconds",
      "params": {"PK": "<hex>", "EXIT_KEY": "<hex>", "EXIT_DELAY": "00400002"},
      "slots": {},
      "leaves": {
        "spend": {"hash": "<hex>", "control_block": "<hex>"},
        "params": {"hash": "<hex>", "data": "<hex>"},
        "exit": {"hash": "<hex>", "script": "<hex>", "control_block": "<hex>"}
      },
      "merkle_root": "<hex>",
      "tweak": "<hex>",
      "output_key": "<hex>",
      "output_key_parity": 1,
      "script_pubkey": "<hex>",
      "address": {"elementsregtest": "ert1p…", "sequentia-testnet": "tb1p…"}
    }
  ]
}
```

A Simplicity leaf has its hash and control block, a tapscript leaf also its
script, and a data leaf its hash and bytes. A version 1 descriptor's vectors have
`"vectors": 1`, the program's `cmr`, and for each instance `param_bytes`,
`data_leaf` and `program_leaf` in place of `slots` and `leaves`.

Each implementation reads `name`, `params` and `slots` and must reproduce every
other field exactly, and the template hash. A template's vectors cover every
combination of the order of each branch's two hashes and the parity of the output
key, so that an implementation that does not sort a branch, or that drops the
parity from a control block, fails them.

## Tools

```sh
cargo run --bin seqc -- descriptor seal templates/<t>      # fill in source hashes, roots, cost bounds, template hash
cargo run --bin seqc -- descriptor vectors templates/<t>   # rewrite the vectors' derived fields
cargo run --bin seqc -- descriptor check templates/<t>     # validate; the vectors must match
cargo run --bin seqc -- descriptor as-v2 templates/<t>     # a version 1 template, written as version 2
```

`check` compiles every source with the pinned compiler, so a descriptor whose
source, compiler, root, witness or cost bound disagree fails, as does one whose
source fails the lints. `cargo test` runs it over every template and fixture, and
runs the refusals; the mirrors run their own checks:

```sh
python3 mirrors/python/test_sequentia_address.py
node --test mirrors/js/sequentia-address.test.mjs
(cd mirrors/go && go test ./...)
```

## Signing for a contract

A wallet signs for a contract only when all of these hold:

1. the template hash is on its list of known templates;
2. it recomputed the output script from the template and the instance's
   parameters and slots, and it equals the coin being spent;
3. it ran the program against the final transaction itself;
4. the approval shows the template's name, the path, the parameters by role, and
   the wallet's own balance changes;
5. the signing key is one reserved for contracts.

A signature binds only what its hash covers. `sig_all_hash` covers the whole
transaction, the chain's genesis, and the spent leaf and its path, so a program's
signature is never valid on another leaf of the same output, even under the same
key; a tapscript signature covers its own leaf through the BIP341 hash.
`harness/tests/d2_tree_descriptor.py` offers each leaf's signature on the other,
under one key, and both are refused.
