//! Contract descriptors, versions 1 and 2, and the golden vectors that pin them.
//!
//! A descriptor names a contract template: its taproot tree (Simplicity
//! programs, tapscripts and data leaves), its parameters and storage slots with
//! their types and roles, and its spending paths. `docs/descriptor.md` is the
//! specification; this module is its reference implementation.
//!
//! Version 2 describes any tree. Version 1 has one layout, the fixed root: one
//! program beside a hidden data leaf that holds the parameters,
//!
//! ```text
//! P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
//! ```
//!
//! which is the version 2 tree `branch(program, data(params))`. Both versions are
//! read into one [`Model`], and every output is derived from it: an instance's
//! script is its parameters and slots put in place in the tree, then one curve
//! tweak. This module computes it with the `elements` crate's own taproot
//! builder; the mirrors in `mirrors/` compute it from first principles, and every
//! implementation is checked against the same golden vectors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use simplicityhl::elements::bitcoin::key::XOnlyPublicKey;
use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::secp256k1_zkp::{Parity, Secp256k1};
use simplicityhl::elements::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use simplicityhl::elements::{Address, AddressParams, Script};

use crate::{cmr_hex, compile, hex, COMPILER_VERSION};

/// The descriptor format versions this module reads.
pub const DESCRIPTOR_VERSIONS: &[u64] = &[1, 2];
/// The golden-vector format of a version 1 descriptor.
pub const VECTORS_V1: u64 = 1;
/// The golden-vector format of a version 2 descriptor.
pub const VECTORS_V2: u64 = 2;
/// The only layout of version 1.
pub const LAYOUT_FIXED_ROOT: &str = "fixed-root";
/// The taproot leaf version of a Simplicity program.
pub const LEAF_VERSION_SIMPLICITY: u8 = 0xbe;
/// The taproot leaf version of a tapscript.
pub const LEAF_VERSION_TAPSCRIPT: u8 = 0xc4;
/// BIP341's nothing-up-my-sleeve point: no known discrete logarithm, so no key path.
pub const NUMS_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
/// The deepest a leaf may sit: a control block holds at most 128 hashes.
pub const MAX_TREE_DEPTH: usize = 128;
/// The name a version 1 template's program takes as a version 2 leaf.
pub const V1_PROGRAM_LEAF: &str = "program";
/// The name a version 1 template's data leaf takes as a version 2 leaf.
pub const V1_DATA_LEAF: &str = "params";

/// The execution budget rule a Sequentia node applies to a Simplicity spend:
/// `min(per_witness_byte * witness_bytes + offset, max)` weight units, where
/// `witness_bytes` is the serialized size of the input's witness stack.
pub const SEQUENTIA_BUDGET: Budget = Budget {
    per_witness_byte: 4,
    offset: 50,
    max: 4_000_050,
};

/// A descriptor file: the template, its hash, the chains it is addressed on,
/// and what was measured of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// 1 or 2.
    pub descriptor: u64,
    /// The template. Its canonical JSON is what [`template_hash`] hashes.
    pub template: Value,
    /// SHA-256 of the template's canonical JSON, hex.
    pub template_hash: String,
    /// The chains on which an address is given, with their address prefixes.
    pub chains: Vec<Chain>,
    /// Measured sizes and costs, from the regtest harness. Not part of the hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured: Option<Value>,
}

/// A chain an instance can be addressed on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    /// The name used in vectors and instances, such as `sequentia-testnet`.
    pub name: String,
    /// The chain's genesis block hash, display hex; `null` for a local chain
    /// whose genesis depends on how it was started.
    pub genesis: Option<String>,
    /// The bech32 prefix of an unblinded segwit address.
    pub bech32_hrp: String,
}

/// The typed view of a version 1 template.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub name: String,
    pub version: u64,
    pub summary: String,
    pub layout: String,
    pub internal_key: String,
    /// The name of the path in `paths` that the internal key spends by. Present
    /// exactly when `internal_key` is not [`NUMS_KEY`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    pub program: Program,
    pub params: Vec<Param>,
    pub paths: Vec<SpendPath>,
}

/// A version 1 template's Simplicity program.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// Path of the source, relative to the descriptor file.
    pub source: String,
    /// SHA-256 of the source with its helper includes resolved (`seqc expand`), hex.
    pub source_sha256: String,
    pub compiler: Compiler,
    /// The commitment Merkle root, hex.
    pub cmr: String,
    /// The program's witness values and where each comes from.
    pub witness: Vec<WitnessValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compiler {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessValue {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// `param:<NAME>`, `slot:<NAME>` (version 2), `signature:sig_all_hash:<NAME>`,
    /// or `spender`.
    pub source: String,
}

/// A template parameter, or a version 2 storage slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// What the value means: one of [`ROLES`].
    pub role: String,
    pub label: String,
}

/// A version 1 spending path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpendPath {
    pub name: String,
    pub who: String,
    pub effect: String,
}

/// The typed view of a version 2 template. Its tree is read by [`parse_node`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateV2 {
    pub name: String,
    pub version: u64,
    pub summary: String,
    pub internal_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    pub params: Vec<Param>,
    pub slots: Vec<Param>,
    pub budget: Budget,
    pub tree: Value,
    pub paths: Vec<Path2>,
}

/// The execution budget rule a template's Simplicity leaves are costed under.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub per_witness_byte: u64,
    pub offset: u64,
    pub max: u64,
}

impl Budget {
    /// The budget, in weight units, a witness stack of `stack_bytes` serialized
    /// bytes earns.
    #[must_use]
    pub fn earned(&self, stack_bytes: u64) -> u64 {
        stack_bytes
            .saturating_mul(self.per_witness_byte)
            .saturating_add(self.offset)
            .min(self.max)
    }
}

/// A version 2 spending path: by a leaf, or, for the key path, by the internal key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Path2 {
    pub name: String,
    pub who: String,
    pub effect: String,
    /// The Simplicity or tapscript leaf this path spends; absent for the key path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf: Option<String>,
}

/// A version 2 Simplicity leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimplicityLeaf {
    pub source: String,
    pub source_sha256: String,
    pub compiler: Compiler,
    pub cmr: String,
    pub witness: Vec<WitnessValue>,
    /// The static cost bound of the program with every branch kept, in weight
    /// units rounded up: no spend of the leaf costs more.
    pub max_cost_wu: u64,
}

/// One item of a tapscript leaf's script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptItem {
    /// Bytes copied as they are: opcodes, and pushes of constants.
    Bytes(Vec<u8>),
    /// A push of a parameter's bytes.
    Push(String),
    /// A push of a parameter's value as a minimal script number.
    Num(String),
}

/// A node of a version 2 tree.
#[derive(Debug, Clone)]
pub enum Node {
    Branch(Box<Node>, Box<Node>),
    Simplicity {
        name: String,
        program: SimplicityLeaf,
    },
    Tapscript {
        name: String,
        items: Vec<ScriptItem>,
    },
    Data {
        name: String,
        values: Vec<String>,
    },
}

impl Node {
    fn visit<'a>(&'a self, depth: usize, f: &mut dyn FnMut(&'a Node, usize)) {
        match self {
            Node::Branch(a, b) => {
                a.visit(depth + 1, f);
                b.visit(depth + 1, f);
            }
            leaf => f(leaf, depth),
        }
    }

    /// The leaves, depth-first, left before right, with their depths.
    #[must_use]
    pub fn leaves(&self) -> Vec<(&Node, usize)> {
        let mut out = Vec::new();
        self.visit(0, &mut |n, d| out.push((n, d)));
        out
    }

    /// The leaf's name; `None` for a branch.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Node::Branch(..) => None,
            Node::Simplicity { name, .. }
            | Node::Tapscript { name, .. }
            | Node::Data { name, .. } => Some(name),
        }
    }

    /// The number of branches.
    #[must_use]
    pub fn branches(&self) -> usize {
        match self {
            Node::Branch(a, b) => 1 + a.branches() + b.branches(),
            _ => 0,
        }
    }
}

/// The largest integer a descriptor or vector file may hold, plus one. Every
/// number in these files is a non-negative integer below 2^53, the range in
/// which every JSON reader, JavaScript's included, reads the same value.
pub const INTEGER_LIMIT: u64 = 1 << 53;

/// Refuses any number that is not a non-negative integer below 2^53.
///
/// # Errors
/// Names the first such number and where it is.
pub fn check_integers(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Number(n) => match n.as_u64() {
            Some(x) if x < INTEGER_LIMIT => Ok(()),
            _ => Err(format!(
                "{at}: {n} is not an integer in [0, 2^53); descriptors hold no other number"
            )),
        },
        Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, v)| check_integers(v, &format!("{at}[{i}]"))),
        Value::Object(map) => map
            .iter()
            .try_for_each(|(k, v)| check_integers(v, &format!("{at}.{k}"))),
        _ => Ok(()),
    }
}

/// Reads JSON text, refusing an object that names one field twice: readers
/// differ on which of the two they keep, so such a file has no one meaning.
///
/// # Errors
/// When the text is not JSON, or an object repeats a field.
pub fn parse_json(text: &str) -> Result<Value, String> {
    check_json_depth(text)?;
    let mut de = serde_json::Deserializer::from_str(text);
    // The depth is bounded above, by MAX_JSON_DEPTH rather than serde_json's 128.
    de.disable_recursion_limit();
    let value = StrictValue
        .deserialize(&mut de)
        .map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// The most levels of arrays and objects a descriptor or vector file nests.
/// A tree of the greatest depth, 128, nests about 262; serde_json's own
/// limit, 128, would refuse a tree of depth 63.
pub const MAX_JSON_DEPTH: usize = 300;

/// Refuses JSON text that nests arrays and objects deeper than [`MAX_JSON_DEPTH`].
///
/// # Errors
/// When it does.
pub fn check_json_depth(text: &str) -> Result<(), String> {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(format!(
                        "the JSON nests deeper than {MAX_JSON_DEPTH} levels"
                    ));
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(StrictValue)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(format!("field {key} appears twice")));
            }
            let v = map.next_value_seed(StrictValue)?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value = parse_json(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    check_integers(&value, &path.display().to_string())?;
    Ok(value)
}

/// The roles a parameter or slot may take. `sequence` is a BIP68 relative
/// lock as its `nSequence` value: bit 22 set counts units of 512 seconds,
/// clear counts blocks.
pub const ROLES: &[&str] = &[
    "pubkey",
    "asset",
    "amount",
    "script_hash",
    "height",
    "time",
    "hash",
    "feed",
    "number",
    "sequence",
];

/// The byte width of a parameter type, or `None` for a type a descriptor does not allow.
#[must_use]
pub fn type_width(ty: &str) -> Option<usize> {
    match ty {
        "u8" => Some(1),
        "u16" => Some(2),
        "u32" => Some(4),
        "u64" => Some(8),
        "u128" => Some(16),
        "u256" | "Pubkey" => Some(32),
        _ => None,
    }
}

/// The canonical JSON of a value: object keys sorted bytewise, no whitespace.
/// Descriptors are printable ASCII, so this matches every mirror's encoder.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    // serde_json's map is ordered by key unless `preserve_order` is enabled,
    // which this crate does not enable.
    value.to_string()
}

/// SHA-256 of the template's canonical JSON, hex.
#[must_use]
pub fn template_hash(template: &Value) -> String {
    hex(sha256::Hash::hash(canonical_json(template).as_bytes()).as_ref())
}

/// The plain-tag `TapData` hash of a hidden data leaf: what `jet::tapdata_init`
/// starts and the program finishes.
#[must_use]
pub fn tapdata_hash(data: &[u8]) -> sha256::Hash {
    let tag = sha256::Hash::hash(b"TapData");
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_ref());
    engine.input(tag.as_ref());
    engine.input(data);
    sha256::Hash::from_engine(engine)
}

/// A minimal push of `v` as a script number: `OP_0`, `OP_1` to `OP_16`, or
/// the shortest little-endian form with a clear sign bit.
#[must_use]
pub fn script_num(v: u64) -> Vec<u8> {
    match v {
        0 => vec![0x00],
        1..=16 => vec![0x50 + u8::try_from(v).expect("at most 16")],
        _ => {
            let mut bytes = v.to_le_bytes().to_vec();
            while bytes.last() == Some(&0) {
                bytes.pop();
            }
            if bytes.last().is_some_and(|b| b & 0x80 != 0) {
                bytes.push(0);
            }
            let mut out = vec![u8::try_from(bytes.len()).expect("at most 9")];
            out.extend(bytes);
            out
        }
    }
}

/// Everything a version 1 instance's output is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    pub param_bytes: Vec<u8>,
    pub data_leaf: String,
    pub program_leaf: String,
    pub merkle_root: String,
    pub tweak: String,
    pub output_key: String,
    pub output_key_parity: u8,
    pub script_pubkey: String,
}

/// What a descriptor of either version says about its output: the version 2
/// model, into which a version 1 template is read as `branch(program, params)`.
#[derive(Debug, Clone)]
pub struct Model {
    pub internal_key: String,
    pub key_path: Option<String>,
    pub params: Vec<Param>,
    pub slots: Vec<Param>,
    pub budget: Budget,
    pub tree: Node,
    pub paths: Vec<Path2>,
}

/// One leaf of a derived output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeafVector {
    /// The leaf hash: a tapleaf hash, or a data leaf's `TapData` hash.
    pub hash: String,
    /// For a Simplicity or tapscript leaf: the control block that reveals it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_block: Option<String>,
    /// For a tapscript leaf: the script, its parameters in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// For a data leaf: the bytes it commits to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Everything an instance's output is made of, for a tree of any shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDerived {
    pub leaves: BTreeMap<String, LeafVector>,
    pub merkle_root: String,
    pub tweak: String,
    pub output_key: String,
    pub output_key_parity: u8,
    pub script_pubkey: String,
}

/// The bits of a BIP68 sequence a `sequence` value may set: the type flag
/// and the 16-bit lock. The disable flag, bit 31, would turn the lock off.
pub const SEQUENCE_BITS: u32 = (1 << 22) | 0xffff;

/// Refuses a value its role rules out: a `pubkey` that is no x-only point,
/// which no signature can ever satisfy, and a `sequence` with a bit outside
/// [`SEQUENCE_BITS`], whose disable flag would make a relative lock pass at once.
///
/// # Errors
/// Says which.
pub fn check_role_value(role: &str, bytes: &[u8]) -> Result<(), String> {
    match role {
        "pubkey" => XOnlyPublicKey::from_slice(bytes)
            .map(|_| ())
            .map_err(|_| "not a point".to_string()),
        "sequence" => {
            let v = u32::from_be_bytes(bytes.try_into().map_err(|_| "a sequence is 4 bytes")?);
            if v & !SEQUENCE_BITS != 0 {
                return Err(format!(
                    "sequence {v:#010x} sets a bit outside the type flag and the 16-bit lock"
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// A program's source is a file in the descriptor's own directory, so that a
/// verifier reading it never leaves that directory: letters, digits, `_` and
/// `-`, then `.simf`.
#[must_use]
pub fn source_name_ok(s: &str) -> bool {
    s.strip_suffix(".simf").is_some_and(|stem| {
        !stem.is_empty()
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Refuses a value holding a string or field name that is not printable ASCII.
///
/// # Errors
/// Names where.
pub fn printable_value(v: &Value, at: &str) -> Result<(), String> {
    match v {
        Value::String(s) if !printable(s) => Err(format!("{at}: a template is printable ASCII")),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .try_for_each(|(i, x)| printable_value(x, &format!("{at}[{i}]"))),
        Value::Object(map) => map.iter().try_for_each(|(k, x)| {
            if printable(k) {
                printable_value(x, &format!("{at}.{k}"))
            } else {
                Err(format!("{at}: a template is printable ASCII"))
            }
        }),
        _ => Ok(()),
    }
}

fn bad_name(s: &str) -> bool {
    s.is_empty() || !printable(s)
}

impl Model {
    fn field(&self, name: &str) -> Option<(&Param, bool)> {
        self.params
            .iter()
            .find(|p| p.name == name)
            .map(|p| (p, false))
            .or_else(|| {
                self.slots
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| (p, true))
            })
    }

    /// Checks everything a reader checks without a compiler.
    ///
    /// # Errors
    /// The first rule the model breaks.
    #[allow(clippy::too_many_lines)]
    pub fn check(&self) -> Result<(), String> {
        let key = unhex_exact(&self.internal_key, 32).map_err(|e| format!("internal_key: {e}"))?;
        XOnlyPublicKey::from_slice(&key).map_err(|_| "internal_key: not a point".to_string())?;
        let nums = self.internal_key == NUMS_KEY;
        match (&self.key_path, nums) {
            (None, true) => {}
            (Some(_), true) => return Err(
                "key_path is declared, but the internal key is the NUMS key, which has no key path"
                    .into(),
            ),
            (None, false) => {
                return Err(format!(
                    "internal_key {} is not the NUMS key, so the output has a key path, and the \
                     template does not declare it (key_path, and a path of that name in paths)",
                    self.internal_key
                ))
            }
            (Some(name), false) => {
                if !self.paths.iter().any(|p| &p.name == name) {
                    return Err(format!(
                        "key_path {name} is not one of the template's paths"
                    ));
                }
            }
        }

        let mut names = BTreeSet::new();
        for (p, kind) in self
            .params
            .iter()
            .map(|p| (p, "parameter"))
            .chain(self.slots.iter().map(|p| (p, "slot")))
        {
            if bad_name(&p.name) {
                return Err(format!(
                    "{kind} name {:?} is empty or not printable",
                    p.name
                ));
            }
            if !names.insert(p.name.as_str()) {
                return Err(format!("{kind} {} is named twice", p.name));
            }
            if type_width(&p.ty).is_none() {
                return Err(format!("{kind} {}: type {} is not allowed", p.name, p.ty));
            }
            if !ROLES.contains(&p.role.as_str()) {
                return Err(format!("{kind} {}: role {} is not allowed", p.name, p.role));
            }
            if p.role == "pubkey" && p.ty != "Pubkey" {
                return Err(format!("{kind} {}: a pubkey is of type Pubkey", p.name));
            }
            if p.role == "sequence" && p.ty != "u32" {
                return Err(format!("{kind} {}: a sequence is of type u32", p.name));
            }
        }

        let mut leaf_names = BTreeSet::new();
        let mut used = BTreeSet::new();
        let mut spendable = BTreeSet::new();
        for (leaf, depth) in self.tree.leaves() {
            let name = leaf.name().expect("a leaf");
            if depth > MAX_TREE_DEPTH {
                return Err(format!(
                    "leaf {name} is at depth {depth}, deeper than {MAX_TREE_DEPTH}"
                ));
            }
            if bad_name(name) {
                return Err(format!("leaf name {name:?} is empty or not printable"));
            }
            if !leaf_names.insert(name) {
                return Err(format!("leaf {name} is named twice"));
            }
            match leaf {
                Node::Data { values, .. } => {
                    if values.is_empty() {
                        return Err(format!("data leaf {name} commits to nothing"));
                    }
                    for v in values {
                        if self.field(v).is_none() {
                            return Err(format!("data leaf {name}: {v} is no parameter or slot"));
                        }
                        used.insert(v.as_str());
                    }
                }
                Node::Tapscript { items, .. } => {
                    spendable.insert(name);
                    if items.is_empty() {
                        return Err(format!("tapscript leaf {name} is empty"));
                    }
                    for item in items {
                        let (ScriptItem::Push(p) | ScriptItem::Num(p)) = item else {
                            continue;
                        };
                        let Some((param, is_slot)) = self.field(p) else {
                            return Err(format!("tapscript leaf {name}: {p} is no parameter"));
                        };
                        if is_slot {
                            return Err(format!(
                                "tapscript leaf {name}: {p} is a slot; a script holds parameters only"
                            ));
                        }
                        let width = type_width(&param.ty).expect("checked above");
                        if matches!(item, ScriptItem::Push(_)) && width < 2 {
                            return Err(format!(
                                "tapscript leaf {name}: push {p} is one byte; use num"
                            ));
                        }
                        if matches!(item, ScriptItem::Num(_)) && width > 8 {
                            return Err(format!(
                                "tapscript leaf {name}: num {p} is wider than 8 bytes"
                            ));
                        }
                        used.insert(p.as_str());
                    }
                }
                Node::Simplicity { program, .. } => {
                    spendable.insert(name);
                    let mut witness_names = BTreeSet::new();
                    for w in &program.witness {
                        if bad_name(&w.name) || !witness_names.insert(w.name.as_str()) {
                            return Err(format!(
                                "leaf {name}: witness {:?} is empty, not printable or named twice",
                                w.name
                            ));
                        }
                        self.check_witness_source(name, w)?;
                    }
                    if !source_name_ok(&program.source) {
                        return Err(format!(
                            "leaf {name}: source {:?} is not a file name of the form <name>.simf beside the descriptor",
                            program.source
                        ));
                    }
                    unhex_exact(&program.cmr, 32).map_err(|e| format!("leaf {name}: cmr: {e}"))?;
                    unhex_exact(&program.source_sha256, 32)
                        .map_err(|e| format!("leaf {name}: source_sha256: {e}"))?;
                }
                Node::Branch(..) => unreachable!("leaves only"),
            }
        }
        for p in self.params.iter().chain(&self.slots) {
            if !used.contains(p.name.as_str()) {
                return Err(format!(
                    "{} is in no leaf, so it does not change the output",
                    p.name
                ));
            }
        }

        if self.paths.is_empty() {
            return Err("the template has no path".into());
        }
        let mut path_names = BTreeSet::new();
        let mut covered = BTreeSet::new();
        for p in &self.paths {
            if bad_name(&p.name) || !path_names.insert(p.name.as_str()) {
                return Err(format!(
                    "path name {:?} is empty, not printable or used twice",
                    p.name
                ));
            }
            let is_key = self.key_path.as_deref() == Some(p.name.as_str());
            match (&p.leaf, is_key) {
                (Some(_), true) => {
                    return Err(format!("path {}: the key path spends no leaf", p.name))
                }
                (None, false) => return Err(format!("path {} names no leaf", p.name)),
                (Some(l), false) => {
                    if !spendable.contains(l.as_str()) {
                        return Err(format!(
                            "path {}: {l} is not a Simplicity or tapscript leaf",
                            p.name
                        ));
                    }
                    covered.insert(l.as_str());
                }
                (None, true) => {}
            }
        }
        if let Some(l) = spendable.iter().find(|l| !covered.contains(*l)) {
            return Err(format!("leaf {l} is spendable and no path describes it"));
        }
        Ok(())
    }

    fn check_witness_source(&self, leaf: &str, w: &WitnessValue) -> Result<(), String> {
        let bad = |why: &str| Err(format!("leaf {leaf}: witness {}: {why}", w.name));
        if w.source == "spender" {
            return Ok(());
        }
        if let Some(name) = w.source.strip_prefix("param:") {
            return match self.params.iter().find(|p| p.name == name) {
                Some(p) if p.ty == w.ty => Ok(()),
                Some(p) => bad(&format!("type {} is not the parameter's {}", w.ty, p.ty)),
                None => bad(&format!("{name} is no parameter")),
            };
        }
        if let Some(name) = w.source.strip_prefix("slot:") {
            return match self.slots.iter().find(|p| p.name == name) {
                Some(p) if p.ty == w.ty => Ok(()),
                Some(p) => bad(&format!("type {} is not the slot's {}", w.ty, p.ty)),
                None => bad(&format!("{name} is no slot")),
            };
        }
        if let Some(name) = w.source.strip_prefix("signature:sig_all_hash:") {
            return match self.params.iter().find(|p| p.name == name) {
                Some(p) if p.ty == "Pubkey" && w.ty == "Signature" => Ok(()),
                Some(_) => bad("a signature is of type Signature, by a Pubkey parameter"),
                None => bad(&format!("{name} is no parameter")),
            };
        }
        bad(&format!(
            "source {} is not one the specification lists",
            w.source
        ))
    }

    fn bytes_of(&self, name: &str, values: &BTreeMap<String, String>) -> Result<Vec<u8>, String> {
        let (p, _) = self
            .field(name)
            .ok_or_else(|| format!("{name} is unknown"))?;
        let width = type_width(&p.ty).ok_or_else(|| format!("type {}", p.ty))?;
        let value = values
            .get(name)
            .ok_or_else(|| format!("{name} is missing"))?;
        let bytes = unhex_exact(value, width).map_err(|e| format!("{name}: {e}"))?;
        check_role_value(&p.role, &bytes).map_err(|e| format!("{name}: {e}"))?;
        Ok(bytes)
    }

    /// The script of a tapscript leaf with its parameters in place.
    ///
    /// # Errors
    /// When a parameter is missing or not of its width.
    pub fn script(
        &self,
        items: &[ScriptItem],
        values: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for item in items {
            match item {
                ScriptItem::Bytes(b) => out.extend_from_slice(b),
                ScriptItem::Push(p) => {
                    let b = self.bytes_of(p, values)?;
                    out.push(u8::try_from(b.len()).map_err(|e| e.to_string())?);
                    out.extend(b);
                }
                ScriptItem::Num(p) => {
                    let b = self.bytes_of(p, values)?;
                    let v = b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
                    out.extend(script_num(v));
                }
            }
        }
        Ok(out)
    }

    /// The bytes a data leaf commits to.
    ///
    /// # Errors
    /// When a value is missing or not of its width.
    pub fn data(
        &self,
        names: &[String],
        values: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for n in names {
            out.extend(self.bytes_of(n, values)?);
        }
        Ok(out)
    }

    /// The output of an instance: `params` and `slots` give each value by name,
    /// lowercase hex of exactly its type's width. Computed with `elements`'
    /// taproot builder.
    ///
    /// # Errors
    /// When a value is missing, extra or of the wrong width, a key is invalid,
    /// or two spendable leaves have one script.
    pub fn derive(
        &self,
        params: &BTreeMap<String, String>,
        slots: &BTreeMap<String, String>,
    ) -> Result<TreeDerived, String> {
        let want: BTreeSet<&str> = self.params.iter().map(|p| p.name.as_str()).collect();
        let got: BTreeSet<&str> = params.keys().map(String::as_str).collect();
        if want != got {
            return Err(format!(
                "parameters given {got:?}, the template has {want:?}"
            ));
        }
        let want: BTreeSet<&str> = self.slots.iter().map(|p| p.name.as_str()).collect();
        let got: BTreeSet<&str> = slots.keys().map(String::as_str).collect();
        if want != got {
            return Err(format!("slots given {got:?}, the template has {want:?}"));
        }
        let mut values = params.clone();
        values.extend(slots.iter().map(|(k, v)| (k.clone(), v.clone())));

        let internal = XOnlyPublicKey::from_slice(&unhex_exact(&self.internal_key, 32)?)
            .map_err(|e| format!("internal_key: {e}"))?;
        let mut builder = TaprootBuilder::new();
        let mut scripts: Vec<(String, Script, LeafVersion)> = Vec::new();
        let mut leaves = BTreeMap::new();
        for (leaf, depth) in self.tree.leaves() {
            match leaf {
                Node::Data {
                    name,
                    values: names,
                } => {
                    let bytes = self.data(names, &values)?;
                    let h = tapdata_hash(&bytes);
                    builder = builder.add_hidden(depth, h).map_err(|e| e.to_string())?;
                    leaves.insert(
                        name.clone(),
                        LeafVector {
                            hash: hex(h.as_ref()),
                            control_block: None,
                            script: None,
                            data: Some(hex(&bytes)),
                        },
                    );
                }
                Node::Simplicity { name, program } => {
                    let version =
                        LeafVersion::from_u8(LEAF_VERSION_SIMPLICITY).map_err(|e| e.to_string())?;
                    let script = Script::from(unhex_exact(&program.cmr, 32)?);
                    builder = builder
                        .add_leaf_with_ver(depth, script.clone(), version)
                        .map_err(|e| e.to_string())?;
                    scripts.push((name.clone(), script, version));
                }
                Node::Tapscript { name, items } => {
                    let version =
                        LeafVersion::from_u8(LEAF_VERSION_TAPSCRIPT).map_err(|e| e.to_string())?;
                    let script = Script::from(self.script(items, &values)?);
                    builder = builder
                        .add_leaf_with_ver(depth, script.clone(), version)
                        .map_err(|e| e.to_string())?;
                    scripts.push((name.clone(), script, version));
                }
                Node::Branch(..) => unreachable!("leaves only"),
            }
        }
        for (i, (a, sa, va)) in scripts.iter().enumerate() {
            if let Some((b, ..)) = scripts[i + 1..]
                .iter()
                .find(|(_, sb, vb)| sb == sa && vb == va)
            {
                return Err(format!(
                    "leaves {a} and {b} are one script at one leaf version, so no control block \
                     tells them apart"
                ));
            }
        }
        let secp = Secp256k1::verification_only();
        let info = builder
            .finalize(&secp, internal)
            .map_err(|e| format!("the tree is incomplete: {e}"))?;
        for (name, script, version) in scripts {
            let cb = info
                .control_block(&(script.clone(), version))
                .ok_or("a leaf is missing from its tree")?;
            let is_tapscript = version.as_u8() == LEAF_VERSION_TAPSCRIPT;
            leaves.insert(
                name,
                LeafVector {
                    hash: hex(TapLeafHash::from_script(&script, version).as_ref()),
                    control_block: Some(hex(&cb.serialize())),
                    script: is_tapscript.then(|| hex(script.as_bytes())),
                    data: None,
                },
            );
        }
        let output_key = info.output_key();
        let script_pubkey = Script::new_v1_p2tr_tweaked(output_key);
        Ok(TreeDerived {
            leaves,
            merkle_root: hex(info.merkle_root().ok_or("no merkle root")?.as_ref()),
            tweak: hex(info.tap_tweak().as_ref()),
            output_key: hex(&output_key.into_inner().serialize()),
            output_key_parity: u8::from(info.output_key_parity() == Parity::Odd),
            script_pubkey: hex(script_pubkey.as_bytes()),
        })
    }
}

/// Reads a version 2 tree node.
///
/// # Errors
/// When the node is not a branch of exactly two nodes or a leaf of exactly one kind.
pub fn parse_node(v: &Value, depth: usize, at: &str) -> Result<Node, String> {
    const KINDS: [&str; 3] = ["simplicity", "tapscript", "data"];
    if depth > MAX_TREE_DEPTH {
        return Err(format!("{at}: the tree is deeper than {MAX_TREE_DEPTH}"));
    }
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{at} is not an object"))?;
    if let Some(children) = obj.get("branch") {
        if let Some(k) = obj.keys().find(|k| *k != "branch") {
            return Err(format!("{at}: unknown field {k}"));
        }
        let children = children
            .as_array()
            .filter(|a| a.len() == 2)
            .ok_or_else(|| format!("{at}.branch is not an array of two nodes"))?;
        return Ok(Node::Branch(
            Box::new(parse_node(
                &children[0],
                depth + 1,
                &format!("{at}.branch[0]"),
            )?),
            Box::new(parse_node(
                &children[1],
                depth + 1,
                &format!("{at}.branch[1]"),
            )?),
        ));
    }
    if let Some(k) = obj
        .keys()
        .find(|k| *k != "leaf" && !KINDS.contains(&k.as_str()))
    {
        return Err(format!("{at}: unknown field {k}"));
    }
    let name = obj
        .get("leaf")
        .ok_or_else(|| format!("{at}: missing field leaf"))?
        .as_str()
        .ok_or_else(|| format!("{at}.leaf is not a string"))?
        .to_string();
    let kinds: Vec<&str> = KINDS.into_iter().filter(|k| obj.contains_key(*k)).collect();
    if kinds.len() != 1 {
        return Err(format!(
            "{at}: a leaf has exactly one of simplicity, tapscript and data"
        ));
    }
    match kinds[0] {
        "simplicity" => {
            let program: SimplicityLeaf = serde_json::from_value(obj["simplicity"].clone())
                .map_err(|e| format!("{at}.simplicity: {e}"))?;
            Ok(Node::Simplicity { name, program })
        }
        "tapscript" => {
            let items = obj["tapscript"]
                .as_array()
                .ok_or_else(|| format!("{at}.tapscript is not an array"))?;
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let iat = format!("{at}.tapscript[{i}]");
                out.push(match item {
                    Value::String(s) => {
                        let b = unhex(s).map_err(|e| format!("{iat}: {e}"))?;
                        if b.is_empty() {
                            return Err(format!("{iat}: empty"));
                        }
                        ScriptItem::Bytes(b)
                    }
                    Value::Object(m) if m.len() == 1 => {
                        let (k, v) = m.iter().next().expect("one entry");
                        let p = v
                            .as_str()
                            .ok_or_else(|| format!("{iat}.{k} is not a string"))?
                            .to_string();
                        match k.as_str() {
                            "push" => ScriptItem::Push(p),
                            "num" => ScriptItem::Num(p),
                            _ => return Err(format!("{iat}: unknown field {k}")),
                        }
                    }
                    _ => {
                        return Err(format!(
                            "{iat}: an item is hex, {{\"push\": P}} or {{\"num\": P}}"
                        ))
                    }
                });
            }
            Ok(Node::Tapscript { name, items: out })
        }
        _ => {
            let values = obj["data"]
                .as_array()
                .ok_or_else(|| format!("{at}.data is not an array"))?
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("{at}.data holds a value that is not a name"))?;
            Ok(Node::Data { name, values })
        }
    }
}

impl Descriptor {
    /// Reads a descriptor file.
    ///
    /// # Errors
    /// When the file cannot be read or is not a descriptor.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::from_value(read_json(path)?).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Reads a descriptor from JSON text.
    ///
    /// # Errors
    /// When the text is not a descriptor.
    pub fn parse(text: &str) -> Result<Self, String> {
        let value = parse_json(text)?;
        check_integers(&value, "descriptor")?;
        Self::from_value(value)
    }

    fn from_value(value: Value) -> Result<Self, String> {
        let d: Self = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if !DESCRIPTOR_VERSIONS.contains(&d.descriptor) {
            return Err(format!("descriptor version {} is not 1 or 2", d.descriptor));
        }
        Ok(d)
    }

    /// The typed version 1 template.
    ///
    /// # Errors
    /// When the descriptor is not version 1 or the template does not have its shape.
    pub fn typed(&self) -> Result<Template, String> {
        if self.descriptor != 1 {
            return Err(format!("descriptor version {} is not 1", self.descriptor));
        }
        serde_json::from_value(self.template.clone()).map_err(|e| format!("template: {e}"))
    }

    /// The typed version 2 template.
    ///
    /// # Errors
    /// When the descriptor is not version 2 or the template does not have its shape.
    pub fn typed_v2(&self) -> Result<TemplateV2, String> {
        if self.descriptor != 2 {
            return Err(format!("descriptor version {} is not 2", self.descriptor));
        }
        serde_json::from_value(self.template.clone()).map_err(|e| format!("template: {e}"))
    }

    /// The output the template describes. A version 1 template is the tree
    /// `branch(program, params)`: its program the leaf [`V1_PROGRAM_LEAF`],
    /// its parameters, in order, the data leaf [`V1_DATA_LEAF`], and every path
    /// but the key path a spend of the program.
    ///
    /// # Errors
    /// When the template does not have its version's shape.
    pub fn model(&self) -> Result<Model, String> {
        if self.descriptor == 1 {
            let t = self.typed()?;
            if t.layout != LAYOUT_FIXED_ROOT {
                return Err(format!("layout {} is not {LAYOUT_FIXED_ROOT}", t.layout));
            }
            let program = SimplicityLeaf {
                source: t.program.source,
                source_sha256: t.program.source_sha256,
                compiler: t.program.compiler,
                cmr: t.program.cmr,
                witness: t.program.witness,
                max_cost_wu: 0,
            };
            let names = t.params.iter().map(|p| p.name.clone()).collect();
            let key_path = t.key_path.clone();
            return Ok(Model {
                internal_key: t.internal_key,
                paths: t
                    .paths
                    .into_iter()
                    .map(|p| Path2 {
                        leaf: (key_path.as_deref() != Some(p.name.as_str()))
                            .then(|| V1_PROGRAM_LEAF.to_string()),
                        name: p.name,
                        who: p.who,
                        effect: p.effect,
                    })
                    .collect(),
                key_path: t.key_path,
                params: t.params,
                slots: Vec::new(),
                budget: SEQUENTIA_BUDGET,
                tree: Node::Branch(
                    Box::new(Node::Simplicity {
                        name: V1_PROGRAM_LEAF.into(),
                        program,
                    }),
                    Box::new(Node::Data {
                        name: V1_DATA_LEAF.into(),
                        values: names,
                    }),
                ),
            });
        }
        let t = self.typed_v2()?;
        Ok(Model {
            internal_key: t.internal_key,
            key_path: t.key_path,
            params: t.params,
            slots: t.slots,
            budget: t.budget,
            tree: parse_node(&t.tree, 0, "template.tree")?,
            paths: t.paths,
        })
    }

    /// The version 2 template a version 1 template is: the same tree written
    /// out, so the same addresses. `dir` is the descriptor's directory; the
    /// program is compiled for its cost bound.
    ///
    /// # Errors
    /// When the descriptor is not version 1, or its program does not compile.
    pub fn as_v2(&self, dir: &Path) -> Result<Value, String> {
        let t = self.typed()?;
        let program = compile_leaf_source(dir, &t.program.source)?;
        let mut leaf = serde_json::to_value(&t.program).map_err(|e| e.to_string())?;
        leaf["max_cost_wu"] = max_cost_wu(&program)?.into();
        let names: Vec<String> = t.params.iter().map(|p| p.name.clone()).collect();
        let mut v = serde_json::json!({
            "name": t.name,
            "version": t.version,
            "summary": t.summary,
            "internal_key": t.internal_key,
            "params": t.params,
            "slots": [],
            "budget": SEQUENTIA_BUDGET,
            "tree": {"branch": [
                {"leaf": V1_PROGRAM_LEAF, "simplicity": leaf},
                {"leaf": V1_DATA_LEAF, "data": names},
            ]},
            "paths": self.model()?.paths,
        });
        if let Some(k) = t.key_path {
            v["key_path"] = k.into();
        }
        Ok(v)
    }

    /// Checks everything that can be checked without a chain: the version, the
    /// template hash, printable-ASCII text, the tree, the parameter and slot
    /// types and roles, the paths, and, by compiling each source with the pinned
    /// compiler, each program's source hash, compiler, commitment root, lints,
    /// and in version 2 its witness and cost bound.
    ///
    /// `dir` is the directory the descriptor sits in.
    ///
    /// # Errors
    /// The first check that fails.
    pub fn validate(&self, dir: &Path) -> Result<(), String> {
        self.validate_with(&mut |source| {
            let path = dir.join(source);
            let raw =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            crate::expand(&raw)
        })
    }

    /// [`Descriptor::validate`] with no file system: `sources` maps each
    /// Simplicity leaf's `source` name to its text with the helper includes
    /// already resolved, exactly what `seqc expand` prints and what
    /// `source_sha256` hashes. This is how a wallet or a browser, which has no
    /// directory and no helpers, checks a template it was handed: the same
    /// checks, the same compiler, the same refusals.
    ///
    /// # Errors
    /// The first check that fails; a source missing from `sources` is one.
    pub fn validate_sources(&self, sources: &BTreeMap<String, String>) -> Result<(), String> {
        self.validate_with(&mut |source| {
            sources
                .get(source)
                .cloned()
                .ok_or_else(|| format!("no text given for the source {source}"))
        })
    }

    fn validate_with(
        &self,
        read: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> Result<(), String> {
        if !DESCRIPTOR_VERSIONS.contains(&self.descriptor) {
            return Err(format!(
                "descriptor version {} is not 1 or 2",
                self.descriptor
            ));
        }
        check_integers(&self.template, "template")?;
        // Every string and field name as read. The canonical text alone would
        // pass a tab, which it writes as the two printable characters `\t`,
        // and encoders differ on how they write some control characters.
        printable_value(&self.template, "template")?;
        let hash = template_hash(&self.template);
        if hash != self.template_hash {
            return Err(format!(
                "template_hash is {}, the template hashes to {hash}",
                self.template_hash
            ));
        }
        for c in &self.chains {
            if let Some(g) = &c.genesis {
                unhex_exact(g, 32).map_err(|e| format!("chain {}: genesis: {e}", c.name))?;
            }
        }
        let model = self.model()?;
        model.check()?;
        if self.descriptor == 2 && model.budget != SEQUENTIA_BUDGET {
            return Err(format!(
                "budget {:?} is not the rule a Sequentia node applies, {SEQUENTIA_BUDGET:?}",
                model.budget
            ));
        }
        for (leaf, _) in model.tree.leaves() {
            if let Node::Simplicity { name, program } = leaf {
                check_simplicity_leaf(read, program, self.descriptor == 2)
                    .map_err(|e| format!("leaf {name}: {e}"))?;
            }
        }
        Ok(())
    }

    /// The data leaf's bytes for these parameter values, for a version 1
    /// template: each parameter's value, big-endian at its type's width, in
    /// the template's order.
    ///
    /// # Errors
    /// When a parameter is missing or extra, or a value is not hex of its width.
    pub fn param_bytes(&self, params: &BTreeMap<String, String>) -> Result<Vec<u8>, String> {
        let t = self.typed()?;
        if params.len() != t.params.len() {
            return Err(format!(
                "{} parameters given, the template has {}",
                params.len(),
                t.params.len()
            ));
        }
        let mut out = Vec::new();
        for p in &t.params {
            let value = params
                .get(&p.name)
                .ok_or_else(|| format!("parameter {} is missing", p.name))?;
            let width = type_width(&p.ty).ok_or_else(|| format!("type {}", p.ty))?;
            let bytes = unhex(value)?;
            if bytes.len() != width {
                return Err(format!(
                    "parameter {} is {} bytes, its type {} is {width}",
                    p.name,
                    bytes.len(),
                    p.ty
                ));
            }
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// The output of a version 1 instance.
    ///
    /// # Errors
    /// When the parameters are wrong or a key is invalid.
    pub fn derive(&self, params: &BTreeMap<String, String>) -> Result<Derived, String> {
        let param_bytes = self.param_bytes(params)?;
        let x = self.model()?.derive(params, &BTreeMap::new())?;
        Ok(Derived {
            param_bytes,
            data_leaf: x.leaves[V1_DATA_LEAF].hash.clone(),
            program_leaf: x.leaves[V1_PROGRAM_LEAF].hash.clone(),
            merkle_root: x.merkle_root,
            tweak: x.tweak,
            output_key: x.output_key,
            output_key_parity: x.output_key_parity,
            script_pubkey: x.script_pubkey,
        })
    }

    /// The address of an output key on each of the descriptor's chains.
    ///
    /// # Errors
    /// When a chain's prefix is not a bech32 prefix.
    pub fn addresses(&self, output_key: &str) -> Result<BTreeMap<String, String>, String> {
        let mut out = BTreeMap::new();
        for c in &self.chains {
            let a = address(output_key, &c.bech32_hrp)
                .ok_or_else(|| format!("chain {}: bad prefix {}", c.name, c.bech32_hrp))?;
            out.insert(c.name.clone(), a);
        }
        Ok(out)
    }
}

/// Compiles a leaf's source, with its helper includes resolved, with no arguments.
///
/// # Errors
/// When the source cannot be read or does not compile.
pub fn compile_leaf_source(
    dir: &Path,
    source: &str,
) -> Result<simplicityhl::CompiledProgram, String> {
    let path = dir.join(source);
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = crate::expand(&raw)?;
    compile(&text, simplicityhl::Arguments::default())
        .map_err(|e| format!("the source does not compile without parameters: {e}"))
}

/// The static cost bound, in weight units rounded up, of a program with every
/// branch kept: an upper bound on every pruned spend of it. Witness values do
/// not change the bound, so each is given its all-zero value.
///
/// # Errors
/// When the program cannot be given witness values of its declared types.
pub fn max_cost_wu(program: &simplicityhl::CompiledProgram) -> Result<u64, String> {
    use simplicityhl::types::StructuralType;
    use simplicityhl::value::StructuralValue;
    use simplicityhl::Value as HlValue;

    let mut map = std::collections::HashMap::new();
    for (name, ty) in program.witness_types().iter() {
        let structural = StructuralType::from(ty);
        let zero = simplicityhl::simplicity::Value::zero(structural.as_ref());
        let value = HlValue::reconstruct(&StructuralValue::from(zero), ty).ok_or_else(|| {
            format!(
                "witness {}: no all-zero value of its type",
                name.as_ref() as &str
            )
        })?;
        map.insert(name.shallow_clone(), value);
    }
    let satisfied = program.satisfy(simplicityhl::WitnessValues::from(map))?;
    let cost = format!("{:?}", satisfied.redeem().bounds().cost);
    let milli: u64 = cost
        .trim_start_matches("Cost(")
        .trim_end_matches(')')
        .parse()
        .map_err(|e| format!("cost {cost}: {e}"))?;
    Ok(milli.div_ceil(1000))
}

fn check_simplicity_leaf(
    read: &mut dyn FnMut(&str) -> Result<String, String>,
    p: &SimplicityLeaf,
    v2: bool,
) -> Result<(), String> {
    use simplicityhl::parse::ParseFromStr;
    use simplicityhl::types::ResolvedType;

    if p.compiler
        != (Compiler {
            name: "simplicityhl".into(),
            version: COMPILER_VERSION.into(),
        })
    {
        return Err(format!(
            "compiled with {} {}; this repository pins simplicityhl {COMPILER_VERSION}",
            p.compiler.name, p.compiler.version
        ));
    }
    let text = read(&p.source)?;
    let source_hash = hex(sha256::Hash::hash(text.as_bytes()).as_ref());
    if source_hash != p.source_sha256 {
        return Err(format!(
            "source_sha256 is {}, the source with its includes resolved hashes to {source_hash}",
            p.source_sha256
        ));
    }
    // The text is already resolved: compiling it reads no helper file.
    let program = crate::compile_expanded(&text, simplicityhl::Arguments::default())
        .map_err(|e| format!("the source does not compile without parameters: {e}"))?;
    let cmr = cmr_hex(&program);
    if cmr != p.cmr {
        return Err(format!("cmr is {}, the source compiles to {cmr}", p.cmr));
    }
    let report = crate::lint::lint_expanded(&text);
    if !report.is_clean() {
        return Err(format!("the source fails the lints: {:?}", report.findings));
    }
    if !v2 {
        return Ok(());
    }
    // The witness the descriptor lists is the one the program declares.
    let declared: BTreeMap<String, &ResolvedType> = program
        .witness_types()
        .iter()
        .map(|(n, t)| ((n.as_ref() as &str).to_string(), t))
        .collect();
    let listed: BTreeSet<&str> = p.witness.iter().map(|w| w.name.as_str()).collect();
    let names: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
    if listed != names {
        return Err(format!(
            "witness lists {listed:?}; the program declares {names:?}"
        ));
    }
    for w in &p.witness {
        let ty = ResolvedType::parse_from_str(&w.ty)
            .map_err(|e| format!("witness {}: type {}: {e}", w.name, w.ty))?;
        let have = declared[&w.name];
        if &ty != have {
            return Err(format!(
                "witness {}: type {} is not the program's {have}",
                w.name, w.ty
            ));
        }
    }
    let bound = max_cost_wu(&program)?;
    if bound != p.max_cost_wu {
        return Err(format!(
            "max_cost_wu is {}, the program's cost bound is {bound}",
            p.max_cost_wu
        ));
    }
    Ok(())
}

/// The unblinded address of an output key on a chain with this bech32 prefix.
#[must_use]
pub fn address(output_key_hex: &str, hrp: &str) -> Option<String> {
    let key = XOnlyPublicKey::from_str(output_key_hex).ok()?;
    let hrp = simplicityhl::elements::bitcoin::bech32::Hrp::parse(hrp).ok()?;
    // Address parameters are 'static; the bech32 prefix is the only field an
    // unblinded segwit address reads.
    let params: &'static AddressParams = Box::leak(Box::new(AddressParams {
        p2pkh_prefix: 0,
        p2sh_prefix: 0,
        blinded_prefix: 0,
        bech_hrp: hrp,
        blech_hrp: hrp,
    }));
    let tweaked = simplicityhl::elements::schnorr::TapTweak::dangerous_assume_tweaked(key);
    Some(Address::p2tr_tweaked(tweaked, None, params).to_string())
}

/// A version 1 golden-vector file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Vectors {
    /// Always [`VECTORS_V1`].
    pub vectors: u64,
    pub template_hash: String,
    pub cmr: String,
    pub addresses: Vec<AddressVector>,
}

/// One version 1 instance and everything its output is made of.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddressVector {
    pub name: String,
    pub params: BTreeMap<String, String>,
    pub param_bytes: String,
    pub data_leaf: String,
    pub program_leaf: String,
    pub merkle_root: String,
    pub tweak: String,
    pub output_key: String,
    pub output_key_parity: u8,
    pub script_pubkey: String,
    /// The address on each of the descriptor's chains, by chain name.
    pub address: BTreeMap<String, String>,
}

impl Vectors {
    /// Reads a version 1 golden-vector file.
    ///
    /// # Errors
    /// When the file cannot be read or is not a version 1 vector file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let v: Self = serde_json::from_value(read_json(path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if v.vectors != VECTORS_V1 {
            return Err(format!(
                "{}: vectors version {} is not 1",
                path.display(),
                v.vectors
            ));
        }
        Ok(v)
    }

    /// Recomputes every derived field from each vector's name and parameters.
    ///
    /// # Errors
    /// When a vector's parameters do not fit the template.
    pub fn regenerate(&self, d: &Descriptor) -> Result<Self, String> {
        let t = d.typed()?;
        let mut addresses = Vec::new();
        for v in &self.addresses {
            let x = d.derive(&v.params)?;
            addresses.push(AddressVector {
                name: v.name.clone(),
                params: v.params.clone(),
                param_bytes: hex(&x.param_bytes),
                address: d.addresses(&x.output_key)?,
                data_leaf: x.data_leaf,
                program_leaf: x.program_leaf,
                merkle_root: x.merkle_root,
                tweak: x.tweak,
                output_key: x.output_key,
                output_key_parity: x.output_key_parity,
                script_pubkey: x.script_pubkey,
            });
        }
        Ok(Vectors {
            vectors: VECTORS_V1,
            template_hash: d.template_hash.clone(),
            cmr: t.program.cmr,
            addresses,
        })
    }
}

/// A version 2 golden-vector file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VectorsV2 {
    /// Always [`VECTORS_V2`].
    pub vectors: u64,
    pub template_hash: String,
    pub addresses: Vec<TreeVector>,
}

/// One version 2 instance and everything its output is made of.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreeVector {
    pub name: String,
    pub params: BTreeMap<String, String>,
    pub slots: BTreeMap<String, String>,
    /// Every leaf, by name.
    pub leaves: BTreeMap<String, LeafVector>,
    pub merkle_root: String,
    pub tweak: String,
    pub output_key: String,
    pub output_key_parity: u8,
    pub script_pubkey: String,
    pub address: BTreeMap<String, String>,
}

impl VectorsV2 {
    /// Reads a version 2 golden-vector file.
    ///
    /// # Errors
    /// When the file cannot be read or is not a version 2 vector file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let v: Self = serde_json::from_value(read_json(path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if v.vectors != VECTORS_V2 {
            return Err(format!(
                "{}: vectors version {} is not 2",
                path.display(),
                v.vectors
            ));
        }
        Ok(v)
    }

    /// Recomputes every derived field from each vector's name, parameters and slots.
    ///
    /// # Errors
    /// When a vector's values do not fit the template.
    pub fn regenerate(&self, d: &Descriptor) -> Result<Self, String> {
        let model = d.model()?;
        let mut addresses = Vec::new();
        for v in &self.addresses {
            let x = model.derive(&v.params, &v.slots)?;
            addresses.push(TreeVector {
                name: v.name.clone(),
                params: v.params.clone(),
                slots: v.slots.clone(),
                address: d.addresses(&x.output_key)?,
                leaves: x.leaves,
                merkle_root: x.merkle_root,
                tweak: x.tweak,
                output_key: x.output_key,
                output_key_parity: x.output_key_parity,
                script_pubkey: x.script_pubkey,
            });
        }
        Ok(VectorsV2 {
            vectors: VECTORS_V2,
            template_hash: d.template_hash.clone(),
            addresses,
        })
    }
}

/// Lowercase hex of exactly `width` bytes.
///
/// # Errors
/// When the text is not lowercase hex, or not of that width.
pub fn unhex_exact(s: &str, width: usize) -> Result<Vec<u8>, String> {
    let b = unhex(s)?;
    if b.len() != width {
        return Err(format!("{} bytes where {width} are needed", b.len()));
    }
    Ok(b)
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("not lowercase hex: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_numbers_are_minimal() {
        assert_eq!(script_num(0), vec![0x00]);
        assert_eq!(script_num(1), vec![0x51]);
        assert_eq!(script_num(16), vec![0x60]);
        assert_eq!(script_num(17), vec![0x01, 0x11]);
        assert_eq!(script_num(0x7f), vec![0x01, 0x7f]);
        assert_eq!(script_num(0x80), vec![0x02, 0x80, 0x00]);
        assert_eq!(script_num(0x0040_0000 | 7), vec![0x03, 0x07, 0x00, 0x40]);
        assert_eq!(
            script_num(0xffff_ffff),
            vec![0x05, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
        assert_eq!(
            script_num(u64::MAX),
            vec![0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
    }

    #[test]
    fn a_repeated_field_is_refused() {
        assert!(parse_json(r#"{"a": 1, "a": 1}"#)
            .unwrap_err()
            .contains("twice"));
        assert!(parse_json(r#"{"a": {"b": 1, "b": 2}}"#)
            .unwrap_err()
            .contains("twice"));
        assert!(parse_json(r#"[{"b": 1}, {"b": 2}]"#).is_ok());
        assert!(parse_json(r#"{"a": 1} x"#).is_err());
    }
}
