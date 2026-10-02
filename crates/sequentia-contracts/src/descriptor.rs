//! Contract descriptors, version 1, and the golden vectors that pin them.
//!
//! A descriptor names a contract template: its program (source, source hash, the
//! pinned compiler, the commitment root), its parameters with their types and
//! roles, its taproot layout and its spending paths. `docs/descriptor.md` is the
//! specification; this module is its reference implementation.
//!
//! Version 1 has one layout, the fixed root: the program takes no compile-time
//! parameter, so its commitment root is one constant per template, and the
//! parameters sit in a hidden data leaf beside it,
//!
//! ```text
//! P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
//! ```
//!
//! An instance's output is therefore computed from its parameters with one hash
//! and one curve tweak. This module computes it with the `elements` crate's own
//! taproot builder; the mirrors in `mirrors/` compute it from first principles,
//! and every implementation is checked against the same golden vectors.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use simplicityhl::elements::bitcoin::key::XOnlyPublicKey;
use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::secp256k1_zkp::{Parity, Secp256k1};
use simplicityhl::elements::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use simplicityhl::elements::{Address, AddressParams, Script};

use crate::{cmr_hex, compile, hex, COMPILER_VERSION};

/// The descriptor format version this module reads and writes.
pub const DESCRIPTOR_VERSION: u64 = 1;
/// The golden-vector format version this module reads and writes.
pub const VECTORS_VERSION: u64 = 1;
/// The only layout of version 1.
pub const LAYOUT_FIXED_ROOT: &str = "fixed-root";
/// The taproot leaf version of a Simplicity program.
pub const LEAF_VERSION_SIMPLICITY: u8 = 0xbe;
/// BIP341's nothing-up-my-sleeve point: no known discrete logarithm, so no key path.
pub const NUMS_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// A descriptor file: the template, its hash, the chains it is addressed on,
/// and what was measured of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Always [`DESCRIPTOR_VERSION`].
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

/// The template's Simplicity program.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessValue {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// `param:<NAME>`, `signature:sig_all_hash:<NAME>`, or `spender`.
    pub source: String,
}

/// A template parameter. Parameters are committed in the data leaf, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// What the value means: `pubkey`, `asset`, `amount`, `script_hash`,
    /// `height`, `time`, `hash`, `feed` or `number`.
    pub role: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendPath {
    pub name: String,
    pub who: String,
    pub effect: String,
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

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    check_integers(&value, &path.display().to_string())?;
    Ok(value)
}

/// The roles a parameter may take.
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
];

/// The byte width of a parameter type, or `None` for a type version 1 does not allow.
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

/// Everything an instance's output is made of.
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

impl Descriptor {
    /// Reads a descriptor file.
    ///
    /// # Errors
    /// When the file cannot be read or is not a descriptor.
    pub fn load(path: &Path) -> Result<Self, String> {
        serde_json::from_value(read_json(path)?).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The typed template.
    ///
    /// # Errors
    /// When the template does not have version 1's shape.
    pub fn typed(&self) -> Result<Template, String> {
        serde_json::from_value(self.template.clone()).map_err(|e| format!("template: {e}"))
    }

    /// Checks everything that can be checked without a chain: the version, the
    /// template hash, printable-ASCII text, the layout, the parameter types and
    /// roles, and, by compiling the source with the pinned compiler, the source
    /// hash, the compiler version and the commitment root.
    ///
    /// `dir` is the directory the descriptor sits in.
    ///
    /// # Errors
    /// The first check that fails.
    pub fn validate(&self, dir: &Path) -> Result<(), String> {
        if self.descriptor != DESCRIPTOR_VERSION {
            return Err(format!(
                "descriptor version {} is not {DESCRIPTOR_VERSION}",
                self.descriptor
            ));
        }
        check_integers(&self.template, "template")?;
        let text = canonical_json(&self.template);
        if !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err("a template is printable ASCII".into());
        }
        let hash = template_hash(&self.template);
        if hash != self.template_hash {
            return Err(format!(
                "template_hash is {}, the template hashes to {hash}",
                self.template_hash
            ));
        }
        let t = self.typed()?;
        if t.layout != LAYOUT_FIXED_ROOT {
            return Err(format!("layout {} is not {LAYOUT_FIXED_ROOT}", t.layout));
        }
        XOnlyPublicKey::from_str(&t.internal_key).map_err(|e| format!("internal_key: {e}"))?;
        // An output has a key path unless its internal key is one nobody can
        // sign for. A template either uses the NUMS key, or names the key path
        // and describes it among its paths, so that a wallet shows it.
        match (&t.key_path, t.internal_key == NUMS_KEY) {
            (None, true) => {}
            (Some(_), true) => {
                return Err(
                    "key_path is declared, but the internal key is the NUMS key, which \
                            has no key path"
                        .into(),
                )
            }
            (None, false) => {
                return Err(format!(
                    "internal_key {} is not the NUMS key, so the output has a key path, and the \
                     template does not declare it (key_path, and a path of that name in paths)",
                    t.internal_key
                ))
            }
            (Some(name), false) => {
                if !t.paths.iter().any(|p| &p.name == name) {
                    return Err(format!(
                        "key_path {name} is not one of the template's paths"
                    ));
                }
            }
        }
        for p in &t.params {
            if type_width(&p.ty).is_none() {
                return Err(format!(
                    "parameter {}: type {} is not allowed",
                    p.name, p.ty
                ));
            }
            if !ROLES.contains(&p.role.as_str()) {
                return Err(format!(
                    "parameter {}: role {} is not allowed",
                    p.name, p.role
                ));
            }
        }
        if t.program.compiler
            != (Compiler {
                name: "simplicityhl".into(),
                version: COMPILER_VERSION.into(),
            })
        {
            return Err(format!(
                "compiled with {} {}; this repository pins simplicityhl {COMPILER_VERSION}",
                t.program.compiler.name, t.program.compiler.version
            ));
        }
        let source_path = self.source_path(dir, &t);
        let raw = std::fs::read_to_string(&source_path)
            .map_err(|e| format!("{}: {e}", source_path.display()))?;
        let text = crate::expand(&raw)?;
        let source_hash = hex(sha256::Hash::hash(text.as_bytes()).as_ref());
        if source_hash != t.program.source_sha256 {
            return Err(format!(
                "source_sha256 is {}, the source with its includes resolved hashes to {source_hash}",
                t.program.source_sha256
            ));
        }
        let program = compile(&text, simplicityhl::Arguments::default())
            .map_err(|e| format!("the source does not compile without parameters: {e}"))?;
        let cmr = cmr_hex(&program);
        if cmr != t.program.cmr {
            return Err(format!(
                "cmr is {}, the source compiles to {cmr}",
                t.program.cmr
            ));
        }
        let report = crate::lint::lint_source(&text);
        if !report.is_clean() {
            return Err(format!("the source fails the lints: {:?}", report.findings));
        }
        Ok(())
    }

    fn source_path(&self, dir: &Path, t: &Template) -> PathBuf {
        dir.join(&t.program.source)
    }

    /// The data leaf's bytes for these parameter values: each parameter's value,
    /// big-endian at its type's width, in the template's order.
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

    /// The output of an instance, computed with `elements`' taproot builder.
    ///
    /// # Errors
    /// When the parameters are wrong or a key is invalid.
    pub fn derive(&self, params: &BTreeMap<String, String>) -> Result<Derived, String> {
        let t = self.typed()?;
        let param_bytes = self.param_bytes(params)?;
        let cmr = unhex(&t.program.cmr)?;
        let internal =
            XOnlyPublicKey::from_str(&t.internal_key).map_err(|e| format!("internal_key: {e}"))?;

        let version = LeafVersion::from_u8(LEAF_VERSION_SIMPLICITY).map_err(|e| e.to_string())?;
        let script = Script::from(cmr);
        let data = tapdata_hash(&param_bytes);
        let secp = Secp256k1::verification_only();
        let info = TaprootBuilder::new()
            .add_leaf_with_ver(1, script.clone(), version)
            .and_then(|b| b.add_hidden(1, data))
            .map_err(|e| e.to_string())?
            .finalize(&secp, internal)
            .map_err(|_| "the tree is incomplete".to_string())?;

        let output_key = info.output_key();
        let script_pubkey = Script::new_v1_p2tr_tweaked(output_key);

        Ok(Derived {
            data_leaf: hex(data.as_ref()),
            program_leaf: hex(TapLeafHash::from_script(&script, version).as_ref()),
            merkle_root: hex(info.merkle_root().ok_or("no merkle root")?.as_ref()),
            tweak: hex(info.tap_tweak().as_ref()),
            output_key: hex(&output_key.into_inner().serialize()),
            output_key_parity: u8::from(info.output_key_parity() == Parity::Odd),
            script_pubkey: hex(script_pubkey.as_bytes()),
            param_bytes,
        })
    }
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

/// A golden-vector file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Vectors {
    /// Always [`VECTORS_VERSION`].
    pub vectors: u64,
    pub template_hash: String,
    pub cmr: String,
    pub addresses: Vec<AddressVector>,
}

/// One instance and everything its output is made of.
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
    /// Reads a golden-vector file.
    ///
    /// # Errors
    /// When the file cannot be read or is not a vector file.
    pub fn load(path: &Path) -> Result<Self, String> {
        serde_json::from_value(read_json(path)?).map_err(|e| format!("{}: {e}", path.display()))
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
            let mut address = BTreeMap::new();
            for c in &d.chains {
                let a = self::address(&x.output_key, &c.bech32_hrp)
                    .ok_or_else(|| format!("chain {}: bad prefix {}", c.name, c.bech32_hrp))?;
                address.insert(c.name.clone(), a);
            }
            addresses.push(AddressVector {
                name: v.name.clone(),
                params: v.params.clone(),
                param_bytes: hex(&x.param_bytes),
                data_leaf: x.data_leaf,
                program_leaf: x.program_leaf,
                merkle_root: x.merkle_root,
                tweak: x.tweak,
                output_key: x.output_key,
                output_key_parity: x.output_key_parity,
                script_pubkey: x.script_pubkey,
                address,
            });
        }
        Ok(Vectors {
            vectors: VECTORS_VERSION,
            template_hash: d.template_hash.clone(),
            cmr: t.program.cmr,
            addresses,
        })
    }
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
