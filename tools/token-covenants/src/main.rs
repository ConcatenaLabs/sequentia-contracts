//! `token-covenants`: builds and signs spends of the covenants that hold an
//! asset's reissuance token.
//!
//! ```text
//! token-covenants key [--new] [--mnemonic-file F | --key-file F]
//! token-covenants supply-cap instance --asset A --token T --entropy E --operator-key K
//!                                     --cold-key K --cap ATOMS --genesis HASH
//! token-covenants supply-cap address  --instance I [--minted ATOMS]
//! token-covenants supply-cap build    --instance I (--mnemonic-file F | --key-file F) < request.json
//! token-covenants supply-cap follow   --instance I < request.json
//! ```
//!
//! The tool reaches no node and holds no credential. A service reads the
//! chain and its wallet itself, hands the tool the coins as the transactions
//! that made them, and broadcasts what the tool returns once its wallet has
//! signed the fee coins. `build` returns a transaction whose covenant input is
//! finalized: the program is compiled from the template built into the tool,
//! placed in its tree, run and pruned against the final transaction, so a
//! spend the covenant would refuse is never returned, and its cost is checked
//! against the budget its witness earns. The covenant's signature commits to
//! every input and output, so the wallet's signatures on the fee coins, added
//! after, change nothing it signed, and the transaction id it returns is final.
//!
//! Every command prints one JSON object on success; on failure it prints the
//! reason on stderr and exits 1.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use serde_json::{json, Value};

use sequentia_contracts::descriptor::{Descriptor, Model, Node as TreeNode, TreeDerived};
use sequentia_contracts::simplicityhl::elements::encode::{deserialize, serialize_hex};
use sequentia_contracts::simplicityhl::elements::hashes::{sha256, Hash};
use sequentia_contracts::simplicityhl::elements::pset::PartiallySignedTransaction;
use sequentia_contracts::simplicityhl::elements::secp256k1_zkp::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use sequentia_contracts::simplicityhl::elements::{
    confidential, AssetId, BlockHash, OutPoint, Script, Sequence, Transaction, TxOut,
};
use sequentia_contracts::simplicityhl::str::WitnessName;
use sequentia_contracts::simplicityhl::{Arguments, Value as HlValue, WitnessValues};

use smplx_sdk::program::{ArgumentsTrait, BudgetRule, Program, ProgramTrait};
use smplx_sdk::provider::SimplicityNetwork;
use smplx_sdk::signer::{Signer, SignerTrait};
use smplx_sdk::taptree::{ContractTree, TapTree};
use smplx_sdk::transaction::partial_input::IssuanceInput;
use smplx_sdk::transaction::{
    FinalTransaction, PartialInput, PartialOutput, RequiredSignature, SigMessage, UTXO,
};

/// BIP341's point with no known discrete logarithm: the covenants' internal
/// key, and the key a supply cap is retired to.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

type Res<T> = Result<T, String>;

fn fail<T>(m: impl Into<String>) -> Res<T> {
    Err(m.into())
}

fn e<E: std::fmt::Display>(x: E) -> String {
    x.to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return fail(format!("{s:.20}…: not hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(e))
        .collect()
}

// ---------------------------------------------------------------------------
// Arguments

struct Args {
    command: Vec<String>,
    values: BTreeMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse() -> Res<Self> {
        Self::from(std::env::args().skip(1).collect())
    }

    fn from(all: Vec<String>) -> Res<Self> {
        let mut it = all.into_iter();
        let mut command = Vec::new();
        let (mut values, mut flags) = (BTreeMap::new(), Vec::new());
        while let Some(a) = it.next() {
            match a.as_str() {
                "--new" => flags.push(a),
                s if s.starts_with("--") => {
                    let v = it.next().ok_or_else(|| format!("{s} wants a value"))?;
                    if values.insert(s[2..].to_string(), v).is_some() {
                        return fail(format!("{s} is given twice"));
                    }
                }
                _ if values.is_empty() && flags.is_empty() => command.push(a),
                _ => return fail(format!("unexpected argument {a}\n{USAGE}")),
            }
        }
        Ok(Args {
            command,
            values,
            flags,
        })
    }

    fn get(&self, k: &str) -> Res<&str> {
        self.values
            .get(k)
            .map(String::as_str)
            .ok_or_else(|| format!("--{k} is required"))
    }

    fn opt(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(String::as_str)
    }

    fn only(&self, allowed: &[&str]) -> Res<()> {
        for k in self.values.keys() {
            if !allowed.contains(&k.as_str()) {
                return fail(format!("{} does not take --{k}", self.command.join(" ")));
            }
        }
        Ok(())
    }
}

const USAGE: &str = "usage: token-covenants key [options] | token-covenants supply-cap (instance | address | build | follow) [options]; see tools/token-covenants/README.md";

// ---------------------------------------------------------------------------
// Keys

/// A key that signs a covenant spend: the contract key of a mnemonic
/// (m/8383h/1h/0h/0/0 on the testnet and local chains), or a raw secret key.
enum Key {
    Mnemonic(Box<Signer>),
    Raw(Keypair),
}

impl Key {
    fn public(&self) -> XOnlyPublicKey {
        match self {
            Key::Mnemonic(s) => s.get_schnorr_public_key(),
            Key::Raw(k) => k.x_only_public_key().0,
        }
    }

    /// A BIP340 signature over the input's sig_all_hash.
    fn sign(
        &self,
        pst: &PartiallySignedTransaction,
        program: &Program,
        index: usize,
        net: &SimplicityNetwork,
    ) -> Res<[u8; 64]> {
        match self {
            Key::Mnemonic(s) => Ok(s
                .sign_program(pst, program, index, net, None, &SigMessage::Sighash)
                .map_err(e)?
                .serialize()),
            Key::Raw(k) => {
                let env = program.get_env(pst, index, net).map_err(e)?;
                let sighash = env.c_tx_env().sighash_all().to_byte_array();
                let secp = Secp256k1::new();
                Ok(secp
                    .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), k)
                    .serialize())
            }
        }
    }
}

fn words(path: &str) -> Res<String> {
    let text = std::fs::read_to_string(path).map_err(|x| format!("{path}: {x}"))?;
    Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn signer_from_words(w: &str, net: SimplicityNetwork) -> Res<Signer> {
    let w = w.to_string();
    std::panic::catch_unwind(move || Signer::from_mnemonic(&w, net))
        .map_err(|_| "the mnemonic does not parse".to_string())
}

/// A raw secret key file: 64 hex characters, whitespace around them ignored.
fn raw_key(path: &str) -> Res<Keypair> {
    let text = std::fs::read_to_string(path).map_err(|x| format!("{path}: {x}"))?;
    let b = unhex(text.trim())?;
    let sk = SecretKey::from_slice(&b).map_err(|x| format!("{path}: {x}"))?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &sk))
}

/// The key a command was given, checked to be `want`.
fn key_for(a: &Args, net: SimplicityNetwork, want: &str, name: &str) -> Res<Key> {
    let key = match (a.opt("mnemonic-file"), a.opt("key-file")) {
        (Some(m), None) => Key::Mnemonic(Box::new(signer_from_words(&words(m)?, net)?)),
        (None, Some(k)) => Key::Raw(raw_key(k)?),
        _ => return fail(format!("give {name}'s key: --mnemonic-file or --key-file, one of them")),
    };
    if hex(&key.public().serialize()) != want {
        return fail(format!("this key is not the instance's {name}"));
    }
    Ok(key)
}

fn cmd_key(a: &Args) -> Res<Value> {
    a.only(&["mnemonic-file", "key-file"])?;
    let new = a.flags.iter().any(|f| f == "--new");
    // The contract key at m/8383h/1h/0h/0/0, the account every Sequentia
    // chain but the mainnet derives under.
    let of_words = |w: &str| -> Res<String> {
        Ok(hex(&signer_from_words(w, SimplicityNetwork::SequentiaTestnet)?
            .get_schnorr_public_key()
            .serialize()))
    };
    let create = |path: &str, text: &str| -> Res<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|x| format!("{path}: {x}; a new key is never written over a file"))?;
        writeln!(f, "{text}").and_then(|()| f.sync_all()).map_err(e)
    };
    match (new, a.opt("mnemonic-file"), a.opt("key-file")) {
        (false, Some(m), None) => Ok(json!({"key": of_words(&words(m)?)?})),
        (false, None, Some(k)) => Ok(json!({"key": hex(&raw_key(k)?.x_only_public_key().0.serialize())})),
        // A new mnemonic: twelve words from the operating system's
        // randomness, printed once or written once to a new file readable by
        // its owner alone, never to stderr.
        (true, None, None) => {
            let w = smplx_sdk::utils::random_mnemonic();
            let k = of_words(&w)?;
            Ok(json!({"mnemonic": w, "key": k}))
        }
        (true, Some(path), None) => {
            let w = smplx_sdk::utils::random_mnemonic();
            let k = of_words(&w)?;
            create(path, &w)?;
            Ok(json!({"mnemonic_file": path, "key": k}))
        }
        // A new raw key, for a service that keeps its key in a file.
        (true, None, Some(path)) => {
            let secp = Secp256k1::new();
            let (sk, _) = secp.generate_keypair(&mut sequentia_contracts::simplicityhl::elements::secp256k1_zkp::rand::thread_rng());
            let k = Keypair::from_secret_key(&secp, &sk);
            create(path, &hex(&sk.secret_bytes()))?;
            Ok(json!({"key_file": path, "key": hex(&k.x_only_public_key().0.serialize())}))
        }
        _ => fail("key takes --mnemonic-file or --key-file, not both"),
    }
}

// ---------------------------------------------------------------------------
// Templates and instances

/// A template built into the binary, so that an installed tool needs no
/// checkout beside it: its hash, descriptor, source and the helpers the source
/// includes.
struct Builtin {
    template_hash: &'static str,
    leaf: &'static str,
    descriptor: &'static str,
    source_name: &'static str,
    source: &'static str,
    helpers: &'static [(&'static str, &'static str)],
}

const OUTPUT_READER: (&str, &str) = (
    "output_reader",
    include_str!("../../../helpers/output_reader.simf"),
);

/// `sequentia/supply-cap`, version 1.
const SUPPLY_CAP: Builtin = Builtin {
    template_hash: "f93a2bffc93db5280ef17f6dc09e99fdee5e4253ccc152afdbebe135265b900d",
    leaf: "cap",
    descriptor: include_str!("../../../templates/supply_cap/descriptor.json"),
    source_name: "supply_cap.simf",
    source: include_str!("../../../templates/supply_cap/supply_cap.simf"),
    helpers: &[OUTPUT_READER],
};

struct Template {
    builtin: &'static Builtin,
    descriptor: Descriptor,
    model: Model,
    /// Each Simplicity leaf's source by name, its helper includes resolved.
    sources: BTreeMap<String, String>,
}

fn builtin_sources(b: &Builtin) -> Res<BTreeMap<String, String>> {
    let text = sequentia_contracts::expand_with(b.source, &mut |name| {
        b.helpers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| t.to_string())
            .ok_or_else(|| format!("no helper {name} is built into this tool"))
    })?;
    Ok(BTreeMap::from([(b.source_name.to_string(), text)]))
}

/// The template: the one built in, or with `--template DIR` a directory's
/// copy, which must be the same template.
fn template(a: &Args, b: &'static Builtin) -> Res<Template> {
    let (descriptor, sources, at) = match a.opt("template") {
        Some(d) => {
            let dir = PathBuf::from(d);
            let descriptor = Descriptor::load(&dir.join("descriptor.json"))?;
            let raw = std::fs::read_to_string(dir.join(b.source_name)).map_err(e)?;
            let sources =
                BTreeMap::from([(b.source_name.to_string(), sequentia_contracts::expand(&raw)?)]);
            (descriptor, sources, dir.display().to_string())
        }
        None => (
            Descriptor::parse(b.descriptor)?,
            builtin_sources(b)?,
            "the built-in template".to_string(),
        ),
    };
    if descriptor.template_hash != b.template_hash {
        return fail(format!(
            "{at}: template {} is not the one this tool spends, {}",
            descriptor.template_hash, b.template_hash
        ));
    }
    // Compiles each source with the pinned compiler and checks its source
    // hash, root, lints, witness and cost bound against the descriptor.
    descriptor.validate_sources(&sources)?;
    let model = descriptor.model()?;
    Ok(Template {
        builtin: b,
        descriptor,
        model,
        sources,
    })
}

#[derive(Clone)]
struct Instance {
    params: BTreeMap<String, String>,
    genesis: BlockHash,
}

fn strings(v: &Value, at: &str) -> Res<BTreeMap<String, String>> {
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{at} is not an object"))?;
    obj.iter()
        .map(|(k, v)| {
            v.as_str()
                .map(|s| (k.clone(), s.to_string()))
                .ok_or_else(|| format!("{at}.{k} is not a string"))
        })
        .collect()
}

fn instance(a: &Args, t: &Template) -> Res<Instance> {
    let path = a.get("instance")?;
    let text = std::fs::read_to_string(path).map_err(|x| format!("{path}: {x}"))?;
    let v = sequentia_contracts::descriptor::parse_json(&text)?;
    instance_from(&v, t).map_err(|x| format!("{path}: {x}"))
}

fn instance_from(v: &Value, t: &Template) -> Res<Instance> {
    let obj = v.as_object().ok_or("an instance is a JSON object")?;
    for k in obj.keys() {
        if !["instance", "template_hash", "params", "slots", "genesis", "address"].contains(&k.as_str()) {
            return fail(format!("unknown field {k}"));
        }
    }
    if v["instance"] != json!(2) {
        return fail("instance is not 2");
    }
    if v["template_hash"] != json!(t.builtin.template_hash) {
        return fail(format!(
            "the instance is of template {}, not {}",
            v["template_hash"], t.builtin.template_hash
        ));
    }
    let genesis = match &v["genesis"] {
        Value::String(s) => BlockHash::from_str(s).map_err(e)?,
        _ => return fail("genesis names the chain: a block hash"),
    };
    Ok(Instance {
        params: strings(&v["params"], "params")?,
        genesis,
    })
}

fn param_hex<'a>(inst: &'a Instance, name: &str) -> Res<&'a str> {
    inst.params
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("no parameter {name}"))
}

fn param_u64(inst: &Instance, name: &str) -> Res<u64> {
    u64::from_str_radix(param_hex(inst, name)?, 16).map_err(e)
}

/// An asset parameter, held in internal byte order as the program reads it.
fn param_asset(inst: &Instance, name: &str) -> Res<AssetId> {
    AssetId::from_slice(&unhex(param_hex(inst, name)?)?).map_err(e)
}

/// An asset id as the program reads it, in internal byte order: the reverse
/// of the hex an RPC prints.
fn internal(x: AssetId) -> String {
    hex(&unhex(&x.to_string())
        .unwrap_or_default()
        .into_iter()
        .rev()
        .collect::<Vec<_>>())
}

#[derive(Clone)]
struct NoArguments;

impl ArgumentsTrait for NoArguments {
    fn build_arguments(&self) -> Arguments {
        Arguments::default()
    }
}

/// The covenant's contract tree for the slots `slots`, built with the
/// framework from the descriptor's tree and checked against the descriptor's
/// own derivation.
fn contract(
    t: &Template,
    inst: &Instance,
    slots: &BTreeMap<String, String>,
) -> Res<(ContractTree, TreeDerived)> {
    let derived = t.model.derive(&inst.params, slots)?;
    let mut values = inst.params.clone();
    values.extend(slots.clone());
    fn walk(t: &Template, n: &TreeNode, values: &BTreeMap<String, String>) -> Res<TapTree> {
        Ok(match n {
            TreeNode::Branch(a, b) => TapTree::branch(walk(t, a, values)?, walk(t, b, values)?),
            TreeNode::Simplicity { name, program } => {
                let text = t
                    .sources
                    .get(&program.source)
                    .ok_or_else(|| format!("leaf {name}: no source {}", program.source))?;
                let p = Program::new(text.clone(), &NoArguments).with_debug_symbols(false);
                let cmr = hex(&p.try_cmr().map_err(e)?);
                if cmr != program.cmr {
                    return fail(format!(
                        "leaf {name}: the framework compiles it to {cmr}, the descriptor says {}",
                        program.cmr
                    ));
                }
                TapTree::simplicity(name.clone(), p)
            }
            TreeNode::Tapscript { name, items } => {
                TapTree::tapscript(name.clone(), Script::from(t.model.script(items, values)?))
            }
            TreeNode::Data { values: names, .. } => TapTree::data(&t.model.data(names, values)?),
        })
    }
    let key = XOnlyPublicKey::from_str(&t.model.internal_key).map_err(e)?;
    let tree = ContractTree::new(key, walk(t, &t.model.tree, &values)?).map_err(e)?;
    if hex(tree.script_pubkey().as_bytes()) != derived.script_pubkey {
        return fail("the framework's tree and the descriptor derive different scripts");
    }
    let leaf = t.builtin.leaf;
    if hex(&tree.control_block(leaf).map_err(e)?.serialize())
        != derived.leaves[leaf].control_block.clone().unwrap_or_default()
    {
        return fail("the framework's control block is not the descriptor's");
    }
    Ok((tree, derived))
}

fn network(inst: &Instance, any_asset: AssetId) -> SimplicityNetwork {
    if inst.genesis == SimplicityNetwork::SequentiaTestnet.genesis_block_hash() {
        return SimplicityNetwork::SequentiaTestnet;
    }
    // A local chain. Its policy asset is one fee asset among any, and nothing
    // here pays a fee through the framework, so an asset of the instance
    // stands in.
    SimplicityNetwork::SequentiaRegtest {
        policy_asset: any_asset,
        genesis_hash: inst.genesis,
    }
}

/// The program's witness values: the parameters and slots by name, `fixed`
/// for the spender's own values (PATH and any keys it names), each signature
/// named in `sigs` zero unless it is `sig_name`, which pruning keeps.
fn witness(
    program: &Program,
    inst: &Instance,
    slots: &BTreeMap<String, String>,
    fixed: &BTreeMap<&str, String>,
    sig_name: &str,
    sig: &[u8; 64],
) -> Res<WitnessValues> {
    let types = program.get_witness_types().map_err(e)?;
    let mut map = std::collections::HashMap::new();
    for (name, ty) in types.iter() {
        let n: &str = name.as_ref();
        let literal = if let Some(v) = fixed.get(n) {
            v.clone()
        } else if n.ends_with("_SIG") {
            format!("0x{}", hex(if n == sig_name { sig } else { &[0; 64] }))
        } else {
            let h = inst
                .params
                .get(n)
                .or_else(|| slots.get(n))
                .ok_or_else(|| format!("no value for witness {n}"))?;
            match ty.to_string().as_str() {
                "u8" | "u16" | "u32" | "u64" => u64::from_str_radix(h, 16).map_err(e)?.to_string(),
                _ => format!("0x{h}"),
            }
        };
        let value =
            HlValue::parse_from_str(&literal, ty).map_err(|x| format!("witness {n}: {x}"))?;
        map.insert(WitnessName::from_str_unchecked(n), value);
    }
    Ok(WitnessValues::from(map))
}

// ---------------------------------------------------------------------------
// Coins and amounts

struct Coin {
    outpoint: OutPoint,
    txout: TxOut,
}

fn coin(v: &Value, what: &str) -> Res<Coin> {
    let raw = v["tx"]
        .as_str()
        .ok_or_else(|| format!("{what}.tx: the hex of the transaction that made it"))?;
    let tx: Transaction = deserialize(&unhex(raw)?).map_err(|x| format!("{what}.tx: {x}"))?;
    let vout =
        u32::try_from(v["vout"].as_u64().ok_or_else(|| format!("{what}.vout"))?).map_err(e)?;
    let txout = tx
        .output
        .get(vout as usize)
        .ok_or_else(|| format!("{what}: vout {vout} out of range"))?
        .clone();
    Ok(Coin {
        outpoint: OutPoint::new(tx.txid(), vout),
        txout,
    })
}

fn explicit(o: &TxOut) -> Option<(AssetId, u64)> {
    match (o.asset, o.value) {
        (confidential::Asset::Explicit(a), confidential::Value::Explicit(v)) => Some((a, v)),
        _ => None,
    }
}

fn script_arg(v: &Value, what: &str) -> Res<Script> {
    Ok(Script::from(unhex(v.as_str().ok_or_else(|| {
        format!("{what}: a scriptPubKey in hex")
    })?)?))
}

/// An amount of atoms: a decimal string, as this tool writes them, or a JSON
/// number no larger than 2^53, which every reader parses exactly.
fn atoms(v: &Value, what: &str) -> Res<u64> {
    match v {
        Value::String(s)
            if !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_digit())
                && (s == "0" || !s.starts_with('0')) =>
        {
            s.parse::<u64>().map_err(|x| format!("{what}: {x}"))
        }
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= 1 << 53 => Ok(x),
            _ => fail(format!(
                "{what}: a number above 2^53 is not read exactly everywhere; give it as a decimal string"
            )),
        },
        _ => fail(format!("{what}: a whole number of atoms, as a decimal string")),
    }
}

/// The fee coins, all of one asset and explicit, added as unsigned inputs for
/// the service's wallet to sign; the change returns to `change_to` and the fee
/// is an explicit fee output in that asset. No asset is assumed: the coins say
/// which pays.
struct Fee {
    asset: AssetId,
    atoms: u64,
    change: u64,
    change_to: Option<Script>,
}

fn add_fee_coins(ft: &mut FinalTransaction, fee: &Value, forbidden: &[AssetId]) -> Res<Fee> {
    let fee_atoms = atoms(&fee["atoms"], "fee.atoms")?;
    let mut fee_asset: Option<AssetId> = None;
    let mut fee_in = 0u64;
    for (i, f) in fee["coins"]
        .as_array()
        .ok_or("fee.coins: the coins that pay the fee")?
        .iter()
        .enumerate()
    {
        let fc = coin(f, &format!("fee.coins[{i}]"))?;
        let (fa, fv) = explicit(&fc.txout).ok_or("a fee coin is confidential")?;
        if fee_asset.is_some_and(|x| x != fa) {
            return fail("the fee coins hold more than one asset; one asset pays a transaction's fee");
        }
        if forbidden.contains(&fa) {
            return fail("a fee coin holds an asset the covenant itself moves");
        }
        fee_asset = Some(fa);
        fee_in = fee_in.checked_add(fv).ok_or("fee coins overflow")?;
        ft.add_input(
            PartialInput::new(UTXO {
                outpoint: fc.outpoint,
                txout: fc.txout,
                secrets: None,
            }),
            RequiredSignature::None,
        );
    }
    let asset = fee_asset.ok_or("no fee coin: a covenant spend takes its fee from another coin")?;
    let change = fee_in
        .checked_sub(fee_atoms)
        .ok_or_else(|| format!("the fee coins hold {fee_in}, less than the fee of {fee_atoms}"))?;
    let change_to = if change > 0 {
        Some(script_arg(&fee["change_to"], "fee.change_to")?)
    } else {
        None
    };
    Ok(Fee {
        asset,
        atoms: fee_atoms,
        change,
        change_to,
    })
}

fn add_fee_outputs(ft: &mut FinalTransaction, fee: &Fee) {
    if let Some(to) = &fee.change_to {
        ft.add_output(PartialOutput::new(to.clone(), fee.change, fee.asset));
    }
    ft.add_output(PartialOutput::new(Script::new(), fee.atoms, fee.asset));
}

/// Finalizes the covenant input `index` of `pst` with `program` and `wv`,
/// refusing a spend the covenant refuses or whose witness does not earn its
/// cost, and reports the transaction.
fn finalize(
    pst: &mut PartiallySignedTransaction,
    program: &Program,
    wv: &WitnessValues,
    index: usize,
    net: &SimplicityNetwork,
) -> Res<(Transaction, Value)> {
    let spend = program
        .finalize_spend(pst, wv, index, net)
        .map_err(|x| format!("the covenant refuses this spend: {x}"))?;
    let rule: BudgetRule = net.simplicity_budget();
    if !rule.covers(spend.cost, &spend.stack) {
        return fail("the spend's witness does not earn its cost bound; this tool does not pad");
    }
    let budget = rule.report(spend.cost, &spend.stack);
    pst.inputs_mut()[index].final_script_witness = Some(spend.stack.clone());
    let tx = pst.extract_tx().map_err(e)?;
    let report = json!({
        "txid": tx.txid().to_string(),
        "hex": serialize_hex(&tx),
        "weight_before_wallet_signatures": tx.weight(),
        "program_bytes": spend.stack[1].len(),
        "witness_bytes": spend.stack[0].len(),
        "cost_bound_milli_wu": budget.cost_milliweight,
        "budget_wu": budget.budget,
    });
    Ok((tx, report))
}

fn read_request() -> Res<Value> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(e)?;
    sequentia_contracts::descriptor::parse_json(&text)
}

/// The issuance entropy of an asset whose explicit reissuance token is
/// `token`, checked against both.
fn entropy_of(v: &Value, asset: AssetId, token: AssetId) -> Res<sha256::Midstate> {
    let entropy = sha256::Midstate::from_str(
        v.as_str().ok_or("entropy: the asset's issuance entropy")?,
    )
    .map_err(e)?;
    if AssetId::from_entropy(entropy) != asset {
        return fail("this entropy issues another asset than the instance's");
    }
    if AssetId::reissuance_token_from_entropy(entropy, false) != token {
        return fail("this entropy's explicit reissuance token is not the instance's token");
    }
    Ok(entropy)
}

// ---------------------------------------------------------------------------
// The supply cap

mod cap {
    use super::*;

    pub const PATHS: [(&str, &str); 2] = [("mint", "Left(())"), ("rekey", "Right(())")];

    pub fn slots(minted: u64) -> BTreeMap<String, String> {
        BTreeMap::from([("MINTED".to_string(), format!("{minted:016x}"))])
    }

    /// The keys an instance may hold: two different keys, so the cold key can
    /// replace a lost operator key, or both the NUMS point, which retires it.
    pub fn check_keys(operator: &str, cold: &str) -> Res<()> {
        for k in [operator, cold] {
            XOnlyPublicKey::from_str(k).map_err(|x| format!("{k}: {x}"))?;
        }
        if operator == cold && operator != NUMS {
            return fail(
                "the operator key and the cold key are one key: the cold key is what replaces a lost operator key",
            );
        }
        Ok(())
    }

    /// The instance with other keys: what a rekey leads to.
    pub fn rekeyed(inst: &Instance, operator: &str, cold: &str) -> Instance {
        let mut n = inst.clone();
        n.params.insert("OPERATOR_KEY".into(), operator.into());
        n.params.insert("COLD_KEY".into(), cold.into());
        n
    }

    pub fn instance_json(t: &Template, inst: &Instance, minted: u64) -> Res<Value> {
        let (_, derived) = contract(t, inst, &slots(minted))?;
        Ok(json!({
            "instance": 2, "template_hash": t.builtin.template_hash, "params": inst.params,
            "slots": slots(minted), "genesis": inst.genesis.to_string(),
            "address": t.descriptor.addresses(&derived.output_key)?,
        }))
    }

    pub fn cmd_instance(a: &Args) -> Res<Value> {
        a.only(&[
            "template", "asset", "token", "entropy", "operator-key", "cold-key", "cap", "genesis",
        ])?;
        let t = template(a, &SUPPLY_CAP)?;
        let asset = AssetId::from_str(a.get("asset")?).map_err(e)?;
        let token = AssetId::from_str(a.get("token")?).map_err(e)?;
        let entropy = sha256::Midstate::from_str(a.get("entropy")?).map_err(e)?;
        if AssetId::from_entropy(entropy) != asset {
            return fail("the entropy issues another asset than --asset");
        }
        if AssetId::reissuance_token_from_entropy(entropy, false) != token {
            return fail("--token is not the explicit reissuance token of --asset: an explicit mint could never spend it");
        }
        let (operator, cold) = (a.get("operator-key")?, a.get("cold-key")?);
        check_keys(operator, cold)?;
        let cap: u64 = a.get("cap")?.parse().map_err(e)?;
        let inst = Instance {
            params: strings(
                &json!({
                    "ASSET": internal(asset), "TOKEN": internal(token),
                    "OPERATOR_KEY": operator, "COLD_KEY": cold, "CAP": format!("{cap:016x}"),
                }),
                "params",
            )?,
            genesis: BlockHash::from_str(a.get("genesis")?).map_err(e)?,
        };
        instance_json(&t, &inst, 0)
    }

    pub fn cmd_address(a: &Args) -> Res<Value> {
        a.only(&["instance", "template", "minted"])?;
        let t = template(a, &SUPPLY_CAP)?;
        let inst = instance(a, &t)?;
        let minted = match a.opt("minted") {
            Some(m) => atoms(&json!(m), "--minted")?,
            None => 0,
        };
        let (_, derived) = contract(&t, &inst, &slots(minted))?;
        Ok(json!({
            "template_hash": t.builtin.template_hash,
            "minted": minted.to_string(),
            "cap": param_u64(&inst, "CAP")?.to_string(),
            "address": t.descriptor.addresses(&derived.output_key)?,
            "script_pubkey": derived.script_pubkey,
            "leaves": derived.leaves,
        }))
    }

    pub fn cmd_build(a: &Args) -> Res<Value> {
        a.only(&["instance", "template", "mnemonic-file", "key-file"])?;
        let t = template(a, &SUPPLY_CAP)?;
        let inst = instance(a, &t)?;
        let token = param_asset(&inst, "TOKEN")?;
        let asset = param_asset(&inst, "ASSET")?;
        let net = network(&inst, asset);
        let req = read_request()?;
        let path = req["path"].as_str().ok_or("path: mint or rekey")?;
        let path_value = PATHS
            .iter()
            .find(|(p, _)| *p == path)
            .ok_or_else(|| format!("path {path}: mint or rekey"))?
            .1;
        let minted = atoms(&req["minted"], "minted: the coin's count")?;
        let cap = param_u64(&inst, "CAP")?;
        let (tree, _) = contract(&t, &inst, &slots(minted))?;

        // The coin: this instance holding this count, with the token explicitly.
        let c = coin(&req["coin"], "coin")?;
        if c.txout.script_pubkey != tree.script_pubkey() {
            return fail(format!(
                "the coin's script is not the instance's with {minted} minted: {}",
                hex(c.txout.script_pubkey.as_bytes())
            ));
        }
        let (held, amount) = explicit(&c.txout)
            .ok_or("the coin is confidential; the covenant reads only explicit coins")?;
        if held != token {
            return fail(format!("the coin holds {held}, not the token {token}"));
        }

        let mut ft = FinalTransaction::new();
        let input = PartialInput::new(UTXO {
            outpoint: c.outpoint,
            txout: c.txout.clone(),
            secrets: None,
        })
        .with_sequence(Sequence::MAX);
        let mut fixed: BTreeMap<&str, String> = BTreeMap::from([("PATH", path_value.to_string())]);
        let (next_inst, next_minted, issue) = match path {
            "mint" => {
                let x = atoms(&req["amount"], "amount: the atoms to mint")?;
                if x == 0 {
                    return fail("a reissuance of zero is not valid");
                }
                let entropy = entropy_of(&req["entropy"], asset, token)?;
                let total = minted.checked_add(x).ok_or("the count would overflow")?;
                if total > cap {
                    return fail(format!(
                        "a mint of {x} would bring the total minted to {total}, above the cap of {cap}"
                    ));
                }
                ft.add_issuance_input(
                    input,
                    IssuanceInput::new_reissuance(x, entropy.to_byte_array()),
                    RequiredSignature::None,
                );
                fixed.insert("NEW_OPERATOR_KEY", format!("0x{NUMS}"));
                fixed.insert("NEW_COLD_KEY", format!("0x{NUMS}"));
                (inst.clone(), total, Some(x))
            }
            _ => {
                let op = req["new_operator_key"]
                    .as_str()
                    .ok_or("new_operator_key: the operator key the covenant moves to")?;
                let cold = req["new_cold_key"]
                    .as_str()
                    .ok_or("new_cold_key: the cold key the covenant moves to")?;
                check_keys(op, cold)?;
                fixed.insert("NEW_OPERATOR_KEY", format!("0x{op}"));
                fixed.insert("NEW_COLD_KEY", format!("0x{cold}"));
                ft.add_input(input, RequiredSignature::None);
                (rekeyed(&inst, op, cold), minted, None)
            }
        };
        let fee = add_fee_coins(&mut ft, &req["fee"], &[token, asset])?;
        // The successor first, as the covenant requires.
        let (succ, sd) = contract(&t, &next_inst, &slots(next_minted))?;
        ft.add_output(PartialOutput::new(succ.script_pubkey(), amount, token));
        if let Some(x) = issue {
            ft.add_output(PartialOutput::new(script_arg(&req["mint_to"], "mint_to")?, x, asset));
        }
        add_fee_outputs(&mut ft, &fee);

        let (mut pst, _) = ft.extract_pst();
        let program = tree.program(t.builtin.leaf).map_err(e)?;
        let (sig_name, signer, signer_name) = match path {
            "mint" => ("OPERATOR_SIG", param_hex(&inst, "OPERATOR_KEY")?, "OPERATOR_KEY"),
            _ => ("COLD_SIG", param_hex(&inst, "COLD_KEY")?, "COLD_KEY"),
        };
        let key = key_for(a, net, signer, signer_name)?;
        let sig = key.sign(&pst, &program, 0, &net)?;
        let wv = witness(&program, &inst, &slots(minted), &fixed, sig_name, &sig)?;
        let (_, mut out) = finalize(&mut pst, &program, &wv, 0, &net)?;
        out["path"] = json!(path);
        out["minted"] = json!(minted.to_string());
        out["next_minted"] = json!(next_minted.to_string());
        out["cap"] = json!(cap.to_string());
        out["coin"] = json!({"txid": c.outpoint.txid.to_string(), "vout": c.outpoint.vout});
        out["fee"] = json!({"asset": fee.asset.to_string(), "atoms": fee.atoms.to_string(), "change": fee.change.to_string()});
        out["successor"] = json!({
            "txid": out["txid"], "vout": 0, "amount": amount.to_string(),
            "script_pubkey": hex(succ.script_pubkey().as_bytes()),
            "address": t.descriptor.addresses(&sd.output_key)?,
        });
        if let Some(x) = issue {
            out["amount"] = json!(x.to_string());
        } else {
            out["next_instance"] = instance_json(&t, &next_inst, next_minted)?;
        }
        Ok(out)
    }

    /// What a transaction that spends the covenant's coin did to it.
    pub fn cmd_follow(a: &Args) -> Res<Value> {
        a.only(&["instance", "template"])?;
        let t = template(a, &SUPPLY_CAP)?;
        let inst = instance(a, &t)?;
        let req = read_request()?;
        let minted = atoms(&req["minted"], "minted: the coin's count")?;
        let c = coin(&req["coin"], "coin")?;
        let (tree, _) = contract(&t, &inst, &slots(minted))?;
        if c.txout.script_pubkey != tree.script_pubkey() {
            return fail("the coin's script is not the instance's with that count");
        }
        let raw = req["tx"]
            .as_str()
            .ok_or("tx: the hex of the transaction that spent the coin")?;
        let tx: Transaction = deserialize(&unhex(raw)?).map_err(|x| format!("tx: {x}"))?;
        let at = tx
            .input
            .iter()
            .position(|i| i.previous_output == c.outpoint)
            .ok_or("the transaction does not spend the coin")?;
        if at != 0 {
            return fail("the transaction spends the coin at another input than 0, which the covenant refuses");
        }
        let out0 = tx
            .output
            .first()
            .map(|o| o.script_pubkey.clone())
            .ok_or("the transaction has no output")?;
        let txid = tx.txid().to_string();
        let input = &tx.input[0];
        if input.has_issuance() {
            let x = match input.asset_issuance.amount {
                confidential::Value::Explicit(x) => x,
                _ => return fail("the mint's amount is confidential, which the covenant refuses"),
            };
            let next = minted.checked_add(x).ok_or("the count overflows")?;
            let (succ, sd) = contract(&t, &inst, &slots(next))?;
            if succ.script_pubkey() != out0 {
                return fail("output 0 is not the instance with the count raised by the mint");
            }
            return Ok(json!({"path": "mint", "minted": minted.to_string(), "amount": x.to_string(),
                             "next_minted": next.to_string(),
                             "successor": {"txid": txid, "vout": 0,
                                           "address": t.descriptor.addresses(&sd.output_key)?}}));
        }
        // A rekey: the new keys are in the witness, so the caller names them.
        let mut v = json!({"path": "rekey", "minted": minted.to_string(), "txid": txid,
                           "successor_script_pubkey": hex(out0.as_bytes())});
        if let (Some(op), Some(cold)) = (req["new_operator_key"].as_str(), req["new_cold_key"].as_str()) {
            let next = rekeyed(&inst, op, cold);
            let (succ, _) = contract(&t, &next, &slots(minted))?;
            if succ.script_pubkey() != out0 {
                return fail("output 0 is not the instance with those keys");
            }
            v["next_instance"] = instance_json(&t, &next, minted)?;
        }
        Ok(v)
    }
}

fn run() -> Res<Value> {
    let a = Args::parse()?;
    let cmd: Vec<&str> = a.command.iter().map(String::as_str).collect();
    match cmd.as_slice() {
        ["key"] => cmd_key(&a),
        ["supply-cap", "instance"] => cap::cmd_instance(&a),
        ["supply-cap", "address"] => cap::cmd_address(&a),
        ["supply-cap", "build"] => cap::cmd_build(&a),
        ["supply-cap", "follow"] => cap::cmd_follow(&a),
        _ => fail(USAGE),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(v) => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(m) => {
            let _ = writeln!(std::io::stderr(), "token-covenants: {m}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        Args::from(v.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    #[test]
    fn the_templates_are_the_pinned_ones() {
        for (b, dir) in [(&SUPPLY_CAP, "supply_cap")] {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../templates").join(dir);
            let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
            assert_eq!(d.template_hash, b.template_hash);
            d.validate(&dir).unwrap();
            let file = std::fs::read_to_string(dir.join(b.source_name)).unwrap();
            assert_eq!(
                builtin_sources(b).unwrap()[b.source_name],
                sequentia_contracts::expand(&file).unwrap()
            );
            let t = template(&args(&["x"]), b).unwrap();
            let given = args(&["x", "--template", &dir.display().to_string()]);
            assert_eq!(template(&given, b).unwrap().sources, t.sources);
        }
    }

    #[test]
    fn the_vectors_derive_through_the_framework() {
        let t = template(&args(&["x"]), &SUPPLY_CAP).unwrap();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../templates/supply_cap");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("vectors.json")).unwrap()).unwrap();
        for c in v["addresses"].as_array().unwrap() {
            let inst = Instance {
                params: strings(&c["params"], "params").unwrap(),
                genesis: SimplicityNetwork::SequentiaTestnet.genesis_block_hash(),
            };
            let s = strings(&c["slots"], "slots").unwrap();
            let (tree, _) = contract(&t, &inst, &s).unwrap();
            assert_eq!(hex(tree.script_pubkey().as_bytes()), c["script_pubkey"].as_str().unwrap());
        }
    }

    #[test]
    fn keys_must_differ_unless_retired() {
        let k1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let k2 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        assert!(cap::check_keys(k1, k2).is_ok());
        assert!(cap::check_keys(k1, k1).is_err());
        assert!(cap::check_keys(NUMS, NUMS).is_ok());
        assert!(cap::check_keys(k1, &"00".repeat(32)).is_err());
    }

    #[test]
    fn amounts_read_as_strings_and_small_numbers() {
        assert_eq!(atoms(&json!("18446744073709551615"), "x").ok(), Some(u64::MAX));
        assert_eq!(atoms(&json!(1000), "x").ok(), Some(1000));
        assert!(atoms(&json!(9_007_199_254_740_993u64), "x").is_err());
        assert!(atoms(&json!("012"), "x").is_err());
        assert!(atoms(&json!("-1"), "x").is_err());
    }

    #[test]
    fn the_command_line_reads_two_words() {
        let a = args(&["supply-cap", "build", "--instance", "i.json"]);
        assert_eq!(a.command, vec!["supply-cap", "build"]);
        assert_eq!(a.get("instance").unwrap(), "i.json");
        assert!(Args::from(vec!["--x".into(), "1".into(), "stray".into()]).is_err());
    }
}
