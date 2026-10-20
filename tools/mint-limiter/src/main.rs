//! `mint-limiter`: builds and signs spends of a `sequentia/mint-limiter`
//! covenant, the output that holds an asset's reissuance token.
//!
//! ```text
//! mint-limiter key       --mnemonic-file F | --new [--mnemonic-file F]
//! mint-limiter instance  --asset A --token T --entropy E --operator-key K --cold-key K
//!                        --window BLOCKS --allowance ATOMS --recovery-delay UNITS --genesis HASH
//! mint-limiter address   --instance I [--state MINTED,ELAPSED,ARMED]
//! mint-limiter arm-signature --instance I --mnemonic-file COLD
//! mint-limiter build     --instance I [--mnemonic-file F]   < request.json
//! mint-limiter follow    --instance I                        < request.json
//! ```
//!
//! The tool reaches no node and holds no credential. A bridge reads the chain
//! and its wallet itself, hands the tool the coins as the transactions that
//! made them, and broadcasts what the tool returns once its wallet has signed
//! the fee coins. `build` returns a transaction whose covenant input is
//! finalized: the program is compiled from the template built into the tool,
//! placed in its tree, run and pruned against the final transaction, so a spend
//! the covenant would refuse is never returned, and its cost is checked against
//! the budget its witness earns. The covenant's signature commits to every
//! input and output, so the wallet's signatures on the fee coins, added after,
//! change nothing it signed, and the transaction id it returns is final.
//!
//! Every command prints one JSON object on success; on failure it prints the
//! reason on stderr and exits 1.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use serde_json::{json, Value};

use sequentia_contracts::descriptor::{Descriptor, Model, Node as TreeNode};
use sequentia_contracts::simplicityhl::elements::encode::{deserialize, serialize_hex};
use sequentia_contracts::simplicityhl::elements::hashes::{sha256, Hash};
use sequentia_contracts::simplicityhl::elements::secp256k1_zkp::{
    schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey,
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

/// The template this tool spends, by its hash: `sequentia/mint-limiter`, version 1.
const TEMPLATE_HASH: &str = "77218080daacd33cb636f1411920eb5f2d6ee805cb94d8d0651ce1808c0b557b";
const LEAF: &str = "limiter";
/// The template, built into the binary so that an installed tool needs no
/// checkout beside it: its descriptor, its source and the helpers the source
/// includes. `template` checks them as it would a directory's.
const DESCRIPTOR: &str = include_str!("../../../templates/mint_limiter/descriptor.json");
const SOURCE_NAME: &str = "mint_limiter.simf";
const SOURCE: &str = include_str!("../../../templates/mint_limiter/mint_limiter.simf");
const HELPERS: &[(&str, &str)] = &[(
    "output_reader",
    include_str!("../../../helpers/output_reader.simf"),
)];
/// BIP68's type flag: a relative lock in units of 512 seconds.
const TIME_FLAG: u32 = 1 << 22;
/// The least age, in blocks, of a coin a mint spends.
const MIN_AGE: u16 = 2;
/// The witness type of PATH and its value for each path.
const PATHS: [(&str, &str); 4] = [
    ("mint", "Left(())"),
    ("arm", "Right(Left(()))"),
    ("disarm", "Right(Right(Left(())))"),
    ("recover", "Right(Right(Right(())))"),
];
/// The witness that carries each path's signature.
const SIGS: [(&str, &str); 4] = [
    ("mint", "OPERATOR_SIG"),
    ("arm", "ARM_SIG"),
    ("disarm", "COLD_SIG"),
    ("recover", "RECOVER_SIG"),
];
/// The tag of the arm message: SHA256("sequentia/mint-limiter/arm").
const ARM_TAG: &str = "sequentia/mint-limiter/arm";

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
    command: String,
    values: BTreeMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse() -> Res<Self> {
        let mut it = std::env::args().skip(1);
        let command = it.next().ok_or(USAGE)?;
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
                return fail(format!("{} does not take --{k}", self.command));
            }
        }
        Ok(())
    }
}

const USAGE: &str =
    "usage: mint-limiter (key | instance | address | arm-signature | build | follow) [options]; see tools/mint-limiter/README.md";

// ---------------------------------------------------------------------------
// The template and the instance

struct Template {
    descriptor: Descriptor,
    model: Model,
    /// Each Simplicity leaf's source by name, its helper includes resolved.
    sources: BTreeMap<String, String>,
}

/// The built-in template's sources, expanded from the helpers built in.
fn builtin_sources() -> Res<BTreeMap<String, String>> {
    let text = sequentia_contracts::expand_with(SOURCE, &mut |name| {
        HELPERS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| t.to_string())
            .ok_or_else(|| format!("no helper {name} is built into this tool"))
    })?;
    Ok(BTreeMap::from([(SOURCE_NAME.to_string(), text)]))
}

/// The template: the one built in, or with `--template DIR` a directory's
/// copy, which must be the same template.
fn template(a: &Args) -> Res<Template> {
    let (descriptor, sources, at) = match a.opt("template") {
        Some(d) => {
            let dir = PathBuf::from(d);
            let descriptor = Descriptor::load(&dir.join("descriptor.json"))?;
            let raw = std::fs::read_to_string(dir.join(SOURCE_NAME)).map_err(e)?;
            let sources =
                BTreeMap::from([(SOURCE_NAME.to_string(), sequentia_contracts::expand(&raw)?)]);
            (descriptor, sources, dir.display().to_string())
        }
        None => (
            Descriptor::parse(DESCRIPTOR)?,
            builtin_sources()?,
            "the built-in template".to_string(),
        ),
    };
    if descriptor.template_hash != TEMPLATE_HASH {
        return fail(format!(
            "{at}: template {} is not the mint limiter this tool spends, {TEMPLATE_HASH}",
            descriptor.template_hash
        ));
    }
    // Compiles each source with the pinned compiler and checks its source
    // hash, root, lints, witness and cost bound against the descriptor.
    descriptor.validate_sources(&sources)?;
    let model = descriptor.model()?;
    Ok(Template {
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

fn instance(a: &Args) -> Res<Instance> {
    let path = a.get("instance")?;
    let text = std::fs::read_to_string(path).map_err(|x| format!("{path}: {x}"))?;
    let v = sequentia_contracts::descriptor::parse_json(&text)?;
    let obj = v.as_object().ok_or("an instance is a JSON object")?;
    for k in obj.keys() {
        if !["instance", "template_hash", "params", "slots", "genesis"].contains(&k.as_str()) {
            return fail(format!("{path}: unknown field {k}"));
        }
    }
    if v["instance"] != json!(2) {
        return fail(format!("{path}: instance is not 2"));
    }
    if v["template_hash"] != json!(TEMPLATE_HASH) {
        return fail(format!(
            "{path}: the instance is of template {}, not {TEMPLATE_HASH}",
            v["template_hash"]
        ));
    }
    let genesis = match &v["genesis"] {
        Value::String(s) => BlockHash::from_str(s).map_err(e)?,
        _ => return fail(format!("{path}: genesis names the chain: a block hash")),
    };
    let inst = Instance {
        params: strings(&v["params"], "params")?,
        genesis,
    };
    check_params(&inst)?;
    Ok(inst)
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

/// The values a well-formed instance holds: keys of their own, a window the
/// relative lock can count, a recovery delay that is a delay.
fn check_params(inst: &Instance) -> Res<()> {
    if param_hex(inst, "OPERATOR_KEY")? == param_hex(inst, "COLD_KEY")? {
        return fail(
            "the operator key and the cold key are one key: the operator could lift its own brake",
        );
    }
    let window = param_u64(inst, "WINDOW")?;
    if window < u64::from(MIN_AGE) {
        return fail(format!(
            "a window of {window} blocks is shorter than the {MIN_AGE} blocks between mints"
        ));
    }
    if param_u64(inst, "RECOVERY_DELAY")? == 0 {
        return fail(
            "a recovery delay of zero lets the cold key take the token the moment it brakes",
        );
    }
    if param_u64(inst, "ALLOWANCE")? == 0 {
        return fail("an allowance of zero mints nothing");
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct State {
    minted: u64,
    elapsed: u16,
    armed: u8,
}

impl State {
    fn slots(self) -> BTreeMap<String, String> {
        [
            ("MINTED".to_string(), format!("{:016x}", self.minted)),
            ("ELAPSED".to_string(), format!("{:04x}", self.elapsed)),
            ("ARMED".to_string(), format!("{:02x}", self.armed)),
        ]
        .into_iter()
        .collect()
    }

    /// The count as a decimal string: a JSON number above 2^53 is not read
    /// exactly by every reader (JavaScript's among them).
    fn json(self) -> Value {
        json!({"minted": self.minted.to_string(), "elapsed": self.elapsed, "armed": self.armed})
    }

    fn from_json(v: &Value) -> Res<Self> {
        let n = |k: &str| {
            v[k].as_u64()
                .ok_or_else(|| format!("state.{k} is not a number"))
        };
        let s = State {
            minted: atoms(&v["minted"], "state.minted")?,
            elapsed: u16::try_from(n("elapsed")?).map_err(e)?,
            armed: u8::try_from(n("armed")?).map_err(e)?,
        };
        if s.armed > 1 {
            return fail("state.armed is 0 or 1");
        }
        Ok(s)
    }

    fn from_arg(s: &str) -> Res<Self> {
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        let &[m, el, ar] = parts.as_slice() else {
            return fail("--state is MINTED,ELAPSED,ARMED");
        };
        Self::from_json(
            &json!({"minted": m.to_string(), "elapsed": el.parse::<u64>().map_err(e)?, "armed": ar.parse::<u64>().map_err(e)?}),
        )
    }
}

/// An amount of atoms: a decimal string, as this tool writes them, or a JSON
/// number no larger than 2^53, which every reader parses exactly.
fn atoms(v: &Value, what: &str) -> Res<u64> {
    match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0')) => {
            s.parse::<u64>().map_err(|x| format!("{what}: {x}"))
        }
        Value::Number(n) => match n.as_u64() {
            Some(x) if x <= 1 << 53 => Ok(x),
            _ => fail(format!("{what}: a number above 2^53 is not read exactly everywhere; give it as a decimal string")),
        },
        _ => fail(format!("{what}: a whole number of atoms, as a decimal string")),
    }
}

/// The state a mint of `amount`, from a coin declared `age` blocks old, leads
/// to: as the program computes it. None when the program refuses the mint.
fn mint_next(inst: &Instance, s: State, age: u16, amount: u64) -> Res<State> {
    let window = param_u64(inst, "WINDOW")?;
    let allowance = param_u64(inst, "ALLOWANCE")?;
    if s.armed != 0 {
        return fail("the brake is on: no mint until the cold key lifts it");
    }
    if age < MIN_AGE {
        return fail(format!(
            "a mint spends a coin at least {MIN_AGE} blocks old; this one is declared {age}"
        ));
    }
    let ended = u64::from(s.elapsed) + u64::from(age) >= window;
    let next = if ended {
        State {
            minted: amount,
            elapsed: 0,
            armed: 0,
        }
    } else {
        State {
            minted: s
                .minted
                .checked_add(amount)
                .ok_or("the count would overflow")?,
            elapsed: s.elapsed + age,
            armed: 0,
        }
    };
    if next.minted > allowance {
        return fail(format!(
            "a mint of {amount} would bring the window's count to {}, above its allowance of {allowance}{}",
            next.minted,
            if ended { "" } else { " (the window has not ended)" }
        ));
    }
    Ok(next)
}

#[derive(Clone)]
struct NoArguments;

impl ArgumentsTrait for NoArguments {
    fn build_arguments(&self) -> Arguments {
        Arguments::default()
    }
}

/// The covenant's contract tree for `state`, built with the framework from the
/// descriptor's tree and checked against the descriptor's own derivation.
fn contract(
    t: &Template,
    inst: &Instance,
    state: State,
) -> Res<(ContractTree, sequentia_contracts::descriptor::TreeDerived)> {
    let slots = state.slots();
    let derived = t.model.derive(&inst.params, &slots)?;
    let mut values = inst.params.clone();
    values.extend(slots);
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
    if hex(&tree.control_block(LEAF).map_err(e)?.serialize())
        != derived.leaves[LEAF]
            .control_block
            .clone()
            .unwrap_or_default()
    {
        return fail("the framework's control block is not the descriptor's");
    }
    Ok((tree, derived))
}

fn network(inst: &Instance) -> Res<SimplicityNetwork> {
    if inst.genesis == SimplicityNetwork::SequentiaTestnet.genesis_block_hash() {
        return Ok(SimplicityNetwork::SequentiaTestnet);
    }
    // A local chain. Its policy asset is one fee asset among any, and nothing
    // here pays a fee through the framework, so the minted asset stands in.
    Ok(SimplicityNetwork::SequentiaRegtest {
        policy_asset: param_asset(inst, "ASSET")?,
        genesis_hash: inst.genesis,
    })
}

fn mnemonic(a: &Args) -> Res<String> {
    let path = a.get("mnemonic-file")?;
    let text = std::fs::read_to_string(path).map_err(|x| format!("{path}: {x}"))?;
    Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The contract key a mnemonic derives (m/8383h/1h/0h/0/0 on the testnet and
/// local chains), checked to be the parameter `name`.
fn signer_for(a: &Args, inst: &Instance, net: SimplicityNetwork, name: &str) -> Res<Signer> {
    let words = mnemonic(a)?;
    let signer = std::panic::catch_unwind(|| Signer::from_mnemonic(&words, net))
        .map_err(|_| "the mnemonic does not parse".to_string())?;
    if hex(&signer.get_schnorr_public_key().serialize()) != param_hex(inst, name)? {
        return fail(format!(
            "this mnemonic's contract key is not the instance's {name}"
        ));
    }
    Ok(signer)
}

/// The message COLD_KEY signs to apply the brake: the program's arm_message.
fn arm_message(
    inst: &Instance,
    derived: &sequentia_contracts::descriptor::TreeDerived,
) -> Res<[u8; 32]> {
    let tag = sha256::Hash::hash(ARM_TAG.as_bytes());
    let mut m = Vec::new();
    m.extend_from_slice(tag.as_ref());
    m.extend_from_slice(tag.as_ref());
    m.extend_from_slice(inst.genesis.as_ref());
    m.extend_from_slice(&unhex(&derived.leaves[LEAF].hash)?);
    for p in [
        "ASSET",
        "TOKEN",
        "OPERATOR_KEY",
        "COLD_KEY",
        "WINDOW",
        "ALLOWANCE",
        "RECOVERY_DELAY",
    ] {
        m.extend_from_slice(&unhex(param_hex(inst, p)?)?);
    }
    Ok(sha256::Hash::hash(&m).to_byte_array())
}

// ---------------------------------------------------------------------------
// Coins

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

// ---------------------------------------------------------------------------
// The spend

/// The program's witness values for `path` in `state`, with `sig` at the
/// path's signature and zeros at the others, which pruning removes.
fn witness(
    program: &Program,
    inst: &Instance,
    state: State,
    path: &str,
    sig: &[u8; 64],
) -> Res<WitnessValues> {
    let types = program.get_witness_types().map_err(e)?;
    let slots = state.slots();
    let mut map = std::collections::HashMap::new();
    let path_value = PATHS
        .iter()
        .find(|(p, _)| *p == path)
        .ok_or("unknown path")?
        .1;
    let sig_name = SIGS
        .iter()
        .find(|(p, _)| *p == path)
        .ok_or("unknown path")?
        .1;
    for (name, ty) in types.iter() {
        let n: &str = name.as_ref();
        let literal = if n == "PATH" {
            path_value.to_string()
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

fn cmd_build(a: &Args) -> Res<Value> {
    a.only(&["instance", "template", "mnemonic-file"])?;
    let t = template(a)?;
    let inst = instance(a)?;
    let net = network(&inst)?;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(e)?;
    let req = sequentia_contracts::descriptor::parse_json(&text)?;
    let path = req["path"]
        .as_str()
        .ok_or("path: mint, arm, disarm or recover")?;
    if !PATHS.iter().any(|(p, _)| *p == path) {
        return fail(format!("path {path}: mint, arm, disarm or recover"));
    }
    let state = State::from_json(&req["state"])?;
    let (tree, derived) = contract(&t, &inst, state)?;
    let token = param_asset(&inst, "TOKEN")?;
    let asset = param_asset(&inst, "ASSET")?;

    // The coin: this instance in this state, holding the token explicitly.
    let c = coin(&req["coin"], "coin")?;
    if c.txout.script_pubkey != tree.script_pubkey() {
        return fail(format!(
            "the coin's script is not the instance's in state {:?}: {}",
            state,
            hex(c.txout.script_pubkey.as_bytes())
        ));
    }
    let (held, amount) = explicit(&c.txout)
        .ok_or("the coin is confidential; the covenant reads only explicit coins")?;
    if held != token {
        return fail(format!("the coin holds {held}, not the token {token}"));
    }

    // What the path leads to.
    let (sequence, next, issue) = match path {
        "mint" => {
            let age = u16::try_from(
                req["age"]
                    .as_u64()
                    .ok_or("age: the coin's age in blocks, as the next block finds it")?,
            )
            .map_err(e)?;
            let x = atoms(&req["amount"], "amount: the atoms to mint")?;
            if x == 0 {
                return fail("a reissuance of zero is not valid");
            }
            let entropy = sha256::Midstate::from_str(
                req["entropy"]
                    .as_str()
                    .ok_or("entropy: the asset's issuance entropy")?,
            )
            .map_err(e)?;
            if AssetId::from_entropy(entropy) != asset {
                return fail("this entropy issues another asset than the instance's");
            }
            if AssetId::reissuance_token_from_entropy(entropy, false) != token {
                return fail(
                    "this entropy's explicit reissuance token is not the instance's token",
                );
            }
            (
                u32::from(age),
                Some(mint_next(&inst, state, age, x)?),
                Some((x, entropy)),
            )
        }
        "arm" => {
            if state.armed != 0 {
                return fail("the brake is already on");
            }
            (0, Some(State { armed: 1, ..state }), None)
        }
        "disarm" => {
            if state.armed != 1 {
                return fail("the brake is not on");
            }
            (0, Some(State { armed: 0, ..state }), None)
        }
        _ => {
            if state.armed != 1 {
                return fail("only a braked coin is recovered: apply the brake first");
            }
            (
                TIME_FLAG | u32::try_from(param_u64(&inst, "RECOVERY_DELAY")?).map_err(e)?,
                None,
                None,
            )
        }
    };

    let mut ft = FinalTransaction::new();
    let input = PartialInput::new(UTXO {
        outpoint: c.outpoint,
        txout: c.txout.clone(),
        secrets: None,
    })
    .with_sequence(Sequence::from_consensus(sequence));
    match issue {
        Some((x, entropy)) => {
            ft.add_issuance_input(
                input,
                IssuanceInput::new_reissuance(x, entropy.to_byte_array()),
                RequiredSignature::None,
            );
        }
        None => ft.add_input(input, RequiredSignature::None),
    }
    // The fee coins, all of one asset, unsigned: the bridge's wallet signs them.
    let fee = &req["fee"];
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
            return fail(
                "the fee coins hold more than one asset; one asset pays a transaction's fee",
            );
        }
        if fa == token {
            return fail("a fee coin holds the token");
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
    let fee_asset =
        fee_asset.ok_or("no fee coin: a covenant spend takes its fee from another coin")?;
    let change = fee_in
        .checked_sub(fee_atoms)
        .ok_or_else(|| format!("the fee coins hold {fee_in}, less than the fee of {fee_atoms}"))?;

    // The outputs: the successor first, as the covenant requires.
    let successor = match next {
        Some(n) => {
            let (succ, sd) = contract(&t, &inst, n)?;
            ft.add_output(PartialOutput::new(succ.script_pubkey(), amount, token));
            Some((n, succ, sd))
        }
        None => None,
    };
    match (path, issue) {
        ("mint", Some((x, _))) => ft.add_output(PartialOutput::new(
            script_arg(&req["mint_to"], "mint_to")?,
            x,
            asset,
        )),
        ("recover", _) => ft.add_output(PartialOutput::new(
            script_arg(&req["recover_to"], "recover_to")?,
            amount,
            token,
        )),
        _ => {}
    }
    if change > 0 {
        ft.add_output(PartialOutput::new(
            script_arg(&fee["change_to"], "fee.change_to")?,
            change,
            fee_asset,
        ));
    }
    ft.add_output(PartialOutput::new(Script::new(), fee_atoms, fee_asset));

    let (mut pst, _) = ft.extract_pst();
    let program = tree.program(LEAF).map_err(e)?;
    let secp = Secp256k1::new();
    let sig: [u8; 64] = match path {
        "arm" => {
            let s = unhex(
                req["arm_signature"]
                    .as_str()
                    .ok_or("arm_signature: the cold key's signature over the arm message")?,
            )?;
            let s = schnorr::Signature::from_slice(&s).map_err(e)?;
            let msg = Message::from_digest(arm_message(&inst, &derived)?);
            let cold = XOnlyPublicKey::from_str(param_hex(&inst, "COLD_KEY")?).map_err(e)?;
            secp.verify_schnorr(&s, &msg, &cold).map_err(|_| {
                "arm_signature is not the cold key's signature over this instance's arm message"
            })?;
            s.serialize()
        }
        "mint" => signer_for(a, &inst, net, "OPERATOR_KEY")?
            .sign_program(&pst, &program, 0, &net, None, &SigMessage::Sighash)
            .map_err(e)?
            .serialize(),
        _ => signer_for(a, &inst, net, "COLD_KEY")?
            .sign_program(&pst, &program, 0, &net, None, &SigMessage::Sighash)
            .map_err(e)?
            .serialize(),
    };
    let wv = witness(&program, &inst, state, path, &sig)?;
    let spend = program
        .finalize_spend(&pst, &wv, 0, &net)
        .map_err(|x| format!("the covenant refuses this spend: {x}"))?;
    let rule: BudgetRule = net.simplicity_budget();
    if !rule.covers(spend.cost, &spend.stack) {
        return fail("the spend's witness does not earn its cost bound; this tool does not pad");
    }
    let budget = rule.report(spend.cost, &spend.stack);
    pst.inputs_mut()[0].final_script_witness = Some(spend.stack.clone());
    let tx = pst.extract_tx().map_err(e)?;
    let txid = tx.txid().to_string();
    let mut out = json!({
        "path": path,
        "txid": txid,
        "hex": serialize_hex(&tx),
        "state": state.json(),
        "coin": {"txid": c.outpoint.txid.to_string(), "vout": c.outpoint.vout},
        "sequence": sequence,
        "fee": {"asset": fee_asset.to_string(), "atoms": fee_atoms, "change": change},
        "weight_before_wallet_signatures": tx.weight(),
        "program_bytes": spend.stack[1].len(),
        "witness_bytes": spend.stack[0].len(),
        "cost_bound_milli_wu": budget.cost_milliweight,
        "budget_wu": budget.budget,
    });
    if let Some((n, succ, sd)) = successor {
        out["next_state"] = n.json();
        out["successor"] = json!({
            "txid": txid, "vout": 0, "amount": amount,
            "script_pubkey": hex(succ.script_pubkey().as_bytes()),
            "address": t.descriptor.addresses(&sd.output_key)?,
        });
    }
    if let Some((x, _)) = issue {
        out["minted"] = json!(x.to_string());
    }
    Ok(out)
}

/// What a transaction that spends the covenant's coin did to it.
fn cmd_follow(a: &Args) -> Res<Value> {
    a.only(&["instance", "template"])?;
    let t = template(a)?;
    let inst = instance(a)?;
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).map_err(e)?;
    let req = sequentia_contracts::descriptor::parse_json(&text)?;
    let state = State::from_json(&req["state"])?;
    let c = coin(&req["coin"], "coin")?;
    let (tree, _) = contract(&t, &inst, state)?;
    if c.txout.script_pubkey != tree.script_pubkey() {
        return fail("the coin's script is not the instance's in that state");
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
    let input = &tx.input[at];
    let out0 = tx.output.first().map(|o| o.script_pubkey.clone());
    let txid = tx.txid().to_string();
    let found = |path: &str, n: State| -> Res<Option<Value>> {
        let (succ, sd) = contract(&t, &inst, n)?;
        Ok((Some(succ.script_pubkey()) == out0).then(|| {
            json!({"path": path, "state": state.json(), "next_state": n.json(),
                   "successor": {"txid": txid, "vout": 0,
                                 "address": t.descriptor.addresses(&sd.output_key).ok()}})
        }))
    };
    if input.has_issuance() {
        let d = input.sequence.to_consensus_u32();
        if d & (1 << 31 | TIME_FLAG) == 0 {
            if let confidential::Value::Explicit(x) = input.asset_issuance.amount {
                if let Ok(n) = mint_next(&inst, state, u16::try_from(d & 0xffff).map_err(e)?, x) {
                    if let Some(v) = found("mint", n)? {
                        let mut v = v;
                        v["minted"] = json!(x.to_string());
                        return Ok(v);
                    }
                }
            }
        }
    } else if state.armed == 0 {
        if let Some(v) = found("arm", State { armed: 1, ..state })? {
            return Ok(v);
        }
    } else if let Some(v) = found("disarm", State { armed: 0, ..state })? {
        return Ok(v);
    }
    if state.armed == 1 {
        let token = param_asset(&inst, "TOKEN")?;
        let to: Vec<Value> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| explicit(o).is_some_and(|(asset, _)| asset == token))
            .map(|(i, o)| json!({"vout": i, "script_pubkey": hex(o.script_pubkey.as_bytes()), "amount": explicit(o).map(|x| x.1)}))
            .collect();
        return Ok(json!({"path": "recover", "state": state.json(), "txid": txid, "token_to": to}));
    }
    fail("the transaction spends the coin by no path of the covenant")
}

fn cmd_arm_signature(a: &Args) -> Res<Value> {
    a.only(&["instance", "template", "mnemonic-file"])?;
    let t = template(a)?;
    let inst = instance(a)?;
    let net = network(&inst)?;
    let (_, derived) = contract(
        &t,
        &inst,
        State {
            minted: 0,
            elapsed: 0,
            armed: 0,
        },
    )?;
    let signer = signer_for(a, &inst, net, "COLD_KEY")?;
    let msg = arm_message(&inst, &derived)?;
    let secp = Secp256k1::new();
    let key = signer.get_contract_private_key_at(None);
    let keypair = Keypair::from_secret_key(&secp, &key.inner);
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &keypair);
    Ok(
        json!({"message": hex(&msg), "arm_signature": hex(&sig.serialize()), "cold_key": param_hex(&inst, "COLD_KEY")?}),
    )
}

fn cmd_address(a: &Args) -> Res<Value> {
    a.only(&["instance", "template", "state"])?;
    let t = template(a)?;
    let inst = instance(a)?;
    let state = match a.opt("state") {
        Some(s) => State::from_arg(s)?,
        None => State {
            minted: 0,
            elapsed: 0,
            armed: 0,
        },
    };
    let (_, derived) = contract(&t, &inst, state)?;
    Ok(json!({
        "template_hash": t.descriptor.template_hash,
        "state": state.json(),
        "address": t.descriptor.addresses(&derived.output_key)?,
        "script_pubkey": derived.script_pubkey,
        "leaves": derived.leaves,
    }))
}

fn cmd_key(a: &Args) -> Res<Value> {
    a.only(&["mnemonic-file"])?;
    // The contract key at m/8383h/1h/0h/0/0, the account every Sequentia chain
    // but the mainnet derives under.
    let key = |words: &str| -> Res<String> {
        let w = words.to_string();
        let signer = std::panic::catch_unwind(move || {
            Signer::from_mnemonic(&w, SimplicityNetwork::SequentiaTestnet)
        })
        .map_err(|_| "the mnemonic does not parse".to_string())?;
        Ok(hex(&signer.get_schnorr_public_key().serialize()))
    };
    if !a.flags.iter().any(|f| f == "--new") {
        return Ok(json!({"key": key(&mnemonic(a)?)?}));
    }
    // A new mnemonic: twelve words from the operating system's randomness,
    // printed once or written once to a new file readable by its owner alone,
    // never to stderr.
    let words = smplx_sdk::utils::random_mnemonic();
    let k = key(&words)?;
    match a.opt("mnemonic-file") {
        None => Ok(json!({"mnemonic": words, "key": k})),
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|x| format!("{path}: {x}; a new mnemonic is never written over a file"))?;
            writeln!(f, "{words}")
                .and_then(|()| f.sync_all())
                .map_err(e)?;
            Ok(json!({"mnemonic_file": path, "key": k}))
        }
    }
}

fn cmd_instance(a: &Args) -> Res<Value> {
    a.only(&[
        "template",
        "asset",
        "token",
        "entropy",
        "operator-key",
        "cold-key",
        "window",
        "allowance",
        "recovery-delay",
        "genesis",
    ])?;
    let t = template(a)?;
    let asset = AssetId::from_str(a.get("asset")?).map_err(e)?;
    let token = AssetId::from_str(a.get("token")?).map_err(e)?;
    let entropy = sha256::Midstate::from_str(a.get("entropy")?).map_err(e)?;
    if AssetId::from_entropy(entropy) != asset {
        return fail("the entropy issues another asset than --asset");
    }
    if AssetId::reissuance_token_from_entropy(entropy, false) != token {
        return fail("--token is not the explicit reissuance token of --asset: an explicit mint could never spend it");
    }
    let genesis = BlockHash::from_str(a.get("genesis")?).map_err(e)?;
    let window: u16 = a.get("window")?.parse().map_err(e)?;
    let allowance: u64 = a.get("allowance")?.parse().map_err(e)?;
    let delay: u16 = a.get("recovery-delay")?.parse().map_err(e)?;
    // An asset id, as the program reads it, in internal byte order: the
    // reverse of the hex an RPC prints.
    let internal = |x: AssetId| {
        hex(&unhex(&x.to_string())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect::<Vec<_>>())
    };
    let params = json!({
        "ASSET": internal(asset), "TOKEN": internal(token),
        "OPERATOR_KEY": a.get("operator-key")?, "COLD_KEY": a.get("cold-key")?,
        "WINDOW": format!("{window:04x}"), "ALLOWANCE": format!("{allowance:016x}"),
        "RECOVERY_DELAY": format!("{delay:04x}"),
    });
    let initial = State {
        minted: 0,
        elapsed: 0,
        armed: 0,
    };
    let inst = Instance {
        params: strings(&params, "params")?,
        genesis,
    };
    check_params(&inst)?;
    // The instance must derive: every value of its width and allowed by its role.
    let derived = t.model.derive(&inst.params, &initial.slots())?;
    Ok(json!({
        "instance": 2, "template_hash": TEMPLATE_HASH, "params": params,
        "slots": serde_json::to_value(initial.slots()).map_err(e)?, "genesis": genesis.to_string(),
        "address": t.descriptor.addresses(&derived.output_key)?,
    }))
}

fn run() -> Res<Value> {
    let a = Args::parse()?;
    match a.command.as_str() {
        "key" => cmd_key(&a),
        "instance" => cmd_instance(&a),
        "address" => cmd_address(&a),
        "arm-signature" => cmd_arm_signature(&a),
        "build" => cmd_build(&a),
        "follow" => cmd_follow(&a),
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
            let _ = writeln!(std::io::stderr(), "mint-limiter: {m}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst() -> Instance {
        let p = |k: &str, v: &str| (k.to_string(), v.to_string());
        Instance {
            params: [
                p(
                    "ASSET",
                    "54a2cfc4ecd61c94bc1e51000139ea528f2835365ce123e0e1abd6e1bb3cdb4f",
                ),
                p(
                    "TOKEN",
                    "3451dc1e07263404995266b7ba2df763bae70984936b6edf7bd149d913d2f874",
                ),
                p(
                    "OPERATOR_KEY",
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                ),
                p(
                    "COLD_KEY",
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                ),
                p("WINDOW", "0014"),
                p("ALLOWANCE", "00000000000003e8"),
                p("RECOVERY_DELAY", "0002"),
            ]
            .into_iter()
            .collect(),
            genesis: SimplicityNetwork::SequentiaTestnet.genesis_block_hash(),
        }
    }

    #[test]
    fn the_next_state_is_the_programs() {
        let i = inst();
        let s = |m, el| State {
            minted: m,
            elapsed: el,
            armed: 0,
        };
        assert_eq!(mint_next(&i, s(0, 0), 2, 500).ok(), Some(s(500, 2)));
        assert_eq!(mint_next(&i, s(500, 2), 2, 500).ok(), Some(s(1000, 4)));
        assert!(mint_next(&i, s(500, 2), 2, 501).is_err());
        // The window ends once ELAPSED and the age reach WINDOW (20 blocks).
        assert!(mint_next(&i, s(1000, 4), 15, 1).is_err());
        assert_eq!(mint_next(&i, s(1000, 4), 16, 1000).ok(), Some(s(1000, 0)));
        assert!(mint_next(&i, s(0, 0), 1, 1).is_err());
        assert!(mint_next(
            &i,
            State {
                armed: 1,
                ..s(0, 0)
            },
            2,
            1
        )
        .is_err());
    }

    #[test]
    fn instances_refuse_shared_keys_and_empty_limits() {
        let mut i = inst();
        i.params
            .insert("COLD_KEY".into(), i.params["OPERATOR_KEY"].clone());
        assert!(check_params(&i).is_err());
        let mut i = inst();
        i.params.insert("RECOVERY_DELAY".into(), "0000".into());
        assert!(check_params(&i).is_err());
        let mut i = inst();
        i.params.insert("WINDOW".into(), "0001".into());
        assert!(check_params(&i).is_err());
        assert!(check_params(&inst()).is_ok());
    }

    #[test]
    fn amounts_read_as_strings_and_small_numbers() {
        assert_eq!(
            atoms(&json!("18446744073709551615"), "x").ok(),
            Some(u64::MAX)
        );
        assert_eq!(atoms(&json!(1000), "x").ok(), Some(1000));
        assert_eq!(atoms(&json!("0"), "x").ok(), Some(0));
        assert!(atoms(&json!(9_007_199_254_740_993u64), "x").is_err());
        assert!(atoms(&json!("012"), "x").is_err());
        assert!(atoms(&json!("1.5"), "x").is_err());
        assert!(atoms(&json!("-1"), "x").is_err());
        assert!(atoms(&json!(null), "x").is_err());
        let s = State {
            minted: u64::MAX,
            elapsed: 3,
            armed: 0,
        };
        assert_eq!(State::from_json(&s.json()).ok(), Some(s));
    }

    #[test]
    fn the_template_is_the_pinned_one() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../templates/mint_limiter");
        let d = Descriptor::load(&dir.join("descriptor.json")).unwrap();
        assert_eq!(d.template_hash, TEMPLATE_HASH);
        d.validate(&dir).unwrap();
    }

    #[test]
    fn the_built_in_template_is_the_checkouts() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../templates/mint_limiter");
        let file = std::fs::read_to_string(dir.join(SOURCE_NAME)).unwrap();
        let built = builtin_sources().unwrap();
        assert_eq!(
            built[SOURCE_NAME],
            sequentia_contracts::expand(&file).unwrap()
        );
        let args = |values: BTreeMap<String, String>| Args {
            command: "build".to_string(),
            values,
            flags: Vec::new(),
        };
        let t = template(&args(BTreeMap::new())).unwrap();
        assert_eq!(t.descriptor.template_hash, TEMPLATE_HASH);
        let given = BTreeMap::from([("template".to_string(), dir.display().to_string())]);
        assert_eq!(template(&args(given)).unwrap().sources, t.sources);
    }
}
