//! Arca's collaborative path, `arca/collab-2`, against
//! `templates/arca_collab/collab.json`.
//!
//! The output is `TapBranch(TapBranch(F, D), E)`: this program `F`, the data
//! leaf `D` over the owner's key, the operator's key and the salt, and the
//! exit `E` (only its hash matters here). This test builds that output and
//! the digest both keys sign in Rust, independently of the program, signs it,
//! and runs the program on the Bit Machine: every spend it should accept
//! passes, and the spends it must refuse fail, each attack that a `vtxo-1`
//! pair allows among them. It then prunes the program for every shape of
//! spend (named inputs 1 to 16, outputs 1 to 4, the coin at the first and the
//! last named index, fee inputs and outputs after them) and requires the one
//! constant of `collab.json` each time, with the witness the data leaf's
//! bytes, n, m and the two signatures. `WRITE_COLLAB=1 cargo test --test
//! arca_collab` rewrites the file instead.

use std::sync::Arc;

use secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1, XOnlyPublicKey};
use sequentia_contracts::elements::confidential::{Asset, Nonce, Value as Amount};
use sequentia_contracts::elements::hashes::{sha256, Hash};
use sequentia_contracts::elements::taproot::ControlBlock;
use sequentia_contracts::elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid};
use sequentia_contracts::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::{CompiledProgram, WitnessValues};
use serde_json::{json, Value};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/arca_collab");
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const GENESIS: [u8; 32] = [0x5a; 32];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn h(label: &str) -> [u8; 32] {
    sha256::Hash::hash(label.as_bytes()).to_byte_array()
}

fn sha(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}

fn tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = h(tag);
    sha(&[&t[..], &t[..], msg].concat())
}

fn tapleaf(version: u8, script: &[u8]) -> [u8; 32] {
    assert!(script.len() < 0xfd);
    tagged("TapLeaf/elements", &[&[version, script.len() as u8][..], script].concat())
}

fn tapbranch(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (x, y) = if a < b { (a, b) } else { (b, a) };
    tagged("TapBranch/elements", &[x, y].concat())
}

fn output_key(root: [u8; 32]) -> ([u8; 32], Parity) {
    let secp = Secp256k1::new();
    let nums = XOnlyPublicKey::from_slice(&unhex(NUMS)).unwrap();
    let t = tagged("TapTweak/elements", &[&nums.serialize()[..], &root[..]].concat());
    let (q, parity) = nums.add_tweak(&secp, &Scalar::from_be_bytes(t).unwrap()).unwrap();
    (q.serialize(), parity)
}

/// `K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)`.
fn leaf_constant(genesis: [u8; 32], salt: [u8; 32]) -> [u8; 32] {
    let tag = sha(&[&b"ArcaRbd1"[..], &genesis[..]].concat());
    sha(&[tag, salt].concat())
}

fn exit_script(units: u16, key: [u8; 32]) -> Vec<u8> {
    let u = units.to_le_bytes();
    [vec![0x03, u[0], u[1], 0x40, 0xb2, 0x75, 0x20], key.to_vec(), vec![0xac]].concat()
}

/// A coin's parameters: the data leaf.
#[derive(Clone, Debug)]
struct P {
    owner: [u8; 32],
    operator: [u8; 32],
    salt: [u8; 32],
    /// The tapscript leaf beside `TapBranch(F, D)`: the exit or the sweep.
    other: [u8; 32],
}

impl P {
    fn bytes(&self) -> Vec<u8> {
        [self.owner, self.operator, self.salt].concat()
    }

    fn data_leaf(&self) -> [u8; 32] {
        tagged("TapData", &self.bytes())
    }

    fn root(&self, cmr: [u8; 32]) -> [u8; 32] {
        tapbranch(tapbranch(tapleaf(0xbe, &cmr), self.data_leaf()), self.other)
    }

    fn spk(&self, cmr: [u8; 32]) -> Vec<u8> {
        [&[0x51, 0x20][..], &output_key(self.root(cmr)).0[..]].concat()
    }

    fn control_block(&self, cmr: [u8; 32]) -> Vec<u8> {
        let parity = output_key(self.root(cmr)).1;
        let first = 0xbe | if parity == Parity::Odd { 1 } else { 0 };
        [vec![first], unhex(NUMS), self.data_leaf().to_vec(), self.other.to_vec()].concat()
    }

    fn witness(&self, n: u8, m: u8, owner_sig: &[u8; 64], operator_sig: &[u8; 64]) -> Value {
        let b = |v: &[u8], t: &str| json!({"value": format!("0x{}", hex(v)), "type": t});
        let u = |v: u64, t: &str| json!({"value": v.to_string(), "type": t});
        json!({
            "OWNER": b(&self.owner, "u256"), "OPERATOR": b(&self.operator, "u256"), "SALT": b(&self.salt, "u256"),
            "N": u(n as u64, "u8"), "M": u(m as u64, "u8"),
            "OWNER_SIG": b(owner_sig, "Signature"), "OPERATOR_SIG": b(operator_sig, "Signature"),
        })
    }
}

fn out(asset: &[u8; 32], value: u64, spk: &[u8]) -> TxOut {
    TxOut {
        asset: Asset::Explicit(AssetId::from_slice(asset).unwrap()),
        value: Amount::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::from(spk.to_vec()),
        witness: Default::default(),
    }
}

fn explicit(o: &TxOut) -> ([u8; 32], u64) {
    let asset = match o.asset {
        Asset::Explicit(a) => a.into_inner().to_byte_array(),
        _ => unreachable!(),
    };
    (asset, o.value.explicit().unwrap())
}

/// `input_utxo_hash` of an explicit coin: `SHA256(01 ‖ asset ‖ 01 ‖ value ‖ SHA256(spk))`.
fn utxo_hash(o: &TxOut) -> [u8; 32] {
    let (asset, value) = explicit(o);
    let mut b = vec![0x01];
    b.extend(asset);
    b.push(0x01);
    b.extend(value.to_be_bytes());
    b.extend(sha(o.script_pubkey.as_bytes()));
    sha(&b)
}

/// `output_hash` of an explicit output with no nonce.
fn output_hash(o: &TxOut) -> [u8; 32] {
    let (asset, value) = explicit(o);
    let mut b = vec![0x01];
    b.extend(asset);
    b.push(0x01);
    b.extend(value.to_be_bytes());
    match o.nonce {
        Nonce::Null => b.push(0x00),
        Nonce::Explicit(x) => {
            b.push(0x01);
            b.extend(x);
        },
        _ => unreachable!(),
    }
    b.extend(sha(o.script_pubkey.as_bytes()));
    b.extend(sha(&[]));
    sha(&b)
}

/// The digest both keys sign for the coin of `p` at input `k`, naming
/// `utxos[0..n]` and committing to `outputs[0..m]`.
fn digest(genesis: [u8; 32], p: &P, k: u32, utxos: &[TxOut], outputs: &[TxOut]) -> [u8; 32] {
    let named: Vec<u8> = utxos.iter().flat_map(utxo_hash).collect();
    let committed: Vec<u8> = outputs.iter().flat_map(output_hash).collect();
    let mut b = leaf_constant(genesis, p.salt).to_vec();
    b.extend(k.to_be_bytes());
    b.push(utxos.len() as u8);
    b.extend(sha(&named));
    b.push(outputs.len() as u8);
    b.extend(sha(&committed));
    assert_eq!(b.len(), 102);
    sha(&b)
}

struct Spend {
    tx: Transaction,
    utxos: Vec<TxOut>,
    k: u32,
}

/// A spend naming `n` inputs, the coin of `p` holding `value` at `k`, the
/// others coins of other scripts, with `m` committed outputs, a fee coin
/// after the named inputs and its change and fee output after the committed
/// outputs.
fn spend(p: &P, cmr: [u8; 32], n: u32, k: u32, m: usize, value: u64) -> Spend {
    let asset = h("asset X");
    let fee_asset = h("the fee asset");
    let mut input = vec![];
    let mut utxos = vec![];
    for i in 0..=n {
        input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(h(&format!("coin {i}"))), i),
            sequence: Sequence::MAX,
            ..Default::default()
        });
        if i == k {
            utxos.push(out(&asset, value, &p.spk(cmr)));
        } else if i < n {
            utxos.push(out(&asset, 1_000 + i as u64, &[&[0x51u8, 0x20][..], &h(&format!("checkpoint {i}"))[..]].concat()));
        } else {
            utxos.push(out(&fee_asset, 50_000, &[0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]));
        }
    }
    let mut output = vec![];
    for j in 0..m {
        output.push(out(&asset, 100 + j as u64, &[&[0x51u8, 0x20][..], &h(&format!("new leaf {j}"))[..]].concat()));
    }
    output.push(out(&fee_asset, 49_000, &[0x00, 0x14, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]));
    output.push(TxOut::new_fee(1_000, AssetId::from_slice(&fee_asset).unwrap()));
    Spend { tx: Transaction { version: 2, lock_time: LockTime::ZERO, input, output }, utxos, k }
}

fn coin(seed: &str, operator: &Keypair) -> (P, Keypair) {
    let secp = Secp256k1::new();
    let owner = Keypair::from_seckey_slice(&secp, &h(&format!("{seed} owner"))).unwrap();
    let p = P {
        owner: owner.x_only_public_key().0.serialize(),
        operator: operator.x_only_public_key().0.serialize(),
        salt: h(&format!("{seed} salt")),
        other: tapleaf(0xc4, &exit_script(254, owner.x_only_public_key().0.serialize())),
    };
    (p, owner)
}

fn sign(key: &Keypair, d: [u8; 32]) -> [u8; 64] {
    Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(d), key).serialize()
}

/// Runs the program on `s` with the witness `p`, `n`, `m` and the two
/// signatures; returns (program, witness, cost) or the error.
fn run_with(program: &CompiledProgram, p: &P, s: &Spend, n: u8, m: u8, sigs: ([u8; 64], [u8; 64]), cb: Option<Vec<u8>>, genesis: [u8; 32])
    -> Result<(Vec<u8>, Vec<u8>, String), String>
{
    let cmr: [u8; 32] = program.commit().cmr().to_byte_array();
    let cb = ControlBlock::from_slice(&cb.unwrap_or_else(|| p.control_block(cmr))).unwrap();
    let env = ElementsEnv::new(
        Arc::new(s.tx.clone()),
        s.utxos.iter().cloned().map(ElementsUtxo::from).collect(),
        s.k,
        program.commit().cmr(),
        cb,
        None,
        BlockHash::from_byte_array(genesis),
    );
    let wv: WitnessValues = serde_json::from_str(&p.witness(n, m, &sigs.0, &sigs.1).to_string()).unwrap();
    let satisfied = program.satisfy_with_env(wv, Some(&env)).map_err(|e| format!("satisfy: {e}"))?;
    let node = satisfied.redeem().clone();
    let mut mac = BitMachine::for_program(&node).map_err(|e| format!("machine: {e}"))?;
    mac.exec(&node, &env).map_err(|e| format!("exec: {e}"))?;
    let (prog, w) = node.to_vec_with_witness();
    let mut want = p.bytes();
    want.extend([n, m]);
    want.extend(sigs.0);
    want.extend(sigs.1);
    assert_eq!(hex(&w), hex(&want), "the witness is not the data leaf, n, m and the two signatures");
    Ok((prog, w, format!("{}", node.bounds().cost)))
}

/// Signs `s` honestly for the coin of `p` (the pair made for it) and runs it.
fn run(source: &CompiledProgram, p: &P, owner: &Keypair, operator: &Keypair, s: &Spend, n: u8, m: u8) -> Result<(Vec<u8>, Vec<u8>, String), String> {
    let d = digest(GENESIS, p, s.k, &s.utxos[..n as usize], &s.tx.output[..m as usize]);
    run_with(source, p, s, n, m, (sign(owner, d), sign(operator, d)), None, GENESIS)
}

fn source() -> CompiledProgram {
    let text = sequentia_contracts::expand(&std::fs::read_to_string(format!("{DIR}/arca_collab.simf")).unwrap()).unwrap();
    sequentia_contracts::compile(&text, Default::default()).unwrap()
}

fn cmr_of(program: &CompiledProgram) -> [u8; 32] {
    program.commit().cmr().to_byte_array()
}

fn refuse(name: &str, r: Result<(Vec<u8>, Vec<u8>, String), String>) {
    let e = r.expect_err(&format!("{name}: the program took it"));
    println!("refused, {name}: {e}");
}

#[test]
fn spends_the_program_accepts_and_refuses() {
    let source = source();
    let cmr = cmr_of(&source);
    let secp = Secp256k1::new();
    let s_key = Keypair::from_seckey_slice(&secp, &h("the operator")).unwrap();
    let (p, a) = coin("one", &s_key);

    // Accepted: a checkpoint's shape, a swap's, the most inputs and outputs.
    for (n, k, m) in [(1u32, 0u32, 1usize), (1, 0, 4), (2, 1, 2), (2, 0, 4), (16, 15, 4), (16, 0, 1), (5, 3, 3)] {
        let s = spend(&p, cmr, n, k, m, 10_000_000);
        let (_, _, cost) = run(&source, &p, &a, &s_key, &s, n as u8, m as u8).unwrap();
        println!("accepted n={n} k={k} m={m}: cost {cost}");
    }

    let d_of = |s: &Spend, n: usize, m: usize, k: u32| digest(GENESIS, &p, k, &s.utxos[..n], &s.tx.output[..m]);
    let pair = |d: [u8; 32]| (sign(&a, d), sign(&s_key, d));

    // A1/A2: a pair made for the coin alone at input 0, used at input 1.
    let alone = spend(&p, cmr, 1, 0, 2, 10_000_000);
    let made = pair(d_of(&alone, 1, 2, 0));
    let mut twice = spend(&p, cmr, 2, 1, 2, 10_000_000);
    twice.utxos[0] = twice.utxos[1].clone();
    twice.tx.output = alone.tx.output.clone();
    refuse("a pair made for input 0 at input 1 (n=1)", run_with(&source, &p, &twice, 1, 2, made, None, GENESIS));
    refuse("a pair made for input 0 at input 1 (n=2)", run_with(&source, &p, &twice, 2, 2, made, None, GENESIS));
    // A3: a swap leg spent beside another coin than the one named.
    let swap = spend(&p, cmr, 2, 0, 2, 10_000_000);
    let made = pair(d_of(&swap, 2, 2, 0));
    let mut other = spend(&p, cmr, 2, 0, 2, 10_000_000);
    other.utxos[1].script_pubkey = Script::from([&[0x51u8, 0x20][..], &h("a third party's coin")[..]].concat());
    refuse("a swap leg beside another script", run_with(&source, &p, &other, 2, 2, made, None, GENESIS));
    let mut other = spend(&p, cmr, 2, 0, 2, 10_000_000);
    other.utxos[1].value = Amount::Explicit(other.utxos[1].value.explicit().unwrap() + 1);
    refuse("a swap leg beside the named coin one atom larger", run_with(&source, &p, &other, 2, 2, made, None, GENESIS));
    let mut other = spend(&p, cmr, 2, 0, 2, 10_000_000);
    other.utxos[1].asset = Asset::Explicit(AssetId::from_slice(&h("another asset")).unwrap());
    refuse("a swap leg beside the named coin in another asset", run_with(&source, &p, &other, 2, 2, made, None, GENESIS));
    refuse("a swap leg alone (n=1)", run_with(&source, &p, &alone, 1, 2, made, None, GENESIS));
    // The coin itself: another amount, another asset.
    let mut more = spend(&p, cmr, 1, 0, 2, 10_000_001);
    more.tx.output = alone.tx.output.clone();
    let made = pair(d_of(&alone, 1, 2, 0));
    refuse("the pair on a coin of the script one atom larger", run_with(&source, &p, &more, 1, 2, made, None, GENESIS));
    // The outputs.
    let mut changed = spend(&p, cmr, 1, 0, 2, 10_000_000);
    changed.tx.output[1].value = Amount::Explicit(99);
    refuse("a committed output's value changed", run_with(&source, &p, &changed, 1, 2, made, None, GENESIS));
    let mut changed = spend(&p, cmr, 1, 0, 2, 10_000_000);
    changed.tx.output[0].nonce = Nonce::Explicit([2; 32]);
    refuse("a nonce added to a committed output", run_with(&source, &p, &changed, 1, 2, made, None, GENESIS));
    let mut swapped = spend(&p, cmr, 1, 0, 2, 10_000_000);
    swapped.tx.output.swap(0, 1);
    refuse("committed outputs reordered", run_with(&source, &p, &swapped, 1, 2, made, None, GENESIS));
    refuse("m one fewer than signed", run_with(&source, &p, &alone, 1, 1, made, None, GENESIS));
    // Signatures.
    let d = d_of(&alone, 1, 2, 0);
    refuse("the owner's signature in both places", run_with(&source, &p, &alone, 1, 2, (sign(&a, d), sign(&a, d)), None, GENESIS));
    refuse("the operator's signature in both places", run_with(&source, &p, &alone, 1, 2, (sign(&s_key, d), sign(&s_key, d)), None, GENESIS));
    refuse("the two signatures swapped", run_with(&source, &p, &alone, 1, 2, (sign(&s_key, d), sign(&a, d)), None, GENESIS));
    let (q, b) = coin("two", &s_key);
    let other_salt = digest(GENESIS, &q, 0, &alone.utxos[..1], &alone.tx.output[..2]);
    refuse("a pair made under another salt", run_with(&source, &p, &alone, 1, 2, pair(other_salt), None, GENESIS));
    let other_chain = digest([0x6b; 32], &p, 0, &alone.utxos[..1], &alone.tx.output[..2]);
    refuse("a pair made for another chain", run_with(&source, &p, &alone, 1, 2, pair(other_chain), None, GENESIS));
    // A vtxo-1 message under the same K (its 75-byte rest), signed by both.
    let mut v1 = leaf_constant(GENESIS, p.salt).to_vec();
    v1.extend(explicit(&alone.utxos[0]).0);
    v1.extend([1, 1]);
    v1.extend(10_000_000u64.to_le_bytes());
    v1.push(2);
    for o in &alone.tx.output[..2] {
        v1.extend(sha(&o.script_pubkey.to_bytes()));
    }
    refuse("a vtxo-1 pair under the same salt", run_with(&source, &p, &alone, 1, 2, pair(sha(&v1)), None, GENESIS));
    let _ = b;
    // Parameters, shape bounds.
    let mut wrong = p.clone();
    wrong.owner = q.owner;
    refuse("parameters the coin does not commit to", run_with(&source, &wrong, &alone, 1, 2, pair(d), Some(p.control_block(cmr)), GENESIS));
    refuse("k at or past n", {
        let s = spend(&p, cmr, 2, 1, 2, 10_000_000);
        let d = digest(GENESIS, &p, 1, &s.utxos[..1], &s.tx.output[..2]);
        run_with(&source, &p, &s, 1, 2, pair(d), None, GENESIS)
    });
    refuse("n = 0", {
        let d = digest(GENESIS, &p, 0, &alone.utxos[..0], &alone.tx.output[..2]);
        run_with(&source, &p, &alone, 0, 2, pair(d), None, GENESIS)
    });
    refuse("n = 17", {
        let s = spend(&p, cmr, 17, 0, 2, 10_000_000);
        let d = digest(GENESIS, &p, 0, &s.utxos[..17], &s.tx.output[..2]);
        run_with(&source, &p, &s, 17, 2, pair(d), None, GENESIS)
    });
    refuse("m = 0", {
        let d = digest(GENESIS, &p, 0, &alone.utxos[..1], &alone.tx.output[..0]);
        run_with(&source, &p, &alone, 1, 0, pair(d), None, GENESIS)
    });
    refuse("m = 5", {
        let s = spend(&p, cmr, 1, 0, 5, 10_000_000);
        let d = digest(GENESIS, &p, 0, &s.utxos[..1], &s.tx.output[..5]);
        run_with(&source, &p, &s, 1, 5, pair(d), None, GENESIS)
    });
    // An annex on the spend: the digest covers none, so the program takes
    // none.
    let mut annexed = spend(&p, cmr, 1, 0, 2, 10_000_000);
    annexed.tx.input[0].witness.script_witness = vec![vec![1], vec![2], vec![3], vec![0x50, 0xaa, 0xbb]];
    let d_annexed = digest(GENESIS, &p, 0, &annexed.utxos[..1], &annexed.tx.output[..2]);
    refuse("an annex on the spend", run_with(&source, &p, &annexed, 1, 2, pair(d_annexed), None, GENESIS));
    refuse("n past the transaction's inputs", {
        let s = spend(&p, cmr, 1, 0, 2, 10_000_000);
        let mut t = Spend { tx: s.tx.clone(), utxos: s.utxos.clone(), k: 0 };
        t.tx.input.truncate(1);
        t.utxos.truncate(1);
        let d = digest(GENESIS, &p, 0, &s.utxos[..2], &s.tx.output[..2]);
        run_with(&source, &p, &t, 2, 2, pair(d), None, GENESIS)
    });
}

#[test]
fn every_spend_prunes_to_the_constant_of_collab_json() {
    let source = source();
    let cmr = cmr_of(&source);
    let secp = Secp256k1::new();
    let s_key = Keypair::from_seckey_slice(&secp, &h("the operator")).unwrap();
    let (p, a) = coin("one", &s_key);
    let (mut q, b) = coin("two", &s_key);
    q.operator = q.owner; // equal keys: the program reads each in a statement of its own
    let mut program: Option<Vec<u8>> = None;
    let mut costs = std::collections::BTreeSet::new();
    let mut shapes = 0;
    for (coin, key, sk) in [(&p, &a, &s_key), (&q, &b, &b)] {
        for n in 1..=16u32 {
            for m in 1..=4usize {
                for k in [0, n - 1, n / 2] {
                    let s = spend(coin, cmr, n, k, m, 10_000_000 + n as u64);
                    let (prog, _, cost) = run(&source, coin, key, sk, &s, n as u8, m as u8).unwrap();
                    costs.insert(cost);
                    shapes += 1;
                    let want = program.get_or_insert_with(|| prog.clone());
                    assert_eq!(hex(want), hex(&prog), "n={n} m={m} k={k}: the pruned program differs");
                }
            }
        }
    }
    let prog = program.unwrap();
    println!("{shapes} shapes, one program of {} bytes, cost bound {:?}", prog.len(), costs);
    let want = json!({"collab": 1, "cmr": hex(&cmr), "program": hex(&prog), "program_bytes": prog.len()});
    if std::env::var("WRITE_COLLAB").is_ok() {
        std::fs::write(format!("{DIR}/collab.json"), serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
    }
    let have: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/collab.json")).unwrap()).unwrap();
    assert_eq!(have, want, "collab.json differs from what the program prunes to");
}
