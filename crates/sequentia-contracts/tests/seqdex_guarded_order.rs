//! The guarded SeqDEX order's pruned programs against
//! `templates/seqdex_guarded_order/fills.json`.
//!
//! The template claims what `seqdex/order` claims: a caller with no compiler
//! can build any spend of an order, because the pruned program of each path
//! is one constant, whatever the order's terms (its guard included) and
//! whatever input index k the order is at, and the witness is the data leaf's
//! bytes followed by PATH (and, for the refund, the signature), padded with
//! zero bits to a whole byte. This test satisfies and prunes the program
//! against transactions built for every vector's terms, for terms that hold
//! equal values (a 1:1 price, one asset on both sides, the guard's asset equal
//! to either, a minimum lot and a guard amount equal to the price terms), at
//! k = 1, 2 and 4 with the guard coin at input 0, and requires the constants of
//! `fills.json` every time. `WRITE_FILLS=1 cargo test --test
//! seqdex_guarded_order` rewrites the file from the first order instead.

use std::sync::Arc;

use secp256k1::{Keypair, Message, Secp256k1};
use sequentia_contracts::elements::confidential::{Asset, Nonce, Value as Amount};
use sequentia_contracts::elements::hashes::{sha256, Hash};
use sequentia_contracts::elements::taproot::ControlBlock;
use sequentia_contracts::elements::{
    AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid,
};
use sequentia_contracts::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::WitnessValues;
use serde_json::{json, Value};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/seqdex_guarded_order");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/{name}")).unwrap()).unwrap()
}

fn h(label: &str) -> [u8; 32] {
    sha256::Hash::hash(label.as_bytes()).to_byte_array()
}

/// An order's terms, as the descriptor's hex values.
#[derive(Clone)]
struct Terms(serde_json::Map<String, Value>);

impl Terms {
    fn get(&self, k: &str) -> Vec<u8> {
        unhex(self.0[k].as_str().unwrap())
    }
    fn num(&self, k: &str) -> u64 {
        u64::from_str_radix(self.0[k].as_str().unwrap(), 16).unwrap()
    }
    fn set(&mut self, k: &str, v: &[u8]) {
        self.0.insert(k.into(), hex(v).into());
    }
    /// The data leaf's bytes: the values in the descriptor's order.
    fn bytes(&self) -> Vec<u8> {
        [
            "ASSET_A", "ASSET_B", "RATE_NUM", "RATE_DEN", "MIN_LOT", "MAKER", "EXPIRY", "REFUND_KEY",
            "GUARD_ASSET", "GUARD_AMOUNT",
        ]
        .iter()
        .flat_map(|k| self.get(k))
        .collect()
    }
    fn witness(&self, path: &str, sig: &[u8; 64]) -> Value {
        let u = |k: &str, t: &str| json!({"value": self.num(k).to_string(), "type": t});
        let b = |k: &str, t: &str| json!({"value": format!("0x{}", hex(&self.get(k))), "type": t});
        json!({
            "ASSET_A": b("ASSET_A", "u256"), "ASSET_B": b("ASSET_B", "u256"),
            "RATE_NUM": u("RATE_NUM", "u64"), "RATE_DEN": u("RATE_DEN", "u64"),
            "MIN_LOT": u("MIN_LOT", "u64"), "MAKER": b("MAKER", "u256"),
            "EXPIRY": u("EXPIRY", "u32"), "REFUND_KEY": b("REFUND_KEY", "Pubkey"),
            "GUARD_ASSET": b("GUARD_ASSET", "u256"), "GUARD_AMOUNT": u("GUARD_AMOUNT", "u64"),
            "PATH": {"value": path, "type": "Either<bool, ()>"},
            "REFUND_SIG": {"value": format!("0x{}", hex(sig)), "type": "Signature"},
        })
    }
}

/// An explicit output.
fn out(asset: &[u8], value: u64, spk: &[u8]) -> TxOut {
    TxOut {
        asset: Asset::Explicit(AssetId::from_slice(asset).unwrap()),
        value: Amount::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::from(spk.to_vec()),
        witness: Default::default(),
    }
}

/// (program, witness) of the order's spend at input k of `tx`.
fn spend(
    source: &str,
    terms: &Terms,
    tx: Transaction,
    utxos: Vec<TxOut>,
    k: u32,
    path: &str,
    key: Option<&Keypair>,
) -> (Vec<u8>, Vec<u8>) {
    let program = sequentia_contracts::compile(source, Default::default()).unwrap();
    let cmr = program.commit().cmr();
    let derived = derive(terms);
    let cb = ControlBlock::from_slice(&unhex(derived["leaves"]["order"]["control_block"].as_str().unwrap())).unwrap();
    assert_eq!(
        hex(&utxos[k as usize].script_pubkey.to_bytes()),
        derived["script_pubkey"].as_str().unwrap()
    );
    let tx = Arc::new(tx);
    let env = ElementsEnv::new(
        tx.clone(),
        utxos.into_iter().map(ElementsUtxo::from).collect(),
        k,
        cmr,
        cb.clone(),
        None,
        BlockHash::all_zeros(),
    );
    let sig = match key {
        Some(kp) => {
            let msg = Message::from_digest(env.c_tx_env().sighash_all().to_byte_array());
            Secp256k1::new().sign_schnorr_no_aux_rand(&msg, kp).serialize()
        }
        None => [0u8; 64],
    };
    let wv: WitnessValues = serde_json::from_str(&terms.witness(path, &sig).to_string()).unwrap();
    let satisfied = program.satisfy_with_env(wv, Some(&env)).unwrap();
    let node = satisfied.redeem().clone();
    let mut mac = BitMachine::for_program(&node).unwrap();
    mac.exec(&node, &env).unwrap();
    let (p, w) = node.to_vec_with_witness();
    let mut want = bits(&terms.bytes());
    want.extend(path_bits(path));
    if key.is_some() {
        want.extend(bits(&sig));
    }
    assert_eq!(hex(&w), hex(&pack(&want)), "{path}: the witness is not the terms, PATH and the signature");
    (p, w)
}

fn derive(terms: &Terms) -> Value {
    // The descriptor reader of this crate is the address reference.
    let d = sequentia_contracts::descriptor::Descriptor::load(std::path::Path::new(&format!("{DIR}/descriptor.json")))
        .unwrap();
    let params = terms.0.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
    let x = d.model().unwrap().derive(&params, &Default::default()).unwrap();
    json!({"leaves": serde_json::to_value(&x.leaves).unwrap(), "script_pubkey": x.script_pubkey})
}

fn bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn path_bits(path: &str) -> Vec<bool> {
    match path {
        "Left(true)" => vec![false, true],
        "Left(false)" => vec![false, false],
        "Right(())" => vec![true],
        _ => unreachable!(),
    }
}

fn pack(b: &[bool]) -> Vec<u8> {
    b.chunks(8)
        .map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i))))
        .collect()
}

/// A transaction with the order's coin at input k, the guard coin at input 0
/// and other coins between them, and its credit and (for a partial fill) rest
/// at 2k and 2k+1.
fn fill_tx(terms: &Terms, spk: &[u8], k: u32, locked: u64, filled: u64, partial: bool) -> (Transaction, Vec<TxOut>) {
    let a = terms.get("ASSET_A");
    let b = terms.get("ASSET_B");
    let num = terms.num("RATE_NUM") as u128;
    let den = terms.num("RATE_DEN") as u128;
    let paid = ((filled as u128 * num + den - 1) / den) as u64;
    let maker_spk = [0x51, 0x20].iter().copied().chain(h("maker program")).collect::<Vec<u8>>();
    assert_eq!(sha256::Hash::hash(&maker_spk).to_byte_array().to_vec(), terms.get("MAKER"));
    let other = h("someone else's asset");
    let mut input = Vec::new();
    let mut utxos = Vec::new();
    let mut output = Vec::new();
    for i in 0..=k {
        input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(h(&format!("coin {i}"))), i),
            sequence: Sequence::MAX,
            ..Default::default()
        });
        if i == k {
            utxos.push(out(&a, locked, spk));
        } else if i == 0 {
            utxos.push(out(&terms.get("GUARD_ASSET"), terms.num("GUARD_AMOUNT"), &[0x51]));
            output.push(out(&terms.get("GUARD_ASSET"), terms.num("GUARD_AMOUNT"), &[0x51]));
            output.push(out(&other, 1_000, &[0x51]));
        } else {
            utxos.push(out(&other, 1_000, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
        }
    }
    output.push(out(&b, paid, &maker_spk));
    if partial {
        output.push(out(&a, locked - filled, spk));
    }
    output.push(out(&a, filled, &[0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]));
    (
        Transaction { version: 2, lock_time: LockTime::ZERO, input, output },
        utxos,
    )
}

/// The refund of the order's coin at input 1, the guard coin at input 0.
fn refund_tx(terms: &Terms, spk: &[u8], lock: u32) -> (Transaction, Vec<TxOut>) {
    let a = terms.get("ASSET_A");
    let g = terms.get("GUARD_ASSET");
    let q = terms.num("GUARD_AMOUNT");
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(lock),
        input: vec![
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(h("the guard coin")), 0),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(h("the order coin")), 0),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            },
        ],
        output: vec![out(&g, q, &[0x51]), out(&a, 1_000_000, &[0x51])],
    };
    (tx, vec![out(&g, q, &[0x51]), out(&a, 1_000_000, spk)])
}

#[test]
fn every_guarded_order_spends_by_the_constant_programs_of_fills_json() {
    let raw = std::fs::read_to_string(format!("{DIR}/seqdex_guarded_order.simf")).unwrap();
    let source = sequentia_contracts::expand(&raw).unwrap();
    let descriptor = read("descriptor.json");
    let vectors = read("vectors.json");
    let secp = Secp256k1::new();
    let refund_key = Keypair::from_seckey_slice(&secp, &h("the refund key")).unwrap();
    let maker = sha256::Hash::hash(
        &[0x51u8, 0x20].iter().copied().chain(h("maker program")).collect::<Vec<u8>>(),
    )
    .to_byte_array();

    // Every vector's terms, and terms that hold equal values; each with the
    // test's maker script and refund key, so that its spends can be built.
    let mut orders: Vec<Terms> = vectors["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Terms(v["params"].as_object().unwrap().clone()))
        .collect();
    let base = orders[0].clone();
    let mut eq_rate = base.clone();
    eq_rate.set("RATE_DEN", &eq_rate.get("RATE_NUM"));
    let mut eq_assets = base.clone();
    eq_assets.set("ASSET_B", &eq_assets.get("ASSET_A"));
    let mut eq_all = base.clone();
    for k in ["RATE_NUM", "RATE_DEN", "MIN_LOT", "GUARD_AMOUNT"] {
        eq_all.set(k, &7u64.to_be_bytes());
    }
    let mut guard_is_b = base.clone();
    guard_is_b.set("GUARD_ASSET", &guard_is_b.get("ASSET_B"));
    let mut guard_is_a = base.clone();
    guard_is_a.set("GUARD_ASSET", &guard_is_a.get("ASSET_A"));
    orders.extend([eq_rate, eq_assets, eq_all, guard_is_b, guard_is_a]);
    for o in orders.iter_mut() {
        o.set("MAKER", &maker);
        o.set("REFUND_KEY", &refund_key.x_only_public_key().0.serialize());
        if o.num("MIN_LOT") > 1_000 {
            o.set("MIN_LOT", &1_000u64.to_be_bytes());
        }
    }

    let mut got: std::collections::BTreeMap<&str, Vec<u8>> = Default::default();
    for (n, o) in orders.iter().enumerate() {
        let spk = unhex(derive(o)["script_pubkey"].as_str().unwrap());
        for k in [1u32, 2, 4] {
            for (name, path, partial) in [("fill", "Left(true)", true), ("fill_whole", "Left(false)", false)] {
                let filled = if partial { 4_000_000 } else { 10_000_000 };
                let (tx, utxos) = fill_tx(o, &spk, k, 10_000_000, filled, partial);
                let (p, _) = spend(&source, o, tx, utxos, k, path, None);
                let want = got.entry(name).or_insert_with(|| p.clone());
                assert_eq!(hex(want), hex(&p), "order {n} at k={k}: the {name} program differs");
            }
        }
        let expiry = o.num("EXPIRY") as u32;
        let name = if expiry < 500_000_000 { "refund_height" } else { "refund_time" };
        let (tx, utxos) = refund_tx(o, &spk, expiry);
        let (p, _) = spend(&source, o, tx, utxos, 1, "Right(())", Some(&refund_key));
        let want = got.entry(name).or_insert_with(|| p.clone());
        assert_eq!(hex(want), hex(&p), "order {n}: the {name} program differs");
    }
    assert_eq!(got.len(), 4, "every path was built");

    let cmr = descriptor["template"]["tree"]["branch"][0]["simplicity"]["cmr"].as_str().unwrap();
    let paths = |k: &str, bits: &str, sig: bool| {
        json!({"path_bits": bits, "signature": sig, "program": hex(&got[k]), "program_bytes": got[k].len()})
    };
    let want = json!({
        "fills": 1,
        "template_hash": descriptor["template_hash"],
        "cmr": cmr,
        "paths": {
            "fill": paths("fill", "01", false),
            "fill_whole": paths("fill_whole", "00", false),
            "refund_height": paths("refund_height", "1", true),
            "refund_time": paths("refund_time", "1", true),
        }
    });
    if std::env::var("WRITE_FILLS").is_ok() {
        std::fs::write(format!("{DIR}/fills.json"), serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
    }
    assert_eq!(read("fills.json"), want, "fills.json differs from what the program prunes to");
}
