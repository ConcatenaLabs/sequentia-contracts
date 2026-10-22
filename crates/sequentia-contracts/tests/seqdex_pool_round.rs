//! The SeqDEX pool's and round order's pruned programs against each
//! template's `fills.json`, and the clearer's digest against the program.
//!
//! Each template claims that a caller with no compiler can build any spend:
//! the pruned program of each path is one constant, whatever the terms and
//! whatever input index the coin is at, and the witness is the data leaf's
//! bytes followed by PATH (and a signature), padded with zero bits to a whole
//! byte. This test satisfies and prunes each program against transactions
//! built for every vector's terms and for terms that hold equal values, at
//! input indices 0, 1 and 3, and requires the constants of `fills.json` every
//! time. A round order's fill executes only if the clearer signed
//! `round::clearing_digest` of the transaction, so every fill here also holds
//! that function to the program's own `jet::tx_hash()`.
//! `WRITE_FILLS=1 cargo test --test seqdex_pool_round` rewrites both files.

use std::collections::BTreeMap;
use std::sync::Arc;

use secp256k1::{Keypair, Message, Secp256k1};
use sequentia_contracts::elements::confidential::{Asset, Nonce, Value as Amount};
use sequentia_contracts::elements::hashes::{sha256, Hash};
use sequentia_contracts::elements::taproot::ControlBlock;
use sequentia_contracts::elements::{
    AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid,
};
use sequentia_contracts::round::{clearing_digest, clearing_script};
use sequentia_contracts::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::WitnessValues;
use serde_json::{json, Map, Value};

const TEMPLATES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(t: &str, name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{TEMPLATES}/{t}/{name}")).unwrap()).unwrap()
}

fn h(label: &str) -> [u8; 32] {
    sha256::Hash::hash(label.as_bytes()).to_byte_array()
}

fn out(asset: &[u8], value: u64, spk: &[u8]) -> TxOut {
    TxOut {
        asset: Asset::Explicit(AssetId::from_slice(asset).unwrap()),
        value: Amount::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::from(spk.to_vec()),
        witness: Default::default(),
    }
}

fn input(i: u32, seq: Sequence) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array(h(&format!("coin {i}"))), i),
        sequence: seq,
        ..Default::default()
    }
}

fn bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn pack(b: &[bool]) -> Vec<u8> {
    b.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i)))).collect()
}

fn u64_bits(v: u64) -> Vec<bool> {
    (0..64).rev().map(|i| v >> i & 1 == 1).collect()
}

/// A template instance: its terms as the descriptor's hex values.
#[derive(Clone)]
struct Terms(Map<String, Value>);

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
}

struct Template {
    dir: &'static str,
    leaf: &'static str,
    source: String,
    descriptor: Value,
    /// (name, type) of each term, in the data leaf's order.
    terms: Vec<(String, String)>,
}

impl Template {
    fn load(dir: &'static str, leaf: &'static str) -> Template {
        let descriptor = read(dir, "descriptor.json");
        let sim = &descriptor["template"]["tree"]["branch"][0]["simplicity"];
        let raw = std::fs::read_to_string(format!("{TEMPLATES}/{dir}/{}", sim["source"].as_str().unwrap())).unwrap();
        let types: BTreeMap<String, String> = descriptor["template"]["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["name"].as_str().unwrap().to_string(), p["type"].as_str().unwrap().to_string()))
            .collect();
        let terms = descriptor["template"]["tree"]["branch"][1]["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| (n.as_str().unwrap().to_string(), types[n.as_str().unwrap()].clone()))
            .collect();
        Template { dir, leaf, source: sequentia_contracts::expand(&raw).unwrap(), descriptor, terms }
    }

    fn derive(&self, t: &Terms) -> (Vec<u8>, ControlBlock) {
        let d = sequentia_contracts::descriptor::Descriptor::load(std::path::Path::new(&format!(
            "{TEMPLATES}/{}/descriptor.json",
            self.dir
        )))
        .unwrap();
        let params = t.0.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
        let x = d.model().unwrap().derive(&params, &Default::default()).unwrap();
        let leaves = serde_json::to_value(&x.leaves).unwrap();
        let cb = unhex(leaves[self.leaf]["control_block"].as_str().unwrap());
        (unhex(&x.script_pubkey), ControlBlock::from_slice(&cb).unwrap())
    }

    fn data(&self, t: &Terms) -> Vec<u8> {
        self.terms.iter().flat_map(|(k, _)| t.get(k)).collect()
    }

    /// The witness values: every term, then the spender's values.
    fn witness(&self, t: &Terms, extra: Vec<(&str, Value)>) -> WitnessValues {
        let mut w = Map::new();
        for (k, ty) in &self.terms {
            let v = match ty.as_str() {
                "u64" | "u32" => json!({"value": t.num(k).to_string(), "type": ty}),
                _ => json!({"value": format!("0x{}", hex(&t.get(k))), "type": ty}),
            };
            w.insert(k.clone(), v);
        }
        for (k, v) in extra {
            w.insert(k.into(), v);
        }
        serde_json::from_str(&Value::Object(w).to_string()).unwrap()
    }

    /// Satisfies and prunes the program at input k of `tx`; `sign` returns the
    /// spender's values given the environment's sig_all_hash and the clearer's
    /// digest of `tx`. Returns (program, witness).
    fn spend(
        &self,
        t: &Terms,
        tx: Transaction,
        utxos: Vec<TxOut>,
        k: u32,
        sign: &dyn Fn([u8; 32], [u8; 32]) -> Vec<(&'static str, Value)>,
    ) -> (Vec<u8>, Vec<u8>) {
        self.try_spend(t, tx, utxos, k, None, sign).unwrap()
    }

    /// spend, with `annex` (its bytes after the 0x50 tag) on input k when
    /// given, as the node reads one: the last item of a stack of at least
    /// two. The digest and sig_all_hash the spender signs then cover it, so a
    /// refusal is the program's annex rule alone.
    fn try_spend(
        &self,
        t: &Terms,
        mut tx: Transaction,
        utxos: Vec<TxOut>,
        k: u32,
        annex: Option<Vec<u8>>,
        sign: &dyn Fn([u8; 32], [u8; 32]) -> Vec<(&'static str, Value)>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let program = sequentia_contracts::compile(&self.source, Default::default()).unwrap();
        let cmr = program.commit().cmr();
        let (spk, cb) = self.derive(t);
        assert_eq!(utxos[k as usize].script_pubkey.as_bytes(), &spk[..], "the coin is not at the instance's script");
        if let Some(a) = &annex {
            let mut item = vec![0x50u8];
            item.extend_from_slice(a);
            tx.input[k as usize].witness.script_witness = vec![vec![], item];
        }
        let genesis = BlockHash::all_zeros();
        let digest = clearing_digest(&genesis.to_byte_array(), &tx, &utxos).unwrap();
        let tx = Arc::new(tx);
        let env = ElementsEnv::new(
            tx.clone(),
            utxos.into_iter().map(ElementsUtxo::from).collect(),
            k,
            cmr,
            cb,
            annex,
            genesis,
        );
        let wv = self.witness(t, sign(env.c_tx_env().sighash_all().to_byte_array(), digest));
        let satisfied = program.satisfy_with_env(wv, Some(&env)).map_err(|e| e.to_string())?;
        let node = satisfied.redeem().clone();
        let mut mac = BitMachine::for_program(&node).map_err(|e| e.to_string())?;
        mac.exec(&node, &env).map_err(|e| e.to_string())?;
        Ok(node.to_vec_with_witness())
    }
}

fn schnorr(kp: &Keypair, m: [u8; 32]) -> [u8; 64] {
    Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(m), kp).serialize()
}

fn sig_value(s: &[u8; 64]) -> Value {
    json!({"value": format!("0x{}", hex(s)), "type": "Signature"})
}

fn fills_json(t: &Template, got: &BTreeMap<String, Vec<u8>>, paths: &[(&str, &str, bool)]) -> Value {
    let cmr = t.descriptor["template"]["tree"]["branch"][0]["simplicity"]["cmr"].clone();
    let mut p = Map::new();
    for (name, path_bits, sig) in paths {
        let prog = &got[*name];
        p.insert(
            (*name).into(),
            json!({"path_bits": path_bits, "signature": sig, "program": hex(prog), "program_bytes": prog.len()}),
        );
    }
    json!({"fills": 1, "template_hash": t.descriptor["template_hash"], "cmr": cmr, "paths": p})
}

fn pin(t: &Template, want: Value) {
    if std::env::var("WRITE_FILLS").is_ok() {
        std::fs::write(
            format!("{TEMPLATES}/{}/fills.json", t.dir),
            serde_json::to_string_pretty(&want).unwrap() + "\n",
        )
        .unwrap();
    }
    assert_eq!(read(t.dir, "fills.json"), want, "{}: fills.json differs from what the program prunes to", t.dir);
}

fn record(got: &mut BTreeMap<String, Vec<u8>>, name: &str, p: Vec<u8>, what: &str) {
    let want = got.entry(name.into()).or_insert_with(|| p.clone());
    assert_eq!(hex(want), hex(&p), "{what}: the {name} program differs");
}

#[test]
fn every_pool_spends_by_the_constant_programs_of_fills_json() {
    let t = Template::load("seqdex_pool", "pool");
    let secp = Secp256k1::new();
    let maker = Keypair::from_seckey_slice(&secp, &h("the pool maker")).unwrap();
    let vectors = read("seqdex_pool", "vectors.json");
    let mut pools: Vec<Terms> = vectors["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Terms(v["params"].as_object().unwrap().clone()))
        .collect();
    let mut eq = pools[0].clone();
    for k in ["BID_NUM", "BID_DEN", "ASK_NUM", "ASK_DEN", "MIN_LOT", "RESERVE_BASE", "RESERVE_QUOTE"] {
        eq.set(k, &7u64.to_be_bytes());
    }
    pools.push(eq);
    for p in pools.iter_mut() {
        p.set("MAKER_KEY", &maker.x_only_public_key().0.serialize());
        for k in ["MIN_LOT", "RESERVE_BASE", "RESERVE_QUOTE"] {
            if p.num(k) > 1_000 {
                p.set(k, &1_000u64.to_be_bytes());
            }
        }
        // Quotes the fills below can meet: a bid of at most 1, an ask between 1 and 2.
        if p.num("BID_NUM") > p.num("BID_DEN") {
            p.set("BID_NUM", &p.get("BID_DEN"));
        }
        if p.num("ASK_NUM") < p.num("ASK_DEN") || p.num("ASK_NUM") / p.num("ASK_DEN") >= 2 {
            p.set("ASK_NUM", &(p.num("ASK_DEN") / 2 * 3 + 1).to_be_bytes());
        }
    }
    let mut got = BTreeMap::new();
    for (n, p) in pools.iter().enumerate() {
        let (spk, _) = t.derive(p);
        let (base, quote) = (p.get("BASE"), p.get("QUOTE"));
        let other = h("someone else's asset");
        for j in [0u32, 1, 3] {
            for sell in [true, false] {
                // The pool at inputs j and j+1, other coins before it; the pool
                // again at 2j and 2j+1.
                let (x0, y0, db) = (10_000_000u64, 10_000_000u64, 2_000_000u64);
                let dq = if sell {
                    ((db as u128 * p.num("ASK_NUM") as u128).div_ceil(p.num("ASK_DEN") as u128)) as u64
                } else {
                    (db as u128 * p.num("BID_NUM") as u128 / p.num("BID_DEN") as u128).min(y0 as u128 - 1_000) as u64
                };
                let (x1, y1) = if sell { (x0 - db, y0 + dq) } else { (x0 + db, y0 - dq) };
                let mut inputs = Vec::new();
                let mut utxos = Vec::new();
                let mut outputs = Vec::new();
                for i in 0..j {
                    inputs.push(input(i, Sequence::MAX));
                    utxos.push(out(&other, 1_000, &[0x51]));
                    outputs.push(out(&other, 500, &[0x51]));
                    outputs.push(out(&other, 500, &[0x51]));
                }
                inputs.push(input(j, Sequence::MAX));
                utxos.push(out(&base, x0, &spk));
                inputs.push(input(j + 1, Sequence::MAX));
                utxos.push(out(&quote, y0, &spk));
                outputs.push(out(&base, x1, &spk));
                outputs.push(out(&quote, y1, &spk));
                outputs.push(out(&other, 1, &[0x51]));
                let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: inputs, output: outputs };
                let path = if sell { "Left(true)" } else { "Left(false)" };
                let (prog, w) = t.spend(p, tx.clone(), utxos.clone(), j, &|_, _| {
                    vec![
                        ("PATH", json!({"value": path, "type": "Either<bool, Either<(), ()>>"})),
                        ("MAKER_SIG", sig_value(&[0; 64])),
                    ]
                });
                let mut want = bits(&t.data(p));
                want.extend([false, sell]);
                assert_eq!(hex(&w), hex(&pack(&want)), "pool {n}: the fill's witness is not the terms and PATH");
                record(&mut got, if sell { "sell" } else { "buy" }, prog, &format!("pool {n} at j={j}"));
                let (prog, w) = t.spend(p, tx, utxos, j + 1, &|_, _| {
                    vec![
                        ("PATH", json!({"value": "Right(Left(()))", "type": "Either<bool, Either<(), ()>>"})),
                        ("MAKER_SIG", sig_value(&[0; 64])),
                    ]
                });
                let mut want = bits(&t.data(p));
                want.extend([true, false]);
                assert_eq!(hex(&w), hex(&pack(&want)), "pool {n}: the pair's witness is not the terms and PATH");
                record(&mut got, "pair", prog, &format!("pool {n} at j={j}"));
            }
        }
        // The withdrawal of the BASE coin alone, at input 0 and at input 2.
        for k in [0u32, 2] {
            let mut inputs = Vec::new();
            let mut utxos = Vec::new();
            for i in 0..=k {
                inputs.push(input(i, Sequence::MAX));
                utxos.push(if i == k { out(&base, 5_000, &spk) } else { out(&other, 1_000, &[0x51]) });
            }
            let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: inputs, output: vec![out(&base, 5_000, &[0x51])] };
            let maker = maker;
            let (prog, w) = t.spend(p, tx, utxos, k, &move |sighash, _| {
                let s = schnorr(&maker, sighash);
                vec![
                    ("PATH", json!({"value": "Right(Right(()))", "type": "Either<bool, Either<(), ()>>"})),
                    ("MAKER_SIG", sig_value(&s)),
                ]
            });
            let data = t.data(p);
            assert_eq!(&w[..data.len()], &data[..], "pool {n}: the withdrawal's witness starts with the terms");
            assert_eq!(w[data.len()] >> 6, 0b11, "pool {n}: the withdrawal's PATH");
            assert_eq!(w.len(), data.len() + 65, "pool {n}: the withdrawal's witness is the terms, PATH and a signature");
            record(&mut got, "withdraw", prog, &format!("pool {n} at {k}"));
        }
    }
    assert_eq!(got.len(), 4, "every path was built");
    pin(
        &t,
        fills_json(&t, &got, &[("sell", "01", false), ("buy", "00", false), ("pair", "10", false), ("withdraw", "11", true)]),
    );
}

#[test]
fn every_round_order_spends_by_the_constant_programs_of_fills_json() {
    let t = Template::load("seqdex_round_order", "order");
    let secp = Secp256k1::new();
    let clearer = Keypair::from_seckey_slice(&secp, &h("the clearer")).unwrap();
    let refund = Keypair::from_seckey_slice(&secp, &h("the refund key")).unwrap();
    let maker_spk: Vec<u8> = [0x51u8, 0x20].iter().copied().chain(h("maker program")).collect();
    let vectors = read("seqdex_round_order", "vectors.json");
    let mut orders: Vec<Terms> = vectors["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Terms(v["params"].as_object().unwrap().clone()))
        .collect();
    let mut eq = orders[0].clone();
    for k in ["LIMIT_NUM", "LIMIT_DEN", "MIN_LOT"] {
        eq.set(k, &7u64.to_be_bytes());
    }
    let eq_keys = orders[1].clone();
    orders.extend([eq, eq_keys]);
    let last = orders.len() - 1;
    let refund_keys: Vec<Keypair> = (0..orders.len()).map(|n| if n == last { clearer } else { refund }).collect();
    for (n, o) in orders.iter_mut().enumerate() {
        o.set("MAKER", &sha256::Hash::hash(&maker_spk).to_byte_array());
        // The last order's refund key is its clearer key: two equal keys.
        o.set("REFUND_KEY", &refund_keys[n].x_only_public_key().0.serialize());
        o.set("CLEARER", &clearer.x_only_public_key().0.serialize());
        if o.num("MIN_LOT") > 1_000 {
            o.set("MIN_LOT", &1_000u64.to_be_bytes());
        }
        // A limit every round below meets: at most 1/2.
        o.set("LIMIT_NUM", &1u64.to_be_bytes());
        o.set("LIMIT_DEN", &2u64.to_be_bytes());
    }
    let other = h("someone else's asset");
    let mut got = BTreeMap::new();
    for (n, o) in orders.iter().enumerate() {
        let (spk, _) = t.derive(o);
        let (a, b) = (o.get("ASSET_A"), o.get("ASSET_B"));
        for k in [0u32, 1, 3] {
            for partial in [true, false] {
                for flip in [false, true] {
                    // The round's price: 3 of B per 2 of A, published either way round.
                    let (pn, pd) = if flip { (2u64, 3u64) } else { (3u64, 2u64) };
                    let (base, quote) = if flip { (&b, &a) } else { (&a, &b) };
                    let (locked, filled) = (10_000_000u64, if partial { 4_000_001 } else { 10_000_000 });
                    let paid = (filled as u128 * 3).div_ceil(2) as u64;
                    let mut inputs = Vec::new();
                    let mut utxos = Vec::new();
                    let mut outputs = Vec::new();
                    for i in 0..=k {
                        inputs.push(input(i, Sequence::MAX));
                        if i == k {
                            utxos.push(out(&a, locked, &spk));
                        } else {
                            utxos.push(out(&other, 1_000, &[0x51]));
                            outputs.push(out(&other, 500, &[0x51]));
                            outputs.push(out(&other, 500, &[0x51]));
                        }
                    }
                    outputs.push(out(&b, paid, &maker_spk));
                    outputs.push(if partial { out(&a, locked - filled, &spk) } else { out(&a, filled, &[0x51]) });
                    outputs.push(out(&a, 1, &[0x51]));
                    outputs.push(out(&other, 0, &clearing_script(
                        base.as_slice().try_into().unwrap(), quote.as_slice().try_into().unwrap(), pn, pd)));
                    let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: inputs, output: outputs };
                    let path = format!("Left(({partial}, ({flip}, ({pn}, {pd}))))");
                    let (prog, w) = t.spend(o, tx, utxos, k, &|_, digest| {
                        let s = schnorr(&clearer, digest);
                        vec![
                            ("PATH", json!({"value": path.clone(), "type": "Either<(bool, (bool, (u64, u64))), ()>"})),
                            ("CLEARER_SIG", sig_value(&s)),
                            ("REFUND_SIG", sig_value(&[0; 64])),
                        ]
                    });
                    let mut want = bits(&t.data(o));
                    want.extend([false, partial, flip]);
                    want.extend(u64_bits(pn));
                    want.extend(u64_bits(pd));
                    let tail = (want.len() + 512).div_ceil(8);
                    assert_eq!(w.len(), tail, "order {n}: the fill's witness is the terms, PATH and a signature");
                    assert_eq!(hex(&w[..want.len() / 8]), hex(&pack(&want)[..want.len() / 8]));
                    let name = format!("{}{}", if partial { "fill" } else { "fill_whole" }, if flip { "_flip" } else { "" });
                    record(&mut got, &name, prog, &format!("order {n} at k={k}"));
                }
            }
        }
        let expiry = o.num("EXPIRY") as u32;
        let name = if expiry < 500_000_000 { "refund_height" } else { "refund_time" };
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(expiry),
            input: vec![input(0, Sequence::ENABLE_LOCKTIME_NO_RBF)],
            output: vec![out(&a, 1_000_000, &[0x51])],
        };
        let refund = refund_keys[n];
        let (prog, _) = t.spend(o, tx, vec![out(&a, 1_000_000, &spk)], 0, &move |sighash, _| {
            vec![
                ("PATH", json!({"value": "Right(())", "type": "Either<(bool, (bool, (u64, u64))), ()>"})),
                ("CLEARER_SIG", sig_value(&[0; 64])),
                ("REFUND_SIG", sig_value(&schnorr(&refund, sighash))),
            ]
        });
        record(&mut got, name, prog, &format!("order {n}"));
    }
    assert_eq!(got.len(), 6, "every path was built: {:?}", got.keys().collect::<Vec<_>>());
    pin(
        &t,
        fills_json(
            &t,
            &got,
            &[
                ("fill", "010", true),
                ("fill_flip", "011", true),
                ("fill_whole", "000", true),
                ("fill_whole_flip", "001", true),
                ("refund_height", "1", true),
                ("refund_time", "1", true),
            ],
        ),
    );
}

#[test]
fn a_wrong_digest_does_not_execute() {
    // The digest is the program's: a signature over anything else fails.
    let t = Template::load("seqdex_round_order", "order");
    let secp = Secp256k1::new();
    let clearer = Keypair::from_seckey_slice(&secp, &h("the clearer")).unwrap();
    let mut o = Terms(read("seqdex_round_order", "vectors.json")["addresses"][0]["params"].as_object().unwrap().clone());
    let maker_spk: Vec<u8> = [0x51u8, 0x20].iter().copied().chain(h("maker program")).collect();
    o.set("MAKER", &sha256::Hash::hash(&maker_spk).to_byte_array());
    o.set("CLEARER", &clearer.x_only_public_key().0.serialize());
    o.set("MIN_LOT", &1u64.to_be_bytes());
    o.set("LIMIT_NUM", &1u64.to_be_bytes());
    o.set("LIMIT_DEN", &1u64.to_be_bytes());
    let (spk, _) = t.derive(&o);
    let (a, b) = (o.get("ASSET_A"), o.get("ASSET_B"));
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(0, Sequence::MAX)],
        output: vec![
            out(&b, 1_000, &maker_spk),
            out(&a, 1_000, &[0x51]),
            out(&a, 0, &clearing_script(a.as_slice().try_into().unwrap(), b.as_slice().try_into().unwrap(), 1, 1)),
        ],
    };
    let program = sequentia_contracts::compile(&t.source, Default::default()).unwrap();
    let (_, cb) = t.derive(&o);
    let env = ElementsEnv::new(
        Arc::new(tx),
        vec![ElementsUtxo::from(out(&a, 1_000, &spk))],
        0,
        program.commit().cmr(),
        cb,
        None,
        BlockHash::all_zeros(),
    );
    // sig_all_hash in place of the clearing digest.
    let s = schnorr(&clearer, env.c_tx_env().sighash_all().to_byte_array());
    let wv = t.witness(
        &o,
        vec![
            ("PATH", json!({"value": "Left((false, (false, (1, 1))))", "type": "Either<(bool, (bool, (u64, u64))), ()>"})),
            ("CLEARER_SIG", sig_value(&s)),
            ("REFUND_SIG", sig_value(&[0; 64])),
        ],
    );
    assert!(program.satisfy_with_env(wv, Some(&env)).is_err(), "a signature over sig_all_hash satisfied the fill");
}

#[test]
fn every_path_refuses_an_annex() {
    // A pool sell and its pair, a withdrawal, a round order's fill and its
    // refund, each executed without an annex and refused with one of 3 and of
    // 1,000 bytes, the signatures covering the annexed transaction.
    let secp = Secp256k1::new();
    let maker = Keypair::from_seckey_slice(&secp, &h("the pool maker")).unwrap();
    let clearer = Keypair::from_seckey_slice(&secp, &h("the clearer")).unwrap();
    let pool_t = Template::load("seqdex_pool", "pool");
    let mut p = Terms(read("seqdex_pool", "vectors.json")["addresses"][0]["params"].as_object().unwrap().clone());
    for (k, v) in [("BID_NUM", 9u64), ("BID_DEN", 10), ("ASK_NUM", 11), ("ASK_DEN", 10), ("MIN_LOT", 1), ("RESERVE_BASE", 1), ("RESERVE_QUOTE", 1)] {
        p.set(k, &v.to_be_bytes());
    }
    p.set("MAKER_KEY", &maker.x_only_public_key().0.serialize());
    let (pspk, _) = pool_t.derive(&p);
    let (base, quote) = (p.get("BASE"), p.get("QUOTE"));
    let sell_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(0, Sequence::MAX), input(1, Sequence::MAX)],
        output: vec![out(&base, 9_000, &pspk), out(&quote, 11_100, &pspk), out(&base, 1_000, &[0x51])],
    };
    let pool_utxos = vec![out(&base, 10_000, &pspk), out(&quote, 10_000, &pspk)];
    let path = |v: &'static str| move |_: [u8; 32], _: [u8; 32]| {
        vec![("PATH", json!({"value": v, "type": "Either<bool, Either<(), ()>>"})), ("MAKER_SIG", sig_value(&[0; 64]))]
    };
    let withdraw = move |sighash: [u8; 32], _: [u8; 32]| {
        vec![
            ("PATH", json!({"value": "Right(Right(()))", "type": "Either<bool, Either<(), ()>>"})),
            ("MAKER_SIG", sig_value(&schnorr(&maker, sighash))),
        ]
    };
    let order_t = Template::load("seqdex_round_order", "order");
    let mut o = Terms(read("seqdex_round_order", "vectors.json")["addresses"][0]["params"].as_object().unwrap().clone());
    let maker_spk: Vec<u8> = [0x51u8, 0x20].iter().copied().chain(h("maker program")).collect();
    o.set("MAKER", &sha256::Hash::hash(&maker_spk).to_byte_array());
    o.set("CLEARER", &clearer.x_only_public_key().0.serialize());
    o.set("REFUND_KEY", &clearer.x_only_public_key().0.serialize());
    for (k, v) in [("LIMIT_NUM", 1u64), ("LIMIT_DEN", 1), ("MIN_LOT", 1)] {
        o.set(k, &v.to_be_bytes());
    }
    let (ospk, _) = order_t.derive(&o);
    let (a, b) = (o.get("ASSET_A"), o.get("ASSET_B"));
    let fill_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(0, Sequence::MAX)],
        output: vec![
            out(&b, 1_000, &maker_spk),
            out(&a, 1_000, &[0x51]),
            out(&a, 0, &clearing_script(a.as_slice().try_into().unwrap(), b.as_slice().try_into().unwrap(), 1, 1)),
        ],
    };
    let fill = move |_: [u8; 32], digest: [u8; 32]| {
        vec![
            ("PATH", json!({"value": "Left((false, (false, (1, 1))))", "type": "Either<(bool, (bool, (u64, u64))), ()>"})),
            ("CLEARER_SIG", sig_value(&schnorr(&clearer, digest))),
            ("REFUND_SIG", sig_value(&[0; 64])),
        ]
    };
    let expiry = o.num("EXPIRY") as u32;
    let refund_tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(expiry),
        input: vec![input(0, Sequence::ENABLE_LOCKTIME_NO_RBF)],
        output: vec![out(&a, 1_000, &[0x51])],
    };
    let refund = move |sighash: [u8; 32], _: [u8; 32]| {
        vec![
            ("PATH", json!({"value": "Right(())", "type": "Either<(bool, (bool, (u64, u64))), ()>"})),
            ("CLEARER_SIG", sig_value(&[0; 64])),
            ("REFUND_SIG", sig_value(&schnorr(&clearer, sighash))),
        ]
    };
    let sell = path("Left(true)");
    let pair = path("Right(Left(()))");
    let cases: Vec<(&str, &Template, &Terms, Transaction, Vec<TxOut>, u32, &dyn Fn([u8; 32], [u8; 32]) -> Vec<(&'static str, Value)>)> = vec![
        ("pool sell", &pool_t, &p, sell_tx.clone(), pool_utxos.clone(), 0, &sell),
        ("pool pair", &pool_t, &p, sell_tx, pool_utxos.clone(), 1, &pair),
        ("pool withdrawal", &pool_t, &p, Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input(0, Sequence::MAX)], output: vec![out(&base, 10_000, &[0x51])] }, vec![pool_utxos[0].clone()], 0, &withdraw),
        ("round order fill", &order_t, &o, fill_tx, vec![out(&a, 1_000, &ospk)], 0, &fill),
        ("round order refund", &order_t, &o, refund_tx, vec![out(&a, 1_000, &ospk)], 0, &refund),
    ];
    for (name, t, terms, tx, utxos, k, sign) in cases {
        t.try_spend(terms, tx.clone(), utxos.clone(), k, None, sign).unwrap_or_else(|e| panic!("{name} without an annex: {e}"));
        for n in [3usize, 1000] {
            let annex = vec![0xab; n - 1];
            assert!(t.try_spend(terms, tx.clone(), utxos.clone(), k, Some(annex), sign).is_err(), "{name} took an annex of {n} bytes");
        }
    }
}
