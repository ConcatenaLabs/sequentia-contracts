//! Arca's resting order, `arca/order-2` (`templates/arca_order`) and
//! `arca/order-3` (`templates/arca_order_3`), each against its `fills.json`.
//!
//! The leaf is `TapBranch(TapBranch(C, L), TapBranch(F, D))`: the standard
//! rebindable collaborative script `C`, a landing `L` (only its hash matters
//! here), this program `F` and the data leaf `D`. This test builds that leaf,
//! its fills, the maker's credit leaf and the remainder's leaf in Rust,
//! independently of the program, signs each fill with the operator's key, and
//! runs the program on the Bit Machine: every fill it should accept passes,
//! and the fills it must refuse fail. It then prunes the program for orders
//! holding equal values, at k = 0, 1 and 3, for both paths and every m, and
//! requires the constants of `fills.json` each time, with the witness the
//! data leaf's bytes, the signature, m and PATH. `WRITE_FILLS=1 cargo test
//! --test arca_order` rewrites the files from the first order instead.
//!
//! `order-3` differs from `order-2` in one rule: a fill carries no annex. The
//! operator's digest does not cover one, so whoever holds a signed fill could
//! attach one. The last test runs signed fills with an annex beside the same
//! fills without one, on both programs.

use std::sync::Arc;

use secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1, XOnlyPublicKey};
use sequentia_contracts::elements::confidential::{Asset, Nonce, Value as Amount};
use sequentia_contracts::elements::hashes::{sha256, Hash};
use sequentia_contracts::elements::taproot::ControlBlock;
use sequentia_contracts::elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid};
use sequentia_contracts::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::WitnessValues;
use serde_json::{json, Value};

const V2: (&str, &str) = (concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/arca_order"), "arca_order.simf");
const V3: (&str, &str) = (concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/arca_order_3"), "arca_order_3.simf");
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// The frozen collaborative script around `K`, owner and operator.
const COLLAB_PRE: &str = "825188765155a5697620";
const COLLAB_MID: &str = "cdc87ecdc97c7e7e7e7c7e7c00ce7e00cf7c7e7e00d152937e7ea87b7c7e7c7651a06351ce7e51cf7c7e7e51d152937e7ea87b7c7e7c687652a06352ce7e52cf7c7e7e52d152937e7ea87b7c7e7c687653a06353ce7e53cf7c7e7e53d152937e7ea87b7c7e7c6875a87d20";

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

/// The output key of the NUMS internal key and `root`, with its parity.
fn output_key(root: [u8; 32]) -> ([u8; 32], Parity) {
    let secp = Secp256k1::new();
    let nums = XOnlyPublicKey::from_slice(&unhex(NUMS)).unwrap();
    let t = tagged("TapTweak/elements", &[&nums.serialize()[..], &root[..]].concat());
    let (q, parity) = nums.add_tweak(&secp, &Scalar::from_be_bytes(t).unwrap()).unwrap();
    (q.serialize(), parity)
}

fn spk(root: [u8; 32]) -> Vec<u8> {
    [&[0x51, 0x20][..], &output_key(root).0[..]].concat()
}

/// `K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)`.
fn leaf_constant(genesis: [u8; 32], salt: [u8; 32]) -> [u8; 32] {
    let tag = sha(&[&b"ArcaRbd1"[..], &genesis[..]].concat());
    sha(&[tag, salt].concat())
}

fn collab_script(owner: [u8; 32], operator: [u8; 32], k: [u8; 32]) -> Vec<u8> {
    [unhex(COLLAB_PRE), k.to_vec(), unhex(COLLAB_MID), owner.to_vec(), vec![0xc2, 0x20], operator.to_vec(), vec![0xc1]].concat()
}

fn exit_script(units: u16, key: [u8; 32]) -> Vec<u8> {
    let u = units.to_le_bytes();
    [vec![0x03, u[0], u[1], 0x40, 0xb2, 0x75, 0x20], key.to_vec(), vec![0xac]].concat()
}

/// An order's parameters: the data leaf.
#[derive(Clone, Debug)]
struct P {
    asset_a: [u8; 32],
    asset_b: [u8; 32],
    num: u64,
    den: u64,
    min_lot: u64,
    owner: [u8; 32],
    operator: [u8; 32],
    salt: [u8; 32],
    units: u16,
    land: [u8; 32],
    credits: [[u8; 32]; 4],
}

impl P {
    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(self.asset_a);
        b.extend(self.asset_b);
        b.extend(self.num.to_be_bytes());
        b.extend(self.den.to_be_bytes());
        b.extend(self.min_lot.to_be_bytes());
        b.extend(self.owner);
        b.extend(self.operator);
        b.extend(self.salt);
        b.extend(self.units.to_be_bytes());
        b.extend(self.land);
        for c in self.credits {
            b.extend(c);
        }
        b
    }

    /// The remainder's parameters: the next salt, the credit keys moved up.
    fn next(&self) -> P {
        let mut p = self.clone();
        p.salt = sha(&[h("Arca/order-rest"), self.salt].concat());
        p.credits = [self.credits[1], self.credits[2], self.credits[3], [0; 32]];
        p
    }

    fn data_leaf(&self) -> [u8; 32] {
        tagged("TapData", &self.bytes())
    }

    fn collab_leaf(&self, genesis: [u8; 32]) -> [u8; 32] {
        tapleaf(0xc4, &collab_script(self.owner, self.operator, leaf_constant(genesis, self.salt)))
    }

    fn root(&self, cmr: [u8; 32], genesis: [u8; 32]) -> [u8; 32] {
        tapbranch(tapbranch(self.collab_leaf(genesis), self.land), tapbranch(tapleaf(0xbe, &cmr), self.data_leaf()))
    }

    fn spk(&self, cmr: [u8; 32], genesis: [u8; 32]) -> Vec<u8> {
        spk(self.root(cmr, genesis))
    }

    /// The control block of the fill leaf.
    fn control_block(&self, cmr: [u8; 32], genesis: [u8; 32]) -> Vec<u8> {
        let parity = output_key(self.root(cmr, genesis)).1;
        let first = 0xbe | if parity == Parity::Odd { 1 } else { 0 };
        [vec![first], unhex(NUMS), self.data_leaf().to_vec(), tapbranch(self.collab_leaf(genesis), self.land).to_vec()].concat()
    }

    /// The vtxo-1 leaf the next credit pays.
    fn credit_spk(&self, genesis: [u8; 32]) -> Vec<u8> {
        let salt = sha(&[h("Arca/order-credit"), self.salt].concat());
        let key = self.credits[0];
        spk(tapbranch(
            tapleaf(0xc4, &collab_script(key, self.operator, leaf_constant(genesis, salt))),
            tapleaf(0xc4, &exit_script(self.units, key)),
        ))
    }

    fn witness(&self, sig: &[u8; 64], m: u8, partial: bool) -> Value {
        let b = |v: &[u8], t: &str| json!({"value": format!("0x{}", hex(v)), "type": t});
        let u = |v: u64, t: &str| json!({"value": v.to_string(), "type": t});
        json!({
            "ASSET_A": b(&self.asset_a, "u256"), "ASSET_B": b(&self.asset_b, "u256"),
            "RATE_NUM": u(self.num, "u64"), "RATE_DEN": u(self.den, "u64"), "MIN_LOT": u(self.min_lot, "u64"),
            "OWNER": b(&self.owner, "u256"), "OPERATOR": b(&self.operator, "u256"), "SALT": b(&self.salt, "u256"),
            "EXIT_UNITS": u(self.units as u64, "u16"), "LAND_LEAF": b(&self.land, "u256"),
            "CREDIT_0": b(&self.credits[0], "u256"), "CREDIT_1": b(&self.credits[1], "u256"),
            "CREDIT_2": b(&self.credits[2], "u256"), "CREDIT_3": b(&self.credits[3], "u256"),
            "OPERATOR_SIG": b(sig, "Signature"),
            "M": u(m as u64, "u8"),
            "PATH": {"value": partial.to_string(), "type": "bool"},
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

/// The chain's own commitment to an explicit output: `output_hash`.
fn output_hash(o: &TxOut) -> [u8; 32] {
    let asset = match o.asset {
        Asset::Explicit(a) => a.into_inner().to_byte_array(),
        _ => unreachable!(),
    };
    let value = o.value.explicit().unwrap();
    let mut b = vec![0x01];
    b.extend(asset);
    b.push(0x01);
    b.extend(value.to_be_bytes());
    b.push(0x00);
    b.extend(sha(o.script_pubkey.as_bytes()));
    b.extend(sha(&[]));
    sha(&b)
}

/// What the operator signs for a fill of a coin of `p` holding `value`.
fn fill_digest(genesis: [u8; 32], p: &P, value: u64, outputs: &[TxOut]) -> [u8; 32] {
    let tag = sha(&[h("Arca/order-fill"), genesis].concat());
    let mut b = Vec::new();
    b.extend(tag);
    b.extend(p.salt);
    b.extend(p.asset_a);
    b.extend(value.to_be_bytes());
    b.push(outputs.len() as u8);
    for o in outputs {
        b.extend(output_hash(o));
    }
    sha(&b)
}

const GENESIS: [u8; 32] = [0x5a; 32];

struct Fill {
    tx: Transaction,
    utxos: Vec<TxOut>,
    k: u32,
}

/// A fill of the order coin of `p` holding `locked` at input `k` (k other
/// coins before it, each with its two outputs), filling `filled`: the credit
/// at 2k, the remainder at 2k+1, the taker's leaf and its change after.
/// `extra` takes the outputs after the order's own two (or one) to make `m`.
fn fill(p: &P, cmr: [u8; 32], k: u32, locked: u64, filled: u64, partial: bool, extra: usize) -> Fill {
    let paid = ((filled as u128 * p.num as u128 + p.den as u128 - 1) / p.den as u128) as u64;
    let other = h("another order's asset");
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
            utxos.push(out(&p.asset_a, locked, &p.spk(cmr, GENESIS)));
        } else {
            utxos.push(out(&other, 1_000, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
        }
    }
    input.push(TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array(h("the taker's checkpoint")), 0),
        sequence: Sequence::MAX,
        ..Default::default()
    });
    utxos.push(out(&p.asset_b, paid + 5_000, &[0x51]));
    output.push(out(&p.asset_b, paid, &p.credit_spk(GENESIS)));
    if partial {
        output.push(out(&p.asset_a, locked - filled, &p.next().spk(cmr, GENESIS)));
    }
    let taker = [&[0x51u8, 0x20][..], &h("the taker's leaf")[..]].concat();
    let change = [&[0x51u8, 0x20][..], &h("the taker's change")[..]].concat();
    if extra >= 1 {
        output.push(out(&p.asset_a, filled, &taker));
    }
    if extra >= 2 {
        output.push(out(&p.asset_b, 4_000, &change));
    }
    output.push(TxOut::new_fee(1_000, AssetId::from_slice(&p.asset_b).unwrap()));
    Fill { tx: Transaction { version: 2, lock_time: LockTime::ZERO, input, output }, utxos, k }
}

/// Signs `f` for the coin of `p` over outputs `0..m` and runs the program;
/// returns (program, witness) or the Bit Machine's error.
fn run(source: &str, p: &P, f: &Fill, m: u8, partial: bool, key: &Keypair) -> Result<(Vec<u8>, Vec<u8>), String> {
    run_annexed(source, p, f, m, partial, key, None)
}

/// `run`, the coin's witness stack ending in `annex` when there is one, as the
/// node gives it to the jets.
fn run_annexed(source: &str, p: &P, f: &Fill, m: u8, partial: bool, key: &Keypair, annex: Option<&[u8]>)
    -> Result<(Vec<u8>, Vec<u8>), String> {
    let program = sequentia_contracts::compile(source, Default::default()).unwrap();
    let cmr: [u8; 32] = program.commit().cmr().to_byte_array();
    let cb = ControlBlock::from_slice(&p.control_block(cmr, GENESIS)).unwrap();
    let locked = f.utxos[f.k as usize].value.explicit().unwrap();
    let digest = fill_digest(GENESIS, p, locked, &f.tx.output[..m as usize]);
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), key).serialize();
    let mut tx = f.tx.clone();
    if let Some(a) = annex {
        assert_eq!(a[0], 0x50, "an annex starts 0x50");
        tx.input[f.k as usize].witness.script_witness =
            vec![vec![0], vec![0], cmr.to_vec(), p.control_block(cmr, GENESIS), a.to_vec()];
    }
    let env = ElementsEnv::new(
        Arc::new(tx),
        f.utxos.iter().cloned().map(ElementsUtxo::from).collect(),
        f.k,
        program.commit().cmr(),
        cb,
        annex.map(|a| a.to_vec()),
        BlockHash::from_byte_array(GENESIS),
    );
    let wv: WitnessValues = serde_json::from_str(&p.witness(&sig, m, partial).to_string()).unwrap();
    let satisfied = program.satisfy_with_env(wv, Some(&env)).map_err(|e| format!("satisfy: {e}"))?;
    let node = satisfied.redeem().clone();
    let mut mac = BitMachine::for_program(&node).map_err(|e| format!("machine: {e}"))?;
    mac.exec(&node, &env).map_err(|e| format!("exec: {e}"))?;
    let (prog, w) = node.to_vec_with_witness();
    let mut want = bits(&p.bytes());
    want.extend(bits(&sig));
    want.extend(bits(&[m]));
    want.push(partial);
    assert_eq!(hex(&w), hex(&pack(&want)), "the witness is not the data leaf, the signature, m and PATH");
    Ok((prog, w))
}

fn bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn pack(b: &[bool]) -> Vec<u8> {
    b.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i)))).collect()
}

fn source((dir, simf): (&str, &str)) -> String {
    sequentia_contracts::expand(&std::fs::read_to_string(format!("{dir}/{simf}")).unwrap()).unwrap()
}

fn cmr_of(source: &str) -> [u8; 32] {
    sequentia_contracts::compile(source, Default::default()).unwrap().commit().cmr().to_byte_array()
}

fn order(seed: &str, operator: &Keypair) -> P {
    let secp = Secp256k1::new();
    let key = |s: &str| Keypair::from_seckey_slice(&secp, &h(&format!("{seed} {s}"))).unwrap().x_only_public_key().0.serialize();
    P {
        asset_a: h(&format!("{seed} asset A")),
        asset_b: h(&format!("{seed} asset B")),
        num: 3,
        den: 2,
        min_lot: 1_000,
        owner: key("maker leaf key"),
        operator: operator.x_only_public_key().0.serialize(),
        salt: h(&format!("{seed} salt")),
        units: 254,
        land: tapleaf(0xc4, &[0x51]),
        credits: [key("credit 0"), key("credit 1"), key("credit 2"), key("credit 3")],
    }
}

#[test]
fn fills_order_2_accepts_and_refuses() {
    accepts_and_refuses(V2);
}

#[test]
fn fills_order_3_accepts_and_refuses() {
    accepts_and_refuses(V3);
}

fn accepts_and_refuses(v: (&str, &str)) {
    let source = source(v);
    let cmr = cmr_of(&source);
    let secp = Secp256k1::new();
    let s = Keypair::from_seckey_slice(&secp, &h("the operator")).unwrap();
    let p = order("one", &s);

    // Accepted: part and whole, at k = 0 and 1, for every m the outputs allow.
    for (k, partial, extra) in [(0u32, true, 1usize), (0, true, 2), (0, false, 1), (0, false, 2), (1, true, 0), (1, false, 1)] {
        let filled = if partial { 4_000_000 } else { 10_000_000 };
        let f = fill(&p, cmr, k, 10_000_000, filled, partial, extra);
        let m = 2 * k as u8 + if partial { 2 } else { 1 } + extra as u8;
        run(&source, &p, &f, m, partial, &s).unwrap();
    }
    // A remainder that fills again, under its own parameters.
    let q = p.next();
    let f = fill(&q, cmr, 0, 6_000_000, 2_000_000, true, 2);
    run(&source, &q, &f, 4, true, &s).unwrap();

    let refuse = |name: &str, r: Result<(Vec<u8>, Vec<u8>), String>| {
        let e = r.expect_err(&format!("{name}: the program took it"));
        println!("refused, {name}: {e}");
    };
    // Another key's signature, or the operator's over other outputs.
    let other = Keypair::from_seckey_slice(&secp, &h("not the operator")).unwrap();
    refuse("the maker's signature in the operator's place", run(&source, &p, &fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2), 4, true, &other));
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    let digest_outputs = f.tx.output.clone();
    f.tx.output[2] = out(&p.asset_a, 4_000_000, &[0x51]);
    {
        // sign over the original outputs, spend with the taker's leaf swapped
        let locked = 10_000_000;
        let digest = fill_digest(GENESIS, &p, locked, &digest_outputs[..4]);
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &s).serialize();
        let program = sequentia_contracts::compile(&source, Default::default()).unwrap();
        let env = ElementsEnv::new(Arc::new(f.tx.clone()), f.utxos.iter().cloned().map(ElementsUtxo::from).collect(), 0,
            program.commit().cmr(), ControlBlock::from_slice(&p.control_block(cmr, GENESIS)).unwrap(), None, BlockHash::from_byte_array(GENESIS));
        let wv: WitnessValues = serde_json::from_str(&p.witness(&sig, 4, true).to_string()).unwrap();
        let r = program.satisfy_with_env(wv, Some(&env)).map_err(|e| format!("satisfy: {e}")).and_then(|sat| {
            let node = sat.redeem().clone();
            BitMachine::for_program(&node).unwrap().exec(&node, &env).map(|_| (vec![], vec![])).map_err(|e| format!("exec: {e}"))
        });
        refuse("the taker's leaf swapped after the operator signed", r);
    }
    // The credit one atom short.
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    f.tx.output[0].value = Amount::Explicit(f.tx.output[0].value.explicit().unwrap() - 1);
    refuse("the credit one atom short", run(&source, &p, &f, 4, true, &s));
    // The credit to the maker's leaf key instead of the credit leaf.
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    f.tx.output[0].script_pubkey = Script::from([&[0x51u8, 0x20][..], &p.owner[..]].concat());
    refuse("the credit to another script", run(&source, &p, &f, 4, true, &s));
    // The credit under the remainder's credit key (a credit leaf for later).
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    f.tx.output[0].script_pubkey = Script::from(p.next().credit_spk(GENESIS));
    refuse("the credit to the next credit's leaf", run(&source, &p, &f, 4, true, &s));
    // The remainder under the identical script.
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    f.tx.output[1].script_pubkey = Script::from(p.spk(cmr, GENESIS));
    refuse("the remainder under the coin's own script", run(&source, &p, &f, 4, true, &s));
    // The remainder with the credit keys not moved up.
    let mut f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    let mut wrong = p.next();
    wrong.credits = p.credits;
    f.tx.output[1].script_pubkey = Script::from(wrong.spk(cmr, GENESIS));
    refuse("the remainder with the keys not moved up", run(&source, &p, &f, 4, true, &s));
    // The remainder one atom below the lot.
    let f = fill(&p, cmr, 0, 10_000_000, 10_000_000 - 999, true, 2);
    refuse("a remainder below MIN_LOT", run(&source, &p, &f, 4, true, &s));
    // A fill below the lot.
    let f = fill(&p, cmr, 0, 10_000_000, 999, true, 2);
    refuse("a fill below MIN_LOT", run(&source, &p, &f, 4, true, &s));
    // The fifth fill along one lineage: no credit key left.
    let exhausted = p.next().next().next().next();
    let f = fill(&exhausted, cmr, 0, 10_000_000, 4_000_000, true, 2);
    refuse("a fifth fill, its credit key zero", run(&source, &exhausted, &f, 4, true, &s));
    // m out of range.
    let f = fill(&p, cmr, 0, 10_000_000, 4_000_000, true, 2);
    refuse("m = 1", run(&source, &p, &f, 1, true, &s));
}

#[test]
fn every_fill_of_order_2_spends_by_the_constant_programs_of_fills_json() {
    prunes_to_fills_json(V2);
}

#[test]
fn every_fill_of_order_3_spends_by_the_constant_programs_of_fills_json() {
    prunes_to_fills_json(V3);
}

fn prunes_to_fills_json(v: (&str, &str)) {
    let dir = v.0;
    let source = source(v);
    let cmr = cmr_of(&source);
    let secp = Secp256k1::new();
    let s = Keypair::from_seckey_slice(&secp, &h("the operator")).unwrap();
    let base = order("one", &s);
    let mut eq = order("two", &s);
    eq.den = eq.num;
    eq.min_lot = eq.num;
    eq.asset_b = eq.asset_a;
    eq.credits[1] = eq.credits[0];
    let mut orders = vec![base.clone(), eq, base.next(), base.next().next().next()];
    orders[3].min_lot = 1;

    let mut got: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
    for (n, o) in orders.iter().enumerate() {
        for k in [0u32, 1, 3] {
            for partial in [true, false] {
                for extra in 0..=2usize {
                    let m = 2 * k as usize + if partial { 2 } else { 1 } + extra;
                    if !(2..=4).contains(&m) {
                        continue;
                    }
                    let filled = if partial { 4_000_000 } else { 10_000_000 };
                    let f = fill(o, cmr, k, 10_000_000, filled, partial, extra);
                    let (prog, _) = run(&source, o, &f, m as u8, partial, &s).unwrap();
                    let name = format!("{}_m{}", if partial { "fill" } else { "fill_whole" }, m);
                    let want = got.entry(name.clone()).or_insert_with(|| prog.clone());
                    assert_eq!(hex(want), hex(&prog), "order {n} at k={k}: the {name} program differs");
                }
            }
        }
    }
    let paths: serde_json::Map<String, Value> = got
        .iter()
        .map(|(k, p)| (k.clone(), json!({"program": hex(p), "program_bytes": p.len()})))
        .collect();
    let want = json!({"fills": 1, "cmr": hex(&cmr), "paths": paths});
    if std::env::var("WRITE_FILLS").is_ok() {
        std::fs::write(format!("{dir}/fills.json"), serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
    }
    let have: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/fills.json")).unwrap()).unwrap();
    assert_eq!(have, want, "{dir}/fills.json differs from what the program prunes to");
}

#[test]
fn a_signed_fill_with_an_annex_is_refused_by_order_3_and_taken_by_order_2() {
    let secp = Secp256k1::new();
    let s = Keypair::from_seckey_slice(&secp, &h("the operator")).unwrap();
    let p = order("one", &s);
    let long = [vec![0x50u8], vec![0xab; 999]].concat();
    for v in [V2, V3] {
        let source = source(v);
        let cmr = cmr_of(&source);
        for (k, partial, extra) in [(0u32, true, 2usize), (0, false, 1), (1, true, 0), (1, false, 1)] {
            let filled = if partial { 4_000_000 } else { 10_000_000 };
            let f = fill(&p, cmr, k, 10_000_000, filled, partial, extra);
            let m = 2 * k as u8 + if partial { 2 } else { 1 } + extra as u8;
            let plain = run_annexed(&source, &p, &f, m, partial, &s, None);
            assert!(plain.is_ok(), "{} k={k} partial={partial}: the fill without an annex is refused: {plain:?}", v.1);
            for annex in [&[0x50u8, 0xaa, 0xbb][..], &long[..]] {
                let r = run_annexed(&source, &p, &f, m, partial, &s, Some(annex));
                if v == V3 {
                    let e = r.expect_err("order-3 took a fill with an annex");
                    println!("order-3 k={k} partial={partial} m={m}, {}-byte annex: refused ({e})", annex.len());
                } else {
                    r.unwrap_or_else(|e| panic!("order-2 refused: {e}"));
                    println!("order-2 k={k} partial={partial} m={m}, {}-byte annex: taken", annex.len());
                }
            }
        }
    }
}
