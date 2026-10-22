//! Arca's accumulator batch, `arca/accumulator-1`, against
//! `templates/arca_accumulator/exits.json`.
//!
//! The batch output is `TapBranch(TapBranch(X, D), SWEEP)`: this program `X`,
//! the data leaf `D` of the root, the operator's key and the bitmap, and a
//! sweep leaf (only its hash matters here). This test builds the Merkle-sum
//! tree of 1,024 slots, the records, the data leaf and the batch output in
//! Rust, independently of the program, signs each exit with the owner's or
//! the operator's key, and runs the program on the Bit Machine: every exit it
//! should accept passes, and the exits it must refuse fail. It then prunes the
//! program for batches holding equal values, at several slots, at k = 0, 1 and
//! 3, by both keys, and requires the two constants of `exits.json` each time,
//! with the witness the state, the record, the path, the time, the key's flag
//! and the signature. `WRITE_EXITS=1 cargo test --test arca_accumulator`
//! rewrites the file from the first batch instead.

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

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/arca_accumulator");
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const DEPTH: usize = 10;
const SLOTS: usize = 1 << DEPTH;
const GENESIS: [u8; 32] = [0x5a; 32];
/// A median time, so the lock time is a time.
const NOW: u32 = 1_700_000_000;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}

fn h(label: &str) -> [u8; 32] {
    sha(label.as_bytes())
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

fn p2tr(root: [u8; 32]) -> Vec<u8> {
    [&[0x51, 0x20][..], &output_key(root).0[..]].concat()
}

/// One slot: the key that may take it out, the script and value its exit
/// pays, and the reserve it leaves for the fee.
#[derive(Clone, Debug)]
struct Slot {
    owner: [u8; 32],
    spk: Vec<u8>,
    value: u64,
    reserve: u64,
}

impl Slot {
    fn record(&self, j: u16) -> [u8; 32] {
        let mut b = vec![0x00];
        b.extend(j.to_be_bytes());
        b.extend(self.owner);
        b.extend(sha(&self.spk));
        b.extend(self.value.to_be_bytes());
        b.extend(self.reserve.to_be_bytes());
        sha(&b)
    }

    fn weight(&self) -> u64 {
        self.value + self.reserve
    }
}

fn inner(l: ([u8; 32], u64), r: ([u8; 32], u64)) -> [u8; 32] {
    let mut b = vec![0x01];
    b.extend(l.0);
    b.extend(l.1.to_be_bytes());
    b.extend(r.0);
    b.extend(r.1.to_be_bytes());
    sha(&b)
}

/// A batch: 1,024 slots (an empty one is `None`), the operator, the bitmap.
#[derive(Clone)]
struct Batch {
    slots: Vec<Option<Slot>>,
    operator: [u8; 32],
    bitmap: [u64; 16],
    sweep: [u8; 32],
    /// levels[0] are the slots, levels[DEPTH] the root alone.
    levels: Vec<Vec<([u8; 32], u64)>>,
}

impl Batch {
    fn new(slots: Vec<Option<Slot>>, operator: [u8; 32]) -> Batch {
        assert_eq!(slots.len(), SLOTS);
        let mut levels = vec![slots
            .iter()
            .enumerate()
            .map(|(j, s)| s.as_ref().map(|s| (s.record(j as u16), s.weight())).unwrap_or(([0; 32], 0)))
            .collect::<Vec<_>>()];
        for d in 0..DEPTH {
            let below = &levels[d];
            let up = below.chunks(2).map(|p| (inner(p[0], p[1]), p[0].1 + p[1].1)).collect();
            levels.push(up);
        }
        Batch { slots, operator, bitmap: [0; 16], sweep: tapleaf(0xc4, &[0x51]), levels }
    }

    fn root(&self) -> [u8; 32] {
        self.levels[DEPTH][0].0
    }

    fn total(&self) -> u64 {
        self.levels[DEPTH][0].1
    }

    fn path(&self, j: usize) -> Vec<([u8; 32], u64)> {
        (0..DEPTH).map(|d| self.levels[d][(j >> d) ^ 1]).collect()
    }

    fn data_bytes(&self) -> Vec<u8> {
        let mut b = self.root().to_vec();
        b.extend(self.operator);
        for w in self.bitmap {
            b.extend(w.to_be_bytes());
        }
        b
    }

    fn data_leaf(&self) -> [u8; 32] {
        tagged("TapData", &self.data_bytes())
    }

    fn tree(&self, cmr: [u8; 32]) -> [u8; 32] {
        tapbranch(tapbranch(tapleaf(0xbe, &cmr), self.data_leaf()), self.sweep)
    }

    fn spk(&self, cmr: [u8; 32]) -> Vec<u8> {
        p2tr(self.tree(cmr))
    }

    fn control_block(&self, cmr: [u8; 32]) -> Vec<u8> {
        let parity = output_key(self.tree(cmr)).1;
        let first = 0xbe | if parity == Parity::Odd { 1 } else { 0 };
        [vec![first], unhex(NUMS), self.data_leaf().to_vec(), self.sweep.to_vec()].concat()
    }

    fn left(&self, j: usize) -> Batch {
        let mut b = self.clone();
        b.bitmap[j / 64] |= 1u64 << (63 - j % 64);
        b
    }

    fn witness(&self, j: usize, slot: &Slot, path: &[([u8; 32], u64)], time: u32, by_operator: bool, sig: &[u8; 64]) -> Value {
        let b = |v: &[u8], t: &str| json!({"value": format!("0x{}", hex(v)), "type": t});
        let u = |v: u64, t: &str| json!({"value": v.to_string(), "type": t});
        let words: Vec<String> = self.bitmap.iter().map(|w| w.to_string()).collect();
        let steps: Vec<String> = path.iter().map(|(sh, sw)| format!("(0x{}, {})", hex(sh), sw)).collect();
        json!({
            "ROOT": b(&self.root(), "u256"),
            "OPERATOR": b(&self.operator, "u256"),
            "BITMAP": {"value": format!("[{}]", words.join(", ")), "type": "[u64; 16]"},
            "INDEX": u(j as u64, "u16"),
            "OWNER": b(&slot.owner, "u256"),
            "SPK": b(&sha(&slot.spk), "u256"),
            "VALUE": u(slot.value, "u64"),
            "RESERVE": u(slot.reserve, "u64"),
            "PATH": {"value": format!("[{}]", steps.join(", ")), "type": "[(u256, u64); 10]"},
            "TIME": u(time as u64, "u32"),
            "BY_OPERATOR": {"value": by_operator.to_string(), "type": "bool"},
            "SIG": b(sig, "Signature"),
        })
    }
}

fn exit_digest(root: [u8; 32], rec: [u8; 32], time: u32) -> [u8; 32] {
    let mut b = h("Arca/accumulator-exit").to_vec();
    b.extend(GENESIS);
    b.extend(root);
    b.extend(rec);
    b.extend(time.to_be_bytes());
    sha(&b)
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

/// An exit spend: the transaction, its prevouts and the batch's input.
#[derive(Clone)]
struct Exit {
    tx: Transaction,
    utxos: Vec<TxOut>,
    k: u32,
    /// The batch input's annex, with its 0x50 tag, if any.
    annex: Option<Vec<u8>>,
}

/// The exit of slot `j` from `batch` holding `held` at input `k` (k other
/// coins before it, each with its two outputs): the entry at 2k, the rest at
/// 2k+1 under the next state, a fee output after.
fn exit(batch: &Batch, cmr: [u8; 32], asset: &[u8; 32], j: usize, k: u32, held: u64) -> Exit {
    let slot = batch.slots[j].clone().unwrap();
    let other = h("another coin's asset");
    let mut input = Vec::new();
    let mut utxos = Vec::new();
    let mut output = Vec::new();
    for i in 0..=k {
        input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(h(&format!("coin {i}"))), i),
            sequence: Sequence(0xffff_fffe),
            ..Default::default()
        });
        if i == k {
            utxos.push(out(asset, held, &batch.spk(cmr)));
        } else {
            utxos.push(out(&other, 1_000, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
            output.push(out(&other, 500, &[0x51]));
        }
    }
    output.push(out(asset, slot.value, &slot.spk));
    let rest = held - slot.value - slot.reserve;
    if rest > 0 {
        output.push(out(asset, rest, &batch.left(j).spk(cmr)));
    }
    output.push(TxOut::new_fee(slot.reserve, AssetId::from_slice(asset).unwrap()));
    Exit { tx: Transaction { version: 2, lock_time: LockTime::from_consensus(NOW), input, output }, utxos, k, annex: None }
}

/// What a spend presents: the slot's record values, path, time, flag, key.
#[derive(Clone)]
struct Claim {
    j: usize,
    slot: Slot,
    path: Vec<([u8; 32], u64)>,
    time: u32,
    by_operator: bool,
}

impl Claim {
    fn of(batch: &Batch, j: usize) -> Claim {
        Claim { j, slot: batch.slots[j].clone().unwrap(), path: batch.path(j), time: NOW - 600, by_operator: false }
    }
}

/// Signs the claim's digest with `key` and runs the program on `e`; returns
/// (program, witness) or the Bit Machine's error.
fn run(source: &str, batch: &Batch, e: &Exit, c: &Claim, key: &Keypair) -> Result<(Vec<u8>, Vec<u8>), String> {
    let program = sequentia_contracts::compile(source, Default::default()).unwrap();
    let cmr: [u8; 32] = program.commit().cmr().to_byte_array();
    let cb = ControlBlock::from_slice(&batch.control_block(cmr)).unwrap();
    let digest = exit_digest(batch.root(), c.slot.record(c.j as u16), c.time);
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), key).serialize();
    // The jets read an input's annex from its witness stack, as the node
    // does: the last item, when it starts with 0x50.
    let mut tx = e.tx.clone();
    if let Some(a) = &e.annex {
        tx.input[e.k as usize].witness.script_witness = vec![vec![0x00], vec![0x00], a.clone()];
    }
    let env = ElementsEnv::new(
        Arc::new(tx),
        e.utxos.iter().cloned().map(ElementsUtxo::from).collect(),
        e.k,
        program.commit().cmr(),
        cb,
        e.annex.clone(),
        BlockHash::from_byte_array(GENESIS),
    );
    let wv: WitnessValues =
        serde_json::from_str(&batch.witness(c.j, &c.slot, &c.path, c.time, c.by_operator, &sig).to_string()).unwrap();
    let satisfied = program.satisfy_with_env(wv, Some(&env)).map_err(|e| format!("satisfy: {e}"))?;
    let node = satisfied.redeem().clone();
    let mut mac = BitMachine::for_program(&node).map_err(|e| format!("machine: {e}"))?;
    mac.exec(&node, &env).map_err(|e| format!("exec: {e}"))?;
    let (prog, w) = node.to_vec_with_witness();
    assert_eq!(hex(&w), hex(&pack(&witness_bits(batch, c, &sig))), "the witness is not the documented layout");
    println!("program {} bytes, witness {} bytes, cost bound {:?}, extra cells {}, extra frames {}",
        prog.len(), w.len(), node.bounds().cost, node.bounds().extra_cells, node.bounds().extra_frames);
    Ok((prog, w))
}

/// The witness's bits, in the documented order.
fn witness_bits(batch: &Batch, c: &Claim, sig: &[u8; 64]) -> Vec<bool> {
    let mut b = batch.data_bytes();
    b.extend((c.j as u16).to_be_bytes());
    b.extend(c.slot.owner);
    b.extend(sha(&c.slot.spk));
    b.extend(c.slot.value.to_be_bytes());
    b.extend(c.slot.reserve.to_be_bytes());
    for (sh, sw) in &c.path {
        b.extend(sh);
        b.extend(sw.to_be_bytes());
    }
    b.extend(c.time.to_be_bytes());
    let mut bits = bits(&b);
    bits.push(c.by_operator);
    bits.extend(self::bits(sig));
    bits
}

fn bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn pack(b: &[bool]) -> Vec<u8> {
    b.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i)))).collect()
}

fn source() -> String {
    sequentia_contracts::expand(&std::fs::read_to_string(format!("{DIR}/arca_accumulator.simf")).unwrap()).unwrap()
}

fn cmr_of(source: &str) -> [u8; 32] {
    sequentia_contracts::compile(source, Default::default()).unwrap().commit().cmr().to_byte_array()
}

fn keypair(label: &str) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &h(label)).unwrap()
}

fn xonly(k: &Keypair) -> [u8; 32] {
    k.x_only_public_key().0.serialize()
}

/// A batch whose slots in `live` hold a leaf of owner key "seed j".
fn batch(seed: &str, live: &[usize], operator: &Keypair) -> Batch {
    let mut slots = vec![None; SLOTS];
    for &j in live {
        slots[j] = Some(Slot {
            owner: xonly(&keypair(&format!("{seed} {j}"))),
            spk: [&[0x51u8, 0x20][..], &h(&format!("{seed} entry {j}"))[..]].concat(),
            value: 100_000 + 7 * j as u64,
            reserve: 300 + j as u64 % 5,
        });
    }
    Batch::new(slots, xonly(operator))
}

fn full(seed: &str, operator: &Keypair) -> Batch {
    batch(seed, &(0..SLOTS).collect::<Vec<_>>(), operator)
}

#[test]
fn exits_the_program_accepts_and_refuses() {
    let source = source();
    let cmr = cmr_of(&source);
    let s = keypair("the operator");
    let asset = h("the batch asset");
    let b = full("one", &s);
    let owner = |j: usize| keypair(&format!("one {j}"));

    // Accepted: the owner's exit at the corners and in the middle, at k = 0
    // and 1; the operator's.
    for (j, k) in [(0usize, 0u32), (1023, 0), (341, 1), (512, 3)] {
        run(&source, &b, &exit(&b, cmr, &asset, j, k, b.total()), &Claim::of(&b, j), &owner(j)).unwrap();
    }
    let mut c = Claim::of(&b, 77);
    c.by_operator = true;
    run(&source, &b, &exit(&b, cmr, &asset, 77, 0, b.total()), &c, &s).unwrap();

    // A second exit from the state the first leaves, with the path the second
    // owner held from the start.
    let b1 = b.left(341);
    let held = b.total() - b.slots[341].as_ref().unwrap().weight();
    run(&source, &b1, &exit(&b1, cmr, &asset, 700, 0, held), &Claim::of(&b1, 700), &owner(700)).unwrap();
    // The last leaf of a batch of one: no rest.
    let lone = batch("lone", &[5], &s);
    run(&source, &lone, &exit(&lone, cmr, &asset, 5, 0, lone.total()), &Claim::of(&lone, 5), &keypair("lone 5")).unwrap();

    let refuse = |name: &str, r: Result<(Vec<u8>, Vec<u8>), String>| {
        let e = r.expect_err(&format!("{name}: the program took it"));
        println!("refused, {name}: {e}");
    };
    let j = 341usize;
    let base = || exit(&b, cmr, &asset, j, 0, b.total());

    // The slot has left already: the coin's bitmap has its bit.
    refuse("a slot whose bit is set", run(&source, &b1, &exit(&b1, cmr, &asset, j, 0, held), &Claim::of(&b1, j), &owner(j)));
    // A forged path: one sibling changed; one sibling's weight changed.
    let mut c = Claim::of(&b, j);
    c.path[3].0[0] ^= 1;
    refuse("a forged sibling at level 3", run(&source, &b, &base(), &c, &owner(j)));
    let mut c = Claim::of(&b, j);
    c.path[6].1 += 1;
    refuse("a sibling's weight one more", run(&source, &b, &base(), &c, &owner(j)));
    // Another slot's path for this record.
    let mut c = Claim::of(&b, j);
    c.path = b.path(j ^ 1);
    refuse("the neighbour's path", run(&source, &b, &base(), &c, &owner(j)));
    // A record not in the tree: one atom more than it holds, paid out.
    let mut e = base();
    e.tx.output[0].value = Amount::Explicit(b.slots[j].as_ref().unwrap().value + 1);
    e.tx.output[1].value = Amount::Explicit(e.tx.output[1].value.explicit().unwrap() - 1);
    let mut c = Claim::of(&b, j);
    c.slot.value += 1;
    refuse("a record claiming one atom more", run(&source, &b, &e, &c, &owner(j)));
    // A sibling's weight lowered to make room, with an overflow.
    let mut c = Claim::of(&b, j);
    c.path[0].1 = u64::MAX;
    refuse("a sibling weight that overflows", run(&source, &b, &base(), &c, &owner(j)));
    // The index past the tree, with its own record, on the slot's path.
    let mut c = Claim::of(&b, j);
    c.j = j + 1024;
    refuse("an index of 1,024 or more", run(&source, &b, &base(), &c, &owner(j)));
    // Signatures: a stranger's; the owner's under the operator's flag; the
    // operator's under the owner's; the owner's over another time.
    refuse("a stranger's signature", run(&source, &b, &base(), &Claim::of(&b, j), &keypair("a stranger")));
    let mut c = Claim::of(&b, j);
    c.by_operator = true;
    refuse("the owner's signature with BY_OPERATOR", run(&source, &b, &base(), &c, &owner(j)));
    refuse("the operator's signature without BY_OPERATOR", run(&source, &b, &base(), &Claim::of(&b, j), &s));
    refuse("another slot owner's signature", run(&source, &b, &base(), &Claim::of(&b, j), &owner(j + 1)));
    // The authorisation's time not reached: lock time one second before it;
    // a lock time that is a height; the lock time disabled by final inputs.
    let mut c = Claim::of(&b, j);
    c.time = NOW + 1;
    refuse("a lock time one second before TIME", run(&source, &b, &base(), &c, &owner(j)));
    let mut e = base();
    e.tx.lock_time = LockTime::from_consensus(400_000);
    let mut c = Claim::of(&b, j);
    c.time = 300_000;
    refuse("a lock time that is a height", run(&source, &b, &e, &c, &owner(j)));
    let mut e = base();
    e.tx.input[0].sequence = Sequence::MAX;
    refuse("a final input, so no lock time", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    // The entry: one atom short, to another script, in another asset, with a
    // nonce.
    let mut e = base();
    e.tx.output[0].value = Amount::Explicit(e.tx.output[0].value.explicit().unwrap() - 1);
    refuse("the entry one atom short", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[0].script_pubkey = Script::from([&[0x51u8, 0x20][..], &b.slots[j].as_ref().unwrap().owner[..]].concat());
    refuse("the entry to the owner's key", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[0].asset = Asset::Explicit(AssetId::from_slice(&h("another asset")).unwrap());
    refuse("the entry in another asset", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[0].nonce = Nonce::Explicit([7; 32]);
    refuse("the entry with a nonce", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    // The rest: one atom short; under the old state; with another slot's bit
    // set; with a second bit set as well; under another sweep leaf; with a
    // nonce; missing.
    let mut e = base();
    e.tx.output[1].value = Amount::Explicit(e.tx.output[1].value.explicit().unwrap() - 1);
    refuse("the rest one atom short", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[1].script_pubkey = Script::from(b.spk(cmr));
    refuse("the rest under the old state", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[1].script_pubkey = Script::from(b.left(j + 1).spk(cmr));
    refuse("the rest with another slot's bit", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[1].script_pubkey = Script::from(b.left(j).left(5).spk(cmr));
    refuse("the rest with a second bit as well", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    let mut other_sweep = b.left(j);
    other_sweep.sweep = tapleaf(0xc4, &[0x52]);
    e.tx.output[1].script_pubkey = Script::from(other_sweep.spk(cmr));
    refuse("the rest under another sweep leaf", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output[1].nonce = Nonce::Explicit([7; 32]);
    refuse("the rest with a nonce", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut e = base();
    e.tx.output.remove(1);
    refuse("no rest", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    // The coin: in another asset than the outputs; holding a state with
    // another operator key.
    let mut e = base();
    e.utxos[0].asset = Asset::Explicit(AssetId::from_slice(&h("another asset")).unwrap());
    refuse("a coin of another asset", run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
    let mut other_op = b.clone();
    other_op.operator = xonly(&keypair("another operator"));
    refuse("a data leaf the coin does not hold", run(&source, &other_op, &base(), &Claim::of(&b, j), &owner(j)));

    // An annex on the batch input, which the authorisation does not sign: one
    // byte past its tag, and a large one; the owner's exit, the operator's,
    // and the last leaf's exit (no rest).
    for (name, annex) in [("a 2-byte annex", vec![0x50, 0x00]), ("a 1,000-byte annex", [vec![0x50], vec![0xaa; 999]].concat())] {
        let mut e = base();
        e.annex = Some(annex.clone());
        refuse(&format!("the owner's exit with {name}"), run(&source, &b, &e, &Claim::of(&b, j), &owner(j)));
        let mut e = exit(&b, cmr, &asset, 77, 0, b.total());
        e.annex = Some(annex.clone());
        let mut c = Claim::of(&b, 77);
        c.by_operator = true;
        refuse(&format!("the operator's exit with {name}"), run(&source, &b, &e, &c, &s));
        let mut e = exit(&lone, cmr, &asset, 5, 0, lone.total());
        e.annex = Some(annex);
        refuse(&format!("the last leaf's exit with {name}"), run(&source, &lone, &e, &Claim::of(&lone, 5), &keypair("lone 5")));
    }
}

#[test]
fn every_exit_spends_by_the_constant_programs_of_exits_json() {
    let source = source();
    let cmr = cmr_of(&source);
    let s = keypair("the operator");
    let asset = h("the batch asset");
    let first = full("one", &s);
    // Equal values: the operator holds a slot; a value equal to a reserve.
    let mut eq_slots: Vec<Option<Slot>> = vec![None; SLOTS];
    for j in [0usize, 1, 2, 3, 1022, 1023] {
        eq_slots[j] = Some(Slot { owner: xonly(&s), spk: vec![0x51], value: 500, reserve: 500 });
    }
    let eq = Batch::new(eq_slots, xonly(&s));

    let mut got: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
    let mut check = |name: &str, prog: Vec<u8>, what: &str| {
        let want = got.entry(name.to_string()).or_insert_with(|| prog.clone());
        assert_eq!(hex(want), hex(&prog), "{what}: the {name} program differs");
    };
    for (n, (b, seed)) in [(&first, "one"), (&eq, "")].into_iter().enumerate() {
        for &j in &[0usize, 1, 3, 1022, 1023] {
            for k in [0u32, 1, 3] {
                for by_operator in [false, true] {
                    let mut c = Claim::of(b, j);
                    c.by_operator = by_operator;
                    let key = if by_operator || seed.is_empty() { s } else { keypair(&format!("{seed} {j}")) };
                    let (prog, _) = run(&source, b, &exit(b, cmr, &asset, j, k, b.total()), &c, &key).unwrap();
                    check("exit", prog, &format!("batch {n}, slot {j}, k={k}, operator {by_operator}"));
                }
            }
        }
    }
    // With slots already left, and the last leaf.
    let mut b = first.clone();
    let mut held = b.total();
    for j in [10usize, 64, 65, 1000] {
        let (prog, _) = run(&source, &b, &exit(&b, cmr, &asset, j, 0, held), &Claim::of(&b, j), &keypair(&format!("one {j}"))).unwrap();
        check("exit", prog, &format!("after earlier exits, slot {j}"));
        held -= b.slots[j].as_ref().unwrap().weight();
        b = b.left(j);
    }
    for (seed, j) in [("lone", 0usize), ("lone", 1023), ("lone", 700)] {
        let lone = batch(seed, &[j], &s);
        for k in [0u32, 2] {
            let (prog, _) = run(&source, &lone, &exit(&lone, cmr, &asset, j, k, lone.total()), &Claim::of(&lone, j), &keypair(&format!("{seed} {j}"))).unwrap();
            check("exit_last", prog, &format!("the last leaf, slot {j}, k={k}"));
        }
    }
    let paths: serde_json::Map<String, Value> = got
        .iter()
        .map(|(k, p)| (k.clone(), json!({"program": hex(p), "program_bytes": p.len()})))
        .collect();
    let want = json!({"exits": 1, "cmr": hex(&cmr), "paths": paths});
    if std::env::var("WRITE_EXITS").is_ok() {
        std::fs::write(format!("{DIR}/exits.json"), serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
    }
    let have: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/exits.json")).unwrap()).unwrap();
    assert_eq!(have, want, "exits.json differs from what the program prunes to");
}
