//! Arca's accumulator batch without a sweep, `arca/accumulator-2`, against
//! `templates/arca_accumulator_2/paths.json`.
//!
//! The batch output is `TapBranch(X, D)`: this program `X` and the data leaf
//! `D` of the root, the operator's key and the bitmap. This test builds the
//! Merkle-sum tree of 1,024 slots, the records, the data leaf and the batch
//! output in Rust, independently of the program, signs each exit with the
//! owner's or the operator's key and each release with the owners' keys and
//! the operator's, and runs the program on the Bit Machine: every spend it
//! should accept passes, and the spends it must refuse fail. It then prunes the
//! program at several slots, at k = 0, 1 and 3, for exits by both keys and for
//! releases of every count of slots from 1 to 14, and requires the 30
//! constants of `paths.json` each time; every one of them fits the node's
//! budget with no annex and its Bit Machine's cells. `WRITE_PATHS=1 cargo test
//! --test arca_accumulator_2` rewrites the file instead. `places_that_fit`
//! (ignored by default) measures the program built with other numbers of
//! places, and shows that 15 slots do not fit when they take the last of the
//! batch.

use std::sync::Arc;

use secp256k1::{Keypair, Message, Parity, Scalar, Secp256k1, XOnlyPublicKey};
use sequentia_contracts::elements::confidential::{Asset, Nonce, Value as Amount};
use sequentia_contracts::elements::encode::serialize;
use sequentia_contracts::elements::hashes::{sha256, Hash};
use sequentia_contracts::elements::taproot::ControlBlock;
use sequentia_contracts::elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid};
use sequentia_contracts::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use sequentia_contracts::simplicity::BitMachine;
use sequentia_contracts::simplicityhl::WitnessValues;
use serde_json::{json, Value};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/arca_accumulator_2");
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const DEPTH: usize = 10;
const SLOTS: usize = 1 << DEPTH;
/// The places of a release: the most slots one release takes.
const PLACES: usize = 14;
const GENESIS: [u8; 32] = [0x5a; 32];
/// A median time, so the lock time is a time.
const NOW: u32 = 1_700_000_000;
/// The node's limits (`src/simplicity/limitations.h`, `script.h`): the Bit
/// Machine's cells, and a witness byte's budget on Sequentia.
const CELLS_MAX: usize = 0x500000;
const BUDGET_PER_BYTE: u64 = 4;
const BUDGET_MAX: u64 = 4_000_050;

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

/// One slot: the key that may take it out or release it, the script and value
/// its exit pays, and the reserve it leaves for the fee.
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
        Batch { slots, operator, bitmap: [0; 16], levels }
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
        tapbranch(tapleaf(0xbe, &cmr), self.data_leaf())
    }

    fn spk(&self, cmr: [u8; 32]) -> Vec<u8> {
        p2tr(self.tree(cmr))
    }

    fn control_block(&self, cmr: [u8; 32]) -> Vec<u8> {
        let parity = output_key(self.tree(cmr)).1;
        let first = 0xbe | if parity == Parity::Odd { 1 } else { 0 };
        [vec![first], unhex(NUMS), self.data_leaf().to_vec()].concat()
    }

    fn left(&self, j: usize) -> Batch {
        let mut b = self.clone();
        b.bitmap[j / 64] |= 1u64 << (63 - j % 64);
        b
    }

    fn left_all(&self, js: &[usize]) -> Batch {
        js.iter().fold(self.clone(), |b, &j| b.left(j))
    }

    fn weight_of(&self, js: &[usize]) -> u64 {
        js.iter().map(|&j| self.slots[j].as_ref().unwrap().weight()).sum()
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

fn release_digest(root: [u8; 32], rec: [u8; 32], m: [u8; 32]) -> [u8; 32] {
    let mut b = h("Arca/accumulator-release").to_vec();
    b.extend(GENESIS);
    b.extend(root);
    b.extend(rec);
    b.extend(m);
    sha(&b)
}

/// The chain's commitment to every output of `tx` (Simplicity's
/// `outputs_hash`): the SHA256 of the hashes of every output's asset and
/// amount, of every nonce, of every script's SHA256 and of every range
/// proof's SHA256 (empty for an explicit amount), each field as the
/// transaction encodes it.
fn outputs_hash(tx: &Transaction) -> [u8; 32] {
    let (mut amounts, mut nonces, mut scripts, mut proofs) = (vec![], vec![], vec![], vec![]);
    for o in &tx.output {
        amounts.extend(serialize(&o.asset));
        amounts.extend(serialize(&o.value));
        nonces.extend(serialize(&o.nonce));
        scripts.extend(sha(o.script_pubkey.as_bytes()));
        let proof = match (&o.value, &o.witness.rangeproof) {
            (Amount::Confidential(_), Some(p)) => p.serialize(),
            _ => vec![],
        };
        proofs.extend(sha(&proof));
    }
    sha(&[sha(&amounts), sha(&nonces), sha(&scripts), sha(&proofs)].concat())
}

/// What the operator signs to take released slots out of the coin at input
/// `k` holding the state whose data leaf is `state`.
fn payout_digest(state: [u8; 32], k: u32, tx: &Transaction) -> [u8; 32] {
    let mut b = h("Arca/accumulator-release-outputs").to_vec();
    b.extend(GENESIS);
    b.extend(state);
    b.extend(k.to_be_bytes());
    b.extend(outputs_hash(tx));
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

fn input(label: &str, i: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array(h(label)), i),
        sequence: Sequence(0xffff_fffe),
        ..Default::default()
    }
}

/// A spend of the batch output: the transaction, its prevouts and the
/// batch's input.
#[derive(Clone)]
struct Spend {
    tx: Transaction,
    utxos: Vec<TxOut>,
    k: u32,
    /// The batch input's annex, with its 0x50 tag, if any.
    annex: Option<Vec<u8>>,
}

/// `k` other coins before the batch input, each with its two outputs.
fn others(k: u32, spend: &mut Spend) {
    let other = h("another coin's asset");
    for i in 0..k {
        spend.tx.input.push(input(&format!("coin {i}"), i));
        spend.utxos.push(out(&other, 1_000, &[0x51]));
        spend.tx.output.push(out(&other, 500, &[0x51]));
        spend.tx.output.push(out(&other, 500, &[0x51]));
    }
}

fn empty(k: u32) -> Spend {
    Spend { tx: Transaction { version: 2, lock_time: LockTime::from_consensus(NOW), input: vec![], output: vec![] }, utxos: vec![], k, annex: None }
}

/// The exit of slot `j` from `batch` holding `held` at input `k`: the entry at
/// 2k, the rest at 2k+1 under the next state, a fee output after.
fn exit(batch: &Batch, cmr: [u8; 32], asset: &[u8; 32], j: usize, k: u32, held: u64) -> Spend {
    let slot = batch.slots[j].clone().unwrap();
    let mut e = empty(k);
    others(k, &mut e);
    e.tx.input.push(input("the batch", 0));
    e.utxos.push(out(asset, held, &batch.spk(cmr)));
    e.tx.output.push(out(asset, slot.value, &slot.spk));
    let rest = held - slot.value - slot.reserve;
    if rest > 0 {
        e.tx.output.push(out(asset, rest, &batch.left(j).spk(cmr)));
    }
    e.tx.output.push(TxOut::new_fee(slot.reserve, AssetId::from_slice(asset).unwrap()));
    e
}

/// The connector asset of round `r`.
fn connector(r: usize) -> [u8; 32] {
    h(&format!("the connector asset of round {r}"))
}

/// A release of the slots `js` from `batch` holding `held` at input `k`: the
/// operator's payout at 2k, the rest at 2k+1, a fee output; after the batch's
/// input, one atom of the connector asset of each round in `rounds`.
fn release(batch: &Batch, cmr: [u8; 32], asset: &[u8; 32], js: &[usize], k: u32, held: u64, rounds: &[usize]) -> Spend {
    let mut e = empty(k);
    others(k, &mut e);
    e.tx.input.push(input("the batch", 0));
    e.utxos.push(out(asset, held, &batch.spk(cmr)));
    let taken = batch.weight_of(js);
    let fee = 200;
    e.tx.output.push(out(asset, taken - fee, &[0x51, 0x20, 0x0b, 0x0b]));
    let rest = held - taken;
    if rest > 0 {
        e.tx.output.push(out(asset, rest, &batch.left_all(js).spk(cmr)));
    }
    for &r in rounds {
        e.tx.input.push(input(&format!("round {r}'s connector"), 1));
        e.utxos.push(out(&connector(r), 1, &[0x51]));
        e.tx.output.push(out(&connector(r), 1, &[0x51]));
    }
    e.tx.output.push(TxOut::new_fee(fee, AssetId::from_slice(asset).unwrap()));
    e
}

/// What an exit presents: the slot's record values, path, time, flag, key.
#[derive(Clone)]
struct ExitClaim {
    j: usize,
    slot: Slot,
    path: Vec<([u8; 32], u64)>,
    time: u32,
    by_operator: bool,
    key: Keypair,
}

/// One place of a release: the slot, the input holding `M`, the `M` and the
/// root its owner signed over, and the key that signs.
#[derive(Clone)]
struct Place {
    j: usize,
    slot: Slot,
    path: Vec<([u8; 32], u64)>,
    m_at: u32,
    m: [u8; 32],
    root: [u8; 32],
    key: Keypair,
}

#[derive(Clone)]
struct ReleaseClaim {
    /// The slots, in their places, and how many places the program has.
    places: Vec<Place>,
    size: usize,
    operator: Keypair,
    /// Sign the transaction as the operator, or with these 64 bytes.
    operator_sig: Option<[u8; 64]>,
}

#[derive(Clone)]
enum Action {
    Exit(ExitClaim),
    Release(ReleaseClaim),
}

fn exit_claim(batch: &Batch, j: usize, key: Keypair) -> ExitClaim {
    ExitClaim { j, slot: batch.slots[j].clone().unwrap(), path: batch.path(j), time: NOW - 600, by_operator: false, key }
}

/// The release of `js` by their owners (`owner(j)`), each for round `round(j)`,
/// its atom at the input `at(round)`, the rest of the places empty.
fn release_claim(batch: &Batch, js: &[usize], owner: &dyn Fn(usize) -> Keypair, m_at: &dyn Fn(usize) -> (u32, [u8; 32]), operator: Keypair) -> ReleaseClaim {
    let places: Vec<Place> = js
        .iter()
        .map(|&j| {
            let (at, m) = m_at(j);
            Place { j, slot: batch.slots[j].clone().unwrap(), path: batch.path(j), m_at: at, m, root: batch.root(), key: owner(j) }
        })
        .collect();
    ReleaseClaim { places, size: PLACES, operator, operator_sig: None }
}

fn sign(key: &Keypair, digest: [u8; 32]) -> [u8; 64] {
    Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), key).serialize()
}

fn path_value(path: &[([u8; 32], u64)]) -> String {
    let steps: Vec<String> = path.iter().map(|(sh, sw)| format!("(0x{}, {})", hex(sh), sw)).collect();
    format!("[{}]", steps.join(", "))
}

const PATH_T: &str = "[(u256, u64); 10]";

fn exit_type() -> String {
    format!("(u16, u256, u256, u64, u64, {PATH_T}, u32, bool, Signature)")
}

fn release_type(places: usize) -> String {
    let slot = format!("(u16, u256, u256, u64, u64, {PATH_T}, u32, Signature)");
    let mut t = format!("Option<{slot}>");
    for _ in 2..=places {
        t = format!("Option<({slot}, {t})>");
    }
    format!("({t}, Signature)")
}

/// The witness values, and the witness's bits in the documented order.
fn witness(batch: &Batch, action: &Action, opsig: &[u8; 64]) -> (Value, Vec<bool>) {
    let b = |v: &[u8], t: &str| json!({"value": format!("0x{}", hex(v)), "type": t});
    let words: Vec<String> = batch.bitmap.iter().map(|w| w.to_string()).collect();
    let mut bits = self::bits(&batch.data_bytes());
    let slot_bytes = |j: usize, s: &Slot, path: &[([u8; 32], u64)]| {
        let mut v = (j as u16).to_be_bytes().to_vec();
        v.extend(s.owner);
        v.extend(sha(&s.spk));
        v.extend(s.value.to_be_bytes());
        v.extend(s.reserve.to_be_bytes());
        for (sh, sw) in path {
            v.extend(sh);
            v.extend(sw.to_be_bytes());
        }
        v
    };
    let (value, ty) = match action {
        Action::Exit(c) => {
            let rec = c.slot.record(c.j as u16);
            let sig = sign(&c.key, exit_digest(batch.root(), rec, c.time));
            bits.push(false);
            let mut v = slot_bytes(c.j, &c.slot, &c.path);
            v.extend(c.time.to_be_bytes());
            bits.extend(self::bits(&v));
            bits.push(c.by_operator);
            bits.extend(self::bits(&sig));
            (
                format!(
                    "Left(({}, 0x{}, 0x{}, {}, {}, {}, {}, {}, 0x{}))",
                    c.j, hex(&c.slot.owner), hex(&sha(&c.slot.spk)), c.slot.value, c.slot.reserve, path_value(&c.path), c.time,
                    c.by_operator, hex(&sig)
                ),
                format!("Either<{}, {}>", exit_type(), release_type(PLACES)),
            )
        }
        Action::Release(r) => {
            bits.push(true);
            let mut places = Vec::new();
            for p in &r.places {
                let rec = p.slot.record(p.j as u16);
                let sig = sign(&p.key, release_digest(p.root, rec, p.m));
                let mut v = slot_bytes(p.j, &p.slot, &p.path);
                v.extend(p.m_at.to_be_bytes());
                v.extend(sig);
                places.push((v, format!(
                    "({}, 0x{}, 0x{}, {}, {}, {}, {}, 0x{})",
                    p.j, hex(&p.slot.owner), hex(&sha(&p.slot.spk)), p.slot.value, p.slot.reserve, path_value(&p.path), p.m_at,
                    hex(&sig)
                )));
            }
            assert!(places.len() <= r.size, "more slots than places");
            // Place i (from 1) is P_{size - i + 1}; the innermost, P1, is an
            // Option of a slot alone.
            let mut text = String::new();
            let mut close = String::new();
            for i in 0..r.size {
                let level = r.size - i;
                match places.get(i) {
                    Some((v, t)) => {
                        bits.push(true);
                        bits.extend(self::bits(v));
                        if level == 1 {
                            text += &format!("Some({t})");
                        } else {
                            text += &format!("Some(({t}, ");
                            close += "))";
                        }
                    }
                    None => {
                        bits.push(false);
                        text += "None";
                        break;
                    }
                }
            }
            text += &close;
            bits.extend(self::bits(opsig));
            (format!("Right(({text}, 0x{}))", hex(opsig)), format!("Either<{}, {}>", exit_type(), release_type(r.size)))
        }
    };
    let wv = json!({
        "ROOT": b(&batch.root(), "u256"),
        "OPERATOR": b(&batch.operator, "u256"),
        "BITMAP": {"value": format!("[{}]", words.join(", ")), "type": "[u64; 16]"},
        "ACTION": {"value": value, "type": ty},
    });
    (wv, bits)
}

/// What a run measured.
#[derive(Debug)]
struct Run {
    program: Vec<u8>,
    witness: Vec<u8>,
    /// The static cost bound, milli-WU, and the budget of the witness stack.
    cost: u64,
    budget: u64,
    cells: usize,
}

/// Runs the program on `e` for `action`; returns what it measured or the Bit
/// Machine's error. A run that does not fit the node's budget or cells fails.
fn run(source: &str, batch: &Batch, e: &Spend, action: &Action) -> Result<Run, String> {
    let program = sequentia_contracts::compile(source, Default::default()).unwrap();
    let cmr: [u8; 32] = program.commit().cmr().to_byte_array();
    let cb_bytes = batch.control_block(cmr);
    let cb = ControlBlock::from_slice(&cb_bytes).unwrap();
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
    let opsig = match action {
        Action::Release(r) => r.operator_sig.unwrap_or_else(|| sign(&r.operator, payout_digest(batch.data_leaf(), e.k, &e.tx))),
        Action::Exit(_) => [0; 64],
    };
    let (wv, want_bits) = witness(batch, action, &opsig);
    let wv: WitnessValues = serde_json::from_str(&wv.to_string()).map_err(|e| format!("witness values: {e}"))?;
    let satisfied = program.satisfy_with_env(wv, Some(&env)).map_err(|e| format!("satisfy: {e}"))?;
    let node = satisfied.redeem().clone();
    let mut mac = BitMachine::for_program(&node).map_err(|e| format!("machine: {e}"))?;
    mac.exec(&node, &env).map_err(|e| format!("exec: {e}"))?;
    let (prog, w) = node.to_vec_with_witness();
    if std::env::var("COST_ONLY").is_err() {
        assert_eq!(hex(&w), hex(&pack(&want_bits)), "the witness is not the documented layout");
    }
    let mut stack = vec![w.clone(), prog.clone(), cmr.to_vec(), cb_bytes];
    if let Some(a) = &e.annex {
        stack.push(a.clone());
    }
    let budget = ((serialize(&stack).len() as u64) * BUDGET_PER_BYTE + 50).min(BUDGET_MAX);
    // The cost prints in milli-WU.
    let cost: u64 = node.bounds().cost.to_string().parse().unwrap();
    let cells = node.arrow().source.bit_width() + node.arrow().target.bit_width() + node.bounds().extra_cells;
    if cost > budget * 1000 {
        return Err(format!("budget: cost {cost} mWU over {budget} WU"));
    }
    if cells > CELLS_MAX {
        return Err(format!("cells: {cells} over {CELLS_MAX}"));
    }
    Ok(Run { program: prog, witness: w, cost, budget, cells })
}

fn bits(b: &[u8]) -> Vec<bool> {
    b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn pack(b: &[bool]) -> Vec<u8> {
    b.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i)))).collect()
}

fn source() -> String {
    sequentia_contracts::expand(&std::fs::read_to_string(format!("{DIR}/arca_accumulator_2.simf")).unwrap()).unwrap()
}

/// The text between `// BEGIN name` and `// END name` for `n` places.
fn block(name: &str, n: usize) -> String {
    let mut out = vec![format!("// BEGIN {name}")];
    if name == "PLACES" {
        out.push("/* The places of a release, nested: a release of n slots holds n of them,".into());
        out.push(" * and the program prunes to the n it holds. */".into());
        out.push("type P1 = Option<Released>;".into());
        for i in 2..=n {
            out.push(format!("type P{i} = Option<(Released, P{})>;", i - 1));
        }
        out.push(format!("type Places = P{n};"));
    } else {
        out.push("/* The release of the slots the places hold, from the first. */".into());
        out.extend(["fn places1(p: P1, t: Tally) -> Tally {", "    match p {", "        None => t,", "        Some(s: Released) => release_one(s, t),", "    }", "}"].map(String::from));
        for i in 2..=n {
            out.push(format!("fn places{i}(p: P{i}, t: Tally) -> Tally {{"));
            out.push("    match p {".into());
            out.push("        None => t,".into());
            out.push(format!("        Some(x: (Released, P{})) => {{", i - 1));
            out.push(format!("            let (s, rest): (Released, P{}) = x;", i - 1));
            out.push(format!("            places{}(rest, release_one(s, t))", i - 1));
            out.push("        },".into());
            out.push("    }".into());
            out.push("}".into());
        }
    }
    out.push(format!("// END {name}"));
    out.join("\n")
}

fn replace_block(s: &str, name: &str, n: usize) -> String {
    let a = s.find(&format!("// BEGIN {name}")).unwrap();
    let end = format!("// END {name}");
    let b = s.find(&end).unwrap() + end.len();
    format!("{}{}{}", &s[..a], block(name, n), &s[b..])
}

/// The program with `n` places in a release in place of 14. With 14 it is
/// the template itself.
fn source_with_places(n: usize) -> String {
    let s = source();
    let call = "places14(places, ";
    assert_eq!(s.matches(call).count(), 1);
    assert_eq!(replace_block(&replace_block(&s, "PLACES", PLACES), "LEVELS", PLACES), s, "the template's blocks are not the generated ones");
    replace_block(&replace_block(&s, "PLACES", n), "LEVELS", n).replace(call, &format!("places{n}(places, "))
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

/// Each slot's round is the slot modulo 3, its atom at the input after the
/// batch's, in the order of `rounds`.
fn rounds_of(js: &[usize]) -> Vec<usize> {
    let mut r: Vec<usize> = js.iter().map(|j| j % 3).collect();
    r.sort();
    r.dedup();
    r
}

fn m_at_for(k: u32, rounds: Vec<usize>) -> impl Fn(usize) -> (u32, [u8; 32]) {
    move |j: usize| {
        let r = j % 3;
        let at = k + 1 + rounds.iter().position(|&x| x == r).unwrap() as u32;
        (at, connector(r))
    }
}

#[test]
fn spends_the_program_accepts_and_refuses() {
    let source = source();
    let cmr = cmr_of(&source);
    let s = keypair("the operator");
    let asset = h("the batch asset");
    let b = full("one", &s);
    let owner = |j: usize| keypair(&format!("one {j}"));
    let refuse = |name: &str, r: Result<Run, String>| {
        let e = r.err().unwrap_or_else(|| panic!("{name}: the program took it"));
        println!("refused, {name}: {e}");
    };

    // EXIT. Accepted: the owner's exit at the corners and in the middle, at
    // k = 0, 1 and 3; the operator's.
    for (j, k) in [(0usize, 0u32), (1023, 0), (341, 1), (512, 3)] {
        let r = run(&source, &b, &exit(&b, cmr, &asset, j, k, b.total()), &Action::Exit(exit_claim(&b, j, owner(j)))).unwrap();
        println!("exit of slot {j} at k={k}: program {} B, witness {} B, cost {} mWU, budget {} WU, cells {}", r.program.len(), r.witness.len(), r.cost, r.budget, r.cells);
    }
    let mut c = exit_claim(&b, 77, s);
    c.by_operator = true;
    run(&source, &b, &exit(&b, cmr, &asset, 77, 0, b.total()), &Action::Exit(c)).unwrap();
    let lone = batch("lone", &[5], &s);
    run(&source, &lone, &exit(&lone, cmr, &asset, 5, 0, lone.total()), &Action::Exit(exit_claim(&lone, 5, keypair("lone 5")))).unwrap();

    let j = 341usize;
    let ebase = || exit(&b, cmr, &asset, j, 0, b.total());
    let eclaim = || exit_claim(&b, j, owner(j));
    let ex = |c: ExitClaim| Action::Exit(c);
    let b1 = b.left(j);
    let held1 = b.total() - b.slots[j].as_ref().unwrap().weight();
    refuse("exit: a slot whose bit is set", run(&source, &b1, &exit(&b1, cmr, &asset, j, 0, held1), &ex(eclaim())));
    let mut c = eclaim();
    c.path[3].0[0] ^= 1;
    refuse("exit: a forged sibling at level 3", run(&source, &b, &ebase(), &ex(c)));
    let mut c = eclaim();
    c.path[6].1 += 1;
    refuse("exit: a sibling's weight one more", run(&source, &b, &ebase(), &ex(c)));
    refuse("exit: a stranger's signature", run(&source, &b, &ebase(), &ex(exit_claim(&b, j, keypair("a stranger")))));
    refuse("exit: the operator's signature without BY_OPERATOR", run(&source, &b, &ebase(), &ex(exit_claim(&b, j, s))));
    let mut c = eclaim();
    c.time = NOW + 1;
    refuse("exit: a lock time one second before TIME", run(&source, &b, &ebase(), &ex(c)));
    let mut e = ebase();
    e.tx.output[0].value = Amount::Explicit(e.tx.output[0].value.explicit().unwrap() - 1);
    refuse("exit: the entry one atom short", run(&source, &b, &e, &ex(eclaim())));
    let mut e = ebase();
    e.tx.output[1].value = Amount::Explicit(e.tx.output[1].value.explicit().unwrap() - 1);
    refuse("exit: the rest one atom short", run(&source, &b, &e, &ex(eclaim())));
    let mut e = ebase();
    e.tx.output[1].script_pubkey = Script::from(b.spk(cmr));
    refuse("exit: the rest under the old state", run(&source, &b, &e, &ex(eclaim())));
    let mut e = ebase();
    e.annex = Some(vec![0x50, 0x00]);
    refuse("exit: an annex", run(&source, &b, &e, &ex(eclaim())));

    // RELEASE. Accepted: one slot; eight slots of three rounds; at k = 0, 1
    // and 3; slots at the corners and in one word; the last slots of a batch
    // (no rest); a release after an exit, and an exit after a release.
    let one = [341usize];
    let eight = [0usize, 1, 63, 64, 341, 700, 1022, 1023];
    let operator = s;
    let rel = |b: &Batch, js: &[usize], k: u32| {
        let rounds = rounds_of(js);
        (release(b, cmr, &asset, js, k, b.total(), &rounds), release_claim(b, js, &owner, &m_at_for(k, rounds), operator))
    };
    for (js, k) in [(&one[..], 0u32), (&one[..], 1), (&eight[..], 0), (&eight[..], 3), (&[5usize, 6, 7][..], 0)] {
        let (e, c) = rel(&b, js, k);
        let r = run(&source, &b, &e, &Action::Release(c)).unwrap();
        println!(
            "release of {} slots at k={k}: program {} B, witness {} B, cost {} mWU, budget {} WU, cells {}",
            js.len(), r.program.len(), r.witness.len(), r.cost, r.budget, r.cells
        );
    }
    let few = batch("one", &[3, 9, 800], &s);
    let (e, c) = (release(&few, cmr, &asset, &[3, 9, 800], 0, few.total(), &rounds_of(&[3, 9, 800])), release_claim(&few, &[3, 9, 800], &owner, &m_at_for(0, rounds_of(&[3, 9, 800])), s));
    assert_eq!(e.tx.output.len(), 1 + rounds_of(&[3, 9, 800]).len() + 1, "no rest");
    run(&source, &few, &e, &Action::Release(c)).unwrap();
    // After an exit of 341: release 340 and 342 from the state it left.
    let (mut e, c) = rel(&b1, &[340, 342], 0);
    e.utxos[0] = out(&asset, held1, &b1.spk(cmr));
    e.tx.output[1] = out(&asset, held1 - b.weight_of(&[340, 342]), &b1.left_all(&[340, 342]).spk(cmr));
    run(&source, &b1, &e, &Action::Release(c)).unwrap();
    // An exit of 700 after the release of eight.
    let b8 = b.left_all(&eight);
    let held8 = b.total() - b.weight_of(&eight);
    run(&source, &b8, &exit(&b8, cmr, &asset, 700 - 1, 0, held8), &ex(exit_claim(&b8, 699, owner(699)))).unwrap();

    // Refused releases.
    let rbase = || rel(&b, &[341, 342], 0);
    let rr = |c: ReleaseClaim| Action::Release(c);
    let (e, mut c) = rbase();
    c.places[0].key = keypair("a stranger");
    refuse("release: a stranger's signature", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].key = owner(342);
    refuse("release: another slot owner's signature", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].key = s;
    refuse("release: the operator's signature for the owner's", run(&source, &b, &e, &rr(c)));
    let other_batch = full("two", &s);
    let (e, mut c) = rbase();
    c.places[0].root = other_batch.root();
    refuse("release: the owner's release under another batch's ROOT", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].m = connector(9);
    refuse("release: signed for another round's M", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    let p0 = c.places[0].clone();
    c.places[0].m_at = c.places[1].m_at;
    assert_ne!(p0.m_at, c.places[0].m_at);
    refuse("release: naming the input of another round's M", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].m_at = 0;
    refuse("release: naming the batch input for M", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].m_at = 9;
    refuse("release: naming an input that does not exist", run(&source, &b, &e, &rr(c)));
    let (mut e, c) = rbase();
    let m_in = c.places[0].m_at as usize;
    e.utxos[m_in].asset = Asset::Confidential(sequentia_contracts::elements::secp256k1_zkp::Generator::new_blinded(
        &Secp256k1::new(),
        sequentia_contracts::elements::secp256k1_zkp::Tag::from(connector(1)),
        sequentia_contracts::elements::secp256k1_zkp::Tweak::from_slice(&h("a blinding factor")).unwrap(),
    ));
    refuse("release: M read from a blinded input", run(&source, &b, &e, &rr(c)));
    refuse(
        "release: a slot whose bit is set",
        run(&source, &b1, &{
            let mut e = rel(&b1, &[341, 342], 0).0;
            e.utxos[0] = out(&asset, held1, &b1.spk(cmr));
            e.tx.output[1] = out(&asset, held1 - b.weight_of(&[341, 342]), &b1.left_all(&[341, 342]).spk(cmr));
            e
        }, &rr(rel(&b1, &[341, 342], 0).1)),
    );
    let (e, mut c) = rbase();
    c.places[1] = c.places[0].clone();
    refuse("release: one slot twice", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places.swap(0, 1);
    refuse("release: two slots out of order", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places.clear();
    refuse("release: no slot", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].path[4].1 += 1;
    refuse("release: a weight one more on the path", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].path[4].1 -= 1;
    refuse("release: a weight one less on the path", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].slot.value += 1;
    refuse("release: a record claiming one atom more", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.places[0].j += 1024;
    refuse("release: an index of 1,024 or more", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.operator_sig = Some(sign(&keypair("a stranger"), [1; 32]));
    refuse("release: no operator's signature", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.operator = keypair("a stranger");
    refuse("release: a stranger's signature for the operator's", run(&source, &b, &e, &rr(c)));
    let (e, mut c) = rbase();
    c.operator = owner(341);
    refuse("release: the owner's signature for the operator's", run(&source, &b, &e, &rr(c)));
    // The operator's signature over another transaction: the payout moved;
    // the connector's atom sent elsewhere; the fee one atom more; for the
    // coin at another index; for another state.
    let (e, c) = rbase();
    let mut c2 = c.clone();
    c2.operator_sig = Some(sign(&s, payout_digest(b.data_leaf(), 0, &e.tx)));
    run(&source, &b, &e, &rr(c2.clone())).unwrap();
    let mut e2 = e.clone();
    e2.tx.output[0].script_pubkey = Script::from(vec![0x51]);
    refuse("release: the operator's signature over another payout", run(&source, &b, &e2, &rr(c2.clone())));
    let mut e2 = e.clone();
    let last_m = e2.tx.output.len() - 2;
    e2.tx.output[last_m].script_pubkey = Script::from(vec![0x52]);
    refuse("release: the operator's signature with the connector's atom sent elsewhere", run(&source, &b, &e2, &rr(c2.clone())));
    let mut e2 = e.clone();
    let fee_at = e2.tx.output.len() - 1;
    e2.tx.output[0].value = Amount::Explicit(e2.tx.output[0].value.explicit().unwrap() - 1);
    e2.tx.output[fee_at].value = Amount::Explicit(e2.tx.output[fee_at].value.explicit().unwrap() + 1);
    refuse("release: the operator's signature with the fee one atom more", run(&source, &b, &e2, &rr(c2.clone())));
    let mut c3 = c.clone();
    c3.operator_sig = Some(sign(&s, payout_digest(b.data_leaf(), 1, &e.tx)));
    refuse("release: the operator's signature for the coin at another index", run(&source, &b, &e, &rr(c3)));
    let mut c3 = c.clone();
    c3.operator_sig = Some(sign(&s, payout_digest(b.left(5).data_leaf(), 0, &e.tx)));
    refuse("release: the operator's signature for another state", run(&source, &b, &e, &rr(c3)));
    // The rest: one atom short (the operator takes one more); one atom more;
    // under the old state; one bit missing; another slot's bit; a bit more;
    // another ROOT; another OPERATOR; a nonce; missing.
    let restv = |e: &Spend| e.tx.output[1].value.explicit().unwrap();
    let (mut e, c) = rbase();
    e.tx.output[1].value = Amount::Explicit(restv(&e) - 1);
    e.tx.output[0].value = Amount::Explicit(e.tx.output[0].value.explicit().unwrap() + 1);
    refuse("release: the operator takes one atom more", run(&source, &b, &e, &rr(c)));
    let (mut e, c) = rbase();
    e.tx.output[1].value = Amount::Explicit(restv(&e) + 1);
    e.tx.output[0].value = Amount::Explicit(e.tx.output[0].value.explicit().unwrap() - 1);
    refuse("release: the rest one atom more", run(&source, &b, &e, &rr(c)));
    for (name, spk) in [
        ("the old state", b.spk(cmr)),
        ("one bit missing", b.left(341).spk(cmr)),
        ("another slot's bit", b.left(341).left(343).spk(cmr)),
        ("a bit more", b.left_all(&[341, 342, 343]).spk(cmr)),
        ("another ROOT", {
            let mut o = other_batch.left_all(&[341, 342]);
            o.operator = b.operator;
            o.spk(cmr)
        }),
        ("another OPERATOR", {
            let mut o = b.left_all(&[341, 342]);
            o.operator = xonly(&keypair("another operator"));
            o.spk(cmr)
        }),
        ("another program", b.left_all(&[341, 342]).spk(h("another program"))),
    ] {
        let (mut e, c) = rbase();
        e.tx.output[1].script_pubkey = Script::from(spk);
        refuse(&format!("release: the rest under {name}"), run(&source, &b, &e, &rr(c)));
    }
    let (mut e, c) = rbase();
    e.tx.output[1].nonce = Nonce::Explicit([7; 32]);
    refuse("release: the rest with a nonce", run(&source, &b, &e, &rr(c)));
    let (mut e, c) = rbase();
    e.tx.output.remove(1);
    refuse("release: no rest", run(&source, &b, &e, &rr(c)));
    for (name, annex) in [("a 2-byte annex", vec![0x50, 0x00]), ("a 1,000-byte annex", [vec![0x50], vec![0xaa; 999]].concat())] {
        let (mut e, c) = rbase();
        e.annex = Some(annex);
        refuse(&format!("release: {name}"), run(&source, &b, &e, &rr(c)));
    }
    // A coin holding a state with another operator key.
    let mut other_op = b.clone();
    other_op.operator = xonly(&keypair("another operator"));
    let (e, c) = rbase();
    refuse("release: a data leaf the coin does not hold", run(&source, &other_op, &e, &rr(c)));
}

#[test]
fn every_spend_prunes_to_the_constants_of_paths_json() {
    let source = source();
    let cmr = cmr_of(&source);
    let s = keypair("the operator");
    let asset = h("the batch asset");
    let first = full("one", &s);
    let owner = |j: usize| keypair(&format!("one {j}"));
    let mut got: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
    let mut check = |name: &str, prog: Vec<u8>, what: &str| {
        let want = got.entry(name.to_string()).or_insert_with(|| prog.clone());
        assert_eq!(hex(want), hex(&prog), "{what}: the {name} program differs");
    };
    for &j in &[0usize, 1, 3, 1022, 1023] {
        for k in [0u32, 1, 3] {
            for by_operator in [false, true] {
                let mut c = exit_claim(&first, j, if by_operator { s } else { owner(j) });
                c.by_operator = by_operator;
                let r = run(&source, &first, &exit(&first, cmr, &asset, j, k, first.total()), &Action::Exit(c)).unwrap();
                check("exit", r.program, &format!("slot {j}, k={k}, operator {by_operator}"));
            }
        }
    }
    for (seed, j) in [("lone", 0usize), ("lone", 1023)] {
        let lone = batch(seed, &[j], &s);
        for k in [0u32, 2] {
            let r = run(&source, &lone, &exit(&lone, cmr, &asset, j, k, lone.total()), &Action::Exit(exit_claim(&lone, j, keypair(&format!("{seed} {j}"))))).unwrap();
            check("exit_last", r.program, &format!("the last leaf, slot {j}, k={k}"));
        }
    }
    // Every count of slots, at the corners, across words and in one word,
    // with a rest and as the last of the batch.
    let mut sets: Vec<Vec<usize>> = (1..=PLACES).map(|n| (0..n).map(|i| (i * 73 + 1) % 1024).collect::<Vec<_>>()).collect();
    for js in sets.iter_mut() {
        js.sort();
    }
    sets.push(vec![1023]);
    sets.push(vec![0, 1, 63, 64, 341, 700, 1022, 1023]);
    sets.push((100..100 + PLACES).collect());
    sets.push((1024 - PLACES..1024).collect());
    for js in &sets {
        let ks: &[u32] = if js.len() == 1 || js.len() == PLACES { &[0, 1, 3] } else { &[0] };
        for &k in ks {
            let rounds = rounds_of(js);
            let e = release(&first, cmr, &asset, js, k, first.total(), &rounds);
            let c = release_claim(&first, js, &owner, &m_at_for(k, rounds), s);
            let r = run(&source, &first, &e, &Action::Release(c)).unwrap();
            check(&format!("release_{}", js.len()), r.program, &format!("slots {js:?}, k={k}"));
        }
        let mine = batch("one", js, &s);
        let rounds = rounds_of(js);
        let e = release(&mine, cmr, &asset, js, 0, mine.total(), &rounds);
        let c = release_claim(&mine, js, &owner, &m_at_for(0, rounds), s);
        let r = run(&source, &mine, &e, &Action::Release(c)).unwrap();
        check(&format!("release_{}_last", js.len()), r.program, &format!("the last slots {js:?}"));
    }
    let paths: serde_json::Map<String, Value> = got
        .iter()
        .map(|(k, p)| (k.clone(), json!({"program": hex(p), "program_bytes": p.len()})))
        .collect();
    let want = json!({"cmr": hex(&cmr), "places": PLACES, "paths": paths});
    if std::env::var("WRITE_PATHS").is_ok() {
        std::fs::write(format!("{DIR}/paths.json"), serde_json::to_string_pretty(&want).unwrap() + "\n").unwrap();
    }
    let have: Value = serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/paths.json")).unwrap()).unwrap();
    assert_eq!(have, want, "paths.json differs from what the program prunes to");
}

/// The program with more places than 8: for each, a release of one slot and of
/// every place, the program, witness, cost, budget and cells. A place count
/// fits when both fit the node's budget and cells with no annex.
#[test]
#[ignore]
fn places_that_fit() {
    let s = keypair("the operator");
    let asset = h("the batch asset");
    let b = full("one", &s);
    let owner = |j: usize| keypair(&format!("one {j}"));
    for n in [1usize, 8, 14, 15, 16] {
        let src = source_with_places(n);
        let cmr = cmr_of(&src);
        for count in [1usize, n] {
            let js: Vec<usize> = (0..count).map(|i| 3 + 15 * i).collect();
            for last in [false, true] {
                let b = if last { batch("one", &js, &s) } else { b.clone() };
                let rounds = rounds_of(&js);
                let e = release(&b, cmr, &asset, &js, 0, b.total(), &rounds);
                let mut c = release_claim(&b, &js, &owner, &m_at_for(0, rounds), s);
                c.size = n;
                let form = if last { "the last" } else { "a rest" };
                match run(&src, &b, &e, &Action::Release(c)) {
                    Ok(r) => println!(
                        "places {n:>2}, slots {count:>2}, {form:>8}: program {:>5} B, witness {:>6} B, cost {:>8} mWU, budget {:>7} WU, cells {:>8}",
                        r.program.len(), r.witness.len(), r.cost, r.budget, r.cells
                    ),
                    Err(err) => println!("places {n:>2}, slots {count:>2}, {form:>8}: REFUSED {err}"),
                }
            }
        }
    }
}

