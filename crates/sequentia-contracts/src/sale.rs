//! The capped sale (`templates/capped_sale`): the allocation tree a sale's
//! state commits to, the proof a purchase shows, and the least a purchase
//! pays.
//!
//! These are the rule the purchase program enforces, written out so that a
//! launchpad, a wallet or the explorer can build a sale's first state, a
//! buyer's proof and the next state with no compiler.
//! `templates/capped_sale/allocations.json` holds the golden vectors every
//! implementation reproduces.

use secp256k1::hashes::{sha256, Hash};
use std::collections::{BTreeMap, HashSet};

/// The depth of the allocation tree.
pub const DEPTH: usize = 16;

/// One buyer: an x-only key, the most that buyer may buy and what the buyer
/// has bought, in atoms of the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: [u8; 32],
    pub cap: u64,
    pub bought: u64,
}

fn h(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}

/// A buyer's leaf: `SHA256(0x00 || SHA256(key || cap || bought))`, the cap
/// and the amount bought as 8-byte big-endian numbers.
pub fn leaf(e: &Entry) -> Result<[u8; 32], String> {
    if e.bought > e.cap {
        return Err("bought more than the cap".into());
    }
    let mut b = e.key.to_vec();
    b.extend_from_slice(&e.cap.to_be_bytes());
    b.extend_from_slice(&e.bought.to_be_bytes());
    let mut l = vec![0u8];
    l.extend_from_slice(&h(&b));
    Ok(h(&l))
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = vec![1u8];
    b.extend_from_slice(l);
    b.extend_from_slice(r);
    h(&b)
}

type Levels = (Vec<BTreeMap<usize, [u8; 32]>>, Vec<[u8; 32]>);

fn levels(entries: &[Entry]) -> Result<Levels, String> {
    if entries.len() > 1 << DEPTH {
        return Err("an allocation list holds at most 65536 buyers".into());
    }
    let mut seen = HashSet::new();
    for e in entries {
        if !seen.insert(e.key) {
            return Err("a key is on the allocation list twice".into());
        }
    }
    let mut empty = vec![leaf(&Entry {
        key: [0; 32],
        cap: 0,
        bought: 0,
    })?];
    for l in 0..DEPTH {
        empty.push(node(&empty[l], &empty[l]));
    }
    let mut level = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        level.insert(i, leaf(e)?);
    }
    let mut out = vec![level.clone()];
    for e in empty.iter().take(DEPTH) {
        let mut next = BTreeMap::new();
        for &i in level.keys() {
            let p = i >> 1;
            next.entry(p).or_insert_with(|| {
                node(
                    level.get(&(2 * p)).unwrap_or(e),
                    level.get(&(2 * p + 1)).unwrap_or(e),
                )
            });
        }
        level = next;
        out.push(level.clone());
    }
    Ok((out, empty))
}

/// The `ALLOCATIONS` slot: the root of the tree whose leaf `i` is entry `i`
/// of the list, every other leaf the zero key's with a zero cap.
pub fn root(entries: &[Entry]) -> Result<[u8; 32], String> {
    let (lv, empty) = levels(entries)?;
    Ok(*lv[DEPTH].get(&0).unwrap_or(&empty[DEPTH]))
}

/// The proof for entry `index`: one `(sibling, sibling_is_left)` per level,
/// leaf first.
pub fn proof(entries: &[Entry], index: usize) -> Result<Vec<([u8; 32], bool)>, String> {
    let (lv, empty) = levels(entries)?;
    if !lv[0].contains_key(&index) {
        return Err("no buyer at that position".into());
    }
    let mut i = index;
    let mut out = Vec::with_capacity(DEPTH);
    for (l, level) in lv.iter().enumerate().take(DEPTH) {
        out.push((*level.get(&(i ^ 1)).unwrap_or(&empty[l]), i & 1 == 1));
        i >>= 1;
    }
    Ok(out)
}

/// The least a purchase of `amount` pays: `ceil(amount * num / den)`.
pub fn payment(amount: u64, num: u64, den: u64) -> Result<u128, String> {
    if den == 0 {
        return Err("the price's denominator is zero".into());
    }
    let p = u128::from(amount) * u128::from(num);
    Ok(p.div_ceil(u128::from(den)))
}
