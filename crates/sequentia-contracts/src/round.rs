//! The clearing round of `seqdex/round-order` (`templates/seqdex_round_order`).
//!
//! A round publishes its one price in its last output, a null-data output
//! whose scriptPubKey is exactly
//!
//! ```text
//! OP_RETURN OP_PUSHDATA1 80 <BASE 32> <QUOTE 32> <N 8> <D 8>
//! ```
//!
//! meaning `N` atoms of `QUOTE` for every `D` atoms of `BASE`, each number
//! big-endian and each asset id in internal byte order. Every round order in
//! the transaction reads that output, and its clearer signs the transaction:
//! a BIP340 signature over
//!
//! ```text
//! SHA256(T || T || genesis || tx_hash),  T = SHA256("SeqDEX/clearing")
//! ```
//!
//! where `tx_hash` is Simplicity's `jet::tx_hash()` of the transaction. This
//! module computes both, so a clearer signs what the program checks; the
//! program's own jet is the reference, and the crate's tests and the regtest
//! harness hold this code to it.

use crate::elements::confidential::{Asset, Nonce, Value};
use crate::elements::encode::serialize;
use crate::elements::hashes::{sha256, Hash, HashEngine};
use crate::elements::{Transaction, TxOut};

/// The tag of the digest a clearer signs.
pub const CLEARING_TAG: &str = "SeqDEX/clearing";

/// The scriptPubKey of the clearing output for `(base, quote, n, d)`: 83
/// bytes, the standard data-carrier size exactly.
pub fn clearing_script(base: &[u8; 32], quote: &[u8; 32], n: u64, d: u64) -> Vec<u8> {
    let mut s = Vec::with_capacity(83);
    s.extend_from_slice(&[0x6a, 0x4c, 0x50]);
    s.extend_from_slice(base);
    s.extend_from_slice(quote);
    s.extend_from_slice(&n.to_be_bytes());
    s.extend_from_slice(&d.to_be_bytes());
    s
}

/// Reads a clearing output's scriptPubKey: `(base, quote, n, d)`, or `None`
/// for any other script.
pub fn read_clearing_script(s: &[u8]) -> Option<([u8; 32], [u8; 32], u64, u64)> {
    if s.len() != 83 || s[..3] != [0x6a, 0x4c, 0x50] {
        return None;
    }
    let mut base = [0u8; 32];
    let mut quote = [0u8; 32];
    base.copy_from_slice(&s[3..35]);
    quote.copy_from_slice(&s[35..67]);
    let n = u64::from_be_bytes(s[67..75].try_into().ok()?);
    let d = u64::from_be_bytes(s[75..83].try_into().ok()?);
    Some((base, quote, n, d))
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn h(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}

/// The asset, amount or nonce as Simplicity hashes it: a null value is the
/// byte 0x00, any other the consensus encoding (prefix and 32 or 8 bytes),
/// which is the form Simplicity's environment adds.
fn conf_asset(a: &Asset) -> Vec<u8> {
    match a {
        Asset::Null => vec![0],
        other => serialize(other),
    }
}

fn conf_value(v: &Value) -> Vec<u8> {
    match v {
        Value::Null => vec![0],
        other => serialize(other),
    }
}

fn conf_nonce(n: &Nonce) -> Vec<u8> {
    match n {
        Nonce::Null => vec![0],
        other => serialize(other),
    }
}

/// The annex of an input's witness: the last item, when it starts with 0x50
/// and the stack has at least two items (BIP341).
fn annex(stack: &[Vec<u8>]) -> Option<&[u8]> {
    match stack.last() {
        Some(last) if stack.len() >= 2 && last.first() == Some(&0x50) => Some(last),
        _ => None,
    }
}

/// Simplicity's `jet::tx_hash()` of `tx`, spending `utxos` (one per input,
/// in order). Refuses an input that is a peg-in or carries an issuance, which
/// no clearing round holds.
pub fn tx_hash(tx: &Transaction, utxos: &[TxOut]) -> Result<[u8; 32], String> {
    if utxos.len() != tx.input.len() {
        return Err(format!("{} utxos for {} inputs", utxos.len(), tx.input.len()));
    }
    let (mut outpoints, mut sequences, mut annexes) = (Vec::new(), Vec::new(), Vec::new());
    let (mut in_amounts, mut in_scripts) = (Vec::new(), Vec::new());
    let (mut iss_assets, mut iss_tokens, mut iss_proofs, mut iss_entropy) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let empty = h(&[]);
    for (i, (input, utxo)) in tx.input.iter().zip(utxos).enumerate() {
        if input.is_pegin() {
            return Err(format!("input {i} is a peg-in"));
        }
        if input.has_issuance() {
            return Err(format!("input {i} carries an issuance"));
        }
        outpoints.push(0u8);
        outpoints.extend_from_slice(input.previous_output.txid.as_byte_array());
        outpoints.extend_from_slice(&input.previous_output.vout.to_be_bytes());
        sequences.extend_from_slice(&input.sequence.0.to_be_bytes());
        match annex(&input.witness.script_witness) {
            Some(a) => {
                annexes.push(1u8);
                annexes.extend_from_slice(&h(a));
            }
            None => annexes.push(0u8),
        }
        in_amounts.extend(conf_asset(&utxo.asset));
        in_amounts.extend(conf_value(&utxo.value));
        in_scripts.extend_from_slice(&h(utxo.script_pubkey.as_bytes()));
        iss_assets.extend_from_slice(&[0, 0]);
        iss_tokens.extend_from_slice(&[0, 0]);
        iss_proofs.extend_from_slice(&empty);
        iss_proofs.extend_from_slice(&empty);
        iss_entropy.push(0u8);
    }
    let (mut out_amounts, mut out_nonces, mut out_scripts, mut out_ranges, mut out_surj) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for o in &tx.output {
        out_amounts.extend(conf_asset(&o.asset));
        out_amounts.extend(conf_value(&o.value));
        out_nonces.extend(conf_nonce(&o.nonce));
        out_scripts.extend_from_slice(&h(o.script_pubkey.as_bytes()));
        let range = match (&o.value, &o.witness.rangeproof) {
            (Value::Confidential(_), Some(p)) => h(&p.serialize()),
            _ => empty,
        };
        let surj = match (&o.asset, &o.witness.surjection_proof) {
            (Asset::Confidential(_), Some(p)) => h(&p.serialize()),
            _ => empty,
        };
        out_ranges.extend_from_slice(&range);
        out_surj.extend_from_slice(&surj);
    }
    let inputs = digest(&[&h(&outpoints), &h(&sequences), &h(&annexes)]);
    let utxos_hash = digest(&[&h(&in_amounts), &h(&in_scripts)]);
    let issuances = digest(&[&h(&iss_assets), &h(&iss_tokens), &h(&iss_proofs), &h(&iss_entropy)]);
    let outputs = digest(&[&h(&out_amounts), &h(&out_nonces), &h(&out_scripts), &h(&out_ranges)]);
    Ok(digest(&[
        &(tx.version).to_be_bytes(),
        &tx.lock_time.to_consensus_u32().to_be_bytes(),
        &inputs,
        &outputs,
        &issuances,
        &h(&out_surj),
        &utxos_hash,
    ]))
}

/// What a round order's clearer signs: `SHA256(T || T || genesis || tx_hash)`,
/// with the genesis hash in internal byte order (the reverse of the hex an
/// RPC prints).
pub fn clearing_digest(genesis: &[u8; 32], tx: &Transaction, utxos: &[TxOut]) -> Result<[u8; 32], String> {
    let tag = h(CLEARING_TAG.as_bytes());
    Ok(digest(&[&tag, &tag, genesis, &tx_hash(tx, utxos)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_script_round_trips() {
        let s = clearing_script(&[1; 32], &[2; 32], 23, 20);
        assert_eq!(s.len(), 83);
        assert_eq!(read_clearing_script(&s), Some(([1; 32], [2; 32], 23, 20)));
        assert_eq!(read_clearing_script(&s[..82]), None);
        let mut t = s.clone();
        t[2] = 0x4f;
        assert_eq!(read_clearing_script(&t), None);
    }

    #[test]
    fn the_tag_is_the_programs() {
        // seqdex_round_order.simf carries T as a constant.
        assert_eq!(
            crate::hex(&h(CLEARING_TAG.as_bytes())),
            "132ccf14703b118aa833412f9685f82a2dbba0fe721cd5e731e1ff5a244cf756"
        );
    }
}
