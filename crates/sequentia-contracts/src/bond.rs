//! The oracle bond (`templates/oracle_bond`): the rules its program enforces,
//! written out so that a watcher, a lending book, the explorer or the registry
//! can tell a slashable pair of attestations, check a notice or a withdrawal
//! signature, and know what a slash burns, without running the program.
//! `templates/oracle_bond/rules.json` holds the golden vectors every
//! implementation reproduces, and harness test `b1` runs the program itself.
//!
//! ```text
//! conflict   two format-2 messages by the bonded key, of one base, quote,
//!            precision and time, at two prices, each under a valid signature
//! burn       at least ceil(c / 2) of a coin of c, to the script OP_RETURN
//! notice     BIP340 over tagged(TAG, 0x01 || genesis || txid || vout)
//! withdraw   BIP340 over tagged(TAG, 0x02 || genesis || txid || vout || dest)
//! ```
//!
//! `TAG` is `Sequentia/oracle/bond`; `txid` is in internal byte order (the
//! reverse of the hex an RPC prints), `vout` four bytes big-endian, `dest` the
//! SHA256 of the destination's scriptPubKey, `genesis` the chain's genesis
//! block hash in internal byte order.

use crate::attestation::{tagged_hash, MESSAGE_LEN, TAG, VERSION};
use secp256k1::schnorr::Signature;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};

/// The tag of every digest the oracle key signs for its bond.
pub const BOND_TAG: &str = "Sequentia/oracle/bond";
/// The kind byte of a notice digest.
pub const NOTICE: u8 = 1;
/// The kind byte of a withdrawal digest.
pub const WITHDRAW: u8 = 2;
/// The script a slash burns to: `OP_RETURN`.
pub const BURN_SCRIPT: [u8; 1] = [0x6a];

/// Why a pair of messages is not a slashable conflict, in the order the rule
/// checks: the first that applies is the reason.
pub const REASONS: [&str; 8] = [
    "length",
    "version",
    "key",
    "signature",
    "pair",
    "precision",
    "time",
    "price",
];

fn bip340(key: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    let secp = Secp256k1::verification_only();
    match (
        XOnlyPublicKey::from_slice(key),
        Signature::from_slice(sig),
    ) {
        (Ok(k), Ok(s)) => secp
            .verify_schnorr(&s, &Message::from_digest(*digest), &k)
            .is_ok(),
        _ => false,
    }
}

/// Whether two signed format-2 messages are a conflict the bond of `bonded`
/// is slashed for: `Ok(())` when they are, else the first reason in
/// `REASONS` that they are not. The beacons are not compared: one observation
/// signed under two beacons at one price is no conflict, two prices are one
/// whatever the beacons.
pub fn conflict(
    bonded: &[u8; 32],
    m1: &[u8],
    s1: &[u8; 64],
    m2: &[u8],
    s2: &[u8; 64],
) -> Result<(), &'static str> {
    if m1.len() != MESSAGE_LEN || m2.len() != MESSAGE_LEN {
        return Err("length");
    }
    if m1[0] != VERSION || m2[0] != VERSION {
        return Err("version");
    }
    if m1[1..33] != bonded[..] || m2[1..33] != bonded[..] {
        return Err("key");
    }
    if !bip340(bonded, &tagged_hash(TAG, m1), s1) || !bip340(bonded, &tagged_hash(TAG, m2), s2) {
        return Err("signature");
    }
    // base 33..65, quote 65..97, price 97..105, precision 105, time 106..110.
    if m1[33..97] != m2[33..97] {
        return Err("pair");
    }
    if m1[105] != m2[105] {
        return Err("precision");
    }
    if m1[106..110] != m2[106..110] {
        return Err("time");
    }
    if m1[97..105] == m2[97..105] {
        return Err("price");
    }
    Ok(())
}

/// The least a slash burns from a coin of `c`: half, rounded up.
pub fn burn_min(c: u64) -> u64 {
    c - c / 2
}

/// The digest the oracle key signs to give notice on, or (with `dest`, the
/// SHA256 of the destination script) to withdraw, the coin at `txid:vout`.
pub fn digest(kind: u8, genesis: &[u8; 32], txid: &[u8; 32], vout: u32, dest: Option<&[u8; 32]>) -> [u8; 32] {
    let mut m = Vec::with_capacity(101);
    m.push(kind);
    m.extend_from_slice(genesis);
    m.extend_from_slice(txid);
    m.extend_from_slice(&vout.to_be_bytes());
    if let Some(d) = dest {
        m.extend_from_slice(d);
    }
    tagged_hash(BOND_TAG, &m)
}

/// Whether `sig` is `key`'s notice on the coin `txid:vout`.
pub fn notice_verify(key: &[u8; 32], genesis: &[u8; 32], txid: &[u8; 32], vout: u32, sig: &[u8; 64]) -> bool {
    bip340(key, &digest(NOTICE, genesis, txid, vout, None), sig)
}

/// Whether `sig` is `key`'s withdrawal of the coin `txid:vout` to `dest`.
pub fn withdraw_verify(
    key: &[u8; 32],
    genesis: &[u8; 32],
    txid: &[u8; 32],
    vout: u32,
    dest: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    bip340(key, &digest(WITHDRAW, genesis, txid, vout, Some(dest)), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{xonly_of, Attestation};
    use secp256k1::hashes::{sha256, Hash};
    use secp256k1::{Keypair, SecretKey};
    use serde_json::{json, Value};

    const RULES: &str = include_str!("../../../templates/oracle_bond/rules.json");
    const VECTORS: &str = include_str!("../../../vectors/attestations.json");

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn h32(v: &Value) -> [u8; 32] {
        unhex(v.as_str().unwrap()).try_into().unwrap()
    }

    fn h64(v: &Value) -> [u8; 64] {
        unhex(v.as_str().unwrap()).try_into().unwrap()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn sign(secret: &[u8; 32], digest: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(secret).unwrap());
        secp.sign_schnorr_with_aux_rand(&Message::from_digest(*digest), &kp, &[0u8; 32])
            .serialize()
    }

    /// The rules file as this crate writes it: every input, and what the rule
    /// says of it. `SEQC_WRITE_RULES=1 cargo test bond` rewrites the file.
    fn generate() -> Value {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let a = h32(&v["keys"]["A"]["secret"]);
        let b = h32(&v["keys"]["B"]["secret"]);
        let (ka, kb) = (xonly_of(&a).unwrap(), xonly_of(&b).unwrap());
        let internal = |disp: &str| -> [u8; 32] {
            let mut x: [u8; 32] = unhex(disp).try_into().unwrap();
            x.reverse();
            x
        };
        let gold = internal(v["assets_display"]["GOLD"].as_str().unwrap());
        let usdx = internal(v["assets_display"]["USDX"].as_str().unwrap());
        let silvr = internal(v["assets_display"]["SILVR"].as_str().unwrap());
        let beacon: [u8; 32] = sha256::Hash::hash(b"a beacon").to_byte_array();
        let att = |key: [u8; 32], quote: [u8; 32], price: u64, precision: u8, time: u32, beacon: [u8; 32]| Attestation {
            key,
            base: gold,
            quote,
            price,
            precision,
            time,
            beacon,
        };
        let t = 1_790_000_000u32;
        let base = att(ka, usdx, 300_000_000, 5, t, [0u8; 32]);
        let signed = |x: &Attestation, secret: &[u8; 32]| (x.message().to_vec(), sign(secret, &x.digest()));
        let one = signed(&base, &a);
        let mut cases: Vec<(String, Vec<u8>, [u8; 64], Vec<u8>, [u8; 64])> = Vec::new();
        let mut case = |name: &str, x: (Vec<u8>, [u8; 64]), y: (Vec<u8>, [u8; 64])| {
            cases.push((name.into(), x.0, x.1, y.0, y.1));
        };
        case("two prices of one pair at one time", one.clone(), signed(&att(ka, usdx, 240_000_000, 5, t, [0u8; 32]), &a));
        case("two prices, each under its own beacon", one.clone(), signed(&att(ka, usdx, 240_000_000, 5, t, beacon), &a));
        case("one atom apart", one.clone(), signed(&att(ka, usdx, 300_000_001, 5, t, [0u8; 32]), &a));
        case("two times", one.clone(), signed(&att(ka, usdx, 240_000_000, 5, t + 1, [0u8; 32]), &a));
        case("the same price twice, under two beacons", one.clone(), signed(&att(ka, usdx, 300_000_000, 5, t, beacon), &a));
        case("another quote", one.clone(), signed(&att(ka, silvr, 240_000_000, 5, t, [0u8; 32]), &a));
        let mut swapped = att(ka, usdx, 240_000_000, 5, t, [0u8; 32]);
        swapped.base = usdx;
        swapped.quote = gold;
        case("the pair reversed", one.clone(), signed(&swapped, &a));
        case("another precision", one.clone(), signed(&att(ka, usdx, 2_400_000_000, 6, t, [0u8; 32]), &a));
        case(
            "both by a key the bond does not stand behind",
            signed(&att(kb, usdx, 300_000_000, 5, t, [0u8; 32]), &b),
            signed(&att(kb, usdx, 240_000_000, 5, t, [0u8; 32]), &b),
        );
        case("one by another key", one.clone(), signed(&att(kb, usdx, 240_000_000, 5, t, [0u8; 32]), &b));
        // A message naming the bonded key, signed by another: not its signature.
        case("the bonded key named, another key's signature", one.clone(), signed(&att(ka, usdx, 240_000_000, 5, t, [0u8; 32]), &b));
        let (mut bad_v, sig_v) = signed(&att(ka, usdx, 240_000_000, 5, t, [0u8; 32]), &a);
        bad_v[0] = 1;
        case("a message of version 1", one.clone(), (bad_v, sig_v));
        let (mut short, sig_s) = signed(&att(ka, usdx, 240_000_000, 5, t, [0u8; 32]), &a);
        short.pop();
        case("a message one byte short", one.clone(), (short, sig_s));

        let conflicts: Vec<Value> = cases
            .iter()
            .map(|(name, m1, s1, m2, s2)| {
                let r = conflict(&ka, m1, s1, m2, s2);
                json!({"name": name, "bonded": to_hex(&ka), "m1": to_hex(m1), "s1": to_hex(s1),
                       "m2": to_hex(m2), "s2": to_hex(s2), "conflict": r.is_ok(),
                       "reason": r.err()})
            })
            .collect();

        let genesis: [u8; 32] = h32(&json!("ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e"));
        let mut genesis_internal = genesis;
        genesis_internal.reverse();
        let txid: [u8; 32] = sha256::Hash::hash(b"a bond coin").to_byte_array();
        let dest: [u8; 32] = sha256::Hash::hash(&[0x51, 0x20, 7u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]).to_byte_array();
        let mut digests = Vec::new();
        for (name, kind, vout, d) in [
            ("notice on output 1", NOTICE, 1u32, None),
            ("notice on output 256", NOTICE, 256u32, None),
            ("withdrawal of output 1", WITHDRAW, 1u32, Some(dest)),
        ] {
            let dg = digest(kind, &genesis_internal, &txid, vout, d.as_ref());
            digests.push(json!({"name": name, "kind": kind, "genesis": to_hex(&genesis_internal),
                                "txid": to_hex(&txid), "vout": vout, "dest": d.map(|x| to_hex(&x)),
                                "key": to_hex(&ka), "digest": to_hex(&dg), "signature": to_hex(&sign(&a, &dg))}));
        }
        let burns: Vec<Value> = [0u64, 1, 2, 3, 100_000_000_001, u64::MAX]
            .iter()
            .map(|c| json!({"bond": c.to_string(), "burn_min": burn_min(*c).to_string()}))
            .collect();
        json!({"rules": 1, "template": "templates/oracle_bond", "tag": BOND_TAG,
               "burn_script": to_hex(&BURN_SCRIPT), "reasons": REASONS,
               "conflict": conflicts, "digests": digests, "burn": burns})
    }

    #[test]
    fn the_rules_file_is_what_this_crate_writes() {
        let want = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
        if std::env::var("SEQC_WRITE_RULES").is_ok() {
            std::fs::write(
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/oracle_bond/rules.json"),
                &want,
            )
            .unwrap();
            return;
        }
        assert_eq!(RULES, want, "templates/oracle_bond/rules.json is stale: SEQC_WRITE_RULES=1 cargo test bond");
    }

    #[test]
    fn every_rule_vector_holds() {
        let r: Value = serde_json::from_str(RULES).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for c in r["conflict"].as_array().unwrap() {
            let got = conflict(
                &h32(&c["bonded"]),
                &unhex(c["m1"].as_str().unwrap()),
                &h64(&c["s1"]),
                &unhex(c["m2"].as_str().unwrap()),
                &h64(&c["s2"]),
            );
            assert_eq!(got.is_ok(), c["conflict"].as_bool().unwrap(), "{}", c["name"]);
            assert_eq!(got.err(), c["reason"].as_str(), "{}", c["name"]);
            seen.insert(c["reason"].as_str().unwrap_or("conflict").to_string());
        }
        // Every reason has a case, and so has a conflict.
        for reason in REASONS.iter().chain(["conflict"].iter()) {
            assert!(seen.contains(*reason), "no case for {reason}");
        }
        for d in r["digests"].as_array().unwrap() {
            let dest = d["dest"].as_str().map(|_| h32(&d["dest"]));
            let got = digest(
                d["kind"].as_u64().unwrap() as u8,
                &h32(&d["genesis"]),
                &h32(&d["txid"]),
                d["vout"].as_u64().unwrap() as u32,
                dest.as_ref(),
            );
            assert_eq!(to_hex(&got), d["digest"], "{}", d["name"]);
            let ok = match dest {
                None => notice_verify(&h32(&d["key"]), &h32(&d["genesis"]), &h32(&d["txid"]),
                                      d["vout"].as_u64().unwrap() as u32, &h64(&d["signature"])),
                Some(x) => withdraw_verify(&h32(&d["key"]), &h32(&d["genesis"]), &h32(&d["txid"]),
                                           d["vout"].as_u64().unwrap() as u32, &x, &h64(&d["signature"])),
            };
            assert!(ok, "{}", d["name"]);
        }
        for b in r["burn"].as_array().unwrap() {
            let c: u64 = b["bond"].as_str().unwrap().parse().unwrap();
            assert_eq!(burn_min(c).to_string(), b["burn_min"].as_str().unwrap());
        }
    }

    #[test]
    fn a_notice_is_neither_a_withdrawal_nor_a_price() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let a = h32(&v["keys"]["A"]["secret"]);
        let ka = xonly_of(&a).unwrap();
        let (g, t) = ([1u8; 32], [2u8; 32]);
        let n = sign(&a, &digest(NOTICE, &g, &t, 0, None));
        assert!(notice_verify(&ka, &g, &t, 0, &n));
        assert!(!notice_verify(&ka, &g, &t, 1, &n), "another output");
        assert!(!notice_verify(&ka, &[3u8; 32], &t, 0, &n), "another chain");
        assert!(!withdraw_verify(&ka, &g, &t, 0, &[0u8; 32], &n), "a notice as a withdrawal");
        let w = sign(&a, &digest(WITHDRAW, &g, &t, 0, Some(&[9u8; 32])));
        assert!(withdraw_verify(&ka, &g, &t, 0, &[9u8; 32], &w));
        assert!(!withdraw_verify(&ka, &g, &t, 0, &[8u8; 32], &w), "another destination");
        assert!(!notice_verify(&ka, &g, &t, 0, &w), "a withdrawal as a notice");
    }
}
