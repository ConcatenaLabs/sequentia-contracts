//! Price attestations, format 2: the message a contract rebuilds and the
//! signature it checks.
//!
//! The format is owned by `sequentia-oracle` (`doc/format.md` there). This
//! module is its Rust reader, and `vectors/attestations.json` is a pinned copy
//! of that repository's golden vectors, which the tests reproduce byte for
//! byte. The SimplicityHL side is `helpers/attestation.simf`.
//!
//! ```text
//! message   = version (1) || key (32) || base (32) || quote (32)
//!             || price (8, LE) || precision (1) || time (4, LE) || beacon (32)
//! digest    = SHA256(SHA256(TAG) || SHA256(TAG) || message)
//! signature = BIP340(digest)
//! ```

use secp256k1::hashes::{sha256, Hash, HashEngine};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

/// The format this module reads.
pub const VERSION: u8 = 2;
/// The tag of the tagged hash a format-2 signature is over.
pub const TAG: &str = "Sequentia/oracle/price";
/// The tag that names a unit which is not a Sequentia asset.
pub const UNIT_TAG: &str = "Sequentia/oracle/unit";
/// The length of a format-2 message.
pub const MESSAGE_LEN: usize = 142;
/// The largest precision a message may carry.
pub const MAX_PRECISION: u8 = 18;

/// Why a message or a record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

fn refuse<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(why.into()))
}

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    e.input(msg);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// The id of a unit that is not a Sequentia asset: `"BTC"` (native bitcoin,
/// atom one satoshi) or `"USD"` (atom 1e-8 USD).
pub fn unit_id(name: &str) -> Result<[u8; 32], Refused> {
    match name {
        "BTC" | "USD" => Ok(tagged_hash(UNIT_TAG, name.as_bytes())),
        _ => refuse(format!("{name:?} is not a defined unit")),
    }
}

/// The seven signed fields of a format-2 attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The signer's x-only public key.
    pub key: [u8; 32],
    /// What is priced: an asset id in internal byte order, or a unit id.
    pub base: [u8; 32],
    /// What it is priced in.
    pub quote: [u8; 32],
    /// Quote atoms per base atom, times 10^precision.
    pub price: u64,
    /// The decimal places of `price`.
    pub precision: u8,
    /// When the price was observed, in Unix seconds.
    pub time: u32,
    /// Reserved for freshness through a beacon coin; all zero means none.
    pub beacon: [u8; 32],
}

impl Attestation {
    /// The fields' own rules, independent of any signature.
    pub fn check(&self) -> Result<(), Refused> {
        if self.base == self.quote {
            return refuse("base and quote are the same");
        }
        if self.price == 0 || self.price >= 1 << 63 {
            return refuse(format!("price {} is outside 1..2^63-1", self.price));
        }
        if self.precision > MAX_PRECISION {
            return refuse(format!(
                "precision {} is outside 0..{MAX_PRECISION}",
                self.precision
            ));
        }
        Ok(())
    }

    /// The 142 bytes that are signed (through their tagged hash).
    pub fn message(&self) -> [u8; MESSAGE_LEN] {
        let mut m = [0u8; MESSAGE_LEN];
        m[0] = VERSION;
        m[1..33].copy_from_slice(&self.key);
        m[33..65].copy_from_slice(&self.base);
        m[65..97].copy_from_slice(&self.quote);
        m[97..105].copy_from_slice(&self.price.to_le_bytes());
        m[105] = self.precision;
        m[106..110].copy_from_slice(&self.time.to_le_bytes());
        m[110..142].copy_from_slice(&self.beacon);
        m
    }

    /// Parse a message, refusing any other length, any other version, and
    /// fields outside their ranges.
    pub fn decode(m: &[u8]) -> Result<Self, Refused> {
        if m.len() != MESSAGE_LEN {
            return refuse(format!(
                "a format-2 message is {MESSAGE_LEN} bytes, not {}",
                m.len()
            ));
        }
        if m[0] != VERSION {
            return refuse(format!("message version is {}, not {VERSION}", m[0]));
        }
        let a32 = |r: std::ops::Range<usize>| -> [u8; 32] { m[r].try_into().unwrap() };
        let att = Attestation {
            key: a32(1..33),
            base: a32(33..65),
            quote: a32(65..97),
            price: u64::from_le_bytes(m[97..105].try_into().unwrap()),
            precision: m[105],
            time: u32::from_le_bytes(m[106..110].try_into().unwrap()),
            beacon: a32(110..142),
        };
        att.check()?;
        Ok(att)
    }

    /// The 32 bytes BIP340 signs: the tagged hash of the message.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(TAG, &self.message())
    }

    /// Sign with `aux` as BIP340's auxiliary randomness. The key field must
    /// name this secret's key.
    pub fn sign(&self, secret: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], Refused> {
        self.check()?;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret).map_err(|e| Refused(e.to_string()))?;
        let kp = Keypair::from_secret_key(&secp, &sk);
        if kp.x_only_public_key().0.serialize() != self.key {
            return refuse("the key field names another key than this secret's");
        }
        let msg = Message::from_digest(self.digest());
        Ok(secp.sign_schnorr_with_aux_rand(&msg, &kp, aux).serialize())
    }

    /// The signature is valid for these fields under the key they name, and
    /// that key is `pinned` (the key a contract fixes).
    pub fn verify(&self, pinned: &[u8; 32], signature: &[u8; 64]) -> bool {
        if &self.key != pinned || self.check().is_err() {
            return false;
        }
        let secp = Secp256k1::verification_only();
        let (Ok(pk), Ok(sig)) = (
            XOnlyPublicKey::from_slice(&self.key),
            Signature::from_slice(signature),
        ) else {
            return false;
        };
        secp.verify_schnorr(&sig, &Message::from_digest(self.digest()), &pk)
            .is_ok()
    }
}

/// The x-only public key of a secret, for tests and tools.
pub fn xonly_of(secret: &[u8; 32]) -> Result<[u8; 32], Refused> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).map_err(|e| Refused(e.to_string()))?;
    Ok(Keypair::from_secret_key(&secp, &sk)
        .x_only_public_key()
        .0
        .serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../../vectors/attestations.json");

    fn hex32(v: &Value) -> [u8; 32] {
        hex(v).try_into().unwrap()
    }

    fn hex(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn every_vector_is_reproduced_byte_for_byte() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(v["tag"], TAG);
        assert_eq!(v["message_len"], MESSAGE_LEN as u64);
        assert_eq!(
            to_hex(sha256::Hash::hash(TAG.as_bytes()).as_ref()),
            v["tag_hash"]
        );
        for (u, h) in v["units"].as_object().unwrap() {
            assert_eq!(to_hex(&unit_id(u).unwrap()), *h);
        }
        let cases = v["v2"].as_array().unwrap();
        assert!(cases.len() >= 6);
        for c in cases {
            let signer = c["signer"].as_str().unwrap();
            let secret = hex32(&v["keys"][signer]["secret"]);
            let att = Attestation {
                key: hex32(&c["key"]),
                base: hex32(&c["base"]),
                quote: hex32(&c["quote"]),
                price: c["price"].as_u64().unwrap(),
                precision: c["precision"].as_u64().unwrap() as u8,
                time: c["time"].as_u64().unwrap() as u32,
                beacon: hex32(&c["beacon"]),
            };
            let name = &c["name"];
            assert_eq!(xonly_of(&secret).unwrap(), att.key, "{name}");
            assert_eq!(to_hex(&att.message()), c["message"], "{name}");
            assert_eq!(to_hex(&att.digest()), c["digest"], "{name}");
            assert_eq!(
                Attestation::decode(&hex(&c["message"])).unwrap(),
                att,
                "{name}"
            );
            let sig = att.sign(&secret, &[0u8; 32]).unwrap();
            assert_eq!(to_hex(&sig), c["signature"], "{name}");
            assert!(att.verify(&att.key, &sig), "{name}");
            let other = hex32(&v["keys"][if signer == "A" { "B" } else { "A" }]["key"]);
            assert!(!att.verify(&other, &sig), "{name}");
        }
    }

    #[test]
    fn the_vectors_are_the_pinned_copy() {
        let pin: Value = serde_json::from_str(include_str!("../../../vectors/PIN.json")).unwrap();
        let h = sha256::Hash::hash(VECTORS.as_bytes());
        assert_eq!(
            to_hex(h.as_ref()),
            pin["sha256"],
            "vectors/attestations.json is not the copy PIN.json names"
        );
    }

    #[test]
    fn every_refusal_is_refused_for_its_reason() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for r in v["v2_refusals"].as_array().unwrap() {
            let err = Attestation::decode(&hex(&r["message"])).unwrap_err();
            assert!(
                err.0.contains(r["reason"].as_str().unwrap()),
                "{}: {}",
                r["name"],
                err
            );
        }
    }

    #[test]
    fn every_byte_is_signed() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let c = &v["v2"][4];
        let msg = hex(&c["message"]);
        let sig: [u8; 64] = hex(&c["signature"]).try_into().unwrap();
        let key = XOnlyPublicKey::from_slice(&hex(&c["key"])).unwrap();
        let secp = Secp256k1::verification_only();
        let sig = Signature::from_slice(&sig).unwrap();
        for i in 0..msg.len() {
            let mut m = msg.clone();
            m[i] ^= 1;
            let d = Message::from_digest(tagged_hash(TAG, &m));
            assert!(secp.verify_schnorr(&sig, &d, &key).is_err(), "byte {i}");
        }
    }

    #[test]
    fn a_format_one_signature_is_not_a_format_two_signature() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let (c1, c2) = (&v["v1"][0], &v["v2"][0]);
        let att = Attestation::decode(&hex(&c2["message"])).unwrap();
        let sig1: [u8; 64] = hex(&c1["signature"]).try_into().unwrap();
        assert!(!att.verify(&att.key, &sig1));
    }
}
