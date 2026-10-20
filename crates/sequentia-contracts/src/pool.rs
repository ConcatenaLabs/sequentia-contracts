//! The pool split covenant (`templates/pool_split`, `templates/pool_split_tap3`):
//! the share table's hash and the payouts a claim must make.
//!
//! Both are the rule the programs enforce, written out so that a wallet, the
//! explorer or the registry can show a pool's table and check a claim without
//! running a program. `templates/pool_split/tables.json` holds the golden
//! vectors every implementation reproduces.

use secp256k1::hashes::{sha256, Hash, HashEngine};

/// The most rows `templates/pool_split` takes.
pub const MAX_ROWS: usize = 63;

/// The `TABLE` parameter: SHA256 over the rows in order, each the SHA256 of
/// its scriptPubKey then its numerator as 4 big-endian bytes.
pub fn table_hash(rows: &[(Vec<u8>, u32)]) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    for (script, num) in rows {
        e.input(sha256::Hash::hash(script).as_ref());
        e.input(&num.to_be_bytes());
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

/// What a claim pays each row, row 0 first: of `collected`, at most
/// `cap_bp / 10_000` is withheld; each row from 1 gets
/// `floor(net * numerator / denom)` of `net = collected - withheld`, and row 0
/// the rest. An error is a claim the covenant refuses.
pub fn payouts(
    numerators: &[u32],
    denom: u32,
    cap_bp: u16,
    collected: u64,
    withheld: u64,
) -> Result<Vec<u64>, String> {
    if denom == 0 {
        return Err("denominator or cap out of range".into());
    }
    if u128::from(withheld) * 10_000 > u128::from(collected) * u128::from(cap_bp) {
        return Err("withheld over the cap".into());
    }
    let net = collected
        .checked_sub(withheld)
        .ok_or("withheld over what is collected")?;
    let mut out = vec![0u64];
    let mut paid: u128 = 0;
    for &n in numerators.iter().skip(1) {
        let share = u128::from(net) * u128::from(n) / u128::from(denom);
        paid += share;
        if paid > u128::from(net) {
            return Err("the rows are owed more than the claim holds".into());
        }
        out.push(share as u64);
    }
    out[0] = net - paid as u64;
    Ok(out)
}
