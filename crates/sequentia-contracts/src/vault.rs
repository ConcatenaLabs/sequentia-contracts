//! The Pignus vault, version 2 (`templates/pignus_vault`): the rule its
//! liquidation path enforces, written out so that a wallet, a liquidator, the
//! explorer or the registry can show a vault's health and check a liquidation
//! without running the program. `templates/pignus_vault/rules.json` holds the
//! golden vectors every implementation reproduces, and harness test `l1` runs
//! each liquidation vector through the program itself.
//!
//! Prices are `price / 10^precision` debt atoms per collateral atom, ratios
//! are in basis points, and every comparison is of products of three 64-bit
//! numbers, made at 192 bits as the program makes them.

/// The largest precision the program takes: 10^18 is the largest power of ten
/// below 2^63.
pub const MAX_PRECISION: u8 = 18;

/// A 192-bit number, most significant limb first; arrays compare as numbers.
type W = [u64; 3];

fn mul3(a: u64, b: u64, c: u64) -> W {
    let ab = (a as u128) * (b as u128);
    let (h, l) = ((ab >> 64) as u64, ab as u64);
    let lc = (l as u128) * (c as u128);
    let hc = (h as u128) * (c as u128) + (lc >> 64);
    [(hc >> 64) as u64, hc as u64, lc as u64]
}

fn add(a: W, b: W) -> W {
    let (s0, c0) = a[2].overflowing_add(b[2]);
    let (s1a, c1a) = a[1].overflowing_add(b[1]);
    let (s1, c1b) = s1a.overflowing_add(c0 as u64);
    let s2 = a[0]
        .checked_add(b[0])
        .and_then(|s| s.checked_add((c1a || c1b) as u64))
        .expect("the sums here stay below 2^192");
    [s2, s1, s0]
}

fn sub(a: W, b: W) -> W {
    let (d0, b0) = a[2].overflowing_sub(b[2]);
    let (d1a, b1a) = a[1].overflowing_sub(b[1]);
    let (d1, b1b) = d1a.overflowing_sub(b0 as u64);
    let d2 = a[0] - b[0] - (b1a || b1b) as u64;
    [d2, d1, d0]
}

/// floor(n / d), saturated to 64 bits.
fn div_sat(n: W, d: u128) -> u64 {
    let mut q: W = [0; 3];
    let mut r: u128 = 0;
    for bit in 0..192 {
        let limb = bit / 64;
        let shift = 63 - (bit % 64);
        r = (r << 1) | ((n[limb] >> shift) & 1) as u128;
        if r >= d {
            r -= d;
            q[limb] |= 1 << shift;
        }
    }
    if q[0] != 0 || q[1] != 0 {
        u64::MAX
    } else {
        q[2]
    }
}

fn pow10(precision: u8) -> Result<u64, &'static str> {
    if precision > MAX_PRECISION {
        return Err("precision above 18");
    }
    Ok(10u64.pow(precision as u32))
}

/// Whether a vault is healthy at `price`: collateral * price * 10,000 >=
/// LIQ_BP * debt * 10^precision.
pub fn healthy(
    collateral: u64,
    debt: u64,
    price: u64,
    precision: u8,
    liq_bp: u32,
) -> Result<bool, &'static str> {
    let u = pow10(precision)?;
    Ok(mul3(collateral, price, 10_000) >= mul3(debt, u, liq_bp as u64))
}

/// The most collateral a liquidation that repays `repaid` may keep: the
/// largest s with s * price * 10,000 <= repaid * BONUS_BP * 10^precision,
/// saturated to 64 bits (no coin holds more).
pub fn max_seizure(
    repaid: u64,
    price: u64,
    precision: u8,
    bonus_bp: u32,
) -> Result<u64, &'static str> {
    let u = pow10(precision)?;
    if price == 0 {
        return Err("price out of range");
    }
    Ok(div_sat(
        mul3(repaid, bonus_bp as u64, u),
        price as u128 * 10_000,
    ))
}

/// The most a liquidation before maturity may repay: the largest r <= debt
/// such that repaying r - 1, at the most the liquidator may seize for it,
/// leaves the vault below TARGET_BP. 0 when no r is allowed.
pub fn max_repay(
    collateral: u64,
    debt: u64,
    price: u64,
    precision: u8,
    target_bp: u32,
    bonus_bp: u32,
) -> Result<u64, &'static str> {
    let u = pow10(precision)?;
    let value = mul3(collateral, price, 10_000);
    let owed = mul3(target_bp as u64, debt, u);
    if debt == 0 || owed <= value {
        return Ok(0);
    }
    if target_bp <= bonus_bp {
        return Ok(debt);
    }
    let gap = sub(owed, value);
    let step = u as u128 * (target_bp - bonus_bp) as u128;
    // ceil(gap / step) = floor((gap - 1) / step) + 1
    let q = div_sat(sub(gap, [0, 0, 1]), step);
    Ok(debt.min(q.saturating_add(1)))
}

/// A liquidation the program allows: what it repays and seizes, and the
/// vault's next state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Liquidation {
    pub repaid: u64,
    pub seized: u64,
    pub closes: bool,
    pub debt_after: u64,
    pub last_time_after: u32,
}

/// The vault's terms that rule a liquidation.
#[derive(Debug, Clone, Copy)]
pub struct Ratios {
    pub precision: u8,
    pub liq_bp: u32,
    pub target_bp: u32,
    pub bonus_bp: u32,
}

/// A liquidation as `templates/pignus_vault` rules it, checked in the
/// program's order. `paid` is what output 2k+1 pays the lender; `kept` is the
/// successor's collateral when `paid` is below the debt, else what output 2k
/// returns to the borrower. The error names the first check that refuses.
#[allow(clippy::too_many_arguments)]
pub fn liquidation(
    collateral: u64,
    debt: u64,
    last_time: u32,
    time: u32,
    price: u64,
    t: Ratios,
    paid: u64,
    kept: u64,
    matured: bool,
) -> Result<Liquidation, &'static str> {
    if time <= last_time {
        return Err("attestation not newer than the vault's last");
    }
    let u = pow10(t.precision)?;
    if paid == 0 {
        return Err("nothing paid to the lender");
    }
    let full = paid >= debt;
    let r = if full { debt } else { paid };
    let value = mul3(collateral, price, 10_000);
    if !matured {
        if value >= mul3(debt, u, t.liq_bp as u64) {
            return Err("the vault is healthy at this price");
        }
        let r1 = r - 1;
        let lhs = add(value, mul3(r1, u, t.target_bp as u64));
        let rhs = add(
            mul3(debt, u, t.target_bp as u64),
            mul3(r1, u, t.bonus_bp as u64),
        );
        if lhs >= rhs {
            return Err("repays beyond the target");
        }
    }
    if kept > collateral {
        return Err("keeps more than the collateral");
    }
    let seized = collateral - kept;
    if mul3(seized, price, 10_000) > mul3(r, t.bonus_bp as u64, u) {
        return Err("seizes more than the price allows");
    }
    if !full && mul3(debt - r, t.liq_bp as u64, u) > mul3(kept, price, 10_000) {
        return Err("leaves the vault unhealthy");
    }
    Ok(Liquidation {
        repaid: r,
        seized,
        closes: full,
        debt_after: if full { 0 } else { debt - r },
        last_time_after: time,
    })
}
