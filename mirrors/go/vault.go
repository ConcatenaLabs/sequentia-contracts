package sequentiaaddress

import (
	"errors"
	"math/big"
)

// PignusMaxPrecision is the largest precision templates/pignus_vault takes:
// 10^18 is the largest power of ten below 2^63.
const PignusMaxPrecision = 18

// PignusRatios are the vault terms that rule a liquidation: the price's
// precision and the threshold, target and bonus in basis points.
type PignusRatios struct {
	Precision uint8
	LiqBp     uint32
	TargetBp  uint32
	BonusBp   uint32
}

// PignusLiquidation is what a liquidation the program allows repays and
// seizes, and the vault's next state.
type PignusLiquidation struct {
	Repaid, Seized, DebtAfter uint64
	Closes                    bool
	LastTimeAfter             uint32
}

func bu(x uint64) *big.Int { return new(big.Int).SetUint64(x) }

func pmul(xs ...*big.Int) *big.Int {
	out := big.NewInt(1)
	for _, x := range xs {
		out.Mul(out, x)
	}
	return out
}

func pignusUnit(precision uint8) (*big.Int, error) {
	if precision > PignusMaxPrecision {
		return nil, errors.New("precision above 18")
	}
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil), nil
}

var bp10k = big.NewInt(10000)

// PignusVaultHealthy is whether a vault is healthy at price (price /
// 10^precision debt atoms per collateral atom): collateral * price * 10,000 >=
// LIQ_BP * debt * 10^precision.
func PignusVaultHealthy(collateral, debt, price uint64, precision uint8, liqBp uint32) (bool, error) {
	u, err := pignusUnit(precision)
	if err != nil {
		return false, err
	}
	return pmul(bu(collateral), bu(price), bp10k).Cmp(pmul(bu(uint64(liqBp)), bu(debt), u)) >= 0, nil
}

// PignusVaultMaxSeizure is the most collateral a liquidation that repays
// repaid may keep, saturated to 64 bits: the largest s with s * price * 10,000
// <= repaid * BONUS_BP * 10^precision.
func PignusVaultMaxSeizure(repaid, price uint64, precision uint8, bonusBp uint32) (uint64, error) {
	u, err := pignusUnit(precision)
	if err != nil {
		return 0, err
	}
	if price == 0 {
		return 0, errors.New("price out of range")
	}
	s := new(big.Int).Quo(pmul(bu(repaid), bu(uint64(bonusBp)), u), pmul(bu(price), bp10k))
	if !s.IsUint64() {
		return ^uint64(0), nil
	}
	return s.Uint64(), nil
}

// PignusVaultMaxRepay is the most a liquidation before maturity may repay: the
// largest r <= debt such that repaying r - 1, at the most the liquidator may
// seize for it, leaves the vault below TARGET_BP. 0 when no r is allowed.
func PignusVaultMaxRepay(collateral, debt, price uint64, precision uint8, targetBp, bonusBp uint32) (uint64, error) {
	u, err := pignusUnit(precision)
	if err != nil {
		return 0, err
	}
	gap := new(big.Int).Sub(pmul(bu(uint64(targetBp)), bu(debt), u), pmul(bu(collateral), bu(price), bp10k))
	if debt == 0 || gap.Sign() <= 0 {
		return 0, nil
	}
	if targetBp <= bonusBp {
		return debt, nil
	}
	step := pmul(u, bu(uint64(targetBp-bonusBp)))
	r := new(big.Int).Add(gap, new(big.Int).Sub(step, big.NewInt(1)))
	r.Quo(r, step)
	if r.Cmp(bu(debt)) < 0 {
		return r.Uint64(), nil
	}
	return debt, nil
}

// PignusVaultLiquidation is a liquidation as templates/pignus_vault rules it,
// checked in the program's order. paid is what output 2k+1 pays the lender;
// kept is the successor's collateral when paid is below the debt, else what
// output 2k returns to the borrower. The error names the first check that
// refuses.
func PignusVaultLiquidation(collateral, debt uint64, lastTime, time uint32, price uint64, t PignusRatios,
	paid, kept uint64, matured bool) (PignusLiquidation, error) {
	var none PignusLiquidation
	if time <= lastTime {
		return none, errors.New("attestation not newer than the vault's last")
	}
	u, err := pignusUnit(t.Precision)
	if err != nil {
		return none, err
	}
	if paid == 0 {
		return none, errors.New("nothing paid to the lender")
	}
	full := paid >= debt
	r := paid
	if full {
		r = debt
	}
	value := pmul(bu(collateral), bu(price), bp10k)
	liq, target, bonus := bu(uint64(t.LiqBp)), bu(uint64(t.TargetBp)), bu(uint64(t.BonusBp))
	if !matured {
		if value.Cmp(pmul(liq, bu(debt), u)) >= 0 {
			return none, errors.New("the vault is healthy at this price")
		}
		r1 := bu(r - 1)
		lhs := new(big.Int).Add(value, pmul(r1, target, u))
		rhs := new(big.Int).Add(pmul(target, bu(debt), u), pmul(r1, bonus, u))
		if lhs.Cmp(rhs) >= 0 {
			return none, errors.New("repays beyond the target")
		}
	}
	if kept > collateral {
		return none, errors.New("keeps more than the collateral")
	}
	seized := collateral - kept
	if pmul(bu(seized), bu(price), bp10k).Cmp(pmul(bu(r), bonus, u)) > 0 {
		return none, errors.New("seizes more than the price allows")
	}
	if !full && pmul(bu(debt-r), liq, u).Cmp(pmul(bu(kept), bu(price), bp10k)) > 0 {
		return none, errors.New("leaves the vault unhealthy")
	}
	out := PignusLiquidation{Repaid: r, Seized: seized, Closes: full, LastTimeAfter: time}
	if !full {
		out.DebtAfter = debt - r
	}
	return out, nil
}
