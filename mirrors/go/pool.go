package sequentiaaddress

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// PoolSplitMaxRows is the most rows templates/pool_split takes.
const PoolSplitMaxRows = 63

// PoolRow is one row of a pool split table: a scriptPubKey and its numerator.
type PoolRow struct {
	Script    []byte
	Numerator uint32
}

// PoolSplitTable is the TABLE parameter of templates/pool_split: SHA256 over
// the rows in order, each the SHA256 of its scriptPubKey then its numerator as
// 4 big-endian bytes.
func PoolSplitTable(rows []PoolRow) [32]byte {
	var buf []byte
	for _, r := range rows {
		h := sha256.Sum256(r.Script)
		buf = append(buf, h[:]...)
		buf = binary.BigEndian.AppendUint32(buf, r.Numerator)
	}
	return sha256.Sum256(buf)
}

// PoolSplitPayouts is what a claim pays each row, row 0 first, as both
// templates rule it: of collected, at most capBp / 10,000 is withheld; each
// row from 1 gets floor(net * numerator / denom) of net = collected -
// withheld, and row 0 the rest. It errs for a claim the covenant refuses.
func PoolSplitPayouts(numerators []uint32, denom uint32, capBp uint16, collected, withheld uint64) ([]uint64, error) {
	if denom == 0 {
		return nil, errors.New("denominator or cap out of range")
	}
	s, w := new(big.Int).SetUint64(collected), new(big.Int).SetUint64(withheld)
	lhs := new(big.Int).Mul(w, big.NewInt(10000))
	rhs := new(big.Int).Mul(s, big.NewInt(int64(capBp)))
	if lhs.Cmp(rhs) > 0 {
		return nil, errors.New("withheld over the cap")
	}
	if withheld > collected {
		return nil, errors.New("withheld over what is collected")
	}
	net := new(big.Int).SetUint64(collected - withheld)
	d := big.NewInt(int64(denom))
	out := []uint64{0}
	paid := new(big.Int)
	for _, n := range numerators[1:] {
		sh := new(big.Int).Mul(net, big.NewInt(int64(n)))
		sh.Quo(sh, d)
		paid.Add(paid, sh)
		if paid.Cmp(net) > 0 {
			return nil, errors.New("the rows are owed more than the claim holds")
		}
		out = append(out, sh.Uint64())
	}
	out[0] = new(big.Int).Sub(net, paid).Uint64()
	return out, nil
}
