package sequentiaaddress

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// CappedSaleDepth is the depth of templates/capped_sale's allocation tree.
const CappedSaleDepth = 16

// CappedSaleEntry is one buyer on a capped sale's allocation list: an x-only
// key, the most that buyer may buy and what the buyer has bought, in atoms of
// the token.
type CappedSaleEntry struct {
	Key    [32]byte
	Cap    uint64
	Bought uint64
}

// CappedSaleProofStep is one level of a proof, leaf first.
type CappedSaleProofStep struct {
	Sibling       [32]byte
	SiblingIsLeft bool
}

// CappedSaleLeaf is a buyer's leaf: SHA256(0x00 || SHA256(key || cap ||
// bought)), the cap and the amount bought as 8-byte big-endian numbers.
func CappedSaleLeaf(e CappedSaleEntry) ([32]byte, error) {
	if e.Bought > e.Cap {
		return [32]byte{}, errors.New("bought more than the cap")
	}
	buf := append([]byte{}, e.Key[:]...)
	buf = binary.BigEndian.AppendUint64(buf, e.Cap)
	buf = binary.BigEndian.AppendUint64(buf, e.Bought)
	data := sha256.Sum256(buf)
	return sha256.Sum256(append([]byte{0}, data[:]...)), nil
}

func saleNode(l, r [32]byte) [32]byte {
	buf := append([]byte{1}, l[:]...)
	return sha256.Sum256(append(buf, r[:]...))
}

func saleLevels(entries []CappedSaleEntry) ([]map[int][32]byte, [][32]byte, error) {
	if len(entries) > 1<<CappedSaleDepth {
		return nil, nil, errors.New("an allocation list holds at most 65536 buyers")
	}
	seen := map[[32]byte]bool{}
	for _, e := range entries {
		if seen[e.Key] {
			return nil, nil, errors.New("a key is on the allocation list twice")
		}
		seen[e.Key] = true
	}
	zero, _ := CappedSaleLeaf(CappedSaleEntry{})
	empty := [][32]byte{zero}
	for l := 0; l < CappedSaleDepth; l++ {
		empty = append(empty, saleNode(empty[l], empty[l]))
	}
	level := map[int][32]byte{}
	for i, e := range entries {
		h, err := CappedSaleLeaf(e)
		if err != nil {
			return nil, nil, err
		}
		level[i] = h
	}
	levels := []map[int][32]byte{level}
	for l := 0; l < CappedSaleDepth; l++ {
		next := map[int][32]byte{}
		get := func(i int) [32]byte {
			if h, ok := level[i]; ok {
				return h
			}
			return empty[l]
		}
		for i := range level {
			p := i >> 1
			if _, ok := next[p]; !ok {
				next[p] = saleNode(get(2*p), get(2*p+1))
			}
		}
		level = next
		levels = append(levels, level)
	}
	return levels, empty, nil
}

// CappedSaleRoot is the ALLOCATIONS slot: the root of the 16-level tree whose
// leaf i is entry i of the list, every other leaf the zero key's with a zero cap.
func CappedSaleRoot(entries []CappedSaleEntry) ([32]byte, error) {
	levels, empty, err := saleLevels(entries)
	if err != nil {
		return [32]byte{}, err
	}
	if h, ok := levels[CappedSaleDepth][0]; ok {
		return h, nil
	}
	return empty[CappedSaleDepth], nil
}

// CappedSaleProof is the proof the purchase program folds for entry index.
func CappedSaleProof(entries []CappedSaleEntry, index int) ([]CappedSaleProofStep, error) {
	levels, empty, err := saleLevels(entries)
	if err != nil {
		return nil, err
	}
	if _, ok := levels[0][index]; !ok {
		return nil, errors.New("no buyer at that position")
	}
	out := make([]CappedSaleProofStep, 0, CappedSaleDepth)
	i := index
	for l := 0; l < CappedSaleDepth; l++ {
		s, ok := levels[l][i^1]
		if !ok {
			s = empty[l]
		}
		out = append(out, CappedSaleProofStep{Sibling: s, SiblingIsLeft: i&1 == 1})
		i >>= 1
	}
	return out, nil
}

// CappedSalePayment is the least a purchase of amount pays the treasury:
// ceil(amount * num / den).
func CappedSalePayment(amount, num, den uint64) (*big.Int, error) {
	if den == 0 {
		return nil, errors.New("the price's denominator is zero")
	}
	p := new(big.Int).Mul(new(big.Int).SetUint64(amount), new(big.Int).SetUint64(num))
	d := new(big.Int).SetUint64(den)
	p.Add(p, new(big.Int).Sub(d, big.NewInt(1)))
	return p.Quo(p, d), nil
}
