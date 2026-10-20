package sequentiaaddress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

// The oracle bond (templates/oracle_bond): the rules its program enforces.
const (
	OraclePriceTag      = "Sequentia/oracle/price"
	OracleBondTag       = "Sequentia/oracle/bond"
	OracleBondNotice    = 1
	OracleBondWithdraw  = 2
	oracleMessageLength = 142
)

// OracleBondBurnScript is the script a slash burns to: OP_RETURN.
var OracleBondBurnScript = []byte{0x6a}

// OracleBondReasons are why a pair of messages is not a slashable conflict,
// in the order the rule checks them: the first that applies is the reason.
var OracleBondReasons = []string{"length", "version", "key", "signature", "pair", "precision", "time", "price"}

// BIP340Verify reports whether sig (64 bytes) is key's (32-byte x-only)
// signature over the 32-byte digest.
func BIP340Verify(key, digest, sig []byte) bool {
	if len(key) != 32 || len(digest) != 32 || len(sig) != 64 {
		return false
	}
	pt, err := liftX(new(big.Int).SetBytes(key))
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Cmp(fieldP) >= 0 || s.Cmp(orderN) >= 0 {
		return false
	}
	e := new(big.Int).SetBytes(Tagged("BIP0340/challenge", cat(sig[:32], key, digest)))
	e.Mod(e, orderN)
	negE := new(big.Int).Mod(new(big.Int).Sub(orderN, e), orderN)
	R := add(mul(s, &point{genX, genY}), mul(negE, pt))
	return R != nil && R.y.Bit(0) == 0 && R.x.Cmp(r) == 0
}

// OracleBondConflict reports whether two signed format-2 messages are a
// conflict the bond of the key bonded is slashed for: "" when they are, else
// the first reason in OracleBondReasons that they are not. Beacons are not
// compared.
func OracleBondConflict(bonded, m1, s1, m2, s2 []byte) string {
	if len(m1) != oracleMessageLength || len(m2) != oracleMessageLength {
		return "length"
	}
	if m1[0] != 2 || m2[0] != 2 {
		return "version"
	}
	if !bytes.Equal(m1[1:33], bonded) || !bytes.Equal(m2[1:33], bonded) {
		return "key"
	}
	if !BIP340Verify(bonded, Tagged(OraclePriceTag, m1), s1) || !BIP340Verify(bonded, Tagged(OraclePriceTag, m2), s2) {
		return "signature"
	}
	if !bytes.Equal(m1[33:97], m2[33:97]) {
		return "pair"
	}
	if m1[105] != m2[105] {
		return "precision"
	}
	if !bytes.Equal(m1[106:110], m2[106:110]) {
		return "time"
	}
	if bytes.Equal(m1[97:105], m2[97:105]) {
		return "price"
	}
	return ""
}

// OracleBondBurnMin is the least a slash burns from a bond coin of c atoms:
// half, rounded up.
func OracleBondBurnMin(c uint64) uint64 { return c - c/2 }

// OracleBondDigest is the digest the oracle key signs to give notice on
// (kind 1, dest nil) or to withdraw (kind 2, dest the SHA256 of the
// destination script) the coin txid:vout; genesis and txid in internal byte
// order.
func OracleBondDigest(kind byte, genesis, txid []byte, vout uint32, dest []byte) ([]byte, error) {
	if (kind != OracleBondNotice && kind != OracleBondWithdraw) || (dest == nil) != (kind == OracleBondNotice) {
		return nil, errors.New("a notice names no destination and a withdrawal one")
	}
	if len(genesis) != 32 || len(txid) != 32 || (dest != nil && len(dest) != 32) {
		return nil, errors.New("genesis, txid and destination are 32 bytes each")
	}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, vout)
	m := cat([]byte{kind}, genesis, txid, v)
	if dest != nil {
		m = cat(m, dest)
	}
	return Tagged(OracleBondTag, m), nil
}
