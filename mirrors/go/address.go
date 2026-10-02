// Package sequentiaaddress derives the address of a fixed-root contract
// descriptor's instance with no compiler.
//
// A version 1 descriptor's output is
//
//	P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
//
// so an instance's address takes one hash and one curve tweak. The package uses
// only the standard library. docs/descriptor.md is the specification.
package sequentiaaddress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

const leafVersionSimplicity = 0xbe

var widths = map[string]int{"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16, "u256": 32, "Pubkey": 32}

var (
	fieldP  = mustHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	orderN  = mustHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	genX    = mustHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	genY    = mustHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return n
}

// Descriptor is the part of a descriptor file address derivation reads.
type Descriptor struct {
	Template     json.RawMessage `json:"template"`
	TemplateHash string          `json:"template_hash"`
	Chains       []Chain         `json:"chains"`
}

// Chain names a chain and its bech32 prefix.
type Chain struct {
	Name      string `json:"name"`
	Bech32HRP string `json:"bech32_hrp"`
}

type template struct {
	Layout      string `json:"layout"`
	InternalKey string `json:"internal_key"`
	Program     struct {
		CMR string `json:"cmr"`
	} `json:"program"`
	Params []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"params"`
}

// Derived is everything an instance's output is made of.
type Derived struct {
	ParamBytes      string            `json:"param_bytes"`
	DataLeaf        string            `json:"data_leaf"`
	ProgramLeaf     string            `json:"program_leaf"`
	MerkleRoot      string            `json:"merkle_root"`
	Tweak           string            `json:"tweak"`
	OutputKey       string            `json:"output_key"`
	OutputKeyParity int               `json:"output_key_parity"`
	ScriptPubKey    string            `json:"script_pubkey"`
	Address         map[string]string `json:"address"`
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Tagged is BIP340's tagged hash.
func Tagged(tag string, msg []byte) []byte {
	t := sha([]byte(tag))
	return sha(append(append(append([]byte{}, t...), t...), msg...))
}

// CanonicalJSON writes a value with object keys sorted and no whitespace.
// Descriptors are printable ASCII.
func CanonicalJSON(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeScalar(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return writeScalar(buf, x)
	}
	return nil
}

func writeScalar(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1) // Encode appends a newline
	return nil
}

// TemplateHash is SHA-256 of the template's canonical JSON, hex.
func TemplateHash(raw []byte) (string, error) {
	c, err := CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sha([]byte(c))), nil
}

type point struct{ x, y *big.Int }

func modP(a *big.Int) *big.Int { return new(big.Int).Mod(a, fieldP) }

func add(a, b *point) *point {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.x.Cmp(b.x) == 0 && modP(new(big.Int).Add(a.y, b.y)).Sign() == 0 {
		return nil
	}
	var lam *big.Int
	if a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 {
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		den := new(big.Int).ModInverse(modP(new(big.Int).Mul(big.NewInt(2), a.y)), fieldP)
		lam = modP(new(big.Int).Mul(num, den))
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).ModInverse(modP(new(big.Int).Sub(b.x, a.x)), fieldP)
		lam = modP(new(big.Int).Mul(num, den))
	}
	x := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lam, lam), a.x), b.x))
	y := modP(new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(a.x, x)), a.y))
	return &point{x, y}
}

func mul(k *big.Int, pt *point) *point {
	var acc *point
	k = new(big.Int).Set(k)
	for k.Sign() > 0 {
		if k.Bit(0) == 1 {
			acc = add(acc, pt)
		}
		pt = add(pt, pt)
		k.Rsh(k, 1)
	}
	return acc
}

func liftX(x *big.Int) (*point, error) {
	c := modP(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), fieldP), big.NewInt(7)))
	e := new(big.Int).Rsh(new(big.Int).Add(fieldP, big.NewInt(1)), 2)
	y := new(big.Int).Exp(c, e, fieldP)
	if modP(new(big.Int).Mul(y, y)).Cmp(c) != 0 {
		return nil, errors.New("not a point")
	}
	if y.Bit(0) == 1 {
		y = new(big.Int).Sub(fieldP, y)
	}
	return &point{x, y}, nil
}

func polymod(values []int) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// SegwitV1Address encodes a witness version 1 program in bech32m (BIP350).
func SegwitV1Address(hrp string, program []byte) string {
	data := []int{1}
	acc, bits := 0, 0
	for _, b := range program {
		acc = (acc<<8 | int(b)) & 0xffff
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, (acc>>uint(bits))&31)
		}
	}
	if bits > 0 {
		data = append(data, (acc<<uint(5-bits))&31)
	}
	var exp []int
	for _, c := range hrp {
		exp = append(exp, int(c)>>5)
	}
	exp = append(exp, 0)
	for _, c := range hrp {
		exp = append(exp, int(c)&31)
	}
	all := append(append(append([]int{}, exp...), data...), 0, 0, 0, 0, 0, 0)
	pm := polymod(all) ^ 0x2bc830a3
	out := hrp + "1"
	for _, d := range data {
		out += string(charset[d])
	}
	for i := 0; i < 6; i++ {
		out += string(charset[(pm>>uint(5*(5-i)))&31])
	}
	return out
}

// Derive computes an instance's output from its parameter values (hex, by name).
func Derive(d Descriptor, params map[string]string) (*Derived, error) {
	var t template
	if err := json.Unmarshal(d.Template, &t); err != nil {
		return nil, err
	}
	if t.Layout != "fixed-root" {
		return nil, fmt.Errorf("layout %s", t.Layout)
	}
	if len(params) != len(t.Params) {
		return nil, fmt.Errorf("%d parameters given, the template has %d", len(params), len(t.Params))
	}
	var data []byte
	for _, p := range t.Params {
		v, err := hex.DecodeString(params[p.Name])
		if err != nil || len(v) != widths[p.Type] {
			return nil, fmt.Errorf("parameter %s has the wrong width", p.Name)
		}
		data = append(data, v...)
	}
	cmr, err := hex.DecodeString(t.Program.CMR)
	if err != nil {
		return nil, err
	}
	dataLeaf := Tagged("TapData", data)
	programLeaf := Tagged("TapLeaf/elements", append([]byte{leafVersionSimplicity, byte(len(cmr))}, cmr...))
	lo, hi := dataLeaf, programLeaf
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	root := Tagged("TapBranch/elements", append(append([]byte{}, lo...), hi...))
	internal, err := hex.DecodeString(t.InternalKey)
	if err != nil {
		return nil, err
	}
	tweak := Tagged("TapTweak/elements", append(append([]byte{}, internal...), root...))
	p, err := liftX(new(big.Int).SetBytes(internal))
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(new(big.Int).SetBytes(tweak), orderN)
	q := add(p, mul(k, &point{genX, genY}))
	outputKey := make([]byte, 32)
	q.x.FillBytes(outputKey)
	address := map[string]string{}
	for _, c := range d.Chains {
		address[c.Name] = SegwitV1Address(c.Bech32HRP, outputKey)
	}
	return &Derived{
		ParamBytes:      hex.EncodeToString(data),
		DataLeaf:        hex.EncodeToString(dataLeaf),
		ProgramLeaf:     hex.EncodeToString(programLeaf),
		MerkleRoot:      hex.EncodeToString(root),
		Tweak:           hex.EncodeToString(tweak),
		OutputKey:       hex.EncodeToString(outputKey),
		OutputKeyParity: int(q.y.Bit(0)),
		ScriptPubKey:    "5120" + hex.EncodeToString(outputKey),
		Address:         address,
	}, nil
}
