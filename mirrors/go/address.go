// Package sequentiaaddress derives the address of a contract descriptor's
// instance with no compiler.
//
// A version 2 descriptor describes a taproot tree of Simplicity leaves
// (version 0xbe), tapscript leaves (0xc4) and hidden data leaves; an
// instance's output is its parameters and slots put in place in that tree,
// then one curve tweak. A version 1 descriptor is the tree
//
//	P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
//
// and is read as that version 2 tree. The package uses only the standard
// library. docs/descriptor.md is the specification.
package sequentiaaddress

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

const (
	leafVersionSimplicity = 0xbe
	leafVersionTapscript  = 0xc4
)

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

// Descriptor is a descriptor file, read and checked by ParseDescriptor.
type Descriptor struct {
	Version      int
	Template     json.RawMessage
	TemplateHash string
	Chains       []Chain
	model        *model
	template     map[string]any
}

// Chain names a chain and its bech32 prefix.
type Chain struct {
	Name      string
	Bech32HRP string
}

// Derived is everything a version 1 instance's output is made of.
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

// LeafVector is one leaf of a derived output: its hash, and the control block
// of a Simplicity or tapscript leaf, the script of a tapscript leaf, or the
// bytes of a data leaf.
type LeafVector struct {
	Hash         string `json:"hash"`
	ControlBlock string `json:"control_block,omitempty"`
	Script       string `json:"script,omitempty"`
	Data         string `json:"data,omitempty"`
}

// TreeDerived is everything an instance's output is made of, for a tree of any shape.
type TreeDerived struct {
	Leaves          map[string]LeafVector `json:"leaves"`
	MerkleRoot      string                `json:"merkle_root"`
	Tweak           string                `json:"tweak"`
	OutputKey       string                `json:"output_key"`
	OutputKeyParity int                   `json:"output_key_parity"`
	ScriptPubKey    string                `json:"script_pubkey"`
	Address         map[string]string     `json:"address"`
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Tagged is BIP340's tagged hash.
func Tagged(tag string, msg []byte) []byte {
	t := sha([]byte(tag))
	return sha(cat(t, t, msg))
}

// CanonicalJSON writes a value with object keys sorted and no whitespace.
// Templates are printable ASCII.
func CanonicalJSON(raw []byte) (string, error) {
	v, err := decodeNumbers(raw)
	if err != nil {
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
	if x.Cmp(fieldP) >= 0 {
		return nil, errors.New("not a point")
	}
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

// ScriptNum is a minimal push of v as a script number.
func ScriptNum(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	if v <= 16 {
		return []byte{byte(0x50 + v)}
	}
	var b []byte
	for x := v; x > 0; x >>= 8 {
		b = append(b, byte(x))
	}
	if b[len(b)-1]&0x80 != 0 {
		b = append(b, 0)
	}
	return append([]byte{byte(len(b))}, b...)
}

func compactSize(n int) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	default:
		b := make([]byte, 5)
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

type scriptLeaf struct {
	name    string
	version byte
	script  []byte
}

type found struct {
	name string
	path [][]byte
}

// DeriveTree computes an instance's output from its parameter and slot values
// (hex, by name): every leaf's hash and control block, script or data, the
// Merkle root, the tweak, the output key and its parity, the scriptPubKey and
// the address on each chain. It reads a descriptor of either version.
func DeriveTree(d Descriptor, params, slots map[string]string) (*TreeDerived, error) {
	m := d.model
	if m == nil {
		return nil, errors.New("read the descriptor with ParseDescriptor")
	}
	if !sameNames(params, m.params) {
		return nil, fmt.Errorf("parameters given %v, the template has %v", keys(params), names(m.params))
	}
	if !sameNames(slots, m.slots) {
		return nil, fmt.Errorf("slots given %v, the template has %v", keys(slots), names(m.slots))
	}
	values := map[string]string{}
	for k, v := range params {
		values[k] = v
	}
	for k, v := range slots {
		values[k] = v
	}
	leaves := map[string]LeafVector{}
	var scripts []scriptLeaf
	var walk func(n *node) ([]byte, []found, error)
	walk = func(n *node) ([]byte, []found, error) {
		if n.kind == "branch" {
			a, la, err := walk(n.a)
			if err != nil {
				return nil, nil, err
			}
			b, lb, err := walk(n.b)
			if err != nil {
				return nil, nil, err
			}
			lo, hi := a, b
			if bytes.Compare(lo, hi) > 0 {
				lo, hi = hi, lo
			}
			h := Tagged("TapBranch/elements", cat(lo, hi))
			var out []found
			for _, f := range la {
				out = append(out, found{f.name, append(append([][]byte{}, f.path...), b)})
			}
			for _, f := range lb {
				out = append(out, found{f.name, append(append([][]byte{}, f.path...), a)})
			}
			return h, out, nil
		}
		switch n.kind {
		case "data":
			var data []byte
			for _, v := range n.values {
				b, err := m.value(values, v)
				if err != nil {
					return nil, nil, err
				}
				data = append(data, b...)
			}
			h := Tagged("TapData", data)
			leaves[n.name] = LeafVector{Hash: hex.EncodeToString(h), Data: hex.EncodeToString(data)}
			return h, nil, nil
		case "simplicity":
			cmr, err := unhex(n.cmr, 32)
			if err != nil {
				return nil, nil, err
			}
			return scriptLeafHash(n.name, leafVersionSimplicity, cmr, leaves, &scripts)
		default:
			var script []byte
			for _, it := range n.items {
				switch it.k {
				case "bytes":
					script = append(script, it.b...)
				case "push":
					b, err := m.value(values, it.p)
					if err != nil {
						return nil, nil, err
					}
					script = append(append(script, byte(len(b))), b...)
				default:
					b, err := m.value(values, it.p)
					if err != nil {
						return nil, nil, err
					}
					script = append(script, ScriptNum(new(big.Int).SetBytes(b).Uint64())...)
				}
			}
			return scriptLeafHash(n.name, leafVersionTapscript, script, leaves, &scripts)
		}
	}
	root, paths, err := walk(m.tree)
	if err != nil {
		return nil, err
	}
	for i := range scripts {
		for j := i + 1; j < len(scripts); j++ {
			if scripts[i].version == scripts[j].version && bytes.Equal(scripts[i].script, scripts[j].script) {
				return nil, fmt.Errorf("leaves %s and %s are one script at one leaf version", scripts[i].name, scripts[j].name)
			}
		}
	}
	internal, err := unhex(m.internalKey, 32)
	if err != nil {
		return nil, err
	}
	tweak := Tagged("TapTweak/elements", cat(internal, root))
	p, err := liftX(new(big.Int).SetBytes(internal))
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(new(big.Int).SetBytes(tweak), orderN)
	q := add(p, mul(k, &point{genX, genY}))
	outputKey := make([]byte, 32)
	q.x.FillBytes(outputKey)
	parity := int(q.y.Bit(0))
	versions := map[string]byte{}
	for _, s := range scripts {
		versions[s.name] = s.version
	}
	for _, f := range paths {
		l := leaves[f.name]
		l.ControlBlock = hex.EncodeToString(cat([]byte{versions[f.name] | byte(parity)}, internal, cat(f.path...)))
		leaves[f.name] = l
	}
	address := map[string]string{}
	for _, c := range d.Chains {
		address[c.Name] = SegwitV1Address(c.Bech32HRP, outputKey)
	}
	return &TreeDerived{
		Leaves:          leaves,
		MerkleRoot:      hex.EncodeToString(root),
		Tweak:           hex.EncodeToString(tweak),
		OutputKey:       hex.EncodeToString(outputKey),
		OutputKeyParity: parity,
		ScriptPubKey:    "5120" + hex.EncodeToString(outputKey),
		Address:         address,
	}, nil
}

func scriptLeafHash(name string, version byte, script []byte, leaves map[string]LeafVector, scripts *[]scriptLeaf) ([]byte, []found, error) {
	h := Tagged("TapLeaf/elements", cat([]byte{version}, compactSize(len(script)), script))
	*scripts = append(*scripts, scriptLeaf{name, version, script})
	l := LeafVector{Hash: hex.EncodeToString(h)}
	if version == leafVersionTapscript {
		l.Script = hex.EncodeToString(script)
	}
	leaves[name] = l
	return h, []found{{name, nil}}, nil
}

// Derive computes a version 1 instance's output from its parameter values
// (hex, by name), in the fields of a version 1 vector.
func Derive(d Descriptor, params map[string]string) (*Derived, error) {
	if d.Version != 1 {
		return nil, fmt.Errorf("descriptor version %d is not 1; use DeriveTree", d.Version)
	}
	x, err := DeriveTree(d, params, map[string]string{})
	if err != nil {
		return nil, err
	}
	var data []byte
	for _, p := range d.model.params {
		b, err := unhex(params[p.name], widths[p.ty])
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %v", p.name, err)
		}
		data = append(data, b...)
	}
	return &Derived{
		ParamBytes:      hex.EncodeToString(data),
		DataLeaf:        x.Leaves[v1DataLeaf].Hash,
		ProgramLeaf:     x.Leaves[v1ProgramLeaf].Hash,
		MerkleRoot:      x.MerkleRoot,
		Tweak:           x.Tweak,
		OutputKey:       x.OutputKey,
		OutputKeyParity: x.OutputKeyParity,
		ScriptPubKey:    x.ScriptPubKey,
		Address:         x.Address,
	}, nil
}

func sameNames(given map[string]string, fields []field) bool {
	if len(given) != len(fields) {
		return false
	}
	for _, f := range fields {
		if _, ok := given[f.name]; !ok {
			return false
		}
	}
	return true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func names(fs []field) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.name)
	}
	return out
}
