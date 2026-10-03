package sequentiaaddress

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// NUMSKey is BIP341's point with no known discrete logarithm: an output whose
// internal key it is has no key path.
const NUMSKey = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

const (
	maxTreeDepth  = 128
	maxJSONDepth  = 300
	sequenceBits  = uint32(1<<22) | 0xffff
	v1ProgramLeaf = "program"
	v1DataLeaf    = "params"
)

var roles = []string{"pubkey", "asset", "amount", "script_hash", "height", "time", "hash", "feed", "number", "sequence"}

// integerLimit is 2^53: every number in a descriptor is an integer below it,
// the range in which every JSON reader reads the same value.
var integerLimit = new(big.Int).Lsh(big.NewInt(1), 53)

// A file in the descriptor's own directory: letters, digits, _ and -, then .simf.
var sourceName = regexp.MustCompile(`^[A-Za-z0-9_-]+\.simf$`)

// The shape of each version: every field and its type. A key ending in "?"
// is optional. Any other field is refused. A version 2 tree is checked by
// readNode, not by shape.
var (
	paramShape    = map[string]any{"name": "str", "type": "str", "role": "str", "label": "str"}
	witnessShape  = map[string]any{"name": "str", "type": "str", "source": "str"}
	compilerShape = map[string]any{"name": "str", "version": "str"}
	templateV1    = map[string]any{
		"name": "str", "version": "int", "summary": "str", "layout": "str",
		"internal_key": "str", "key_path?": "str",
		"program": map[string]any{
			"source": "str", "source_sha256": "str", "cmr": "str",
			"compiler": compilerShape, "witness": []any{witnessShape},
		},
		"params": []any{paramShape},
		"paths":  []any{map[string]any{"name": "str", "who": "str", "effect": "str"}},
	}
	templateV2 = map[string]any{
		"name": "str", "version": "int", "summary": "str", "internal_key": "str", "key_path?": "str",
		"params": []any{paramShape}, "slots": []any{paramShape},
		"budget": map[string]any{"per_witness_byte": "int", "offset": "int", "max": "int"},
		"tree":   "tree",
		"paths":  []any{map[string]any{"name": "str", "who": "str", "effect": "str", "leaf?": "str"}},
	}
	simplicityLeafShape = map[string]any{
		"source": "str", "source_sha256": "str", "cmr": "str", "compiler": compilerShape,
		"witness": []any{witnessShape}, "max_cost_wu": "int",
	}
)

func descriptorShape(template map[string]any) map[string]any {
	return map[string]any{
		"descriptor": "int", "template": template, "template_hash": "str",
		"chains":    []any{map[string]any{"name": "str", "genesis": "str|null", "bech32_hrp": "str"}},
		"measured?": "any",
	}
}

func isInt(n json.Number) bool {
	s := string(n)
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	b, ok := new(big.Int).SetString(s, 10)
	return ok && b.Cmp(integerLimit) < 0
}

func checkNumbers(v any, at string) error {
	switch x := v.(type) {
	case json.Number:
		if !isInt(x) {
			return fmt.Errorf("%s: %s is not an integer in [0, 2^53)", at, x)
		}
	case []any:
		for i, e := range x {
			if err := checkNumbers(e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if err := checkNumbers(x[k], at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func checkShape(v any, shape any, at string) error {
	switch s := shape.(type) {
	case string:
		switch s {
		case "any", "tree":
			return nil
		case "int":
			if n, ok := v.(json.Number); !ok || !isInt(n) {
				return fmt.Errorf("%s: %v is not an integer in [0, 2^53)", at, v)
			}
		case "str":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("%s is not a string", at)
			}
		case "str|null":
			if _, ok := v.(string); !ok && v != nil {
				return fmt.Errorf("%s is not a string or null", at)
			}
		}
		return nil
	case []any:
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s is not an array", at)
		}
		for i, e := range arr {
			if err := checkShape(e, s[0], fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", at)
		}
		fields := map[string]string{}
		for k := range s {
			fields[strings.TrimSuffix(k, "?")] = k
		}
		for _, k := range sortedKeys(obj) {
			if _, ok := fields[k]; !ok {
				return fmt.Errorf("%s: unknown field %s", at, k)
			}
		}
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			key := fields[name]
			if e, ok := obj[name]; ok {
				if err := checkShape(e, s[key], at+"."+name); err != nil {
					return err
				}
			} else if !strings.HasSuffix(key, "?") {
				return fmt.Errorf("%s: missing field %s", at, name)
			}
		}
		return nil
	}
	return fmt.Errorf("%s: unknown shape", at)
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func checkASCII(v any, at string) error {
	switch x := v.(type) {
	case string:
		if !printable(x) {
			return fmt.Errorf("%s: a template is printable ASCII", at)
		}
	case []any:
		for i, e := range x {
			if err := checkASCII(e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if !printable(k) {
				return fmt.Errorf("%s: a template is printable ASCII", at)
			}
			if err := checkASCII(x[k], at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkNoRepeats refuses JSON text in which an object names a field twice,
// since readers differ on which of the two they keep, that nests arrays and
// objects deeper than maxJSONDepth, or that has text after the value.
func checkNoRepeats(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if depth+1 > maxJSONDepth {
			return fmt.Errorf("the JSON nests deeper than %d levels", maxJSONDepth)
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if seen[k] {
					return fmt.Errorf("field %s appears twice", k)
				}
				seen[k] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func decodeNumbers(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

type field struct {
	name, ty, role string
}

type witness struct {
	name, ty, source string
}

type item struct {
	k string // "bytes", "push" or "num"
	b []byte
	p string
}

type node struct {
	kind    string // "branch", "simplicity", "tapscript" or "data"
	a, b    *node
	name    string
	cmr     string
	sha     string
	source  string
	witness []witness
	items   []item
	values  []string
}

type pathEntry struct {
	name    string
	leaf    string
	hasLeaf bool
}

type model struct {
	internalKey string
	keyPath     string
	hasKeyPath  bool
	params      []field
	slots       []field
	tree        *node
	paths       []pathEntry
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func fields(v any) []field {
	var out []field
	for _, e := range v.([]any) {
		p := e.(map[string]any)
		out = append(out, field{str(p, "name"), str(p, "type"), str(p, "role")})
	}
	return out
}

func witnesses(v any) []witness {
	var out []witness
	for _, e := range v.([]any) {
		w := e.(map[string]any)
		out = append(out, witness{str(w, "name"), str(w, "type"), str(w, "source")})
	}
	return out
}

func readNode(v any, depth int, at string) (*node, error) {
	if depth > maxTreeDepth {
		return nil, fmt.Errorf("%s: the tree is deeper than %d", at, maxTreeDepth)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an object", at)
	}
	if kids, ok := obj["branch"]; ok {
		for _, k := range sortedKeys(obj) {
			if k != "branch" {
				return nil, fmt.Errorf("%s: unknown field %s", at, k)
			}
		}
		arr, ok := kids.([]any)
		if !ok || len(arr) != 2 {
			return nil, fmt.Errorf("%s.branch is not an array of two nodes", at)
		}
		a, err := readNode(arr[0], depth+1, at+".branch[0]")
		if err != nil {
			return nil, err
		}
		b, err := readNode(arr[1], depth+1, at+".branch[1]")
		if err != nil {
			return nil, err
		}
		return &node{kind: "branch", a: a, b: b}, nil
	}
	kinds := []string{"simplicity", "tapscript", "data"}
	for _, k := range sortedKeys(obj) {
		if k != "leaf" && k != "simplicity" && k != "tapscript" && k != "data" {
			return nil, fmt.Errorf("%s: unknown field %s", at, k)
		}
	}
	nameV, ok := obj["leaf"]
	if !ok {
		return nil, fmt.Errorf("%s: missing field leaf", at)
	}
	name, ok := nameV.(string)
	if !ok {
		return nil, fmt.Errorf("%s.leaf is not a string", at)
	}
	var present []string
	for _, k := range kinds {
		if _, ok := obj[k]; ok {
			present = append(present, k)
		}
	}
	if len(present) != 1 {
		return nil, fmt.Errorf("%s: a leaf has exactly one of simplicity, tapscript and data", at)
	}
	body := obj[present[0]]
	switch present[0] {
	case "simplicity":
		if err := checkShape(body, simplicityLeafShape, at+".simplicity"); err != nil {
			return nil, err
		}
		s := body.(map[string]any)
		return &node{kind: "simplicity", name: name, cmr: str(s, "cmr"), sha: str(s, "source_sha256"),
			source: str(s, "source"), witness: witnesses(s["witness"])}, nil
	case "tapscript":
		arr, ok := body.([]any)
		if !ok {
			return nil, fmt.Errorf("%s.tapscript is not an array", at)
		}
		var items []item
		for i, e := range arr {
			iat := fmt.Sprintf("%s.tapscript[%d]", at, i)
			switch x := e.(type) {
			case string:
				b, err := unhexAny(x)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", iat, err)
				}
				if len(b) == 0 {
					return nil, fmt.Errorf("%s: empty", iat)
				}
				items = append(items, item{k: "bytes", b: b})
			case map[string]any:
				if len(x) != 1 {
					return nil, fmt.Errorf(`%s: an item is hex, {"push": P} or {"num": P}`, iat)
				}
				for k, pv := range x {
					if k != "push" && k != "num" {
						return nil, fmt.Errorf("%s: unknown field %s", iat, k)
					}
					p, ok := pv.(string)
					if !ok {
						return nil, fmt.Errorf("%s.%s is not a string", iat, k)
					}
					items = append(items, item{k: k, p: p})
				}
			default:
				return nil, fmt.Errorf(`%s: an item is hex, {"push": P} or {"num": P}`, iat)
			}
		}
		return &node{kind: "tapscript", name: name, items: items}, nil
	default:
		arr, ok := body.([]any)
		if !ok {
			return nil, fmt.Errorf("%s.data is not an array of names", at)
		}
		var values []string
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%s.data is not an array of names", at)
			}
			values = append(values, s)
		}
		return &node{kind: "data", name: name, values: values}, nil
	}
}

func paths(v any) []pathEntry {
	var out []pathEntry
	for _, e := range v.([]any) {
		p := e.(map[string]any)
		l, has := p["leaf"]
		ls, _ := l.(string)
		out = append(out, pathEntry{name: str(p, "name"), leaf: ls, hasLeaf: has})
	}
	return out
}

// readModel reads the tree a template of either version describes. A
// version 1 template is branch(program, params): its program the leaf
// "program", its parameters in order the data leaf "params", and every path
// but the key path a spend of the program.
func readModel(version int, t map[string]any) (*model, error) {
	kp, has := t["key_path"]
	kps, _ := kp.(string)
	m := &model{internalKey: str(t, "internal_key"), keyPath: kps, hasKeyPath: has, params: fields(t["params"])}
	if version == 1 {
		prog := t["program"].(map[string]any)
		var values []string
		for _, p := range m.params {
			values = append(values, p.name)
		}
		m.tree = &node{kind: "branch",
			a: &node{kind: "simplicity", name: v1ProgramLeaf, cmr: str(prog, "cmr"), sha: str(prog, "source_sha256"),
				source: str(prog, "source"), witness: witnesses(prog["witness"])},
			b: &node{kind: "data", name: v1DataLeaf, values: values}}
		for _, p := range paths(t["paths"]) {
			if !(has && p.name == kps) {
				p.leaf, p.hasLeaf = v1ProgramLeaf, true
			}
			m.paths = append(m.paths, p)
		}
		return m, nil
	}
	m.slots = fields(t["slots"])
	tree, err := readNode(t["tree"], 0, "template.tree")
	if err != nil {
		return nil, err
	}
	m.tree = tree
	m.paths = paths(t["paths"])
	return m, nil
}

func (m *model) field(name string) (*field, bool) {
	for i := range m.params {
		if m.params[i].name == name {
			return &m.params[i], false
		}
	}
	for i := range m.slots {
		if m.slots[i].name == name {
			return &m.slots[i], true
		}
	}
	return nil, false
}

type placed struct {
	n     *node
	depth int
}

func leavesOf(n *node, depth int) []placed {
	if n.kind == "branch" {
		return append(leavesOf(n.a, depth+1), leavesOf(n.b, depth+1)...)
	}
	return []placed{{n, depth}}
}

func badName(s string) bool { return s == "" || !printable(s) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// check applies every rule a reader checks without a compiler.
func (m *model) check() error {
	internal, err := unhex(m.internalKey, 32)
	if err != nil {
		return fmt.Errorf("internal_key: %v", err)
	}
	if _, err := liftX(new(big.Int).SetBytes(internal)); err != nil {
		return fmt.Errorf("internal_key: %v", err)
	}
	if m.internalKey == NUMSKey {
		if m.hasKeyPath {
			return errors.New("key_path is declared, but the internal key is the NUMS key")
		}
	} else {
		if !m.hasKeyPath {
			return errors.New("the internal key is not the NUMS key and the template declares no key path")
		}
		ok := false
		for _, p := range m.paths {
			ok = ok || p.name == m.keyPath
		}
		if !ok {
			return fmt.Errorf("key_path %s is not one of the template's paths", m.keyPath)
		}
	}
	seen := map[string]bool{}
	for _, g := range []struct {
		kind  string
		group []field
	}{{"parameter", m.params}, {"slot", m.slots}} {
		for _, p := range g.group {
			if badName(p.name) {
				return fmt.Errorf("%s name %q is empty or not printable", g.kind, p.name)
			}
			if seen[p.name] {
				return fmt.Errorf("%s %s is named twice", g.kind, p.name)
			}
			seen[p.name] = true
			if _, ok := widths[p.ty]; !ok {
				return fmt.Errorf("%s %s: type %s is not allowed", g.kind, p.name, p.ty)
			}
			if !contains(roles, p.role) {
				return fmt.Errorf("%s %s: role %s is not allowed", g.kind, p.name, p.role)
			}
			if p.role == "pubkey" && p.ty != "Pubkey" {
				return fmt.Errorf("%s %s: a pubkey is of type Pubkey", g.kind, p.name)
			}
			if p.role == "sequence" && p.ty != "u32" {
				return fmt.Errorf("%s %s: a sequence is of type u32", g.kind, p.name)
			}
		}
	}
	leafNames, used, spendable := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, pl := range leavesOf(m.tree, 0) {
		n := pl.n
		if pl.depth > maxTreeDepth {
			return fmt.Errorf("leaf %s is deeper than %d", n.name, maxTreeDepth)
		}
		if badName(n.name) {
			return fmt.Errorf("leaf name %q is empty or not printable", n.name)
		}
		if leafNames[n.name] {
			return fmt.Errorf("leaf %s is named twice", n.name)
		}
		leafNames[n.name] = true
		switch n.kind {
		case "data":
			if len(n.values) == 0 {
				return fmt.Errorf("data leaf %s commits to nothing", n.name)
			}
			for _, v := range n.values {
				if f, _ := m.field(v); f == nil {
					return fmt.Errorf("data leaf %s: %s is no parameter or slot", n.name, v)
				}
				used[v] = true
			}
		case "tapscript":
			spendable[n.name] = true
			if len(n.items) == 0 {
				return fmt.Errorf("tapscript leaf %s is empty", n.name)
			}
			for _, it := range n.items {
				if it.k == "bytes" {
					continue
				}
				f, isSlot := m.field(it.p)
				if f == nil {
					return fmt.Errorf("tapscript leaf %s: %s is no parameter", n.name, it.p)
				}
				if isSlot {
					return fmt.Errorf("tapscript leaf %s: %s is a slot; a script holds parameters only", n.name, it.p)
				}
				if it.k == "push" && widths[f.ty] < 2 {
					return fmt.Errorf("tapscript leaf %s: push %s is one byte; use num", n.name, it.p)
				}
				if it.k == "num" && widths[f.ty] > 8 {
					return fmt.Errorf("tapscript leaf %s: num %s is wider than 8 bytes", n.name, it.p)
				}
				used[it.p] = true
			}
		default:
			spendable[n.name] = true
			wnames := map[string]bool{}
			for _, w := range n.witness {
				if badName(w.name) || wnames[w.name] {
					return fmt.Errorf("leaf %s: witness %q is empty, not printable or named twice", n.name, w.name)
				}
				wnames[w.name] = true
				if err := m.checkWitness(n.name, w); err != nil {
					return err
				}
			}
			if !sourceName.MatchString(n.source) {
				return fmt.Errorf("leaf %s: source %q is not a file name of the form <name>.simf beside the descriptor", n.name, n.source)
			}
			if _, err := unhex(n.cmr, 32); err != nil {
				return fmt.Errorf("leaf %s: cmr: %v", n.name, err)
			}
			if _, err := unhex(n.sha, 32); err != nil {
				return fmt.Errorf("leaf %s: source_sha256: %v", n.name, err)
			}
		}
	}
	for _, p := range append(append([]field{}, m.params...), m.slots...) {
		if !used[p.name] {
			return fmt.Errorf("%s is in no leaf, so it does not change the output", p.name)
		}
	}
	if len(m.paths) == 0 {
		return errors.New("the template has no path")
	}
	pnames, covered := map[string]bool{}, map[string]bool{}
	for _, p := range m.paths {
		if badName(p.name) || pnames[p.name] {
			return fmt.Errorf("path name %q is empty, not printable or used twice", p.name)
		}
		pnames[p.name] = true
		isKey := m.hasKeyPath && m.keyPath == p.name
		if p.hasLeaf && isKey {
			return fmt.Errorf("path %s: the key path spends no leaf", p.name)
		}
		if !p.hasLeaf && !isKey {
			return fmt.Errorf("path %s names no leaf", p.name)
		}
		if p.hasLeaf {
			if !spendable[p.leaf] {
				return fmt.Errorf("path %s: %s is not a Simplicity or tapscript leaf", p.name, p.leaf)
			}
			covered[p.leaf] = true
		}
	}
	var unspent []string
	for l := range spendable {
		if !covered[l] {
			unspent = append(unspent, l)
		}
	}
	sort.Strings(unspent)
	if len(unspent) > 0 {
		return fmt.Errorf("leaf %s is spendable and no path describes it", unspent[0])
	}
	return nil
}

func (m *model) checkWitness(leaf string, w witness) error {
	if w.source == "spender" {
		return nil
	}
	for _, g := range []struct {
		prefix, kind string
		group        []field
	}{{"param:", "parameter", m.params}, {"slot:", "slot", m.slots}} {
		if name, ok := strings.CutPrefix(w.source, g.prefix); ok {
			for _, p := range g.group {
				if p.name == name {
					if p.ty != w.ty {
						return fmt.Errorf("leaf %s: witness %s: type %s is not the %s's %s", leaf, w.name, w.ty, g.kind, p.ty)
					}
					return nil
				}
			}
			return fmt.Errorf("leaf %s: witness %s: %s is no %s", leaf, w.name, name, g.kind)
		}
	}
	if name, ok := strings.CutPrefix(w.source, "signature:sig_all_hash:"); ok {
		for _, p := range m.params {
			if p.name == name {
				if p.ty != "Pubkey" || w.ty != "Signature" {
					return fmt.Errorf("leaf %s: witness %s: a signature is of type Signature, by a Pubkey parameter", leaf, w.name)
				}
				return nil
			}
		}
		return fmt.Errorf("leaf %s: witness %s: %s is no parameter", leaf, w.name, name)
	}
	return fmt.Errorf("leaf %s: witness %s: source %s is not one the specification lists", leaf, w.name, w.source)
}

// value reads a parameter's or slot's value: lowercase hex of exactly its
// type's width, which its role does not rule out.
func (m *model) value(values map[string]string, name string) ([]byte, error) {
	f, _ := m.field(name)
	b, err := unhex(values[name], widths[f.ty])
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	switch f.role {
	case "pubkey":
		if _, err := liftX(new(big.Int).SetBytes(b)); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
	case "sequence":
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if v&^sequenceBits != 0 {
			return nil, fmt.Errorf("%s: sequence %#08x sets a bit outside the type flag and the 16-bit lock", name, v)
		}
	}
	return b, nil
}

// ParseDescriptor reads a descriptor file of version 1 or 2, refusing an
// object that names a field twice, a field its version does not list, a
// number other than an integer in [0, 2^53), text in the template that is not
// printable ASCII, a template hash that does not match, and a tree,
// parameter, slot or path that breaks a rule of the specification.
func ParseDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if err := checkNoRepeats(raw); err != nil {
		return d, err
	}
	v, err := decodeNumbers(raw)
	if err != nil {
		return d, err
	}
	if err := checkNumbers(v, "descriptor"); err != nil {
		return d, err
	}
	top, ok := v.(map[string]any)
	if !ok {
		return d, errors.New("descriptor is not an object")
	}
	n, _ := top["descriptor"].(json.Number)
	var shape map[string]any
	switch n {
	case "1":
		shape, d.Version = templateV1, 1
	case "2":
		shape, d.Version = templateV2, 2
	default:
		return d, fmt.Errorf("descriptor version %v is not 1 or 2", top["descriptor"])
	}
	if err := checkShape(v, descriptorShape(shape), "descriptor"); err != nil {
		return d, err
	}
	t := top["template"].(map[string]any)
	if err := checkASCII(t, "template"); err != nil {
		return d, err
	}
	if d.Version == 1 && t["layout"] != "fixed-root" {
		return d, fmt.Errorf("layout %v is not fixed-root", t["layout"])
	}
	var parts struct {
		Template json.RawMessage `json:"template"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return d, err
	}
	h, err := TemplateHash(parts.Template)
	if err != nil {
		return d, err
	}
	if h != top["template_hash"] {
		return d, errors.New("template_hash does not match the template")
	}
	for _, c := range top["chains"].([]any) {
		cm := c.(map[string]any)
		if g, ok := cm["genesis"].(string); ok {
			if _, err := unhex(g, 32); err != nil {
				return d, fmt.Errorf("chain %s: genesis: %v", str(cm, "name"), err)
			}
		}
		d.Chains = append(d.Chains, Chain{Name: str(cm, "name"), Bech32HRP: str(cm, "bech32_hrp")})
	}
	m, err := readModel(d.Version, t)
	if err != nil {
		return d, err
	}
	if err := m.check(); err != nil {
		return d, err
	}
	d.Template, d.TemplateHash, d.model, d.template = parts.Template, h, m, t
	return d, nil
}

// unhexAny reads lowercase hex of any even length.
func unhexAny(s string) ([]byte, error) {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("not lowercase hex: %q", s)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not lowercase hex: %q", s)
	}
	return b, nil
}

// unhex reads lowercase hex of exactly width bytes.
func unhex(s string, width int) ([]byte, error) {
	b, err := unhexAny(s)
	if err != nil {
		return nil, err
	}
	if len(b) != width {
		return nil, fmt.Errorf("%d bytes where %d are needed", len(b), width)
	}
	return b, nil
}
