package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func descriptorDirs(t *testing.T) []string {
	var dirs []string
	for _, base := range []string{filepath.Join("..", "..", "templates"), filepath.Join("..", "fixtures")} {
		paths, err := filepath.Glob(filepath.Join(base, "*", "descriptor.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			dirs = append(dirs, filepath.Dir(p))
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		t.Fatal("no templates")
	}
	return dirs
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type vectorHead struct {
	Vectors      int    `json:"vectors"`
	TemplateHash string `json:"template_hash"`
	CMR          string `json:"cmr"`
}

type vectorsV1 struct {
	Addresses []struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params"`
		Derived
	} `json:"addresses"`
}

type vectorsV2 struct {
	Addresses []struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params"`
		Slots  map[string]string `json:"slots"`
		TreeDerived
	} `json:"addresses"`
}

// TestVectors checks the Go mirror against every template's and fixture's golden vectors.
func TestVectors(t *testing.T) {
	sawTree := false
	for _, dir := range descriptorDirs(t) {
		d, err := ParseDescriptor(readFile(t, filepath.Join(dir, "descriptor.json")))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		h, err := TemplateHash(d.Template)
		if err != nil || h != d.TemplateHash {
			t.Fatalf("%s: template hash %s, want %s (%v)", dir, h, d.TemplateHash, err)
		}
		vraw := readFile(t, filepath.Join(dir, "vectors.json"))
		var head vectorHead
		if err := json.Unmarshal(vraw, &head); err != nil {
			t.Fatal(err)
		}
		if head.TemplateHash != d.TemplateHash || head.Vectors != d.Version {
			t.Fatalf("%s: vectors %d for template %s", dir, head.Vectors, head.TemplateHash)
		}
		n := 0
		if d.Version == 1 {
			var v vectorsV1
			if err := json.Unmarshal(vraw, &v); err != nil {
				t.Fatal(err)
			}
			for _, c := range v.Addresses {
				got, err := Derive(d, c.Params)
				if err != nil {
					t.Fatalf("%s: %s: %v", dir, c.Name, err)
				}
				if !reflect.DeepEqual(*got, c.Derived) {
					t.Errorf("%s: %s:\n got %+v\nwant %+v", dir, c.Name, *got, c.Derived)
				}
				n++
			}
		} else {
			sawTree = true
			var v vectorsV2
			if err := json.Unmarshal(vraw, &v); err != nil {
				t.Fatal(err)
			}
			for _, c := range v.Addresses {
				got, err := DeriveTree(d, c.Params, c.Slots)
				if err != nil {
					t.Fatalf("%s: %s: %v", dir, c.Name, err)
				}
				if !reflect.DeepEqual(*got, c.TreeDerived) {
					t.Errorf("%s: %s:\n got %+v\nwant %+v", dir, c.Name, *got, c.TreeDerived)
				}
				n++
			}
		}
		t.Logf("%s: %d address vectors agree", dir, n)
	}
	if !sawTree {
		t.Fatal("no version 2 template")
	}
}

func TestBech32mMatchesBIP350(t *testing.T) {
	program, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
	want := "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"
	if got := SegwitV1Address("bc", program); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// A version 1 template is its version 2 tree: the fixture is one_key written
// as version 2, and has its addresses.
func TestVersionOneIsATree(t *testing.T) {
	var a vectorsV1
	var b vectorsV2
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "templates", "one_key", "vectors.json")), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "fixtures", "one_key_as_v2", "vectors.json")), &b); err != nil {
		t.Fatal(err)
	}
	if len(a.Addresses) != len(b.Addresses) {
		t.Fatal("not the same instances")
	}
	for i, x := range a.Addresses {
		y := b.Addresses[i]
		if !reflect.DeepEqual(x.Address, y.Address) || x.DataLeaf != y.Leaves["params"].Hash ||
			x.ProgramLeaf != y.Leaves["program"].Hash || x.ParamBytes != y.Leaves["params"].Data {
			t.Fatalf("%s: the version 2 form differs", x.Name)
		}
	}
}

type refusal struct {
	Name   string            `json:"name"`
	Base   string            `json:"base"`
	Edit   []json.RawMessage `json:"edit"`
	Text   [][2]string       `json:"text"`
	Reseal *bool             `json:"reseal"`
	Derive *struct {
		Params map[string]string `json:"params"`
		Slots  map[string]string `json:"slots"`
	} `json:"derive"`
	Expect string `json:"expect"`
	Accept bool   `json:"accept"`
}

func applyEdit(t *testing.T, doc any, raw json.RawMessage) {
	t.Helper()
	opAny, err := decodeNumbers(raw)
	if err != nil {
		t.Fatal(err)
	}
	op := opAny.(map[string]any)
	at := op["at"].([]any)
	target := doc
	step := func(c any, k any) any {
		switch x := k.(type) {
		case string:
			return c.(map[string]any)[x]
		case json.Number:
			i, _ := x.Int64()
			return c.([]any)[i]
		}
		t.Fatalf("bad path %v", k)
		return nil
	}
	for _, k := range at[:len(at)-1] {
		target = step(target, k)
	}
	last := at[len(at)-1]
	setIn := func(v any) {
		switch x := last.(type) {
		case string:
			target.(map[string]any)[x] = v
		case json.Number:
			i, _ := x.Int64()
			target.([]any)[i] = v
		}
	}
	switch {
	case op["set"] != nil || hasKey(op, "set"):
		setIn(op["set"])
	case hasKey(op, "delete"):
		switch x := last.(type) {
		case string:
			delete(target.(map[string]any), x)
		case json.Number:
			i, _ := x.Int64()
			// Deleting from an array changes its length: rebuild it in its parent.
			arr := target.([]any)
			parent := doc
			for _, k := range at[:len(at)-2] {
				parent = step(parent, k)
			}
			out := append(append([]any{}, arr[:i]...), arr[i+1:]...)
			switch pk := at[len(at)-2].(type) {
			case string:
				parent.(map[string]any)[pk] = out
			case json.Number:
				j, _ := pk.Int64()
				parent.([]any)[j] = out
			}
		}
	case hasKey(op, "append"):
		cur := step(target, last).([]any)
		setIn(append(cur, op["append"]))
	case hasKey(op, "suffix"):
		setIn(step(target, last).(string) + op["suffix"].(string))
	default:
		t.Fatalf("unknown edit %s", raw)
	}
}

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

func refusalText(t *testing.T, c refusal) []byte {
	raw := readFile(t, filepath.Join("..", "..", c.Base, "descriptor.json"))
	if len(c.Text) > 0 {
		text := string(raw)
		for _, r := range c.Text {
			if !strings.Contains(text, r[0]) {
				t.Fatalf("%s: %q is not in the file", c.Name, r[0])
			}
			text = strings.Replace(text, r[0], r[1], 1)
		}
		return []byte(text)
	}
	doc, err := decodeNumbers(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range c.Edit {
		applyEdit(t, doc, op)
	}
	d := doc.(map[string]any)
	if c.Reseal == nil || *c.Reseal {
		traw, err := json.Marshal(d["template"])
		if err != nil {
			t.Fatal(err)
		}
		h, err := TemplateHash(traw)
		if err != nil {
			t.Fatal(err)
		}
		d["template_hash"] = h
	}
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRefusals reads every case of mirrors/fixtures/refusals.json and requires
// each to be refused for its reason.
func TestRefusals(t *testing.T) {
	var doc struct {
		Cases []refusal `json:"cases"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "fixtures", "refusals.json")), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 50 {
		t.Fatalf("%d cases", len(doc.Cases))
	}
	refusals := 0
	for _, c := range doc.Cases {
		raw := refusalText(t, c)
		d, err := ParseDescriptor(raw)
		if c.Accept {
			if err != nil {
				t.Errorf("%s: refused: %v", c.Name, err)
			}
			continue
		}
		refusals++
		if c.Derive != nil {
			if err != nil {
				t.Fatalf("%s: the descriptor is refused: %v", c.Name, err)
			}
			_, err = DeriveTree(d, c.Derive.Params, c.Derive.Slots)
		}
		if err == nil {
			t.Errorf("%s: ACCEPTED", c.Name)
		} else if !strings.Contains(err.Error(), c.Expect) {
			t.Errorf("%s: refused, but not for %q: %v", c.Name, c.Expect, err)
		}
	}
	t.Logf("%d refusals made, each for its reason; %d files read", refusals, len(doc.Cases)-refusals)
}

func unsortedRoot(n *node, leaves map[string]LeafVector) []byte {
	if n.kind == "branch" {
		return Tagged("TapBranch/elements", cat(unsortedRoot(n.a, leaves), unsortedRoot(n.b, leaves)))
	}
	b, _ := hex.DecodeString(leaves[n.name].Hash)
	return b
}

// The vectors refuse a mirror that does not sort a branch, or that drops the
// output key's parity from a control block.
func TestVectorsCatchMistakes(t *testing.T) {
	for _, dir := range descriptorDirs(t) {
		d, err := ParseDescriptor(readFile(t, filepath.Join(dir, "descriptor.json")))
		if err != nil {
			t.Fatal(err)
		}
		if d.Version != 2 {
			continue
		}
		var v vectorsV2
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, "vectors.json")), &v); err != nil {
			t.Fatal(err)
		}
		wrong, odd := 0, 0
		for _, c := range v.Addresses {
			if hex.EncodeToString(unsortedRoot(d.model.tree, c.Leaves)) != c.MerkleRoot {
				wrong++
			}
			if c.OutputKeyParity == 1 {
				odd++
				for _, l := range c.Leaves {
					if b, _ := hex.DecodeString(l.ControlBlock); len(b) > 0 && b[0]&1 == 0 {
						t.Fatalf("%s: %s: a control block without the parity", dir, c.Name)
					}
				}
			}
		}
		if wrong < 2 || odd == 0 {
			t.Fatalf("%s: %d vectors catch an unsorted branch, %d have an odd key", dir, wrong, odd)
		}
	}
}

func TestScriptNumIsMinimal(t *testing.T) {
	for v, want := range map[uint64]string{0: "00", 16: "60", 17: "0111", 0x80: "028000", 0x400002: "03020040"} {
		if got := hex.EncodeToString(ScriptNum(v)); got != want {
			t.Fatalf("%d: %s, want %s", v, got, want)
		}
	}
}

const xOfG = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func oneKey(t *testing.T) []byte {
	return readFile(t, filepath.Join("..", "..", "templates", "one_key", "descriptor.json"))
}

// resealed edits the one-key template and recomputes its hash.
func resealed(t *testing.T, edit func(map[string]any)) []byte {
	v, err := decodeNumbers(oneKey(t))
	if err != nil {
		t.Fatal(err)
	}
	d := v.(map[string]any)
	tmpl := d["template"].(map[string]any)
	edit(tmpl)
	traw, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	h, err := TemplateHash(traw)
	if err != nil {
		t.Fatal(err)
	}
	d["template_hash"] = h
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func refused(t *testing.T, raw []byte, words string) {
	t.Helper()
	_, err := ParseDescriptor(raw)
	if err == nil || !strings.Contains(err.Error(), words) {
		t.Fatalf("want an error containing %q, got %v", words, err)
	}
}

func TestKeyPathMustBeDeclared(t *testing.T) {
	refused(t, resealed(t, func(m map[string]any) { m["internal_key"] = xOfG }), "no key path")
	ok := resealed(t, func(m map[string]any) {
		m["internal_key"] = xOfG
		m["key_path"] = "cooperative"
		m["paths"] = append(m["paths"].([]any), map[string]any{"name": "cooperative",
			"who": "the holder of the internal key", "effect": "Spends the output into any transaction that key signs."})
	})
	d, err := ParseDescriptor(ok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Derive(d, map[string]string{"PK": xOfG}); err != nil {
		t.Fatal(err)
	}
	refused(t, resealed(t, func(m map[string]any) { m["internal_key"] = xOfG; m["key_path"] = "cooperative" }), "paths")
	refused(t, resealed(t, func(m map[string]any) { m["key_path"] = "spend" }), "NUMS")
}

func TestUnknownFieldsAreRefused(t *testing.T) {
	refused(t, resealed(t, func(m map[string]any) { m["expiry"] = json.Number("5") }), "unknown field expiry")
	// Go's decoder matches field names without regard to case; this reader does not.
	refused(t, resealed(t, func(m map[string]any) { m["Layout"] = "fixed-root" }), "unknown field Layout")
}

func TestHexWithTrailingJunkIsRefused(t *testing.T) {
	d, err := ParseDescriptor(oneKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{xOfG + "zz", xOfG + "0", strings.ToUpper(xOfG), xOfG[:62]} {
		if _, err := Derive(d, map[string]string{"PK": bad}); err == nil {
			t.Fatalf("%s was accepted", bad)
		}
	}
}
