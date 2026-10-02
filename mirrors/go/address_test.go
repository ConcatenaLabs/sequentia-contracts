package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type vectorFile struct {
	TemplateHash string `json:"template_hash"`
	CMR          string `json:"cmr"`
	Addresses    []struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params"`
		Derived
	} `json:"addresses"`
}

// TestVectors checks the Go mirror against every template's golden vectors.
func TestVectors(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "templates", "*", "descriptor.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseDescriptor(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		h, err := TemplateHash(d.Template)
		if err != nil || h != d.TemplateHash {
			t.Fatalf("%s: template hash %s, want %s (%v)", path, h, d.TemplateHash, err)
		}
		vraw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "vectors.json"))
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(vraw, &v); err != nil {
			t.Fatal(err)
		}
		if v.TemplateHash != d.TemplateHash {
			t.Fatalf("%s: vectors are for template %s", path, v.TemplateHash)
		}
		for _, c := range v.Addresses {
			got, err := Derive(d, c.Params)
			if err != nil {
				t.Fatalf("%s: %s: %v", path, c.Name, err)
			}
			if !reflect.DeepEqual(*got, c.Derived) {
				t.Errorf("%s: %s:\n got %+v\nwant %+v", path, c.Name, *got, c.Derived)
			}
		}
		t.Logf("%s: %d address vectors agree", path, len(v.Addresses))
	}
}

func TestBech32mMatchesBIP350(t *testing.T) {
	program, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
	want := "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"
	if got := SegwitV1Address("bc", program); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

const xOfG = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func oneKey(t *testing.T) []byte {
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "one_key", "descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
	refused(t, resealed(t, func(m map[string]any) { m["program"].(map[string]any)["note"] = "x" }), "unknown field note")
	// Go's decoder matches field names without regard to case; this reader does not.
	refused(t, resealed(t, func(m map[string]any) { m["Layout"] = "fixed-root" }), "unknown field Layout")
}

func TestIntegersOf2Pow53OrMoreAreRefused(t *testing.T) {
	if _, err := ParseDescriptor(resealed(t, func(m map[string]any) { m["version"] = json.Number("9007199254740991") })); err != nil {
		t.Fatal(err)
	}
	refused(t, resealed(t, func(m map[string]any) { m["version"] = json.Number("9007199254740992") }), "2^53")
	text := string(oneKey(t))
	for _, bad := range []string{`"descriptor": 9007199254740993`, `"descriptor": 1.0`, `"descriptor": -1`} {
		refused(t, []byte(strings.Replace(text, `"descriptor": 1`, bad, 1)), "2^53")
	}
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
