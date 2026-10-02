package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		var d Descriptor
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
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
