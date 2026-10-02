package sequentiaaddress

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// NUMSKey is BIP341's point with no known discrete logarithm: an output whose
// internal key it is has no key path.
const NUMSKey = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

// integerLimit is 2^53: every number in a descriptor is an integer below it,
// the range in which every JSON reader reads the same value.
var integerLimit = new(big.Int).Lsh(big.NewInt(1), 53)

// The shape of a version 1 descriptor: every field and its type. A key ending
// in "?" is optional. Any other field is refused.
var templateShape = map[string]any{
	"name": "str", "version": "int", "summary": "str", "layout": "str",
	"internal_key": "str", "key_path?": "str",
	"program": map[string]any{
		"source": "str", "source_sha256": "str", "cmr": "str",
		"compiler": map[string]any{"name": "str", "version": "str"},
		"witness":  []any{map[string]any{"name": "str", "type": "str", "source": "str"}},
	},
	"params": []any{map[string]any{"name": "str", "type": "str", "role": "str", "label": "str"}},
	"paths":  []any{map[string]any{"name": "str", "who": "str", "effect": "str"}},
}

var descriptorShape = map[string]any{
	"descriptor": "int", "template": templateShape, "template_hash": "str",
	"chains":    []any{map[string]any{"name": "str", "genesis": "str|null", "bech32_hrp": "str"}},
	"measured?": "any",
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
		for k, e := range x {
			if err := checkNumbers(e, at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkShape(v any, shape any, at string) error {
	switch s := shape.(type) {
	case string:
		switch s {
		case "any":
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
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
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

// checkTemplate refuses a template whose shape is not version 1's, that
// holds a number other than an integer in [0, 2^53), whose key path is not
// declared, or whose hash is not templateHash.
func checkTemplate(raw []byte, templateHash string) error {
	v, err := decodeNumbers(raw)
	if err != nil {
		return err
	}
	if err := checkNumbers(v, "template"); err != nil {
		return err
	}
	if err := checkShape(v, templateShape, "template"); err != nil {
		return err
	}
	t := v.(map[string]any)
	if t["layout"] != "fixed-root" {
		return fmt.Errorf("layout %v is not fixed-root", t["layout"])
	}
	keyPath, declared := t["key_path"]
	if t["internal_key"] == NUMSKey {
		if declared {
			return errors.New("key_path is declared, but the internal key is the NUMS key")
		}
	} else {
		if !declared {
			return errors.New("the internal key is not the NUMS key and the template declares no key path")
		}
		found := false
		for _, p := range t["paths"].([]any) {
			if p.(map[string]any)["name"] == keyPath {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("key_path %v is not one of the template's paths", keyPath)
		}
	}
	for _, p := range t["params"].([]any) {
		param := p.(map[string]any)
		if _, ok := widths[param["type"].(string)]; !ok {
			return fmt.Errorf("parameter %v: type %v is not allowed", param["name"], param["type"])
		}
	}
	h, err := TemplateHash(raw)
	if err != nil {
		return err
	}
	if h != templateHash {
		return errors.New("template_hash does not match the template")
	}
	return nil
}

// ParseDescriptor reads a descriptor file, refusing an unknown field, a
// number other than an integer in [0, 2^53), and an undeclared key path.
func ParseDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	v, err := decodeNumbers(raw)
	if err != nil {
		return d, err
	}
	if err := checkNumbers(v, "descriptor"); err != nil {
		return d, err
	}
	if err := checkShape(v, descriptorShape, "descriptor"); err != nil {
		return d, err
	}
	if n := v.(map[string]any)["descriptor"].(json.Number); n != "1" {
		return d, fmt.Errorf("descriptor version %s is not 1", n)
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	return d, checkTemplate(d.Template, d.TemplateHash)
}

// unhex reads lowercase hex of exactly width bytes.
func unhex(s string, width int) ([]byte, error) {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("not lowercase hex: %q", s)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not lowercase hex: %q", s)
	}
	if len(b) != width {
		return nil, fmt.Errorf("%d bytes where %d are needed", len(b), width)
	}
	return b, nil
}
