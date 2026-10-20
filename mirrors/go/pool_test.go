package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPoolSplitVectors(t *testing.T) {
	var v struct {
		Entries []struct {
			Name string `json:"name"`
			Rows []struct {
				Script    string `json:"script"`
				Numerator uint32 `json:"numerator"`
			} `json:"rows"`
			Table string `json:"table"`
		} `json:"entries"`
		Payouts []struct {
			Name       string   `json:"name"`
			Numerators []uint32 `json:"numerators"`
			Denom      uint32   `json:"denom"`
			Cap        uint16   `json:"withhold_cap_bp"`
			Collected  string   `json:"collected"`
			Withheld   string   `json:"withheld"`
			Outputs    []string `json:"outputs"`
			Refused    string   `json:"refused"`
		} `json:"payouts"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "templates", "pool_split", "tables.json")), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) == 0 || len(v.Payouts) == 0 {
		t.Fatal("no vectors")
	}
	for _, e := range v.Entries {
		var rows []PoolRow
		for _, r := range e.Rows {
			s, err := hex.DecodeString(r.Script)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, PoolRow{s, r.Numerator})
		}
		got := PoolSplitTable(rows)
		if hex.EncodeToString(got[:]) != e.Table {
			t.Errorf("%s: table %x, want %s", e.Name, got, e.Table)
		}
	}
	for _, p := range v.Payouts {
		s, _ := strconv.ParseUint(p.Collected, 10, 64)
		w, _ := strconv.ParseUint(p.Withheld, 10, 64)
		out, err := PoolSplitPayouts(p.Numerators, p.Denom, p.Cap, s, w)
		if p.Refused != "" {
			if err == nil || !strings.Contains(err.Error(), p.Refused) {
				t.Errorf("%s: want refusal %q, got %v %v", p.Name, p.Refused, out, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", p.Name, err)
			continue
		}
		var got []string
		for _, x := range out {
			got = append(got, strconv.FormatUint(x, 10))
		}
		if strings.Join(got, ",") != strings.Join(p.Outputs, ",") {
			t.Errorf("%s: %v, want %v", p.Name, got, p.Outputs)
		}
	}
}
