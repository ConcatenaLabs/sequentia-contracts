package sequentiaaddress

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
)

func u64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPignusVaultVectors(t *testing.T) {
	var v struct {
		Healthy []struct {
			Name, Collateral, Debt, Price string
			Precision                     uint8
			LiqBp                         uint32 `json:"liq_bp"`
			Healthy                       bool
		}
		MaxSeizure []struct {
			Name, Repaid, Price string
			Precision           uint8
			BonusBp             uint32 `json:"bonus_bp"`
			MaxSeizure          string `json:"max_seizure"`
		} `json:"max_seizure"`
		MaxRepay []struct {
			Name, Collateral, Debt, Price string
			Precision                     uint8
			TargetBp                      uint32 `json:"target_bp"`
			BonusBp                       uint32 `json:"bonus_bp"`
			MaxRepay                      string `json:"max_repay"`
		} `json:"max_repay"`
		Liquidation []struct {
			Name, Collateral, Debt, Price, Paid, Kept string
			LastTime                                  uint32 `json:"last_time"`
			Time                                      uint32
			Precision                                 uint8
			LiqBp                                     uint32 `json:"liq_bp"`
			TargetBp                                  uint32 `json:"target_bp"`
			BonusBp                                   uint32 `json:"bonus_bp"`
			Matured                                   bool
			Refused                                   string
			Result                                    *struct {
				Repaid, Seized string
				Closes         bool
				DebtAfter      string `json:"debt_after"`
				LastTimeAfter  uint32 `json:"last_time_after"`
			}
		}
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "templates", "pignus_vault", "rules.json")), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Healthy) == 0 || len(v.MaxSeizure) == 0 || len(v.MaxRepay) == 0 || len(v.Liquidation) == 0 {
		t.Fatal("no vectors")
	}
	for _, e := range v.Healthy {
		got, err := PignusVaultHealthy(u64(t, e.Collateral), u64(t, e.Debt), u64(t, e.Price), e.Precision, e.LiqBp)
		if err != nil || got != e.Healthy {
			t.Errorf("%s: %v %v", e.Name, got, err)
		}
	}
	for _, e := range v.MaxSeizure {
		got, err := PignusVaultMaxSeizure(u64(t, e.Repaid), u64(t, e.Price), e.Precision, e.BonusBp)
		if err != nil || strconv.FormatUint(got, 10) != e.MaxSeizure {
			t.Errorf("%s: %v %v, want %s", e.Name, got, err, e.MaxSeizure)
		}
	}
	for _, e := range v.MaxRepay {
		got, err := PignusVaultMaxRepay(u64(t, e.Collateral), u64(t, e.Debt), u64(t, e.Price), e.Precision, e.TargetBp, e.BonusBp)
		if err != nil || strconv.FormatUint(got, 10) != e.MaxRepay {
			t.Errorf("%s: %v %v, want %s", e.Name, got, err, e.MaxRepay)
		}
	}
	for _, e := range v.Liquidation {
		got, err := PignusVaultLiquidation(u64(t, e.Collateral), u64(t, e.Debt), e.LastTime, e.Time, u64(t, e.Price),
			PignusRatios{e.Precision, e.LiqBp, e.TargetBp, e.BonusBp}, u64(t, e.Paid), u64(t, e.Kept), e.Matured)
		if e.Refused != "" {
			if err == nil || err.Error() != e.Refused {
				t.Errorf("%s: want refusal %q, got %v %v", e.Name, e.Refused, got, err)
			}
			continue
		}
		r := e.Result
		if err != nil || got.Repaid != u64(t, r.Repaid) || got.Seized != u64(t, r.Seized) || got.Closes != r.Closes ||
			got.DebtAfter != u64(t, r.DebtAfter) || got.LastTimeAfter != r.LastTimeAfter {
			t.Errorf("%s: got %+v %v, want %+v", e.Name, got, err, *r)
		}
	}
}
