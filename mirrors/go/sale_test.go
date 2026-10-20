package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type saleEntryJSON struct {
	Key    string `json:"key"`
	Cap    string `json:"cap"`
	Bought string `json:"bought"`
}

func saleEntries(t *testing.T, xs []saleEntryJSON) []CappedSaleEntry {
	var out []CappedSaleEntry
	for _, x := range xs {
		var e CappedSaleEntry
		k, err := hex.DecodeString(x.Key)
		if err != nil || len(k) != 32 {
			t.Fatalf("bad key %q", x.Key)
		}
		copy(e.Key[:], k)
		if e.Cap, err = strconv.ParseUint(x.Cap, 10, 64); err != nil {
			t.Fatal(err)
		}
		if e.Bought, err = strconv.ParseUint(x.Bought, 10, 64); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestCappedSaleVectors(t *testing.T) {
	var v struct {
		Depth int `json:"depth"`
		Trees []struct {
			Name    string          `json:"name"`
			Entries []saleEntryJSON `json:"entries"`
			Root    string          `json:"root"`
			Proofs  []struct {
				Index int    `json:"index"`
				Leaf  string `json:"leaf"`
				Proof []struct {
					Sibling       string `json:"sibling"`
					SiblingIsLeft bool   `json:"sibling_is_left"`
				} `json:"proof"`
			} `json:"proofs"`
		} `json:"trees"`
		Payments []struct {
			Amount, Num, Den, Payment string
		} `json:"payments"`
		Refusals []struct {
			Name    string          `json:"name"`
			Entries []saleEntryJSON `json:"entries"`
			Reason  string          `json:"reason"`
		} `json:"refusals"`
		PaymentRefusals []struct {
			Amount, Num, Den, Reason string
		} `json:"payment_refusals"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "templates", "capped_sale", "allocations.json")), &v); err != nil {
		t.Fatal(err)
	}
	if v.Depth != CappedSaleDepth || len(v.Trees) == 0 || len(v.Payments) == 0 || len(v.Refusals) == 0 {
		t.Fatal("no vectors, or another depth")
	}
	for _, tr := range v.Trees {
		e := saleEntries(t, tr.Entries)
		root, err := CappedSaleRoot(e)
		if err != nil || hex.EncodeToString(root[:]) != tr.Root {
			t.Fatalf("%s: root %x, %v", tr.Name, root, err)
		}
		for _, p := range tr.Proofs {
			leaf, _ := CappedSaleLeaf(e[p.Index])
			if hex.EncodeToString(leaf[:]) != p.Leaf {
				t.Fatalf("%s: leaf %d", tr.Name, p.Index)
			}
			got, err := CappedSaleProof(e, p.Index)
			if err != nil || len(got) != len(p.Proof) {
				t.Fatalf("%s: proof %d: %v", tr.Name, p.Index, err)
			}
			for i, s := range got {
				if hex.EncodeToString(s.Sibling[:]) != p.Proof[i].Sibling || s.SiblingIsLeft != p.Proof[i].SiblingIsLeft {
					t.Fatalf("%s: proof %d level %d", tr.Name, p.Index, i)
				}
			}
		}
	}
	u := func(s string) uint64 {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, p := range v.Payments {
		got, err := CappedSalePayment(u(p.Amount), u(p.Num), u(p.Den))
		if err != nil || got.String() != p.Payment {
			t.Fatalf("payment %v: %v %v", p, got, err)
		}
	}
	for _, r := range v.Refusals {
		if _, err := CappedSaleRoot(saleEntries(t, r.Entries)); err == nil || !strings.Contains(err.Error(), r.Reason) {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
	for _, r := range v.PaymentRefusals {
		if _, err := CappedSalePayment(u(r.Amount), u(r.Num), u(r.Den)); err == nil || !strings.Contains(err.Error(), r.Reason) {
			t.Fatalf("payment refusal: %v", err)
		}
	}
}
