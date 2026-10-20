package sequentiaaddress

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

func mustUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOracleBondVectors(t *testing.T) {
	var v struct {
		Reasons    []string
		BurnScript string `json:"burn_script"`
		Conflict   []struct {
			Name, Bonded, M1, S1, M2, S2 string
			Conflict                     bool
			Reason                       *string
		}
		Digests []struct {
			Name, Genesis, Txid, Key, Digest, Signature string
			Kind                                        byte
			Vout                                        uint32
			Dest                                        *string
		}
		Burn []struct {
			Bond    string
			BurnMin string `json:"burn_min"`
		}
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "templates", "oracle_bond", "rules.json")), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Reasons) != len(OracleBondReasons) {
		t.Fatalf("reasons %v", v.Reasons)
	}
	for i := range v.Reasons {
		if v.Reasons[i] != OracleBondReasons[i] {
			t.Fatalf("reasons %v", v.Reasons)
		}
	}
	if v.BurnScript != hex.EncodeToString(OracleBondBurnScript) {
		t.Fatal("burn script")
	}
	seen := map[string]bool{}
	for _, c := range v.Conflict {
		got := OracleBondConflict(mustUnhex(t, c.Bonded), mustUnhex(t, c.M1), mustUnhex(t, c.S1), mustUnhex(t, c.M2), mustUnhex(t, c.S2))
		want := ""
		if c.Reason != nil {
			want = *c.Reason
		}
		if got != want || (got == "") != c.Conflict {
			t.Errorf("%s: got %q, want %q", c.Name, got, want)
		}
		if got == "" {
			got = "conflict"
		}
		seen[got] = true
	}
	var seenList []string
	for k := range seen {
		seenList = append(seenList, k)
	}
	sort.Strings(seenList)
	wantList := append(append([]string{}, OracleBondReasons...), "conflict")
	sort.Strings(wantList)
	if len(seenList) != len(wantList) {
		t.Fatalf("cases cover %v", seenList)
	}
	for _, d := range v.Digests {
		var dest []byte
		if d.Dest != nil {
			dest = mustUnhex(t, *d.Dest)
		}
		got, err := OracleBondDigest(d.Kind, mustUnhex(t, d.Genesis), mustUnhex(t, d.Txid), d.Vout, dest)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != d.Digest {
			t.Errorf("%s: digest %x", d.Name, got)
		}
		sig := mustUnhex(t, d.Signature)
		if !BIP340Verify(mustUnhex(t, d.Key), got, sig) {
			t.Errorf("%s: signature refused", d.Name)
		}
		sig[63] ^= 1
		if BIP340Verify(mustUnhex(t, d.Key), got, sig) {
			t.Errorf("%s: a flipped signature verified", d.Name)
		}
	}
	for _, b := range v.Burn {
		c, err := strconv.ParseUint(b.Bond, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if strconv.FormatUint(OracleBondBurnMin(c), 10) != b.BurnMin {
			t.Errorf("burn_min(%s)", b.Bond)
		}
	}
}

func TestBIP340AgainstTheAttestationVectors(t *testing.T) {
	var a struct {
		V2 []struct{ Name, Key, Digest, Signature string }
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "vectors", "attestations.json")), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.V2) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range a.V2 {
		if !BIP340Verify(mustUnhex(t, c.Key), mustUnhex(t, c.Digest), mustUnhex(t, c.Signature)) {
			t.Errorf("%s", c.Name)
		}
	}
}
