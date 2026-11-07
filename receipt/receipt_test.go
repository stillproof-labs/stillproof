package receipt

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const account = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"

type vectors struct {
	Claims []struct {
		FileHex string `json:"file_hex"`
		Signed  string `json:"signed"`
	} `json:"claims"`
	Tree struct {
		Root   string     `json:"root"`
		Proofs [][]string `json:"proofs"`
	} `json:"tree"`
}

type fakeLookup map[string]*Tx

func (f fakeLookup) Transaction(_ context.Context, _, hash string) (*Tx, error) {
	if tx, ok := f[hash]; ok {
		return tx, nil
	}
	return nil, ErrNotFound
}

func fixture(t *testing.T) (file []byte, r Receipt, l fakeLookup) {
	t.Helper()
	b, err := os.ReadFile("../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	file, _ = hex.DecodeString(v.Claims[2].FileHex)
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	r = Receipt{
		Claim: v.Claims[2].Signed, Index: 2, Size: len(v.Claims), Proof: v.Tree.Proofs[2], Root: v.Tree.Root,
		Anchor: Anchor{Network: "testnet", Account: account, Tx: "aa", Ledger: 100, ClosedAt: at},
	}
	root, _ := hash32(v.Tree.Root)
	return file, r, fakeLookup{"aa": {Successful: true, Source: account, MemoHash: &root, Ledger: 100, ClosedAt: at}}
}

func TestVerifyAcceptsTheVectors(t *testing.T) {
	file, r, l := fixture(t)
	v := Verify(context.Background(), file, r, l)
	if !v.OK() {
		t.Fatalf("%s: %s", v.Failed, v.Reason)
	}
	if v.Ledger != 100 || v.Level != "software" || v.Caveat == "" || v.Captured.UnixMilli() != 1762344000123 {
		t.Fatalf("verdict: %+v", v)
	}
}

func TestVerifyNamesTheFirstFailedStep(t *testing.T) {
	cases := map[string]struct {
		edit func(file *[]byte, r *Receipt, l fakeLookup)
		want Step
	}{
		"edited claim":      {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Claim += " " }, StepClaim},
		"other file":        {func(f *[]byte, _ *Receipt, _ fakeLookup) { *f = append(*f, 0) }, StepFile},
		"wrong index":       {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Index = 1 }, StepTree},
		"wrong root":        {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Root = r.Proof[0] }, StepTree},
		"unknown tx":        {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Anchor.Tx = "bb" }, StepAnchor},
		"failed tx":         {func(_ *[]byte, _ *Receipt, l fakeLookup) { l["aa"].Successful = false }, StepAnchor},
		"other source":      {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Anchor.Account = "G" + account[1:] + "X" }, StepAnchor},
		"other memo":        {func(_ *[]byte, _ *Receipt, l fakeLookup) { l["aa"].MemoHash = &[32]byte{} }, StepAnchor},
		"no memo":           {func(_ *[]byte, _ *Receipt, l fakeLookup) { l["aa"].MemoHash = nil }, StepAnchor},
		"ledger mismatch":   {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Anchor.Ledger = 99 }, StepAnchor},
		"unknown version":   {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.V = 2 }, StepClaim},
		"closed_at differs": {func(_ *[]byte, r *Receipt, _ fakeLookup) { r.Anchor.ClosedAt = r.Anchor.ClosedAt.Add(time.Second) }, StepAnchor},
	}
	for name, c := range cases {
		file, r, l := fixture(t)
		c.edit(&file, &r, l)
		if v := Verify(context.Background(), file, r, l); v.Failed != c.want {
			t.Errorf("%s: failed at %q (%s), want %q", name, v.Failed, v.Reason, c.want)
		}
	}
}

func TestHorizonReadsTheMemoHash(t *testing.T) {
	root := [32]byte{1, 2, 3}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transactions/aa" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"successful": true, "source_account": account, "memo_type": "hash",
			"memo": base64.StdEncoding.EncodeToString(root[:]), "ledger": 7, "created_at": "2026-11-05T12:00:00Z",
		})
	}))
	defer srv.Close()
	h := Horizon{URLs: map[string]string{"testnet": srv.URL}}
	tx, err := h.Transaction(context.Background(), "testnet", "aa")
	if err != nil || tx.MemoHash == nil || *tx.MemoHash != root || tx.Ledger != 7 || tx.Source != account {
		t.Fatalf("%+v %v", tx, err)
	}
	if _, err := h.Transaction(context.Background(), "testnet", "bb"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tx: %v", err)
	}
	if _, err := h.Transaction(context.Background(), "mainnet", "aa"); err == nil {
		t.Fatal("unknown network accepted")
	}
}
