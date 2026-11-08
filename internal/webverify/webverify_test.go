package webverify

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stillproof-labs/stillproof/receipt"
)

const account = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"

var closed = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// fixture returns a file and its receipt from the test vectors, and the
// receipt's root.
func fixture(t *testing.T) ([]byte, receipt.Receipt, string) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Claims []struct {
			FileHex string `json:"file_hex"`
			Signed  string `json:"signed"`
		} `json:"claims"`
		Tree struct {
			Root   string     `json:"root"`
			Proofs [][]string `json:"proofs"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	file, _ := hex.DecodeString(v.Claims[2].FileHex)
	r := receipt.Receipt{
		V: 1, Claim: v.Claims[2].Signed, Index: 2, Size: len(v.Claims), Proof: v.Tree.Proofs[2], Root: v.Tree.Root,
		Anchor: receipt.Anchor{Network: "testnet", Account: account, Tx: strings.Repeat("ab", 32), Ledger: 100, ClosedAt: closed},
	}
	return file, r, v.Tree.Root
}

// horizon serves one anchor transaction with memo root.
func horizon(t *testing.T, tx, root string) receipt.Horizon {
	t.Helper()
	m, _ := hex.DecodeString(root)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transactions/"+tx {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"successful": true, "source_account": account, "memo_type": "hash",
			"memo": base64.StdEncoding.EncodeToString(m), "ledger": 100, "created_at": closed.Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	return receipt.Horizon{URLs: map[string]string{"testnet": srv.URL}}
}

// anchor serves SPEC.md §8.4 lookups: status and body for one hash.
func anchor(t *testing.T, sum string, status int, body any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/receipts" || r.URL.Query().Get("sha256") != sum {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexsum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestGivenReceipt(t *testing.T) {
	file, r, root := fixture(t)
	o := Options{Horizon: horizon(t, r.Anchor.Tx, root)}
	res := Verify(context.Background(), file, mustJSON(t, r), o)
	if res.Status != StatusVerified || res.Source != SourceGiven || res.SHA256 != hexsum(file) || len(res.Checks) != 1 {
		t.Fatalf("%+v", res)
	}
	c := res.Checks[0]
	if c.AnchorChecked != CheckedHorizon || c.Ledger != 100 || c.Tx != r.Anchor.Tx || c.Caveat != receipt.Caveat {
		t.Fatalf("%+v", c)
	}
	b := mustJSON(t, res)
	for _, want := range []string{`"anchor_checked":"horizon"`, `"level":"software"`, `"not_after":"2026-11-05T12:00:00Z"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s: %s", want, b)
		}
	}
}

func TestGivenReceiptFails(t *testing.T) {
	file, r, root := fixture(t)
	o := Options{Horizon: horizon(t, r.Anchor.Tx, root)}
	cases := map[string]struct {
		file []byte
		json []byte
		want receipt.Step
	}{
		"other file":    {append(file, 0), mustJSON(t, r), receipt.StepFile},
		"not JSON":      {file, []byte("{"), receipt.StepClaim},
		"unknown field": {file, []byte(strings.Replace(string(mustJSON(t, r)), `"v":1`, `"v":1,"extra":1`, 1)), receipt.StepClaim},
	}
	for name, c := range cases {
		res := Verify(context.Background(), c.file, c.json, o)
		if res.Status != StatusFailed || res.Checks[0].Failed != c.want || res.Checks[0].AnchorChecked != "" {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func TestLookup(t *testing.T) {
	file, r, root := fixture(t)
	sum := hexsum(file)
	other := r
	other.Root = r.Proof[0] // fails at the tree step
	cases := map[string]struct {
		status int
		body   any
		want   string
		checks int
	}{
		"verified":     {200, map[string]any{"receipts": []any{other, r}}, StatusVerified, 2},
		"all fail":     {200, map[string]any{"receipts": []any{other}}, StatusFailed, 1},
		"empty":        {200, map[string]any{"receipts": []any{}}, StatusNone, 0},
		"pending":      {202, map[string]any{"status": "pending"}, StatusPending, 0},
		"unknown":      {404, map[string]any{}, StatusNone, 0},
		"server error": {500, map[string]any{}, StatusError, 0},
	}
	for name, c := range cases {
		o := Options{Anchor: anchor(t, sum, c.status, c.body) + "/", Horizon: horizon(t, r.Anchor.Tx, root)}
		res := Verify(context.Background(), file, nil, o)
		if res.Status != c.want || res.Source != SourceLookup || len(res.Checks) != c.checks {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if res := Verify(context.Background(), file, nil, Options{}); res.Status != StatusError {
		t.Errorf("no anchor URL: %+v", res)
	}
}

func TestEmbedded(t *testing.T) {
	file, r, root := fixture(t)
	photo := append([]byte("APP11"), file...)
	o := Options{
		Horizon: horizon(t, r.Anchor.Tx, root),
		Extract: func(b []byte) (receipt.Receipt, []byte, error) {
			if string(b[:5]) != "APP11" {
				return receipt.Receipt{}, nil, errors.New("no receipt")
			}
			return r, b[5:], nil
		},
	}
	res := Verify(context.Background(), photo, nil, o)
	if res.Status != StatusVerified || res.Source != SourceEmbedded || res.Signed != hexsum(file) || res.SHA256 != hexsum(photo) {
		t.Fatalf("%+v", res)
	}
	// Without an embedded receipt, it falls back to the lookup.
	o.Anchor = anchor(t, hexsum(file), 200, map[string]any{"receipts": []any{r}})
	if res := Verify(context.Background(), file, nil, o); res.Status != StatusVerified || res.Source != SourceLookup {
		t.Fatalf("%+v", res)
	}
}

// claimReport is an Externalize report proving tx in ledger, closing at closed.
func claimReport(tx string, ledger uint32, closed time.Time, succeeded bool) map[string]any {
	return map[string]any{
		"verified": true,
		"ledger":   map[string]any{"sequence": ledger, "hash": strings.Repeat("00", 32), "close_time": closed.Unix(), "signers": []string{}, "orgs": []any{}},
		"claims":   []any{map[string]any{"kind": "transaction", "tx_hash": tx, "succeeded": succeeded}},
	}
}

// realReceipt is a receipt anchored on testnet by stillproof-anchor's
// scripts/testnet-demo.sh, with a validator proof whose bundle has the
// ledger's transaction set, and the photo it is for.
func realReceipt(t *testing.T) ([]byte, receipt.Receipt) {
	t.Helper()
	h, err := os.ReadFile("../../testdata/testnet-photo.hex")
	if err != nil {
		t.Fatal(err)
	}
	file, err := hex.DecodeString(strings.Join(strings.Fields(string(h)), ""))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/testnet-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	return file, r
}

// validators returns a Validators func that answers with rep, or fails with err.
func validators(t *testing.T, rep any, err error) func(context.Context, []byte) ([]byte, error) {
	return func(context.Context, []byte) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return mustJSON(t, rep), nil
	}
}

// noHorizon fails every lookup, so a verdict can't have come from Horizon.
type noHorizon struct{}

func (noHorizon) Transaction(context.Context, string, string) (*receipt.Tx, error) {
	return nil, errors.New("horizon was asked")
}

func TestValidatorProof(t *testing.T) {
	file, r := realReceipt(t)
	a := r.Anchor
	ok := claimReport(a.Tx, a.Ledger, a.ClosedAt, true)
	cases := map[string]struct {
		edit    func(*receipt.Receipt)
		report  any
		err     error
		failed  receipt.Step
		checked string
		note    bool
	}{
		"proven":        {nil, ok, nil, "", CheckedValidators, false},
		"upper-case tx": {nil, claimReport(strings.ToUpper(a.Tx), a.Ledger, a.ClosedAt, true), nil, "", CheckedValidators, false},
		"rejected":      {nil, map[string]any{"verified": false, "error": "bad signature"}, nil, receipt.StepAnchor, "", false},
		"other tx":      {nil, claimReport(strings.Repeat("cd", 32), a.Ledger, a.ClosedAt, true), nil, receipt.StepAnchor, "", false},
		"tx failed":     {nil, claimReport(a.Tx, a.Ledger, a.ClosedAt, false), nil, receipt.StepAnchor, "", false},
		"other ledger":  {nil, claimReport(a.Tx, a.Ledger+1, a.ClosedAt, true), nil, receipt.StepAnchor, "", false},
		"other time":    {nil, claimReport(a.Tx, a.Ledger, a.ClosedAt.Add(time.Second), true), nil, receipt.StepAnchor, "", false},
		"unreadable":    {nil, "nonsense", nil, receipt.StepAnchor, "", false},
		"other source":  {func(r *receipt.Receipt) { r.Anchor.Account = account }, ok, nil, receipt.StepAnchor, "", false},
		"bad account":   {func(r *receipt.Receipt) { r.Anchor.Account = "GNOPE" }, ok, nil, receipt.StepAnchor, "", false},
		"other network": {func(r *receipt.Receipt) { r.Anchor.Network = "mainnet" }, ok, nil, receipt.StepAnchor, "", false},
		"not a bundle":  {func(r *receipt.Receipt) { r.Anchor.Proof = json.RawMessage(`[]`) }, ok, nil, receipt.StepAnchor, "", false},
		// Not checked: step 5 falls back to Horizon, which fails here.
		"unchecked": {nil, nil, errors.New("offline"), receipt.StepAnchor, "", true},
	}
	for name, c := range cases {
		r := r
		if c.edit != nil {
			c.edit(&r)
		}
		o := Options{Horizon: noHorizon{}, Validators: validators(t, c.report, c.err)}
		ch := Verify(context.Background(), file, mustJSON(t, r), o).Checks[0]
		if ch.Failed != c.failed || ch.AnchorChecked != c.checked || (ch.Note != "") != c.note {
			t.Errorf("%s: %+v", name, ch)
		}
		if c.checked == CheckedValidators && (ch.Ledger != a.Ledger || !ch.NotAfter.Equal(a.ClosedAt)) {
			t.Errorf("%s: %+v", name, ch)
		}
	}

	// The memo must be proven too: a transaction set without the anchor
	// transaction fails step 5.
	var b map[string]any
	if err := json.Unmarshal(a.Proof, &b); err != nil {
		t.Fatal(err)
	}
	b["transactions"] = base64.StdEncoding.EncodeToString([]byte("no transactions here"))
	r2 := r
	r2.Anchor.Proof = mustJSON(t, b)
	o := Options{Horizon: noHorizon{}, Validators: validators(t, ok, nil)}
	if ch := Verify(context.Background(), file, mustJSON(t, r2), o).Checks[0]; ch.Failed != receipt.StepAnchor {
		t.Errorf("transaction not in the set: %+v", ch)
	}
}

func TestValidatorProofWithoutATransactionSet(t *testing.T) {
	file, r, root := fixture(t)
	r.Anchor.Proof = json.RawMessage(`{"network":"Test SDF Network ; September 2015"}`)
	a := r.Anchor
	o := Options{Horizon: horizon(t, a.Tx, root), Validators: validators(t, claimReport(a.Tx, a.Ledger, a.ClosedAt, true), nil)}
	if ch := Verify(context.Background(), file, mustJSON(t, r), o).Checks[0]; !ch.OK() || ch.AnchorChecked != CheckedHorizon || ch.Note == "" {
		t.Errorf("ledger proven, source and memo from Horizon: %+v", ch)
	}
	// What the proof does prove must still match.
	o.Validators = validators(t, claimReport(a.Tx, a.Ledger+1, a.ClosedAt, true), nil)
	if ch := Verify(context.Background(), file, mustJSON(t, r), o).Checks[0]; ch.Failed != receipt.StepAnchor {
		t.Errorf("other ledger: %+v", ch)
	}
}

func TestValidatorProofUnchecked(t *testing.T) {
	file, r, root := fixture(t)
	r.Anchor.Proof = json.RawMessage(`{"network":"Test SDF Network ; September 2015"}`)
	for name, v := range map[string]func(context.Context, []byte) ([]byte, error){
		"no checker":     nil,
		"checker failed": validators(t, nil, errors.New("not loaded")),
	} {
		o := Options{Horizon: horizon(t, r.Anchor.Tx, root), Validators: v}
		if ch := Verify(context.Background(), file, mustJSON(t, r), o).Checks[0]; !ch.OK() || ch.AnchorChecked != CheckedHorizon || ch.Note == "" {
			t.Errorf("%s: %+v", name, ch)
		}
	}
}

func TestGivenReceiptForAPhotoWithOneEmbedded(t *testing.T) {
	file, r, root := fixture(t)
	photo := append([]byte("APP11"), file...)
	o := Options{
		Horizon: horizon(t, r.Anchor.Tx, root),
		Extract: func(b []byte) (receipt.Receipt, []byte, error) { return r, b[5:], nil },
	}
	res := Verify(context.Background(), photo, mustJSON(t, r), o)
	if res.Status != StatusVerified || res.Source != SourceGiven || res.Signed != hexsum(file) {
		t.Fatalf("%+v", res)
	}
}

func TestFindMemoInARealTransactionSet(t *testing.T) {
	_, r := realReceipt(t)
	var b bundle
	if err := json.Unmarshal(r.Anchor.Proof, &b); err != nil {
		t.Fatal(err)
	}
	set, err := base64.StdEncoding.DecodeString(b.Transactions)
	if err != nil {
		t.Fatal(err)
	}
	txHash, _ := hex32(r.Anchor.Tx)
	key, err := accountKey(r.Anchor.Account)
	if err != nil {
		t.Fatal(err)
	}
	memo, err := findMemo(set, passphrases["testnet"], txHash, key)
	if err != nil || memo == nil || hex.EncodeToString(memo[:]) != r.Root {
		t.Fatalf("memo %x, %v", memo, err)
	}
	if _, err := findMemo(set, passphrases["mainnet"], txHash, key); err == nil {
		t.Error("found under the wrong network")
	}
	other, _ := accountKey(account)
	if _, err := findMemo(set, passphrases["testnet"], txHash, other); err == nil {
		t.Error("found from another account")
	}
	txHash[0] ^= 1
	if _, err := findMemo(set, passphrases["testnet"], txHash, key); err == nil {
		t.Error("found another hash")
	}
}

func TestAccountKeyChecksAddresses(t *testing.T) {
	if _, err := accountKey(account); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", account[:55] + "A", "S" + account[1:], "nonsense"} {
		if _, err := accountKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
