package receipt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stillproof-labs/stillproof/claim"
)

// A real testnet anchor, ledger 5565106, and its v2 bundle built by
// exnode bundle --network testnet --txset. The bundle also claims realOtherTx, from
// another account.
const (
	realTx      = "7b41ee34a19cc637d7cb977c2bd4dbdf8482738c257b44dc7cd7e1d67a540510"
	realOtherTx = "51711b6774f4142b76e4272808b5081cf4284acadb6f7e51feb6d6ab4e16e544"
	realAccount = "GDZQXC6BL4F2ZZKGDY3JLCZXWEKSXRZRLJF2FR3KLLB3CW5QHJBFQLBJ"
	realMemo    = "bc44ccc81e9f385a7058ed38c0ff44e0a3e0d2f4e471fa160188940cb7172e22"
	realLedger  = 5565106
)

func realBundle(t *testing.T) (b bundle, raw []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/bundle-testnet-5565106.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b, raw
}

// realReceipt is a v1 receipt from scripts/testnet-demo.sh in
// stillproof-anchor, for testnet-photo.hex, with its validator proof.
func realReceipt(t *testing.T) (file []byte, r Receipt) {
	t.Helper()
	h, err := os.ReadFile("../testdata/testnet-photo.hex") // xxd -p
	if err != nil {
		t.Fatal(err)
	}
	file, err = hex.DecodeString(strings.Join(strings.Fields(string(h)), ""))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../testdata/testnet-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return file, r
}

// realReceiptTx is what Horizon says about the real receipt's anchor.
func realReceiptTx(t *testing.T, r Receipt) fakeLookup {
	t.Helper()
	root, _ := hash32(r.Root)
	return fakeLookup{r.Anchor.Tx: {Successful: true, Source: r.Anchor.Account, MemoHash: &root, Ledger: r.Anchor.Ledger, ClosedAt: r.Anchor.ClosedAt}}
}

// needCLI skips the test unless externalize v0.3.0 or later is on PATH, or
// fails it if NEED_EXTERNALIZE is set, as in CI.
func needCLI(t *testing.T) {
	t.Helper()
	if err := (Externalize{}).version(context.Background()); err != nil {
		if os.Getenv("NEED_EXTERNALIZE") != "" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
}

// edit returns the bundle raw with f applied to its JSON.
func edit(t *testing.T, raw []byte, f func(m map[string]any)) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// flipMemo changes one byte of memo in the bundle's transaction set.
func flipMemo(t *testing.T, m map[string]any, memo string) {
	t.Helper()
	set := mustBase64(t, m["transactions"].(string))
	h, _ := hex.DecodeString(memo)
	i := bytes.Index(set, h)
	if i < 0 {
		t.Fatal("memo not in the transaction set")
	}
	set[i] ^= 1
	m["transactions"] = base64.StdEncoding.EncodeToString(set)
}

func TestFindMemoInARealTransactionSet(t *testing.T) {
	b, _ := realBundle(t)
	set := mustBase64(t, b.Transactions)
	txHash, _ := hash32(realTx)
	key, err := accountKey(realAccount)
	if err != nil {
		t.Fatal(err)
	}
	memo, err := findMemo(set, Passphrases["testnet"], txHash, key)
	if err != nil || memo == nil || hex.EncodeToString(memo[:]) != realMemo {
		t.Fatalf("memo %x, %v", memo, err)
	}
	if _, err := findMemo(set, Passphrases["mainnet"], txHash, key); err == nil {
		t.Error("found under the wrong network")
	}
	other, _ := accountKey(account)
	if _, err := findMemo(set, Passphrases["testnet"], txHash, other); err == nil {
		t.Error("found from another account")
	}
	otherTx, _ := hash32(realOtherTx)
	if _, err := findMemo(set, Passphrases["testnet"], otherTx, key); err == nil {
		t.Error("found another account's transaction")
	}
	wrong := txHash
	wrong[0] ^= 1
	if _, err := findMemo(set, Passphrases["testnet"], wrong, key); err == nil {
		t.Error("found another hash")
	}

	// The hash authenticates the bytes: a changed memo is not found, even
	// before the CLI checks the set against the ledger.
	memoBytes, _ := hex.DecodeString(realMemo)
	i := bytes.Index(set, memoBytes)
	set[i+31] ^= 1
	if m, err := findMemo(set, Passphrases["testnet"], txHash, key); err == nil {
		t.Errorf("forged memo found: %x", m)
	}
}

func TestAccountKeyChecksAddresses(t *testing.T) {
	if _, err := accountKey(realAccount); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", realAccount[:55] + "A", "S" + realAccount[1:], "nonsense"} {
		if _, err := accountKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

type fakeProofs struct {
	tx  *Tx
	err error
}

func (f fakeProofs) Check(context.Context, Anchor) (*Tx, error) { return f.tx, f.err }

func TestVerifyWithAProof(t *testing.T) {
	file, r, l := fixture(t)
	r.V, r.Anchor.Proof = 1, json.RawMessage(`{}`)
	root, _ := hash32(r.Root)
	good := func() *Tx {
		return &Tx{Successful: true, Source: account, MemoHash: &root, Ledger: 100, ClosedAt: r.Anchor.ClosedAt}
	}
	failed := good()
	failed.Successful = false
	otherMemo := good()
	otherMemo.MemoHash = &[32]byte{}
	otherSource := good()
	otherSource.Source = realAccount
	otherLedger := good()
	otherLedger.Ledger = 101
	otherTime := good()
	otherTime.ClosedAt = otherTime.ClosedAt.Add(time.Second)

	cases := map[string]struct {
		proofs   ProofChecker
		lookup   Lookup
		anchored string // "" means step 5 fails
	}{
		"checked":                    {fakeProofs{tx: good()}, fakeLookup{}, CheckedValidators},
		"no checker":                 {nil, l, CheckedHorizon},
		"no checker, horizon fails":  {nil, fakeLookup{}, ""},
		"checker unavailable":        {fakeProofs{err: ErrUnchecked}, l, CheckedHorizon},
		"unavailable, horizon fails": {fakeProofs{err: ErrUnchecked}, fakeLookup{}, ""},
		"rejected":                   {fakeProofs{err: errors.New("rejected")}, l, ""},
		"failed tx":                  {fakeProofs{tx: failed}, l, ""},
		"other memo":                 {fakeProofs{tx: otherMemo}, l, ""},
		"other source":               {fakeProofs{tx: otherSource}, l, ""},
		"other ledger":               {fakeProofs{tx: otherLedger}, l, ""},
		"other close time":           {fakeProofs{tx: otherTime}, l, ""},
	}
	for name, c := range cases {
		v := VerifyWith(context.Background(), file, r, c.lookup, VerifyOptions{Proofs: c.proofs})
		if c.anchored == "" {
			if v.Failed != StepAnchor || v.Anchored != "" {
				t.Errorf("%s: failed at %q, anchored %q; want a failed anchor", name, v.Failed, v.Anchored)
			}
			continue
		}
		if !v.OK() || v.Anchored != c.anchored || v.Ledger != 100 {
			t.Errorf("%s: %+v", name, v)
		}
		if (c.anchored == CheckedHorizon) != strings.Contains(v.Note, "not checked") {
			t.Errorf("%s: note %q", name, v.Note)
		}
	}
}

func TestVerifyWithoutAProofUsesHorizon(t *testing.T) {
	file, r, l := fixture(t)
	v := VerifyWith(context.Background(), file, r, l, VerifyOptions{Proofs: fakeProofs{err: errors.New("must not run")}})
	if !v.OK() || v.Anchored != CheckedHorizon || v.Note != "" {
		t.Fatalf("%+v", v)
	}
	if v := Verify(context.Background(), file, r, l); !v.OK() || v.Anchored != CheckedHorizon {
		t.Fatalf("Verify: %+v", v)
	}
}

func TestARealReceiptWithoutTheCLIUsesHorizon(t *testing.T) {
	file, r := realReceipt(t)
	o := VerifyOptions{Proofs: Externalize{Path: "no-such-externalize"}}
	v := VerifyWith(context.Background(), file, r, realReceiptTx(t, r), o)
	if !v.OK() || v.Anchored != CheckedHorizon || !strings.Contains(v.Note, "not checked") {
		t.Fatalf("%+v", v)
	}
	if v := VerifyWith(context.Background(), file, r, fakeLookup{}, o); v.Failed != StepAnchor {
		t.Fatalf("without Horizon either: %+v", v)
	}
}

// A v1 proof is never checked: step 5 goes to Horizon, with a note, even
// with a CLI that could read it.
func TestARealReceiptWithAV1ProofUsesHorizon(t *testing.T) {
	file, r := realReceipt(t)
	r.Anchor.Proof = edit(t, r.Anchor.Proof, func(m map[string]any) {
		m["format"] = "externalize/bundle/v1"
		delete(m, "next_scp")
		delete(m, "next_transactions")
	})
	o := VerifyOptions{Proofs: Externalize{}}
	v := VerifyWith(context.Background(), file, r, realReceiptTx(t, r), o)
	if !v.OK() || v.Anchored != CheckedHorizon || !strings.Contains(v.Note, "externalize/bundle/v1") {
		t.Fatalf("%+v", v)
	}
	if v := VerifyWith(context.Background(), file, r, fakeLookup{}, o); v.Failed != StepAnchor || v.Anchored != "" {
		t.Fatalf("without Horizon: %+v", v)
	}
}

func TestExternalizeChecksTheBundleBeforeRunning(t *testing.T) {
	_, raw := realBundle(t)
	cli := Externalize{Path: "no-such-externalize"} // never reached
	for name, c := range map[string]struct {
		a         Anchor
		unchecked bool
	}{
		"not json":      {Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: json.RawMessage(`[`)}, false},
		"other network": {Anchor{Network: "mainnet", Account: realAccount, Tx: realTx, Proof: raw}, false},
		"bad account":   {Anchor{Network: "testnet", Account: "G", Tx: realTx, Proof: raw}, false},
		"v1": {Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) {
			m["format"] = "externalize/bundle/v1"
		})}, true},
		"no format": {Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) {
			delete(m, "format")
		})}, true},
		"no txset": {Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) {
			delete(m, "transactions")
		})}, true},
	} {
		_, err := cli.Check(context.Background(), c.a)
		if err == nil || errors.Is(err, ErrUnchecked) != c.unchecked || strings.Contains(err.Error(), "no-such-externalize") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestMain lets the test binary stand in for the externalize CLI: with
// FAKE_EXTERNALIZE set, it prints that as its version and rejects every
// bundle, as v0.2.0 rejects v2 bundles.
func TestMain(m *testing.M) {
	if v := os.Getenv("FAKE_EXTERNALIZE"); v != "" {
		if len(os.Args) > 1 && os.Args[1] == "--version" {
			fmt.Println(v)
			os.Exit(0)
		}
		fmt.Println(`{"verified":false,"error":"invalid bundle: unknown field next_scp"}`)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestExternalizeNeedsAV2CLI(t *testing.T) {
	_, raw := realBundle(t)
	a := Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: raw}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for v, unchecked := range map[string]bool{
		"externalize 0.2.0":  true,
		"externalize 0.1.1":  true,
		"something else":     true,
		"externalize 0.3.0":  false, // so its rejection counts
		"externalize 1.0.0":  false,
		"externalize 0.10.2": false,
	} {
		t.Setenv("FAKE_EXTERNALIZE", v)
		_, err := Externalize{Path: self}.Check(context.Background(), a)
		if err == nil || errors.Is(err, ErrUnchecked) != unchecked {
			t.Errorf("%s: %v", v, err)
		}
	}
}

// TestExternalizeCLI runs the real verifier when it is on PATH.
func TestExternalizeCLI(t *testing.T) {
	needCLI(t)
	b, raw := realBundle(t)
	a := Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: raw}
	tx, err := Externalize{}.Check(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	closed := time.Date(2026, 11, 5, 3, 26, 10, 0, time.UTC)
	if !tx.Successful || tx.Ledger != realLedger || !tx.ClosedAt.Equal(closed) ||
		tx.Source != realAccount || tx.MemoHash == nil || hex.EncodeToString(tx.MemoHash[:]) != realMemo {
		t.Fatalf("%+v", tx)
	}

	proof := func(f func(m map[string]any)) json.RawMessage { return edit(t, raw, f) }
	bad := map[string]Anchor{
		"other account":   {Network: "testnet", Account: account, Tx: realTx, Proof: raw},
		"other claimed":   {Network: "testnet", Account: realAccount, Tx: realOtherTx, Proof: raw},
		"unclaimed tx":    {Network: "testnet", Account: realAccount, Tx: strings.Repeat("ab", 32), Proof: raw},
		"not a bundle":    {Network: "testnet", Account: realAccount, Tx: realTx, Proof: json.RawMessage(`{"format":"externalize/bundle/v2","network":"Test SDF Network ; September 2015","transactions":"AAAA"}`)},
		"forged header":   {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { m["ledger"] = flipBase64(t, m["ledger"].(string), 40) })},
		"forged memo":     {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { flipMemo(t, m, realMemo) })},
		"forged txset":    {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { m["transactions"] = b.Transactions[:len(b.Transactions)-8] + "AAAAAAA=" })},
		"forged results":  {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { m["results"] = flipBase64(t, m["results"].(string), 12) })},
		"next scp is N's": {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { m["next_scp"] = m["scp"] })},
		"forged next set": {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { m["next_transactions"] = flipBase64(t, m["next_transactions"].(string), 40) })},
		"no next scp":     {Network: "testnet", Account: realAccount, Tx: realTx, Proof: proof(func(m map[string]any) { delete(m, "next_scp") })},
	}
	for name, a := range bad {
		if _, err := (Externalize{}).Check(context.Background(), a); err == nil || errors.Is(err, ErrUnchecked) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheResultSetIsSigned pins down what a v2 bundle proves. The
// validators sign ledger N's StellarValue, and ledger N+1's, whose
// transaction set commits to the hash of header N. So a result set rewritten
// with a recomputed txSetResultHash and header hash no longer verifies,
// unlike with v1 bundles: success is proven, and so is a transaction claimed
// without a transaction set.
func TestTheResultSetIsSigned(t *testing.T) {
	needCLI(t)
	_, raw := realBundle(t)
	tx, _ := hash32(realTx)

	failed := edit(t, raw, func(m map[string]any) {
		forgeResults(t, m, func(results []byte) {
			i := bytes.Index(results, tx[:]) + 32 + 8         // TransactionResultPair: hash, feeCharged, then the code
			copy(results[i:], []byte{0xff, 0xff, 0xff, 0xff}) // txSUCCESS to txFAILED; the arms have the same shape
		})
	})
	if got, err := (Externalize{}).Check(context.Background(), Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: failed}); err == nil || errors.Is(err, ErrUnchecked) {
		t.Fatalf("forged failure: %+v %v", got, err)
	}

	fake := sha256.Sum256([]byte("never happened"))
	invented := edit(t, raw, func(m map[string]any) {
		forgeResults(t, m, func(results []byte) { copy(results[bytes.Index(results, tx[:]):], fake[:]) })
		delete(m, "transactions")
		m["claims"] = []any{map[string]any{"kind": "transaction", "tx_hash": hex.EncodeToString(fake[:])}}
	})
	rep, err := Externalize{}.verify(context.Background(), invented)
	if err != nil || !strings.Contains(string(rep), `"verified":false`) {
		t.Fatalf("the CLI accepts an invented transaction: %s %v", rep, err)
	}
}

// forgeResults applies f to the bundle's TransactionResultSet and fixes up
// the header's txSetResultHash and hash.
func forgeResults(t *testing.T, m map[string]any, f func(results []byte)) {
	t.Helper()
	entry := mustBase64(t, m["results"].(string)) // ledgerSeq, TransactionResultSet, ext v0
	header := mustBase64(t, m["ledger"].(string)) // hash, LedgerHeader, ext v0
	set := entry[4 : len(entry)-4]
	old := sha256.Sum256(set)
	f(set)
	now := sha256.Sum256(set)
	i := bytes.Index(header, old[:])
	if i < 32 {
		t.Fatal("txSetResultHash not in the header")
	}
	copy(header[i:], now[:])
	h := sha256.Sum256(header[32 : len(header)-4])
	copy(header, h[:])
	m["results"] = base64.StdEncoding.EncodeToString(entry)
	m["ledger"] = base64.StdEncoding.EncodeToString(header)
}

func flipBase64(t *testing.T, s string, i int) string {
	t.Helper()
	b := mustBase64(t, s)
	b[i] ^= 1
	return base64.StdEncoding.EncodeToString(b)
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestARealTestnetReceipt verifies a real receipt against the validators,
// offline, and tampered copies of it.
func TestARealTestnetReceipt(t *testing.T) {
	needCLI(t)
	file, r := realReceipt(t)
	o := VerifyOptions{Proofs: Externalize{}}
	horizon := realReceiptTx(t, r)
	v := VerifyWith(context.Background(), file, r, fakeLookup{}, o) // Horizon would fail
	if !v.OK() || v.Anchored != CheckedValidators || v.Ledger != r.Anchor.Ledger || !v.NotAfter.Equal(r.Anchor.ClosedAt) || v.Note != "" {
		t.Fatalf("%+v", v)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(r *Receipt){
		"ledger":    func(r *Receipt) { r.Anchor.Ledger++ },
		"closed_at": func(r *Receipt) { r.Anchor.ClosedAt = r.Anchor.ClosedAt.Add(time.Second) },
		"account":   func(r *Receipt) { r.Anchor.Account = account },
		"tx":        func(r *Receipt) { r.Anchor.Tx = strings.Repeat("ab", 32) },
		"memo": func(r *Receipt) {
			r.Anchor.Proof = edit(t, r.Anchor.Proof, func(m map[string]any) { flipMemo(t, m, r.Root) })
		},
		"proof from another anchor": func(r *Receipt) {
			_, r.Anchor.Proof = realBundle(t)
		},
		// Someone else's claim over the same file, in a tree of its own,
		// pointing at this anchor: everything up to step 5 passes.
		"root": func(r *Receipt) {
			s, err := claim.Sign(claim.Claim{SHA256: sha256.Sum256(file), Type: "image/jpeg", Captured: time.Now().UnixMilli(), Key: &key.PublicKey}, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf := claim.LeafHash(s.Bytes())
			r.Claim, r.Index, r.Size, r.Proof, r.Root = string(s.Bytes()), 0, 1, []string{}, hex.EncodeToString(leaf[:])
		},
	}
	for name, f := range cases {
		_, r := realReceipt(t)
		f(&r)
		// Horizon agrees with the real receipt; a proof that fails is never
		// overruled by it.
		if v := VerifyWith(context.Background(), file, r, horizon, o); v.Failed != StepAnchor || v.Anchored != "" {
			t.Errorf("tampered %s: failed at %q (%s), anchored %q", name, v.Failed, v.Reason, v.Anchored)
		}
	}
}
