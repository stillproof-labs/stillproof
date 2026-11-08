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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stillproof-labs/stillproof/claim"
)

// A real testnet anchor, ledger 5565106, and its bundle built by
// exnode --network testnet --txset. The bundle also claims realOtherTx, from
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

func needCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("externalize"); err != nil {
		t.Skip("externalize not on PATH")
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

func TestExternalizeChecksTheBundleBeforeRunning(t *testing.T) {
	_, raw := realBundle(t)
	cli := Externalize{Path: "no-such-externalize"} // never reached
	for name, a := range map[string]Anchor{
		"not json":      {Network: "testnet", Account: realAccount, Tx: realTx, Proof: json.RawMessage(`[`)},
		"other network": {Network: "mainnet", Account: realAccount, Tx: realTx, Proof: raw},
		"bad account":   {Network: "testnet", Account: "G", Tx: realTx, Proof: raw},
		"no txset": {Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) {
			delete(m, "transactions")
		})},
	} {
		if _, err := cli.Check(context.Background(), a); err == nil || errors.Is(err, ErrUnchecked) {
			t.Errorf("%s: %v", name, err)
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

	bad := map[string]Anchor{
		"other account":  {Network: "testnet", Account: account, Tx: realTx, Proof: raw},
		"other claimed":  {Network: "testnet", Account: realAccount, Tx: realOtherTx, Proof: raw},
		"unclaimed tx":   {Network: "testnet", Account: realAccount, Tx: strings.Repeat("ab", 32), Proof: raw},
		"not a bundle":   {Network: "testnet", Account: realAccount, Tx: realTx, Proof: json.RawMessage(`{"network":"Test SDF Network ; September 2015","transactions":"AAAA"}`)},
		"forged header":  {Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) { m["ledger"] = flipBase64(t, m["ledger"].(string), 40) })},
		"forged memo":    {Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) { flipMemo(t, m, realMemo) })},
		"forged txset":   {Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) { m["transactions"] = b.Transactions[:len(b.Transactions)-8] + "AAAAAAA=" })},
		"forged results": {Network: "testnet", Account: realAccount, Tx: realTx, Proof: edit(t, raw, func(m map[string]any) { m["results"] = flipBase64(t, m["results"].(string), 12) })},
	}
	for name, a := range bad {
		if _, err := (Externalize{}).Check(context.Background(), a); err == nil || errors.Is(err, ErrUnchecked) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTheResultSetIsNotSigned pins down what a bundle proves. The
// validators sign the ledger's StellarValue (transaction set hash, close
// time), not the rest of the header. The result set is committed only by
// the header's txSetResultHash, so anyone can rewrite it, recompute that
// hash and the header hash, and the CLI still accepts the bundle. That is
// why Check reads source and memo from the transaction set, never trusts a
// bundle without one, and why success isn't proven by the signatures.
func TestTheResultSetIsNotSigned(t *testing.T) {
	needCLI(t)
	_, raw := realBundle(t)
	tx, _ := hash32(realTx)

	failed := edit(t, raw, func(m map[string]any) {
		forgeResults(t, m, func(results []byte) {
			i := bytes.Index(results, tx[:]) + 32 + 8         // TransactionResultPair: hash, feeCharged, then the code
			copy(results[i:], []byte{0xff, 0xff, 0xff, 0xff}) // txSUCCESS to txFAILED; the arms have the same shape
		})
	})
	got, err := Externalize{}.Check(context.Background(), Anchor{Network: "testnet", Account: realAccount, Tx: realTx, Proof: failed})
	if err != nil || got.Successful || hex.EncodeToString(got.MemoHash[:]) != realMemo {
		t.Fatalf("forged failure: %+v %v", got, err)
	}

	fake := sha256.Sum256([]byte("never happened"))
	invented := edit(t, raw, func(m map[string]any) {
		forgeResults(t, m, func(results []byte) { copy(results[bytes.Index(results, tx[:]):], fake[:]) })
		delete(m, "transactions")
		m["claims"] = []any{map[string]any{"kind": "transaction", "tx_hash": hex.EncodeToString(fake[:])}}
	})
	rep, err := Externalize{}.run(context.Background(), invented)
	if err != nil || len(rep.Claims) != 1 || rep.Claims[0].TxHash != hex.EncodeToString(fake[:]) {
		t.Fatalf("the CLI no longer accepts an invented transaction without a txset (good news: update SPEC §8.2): %+v %v", rep, err)
	}
	a := Anchor{Network: "testnet", Account: realAccount, Tx: hex.EncodeToString(fake[:]), Proof: invented}
	if _, err := (Externalize{}).Check(context.Background(), a); err == nil {
		t.Fatal("Check accepted a bundle without a transaction set")
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
