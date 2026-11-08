package receipt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stillproof-labs/stillproof/attest"
	"github.com/stillproof-labs/stillproof/claim"
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

func TestVerifyWithAttestation(t *testing.T) {
	file, r, l := fixture(t)
	s, err := claim.Parse([]byte(r.Claim))
	if err != nil {
		t.Fatal(err)
	}
	// A test root that signs an Android leaf for the claim key.
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	rootCert, _ := x509.ParseCertificate(rootDER)
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	purposes, _ := asn1.MarshalWithParams([]int{2}, "set")
	purpose, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: purposes})
	desc, _ := asn1.Marshal(struct {
		V1        int
		L1        asn1.Enumerated
		V2        int
		L2        asn1.Enumerated
		Challenge []byte
		ID        []byte
		SW, HW    asn1.RawValue
	}{300, 2, 300, 2, []byte(attest.Challenge), []byte{}, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: purpose}})
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Unix(0, 0), NotAfter: time.Now().AddDate(1, 0, 0),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: desc}}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, lt, rootCert, s.Key, rk)
	r.Attestation = &attest.Attestation{Kind: attest.KindAndroidKey, Chain: []string{base64.StdEncoding.EncodeToString(leafDER)}}

	if v := VerifyWith(context.Background(), file, r, l, VerifyOptions{Attest: attest.Options{AndroidRoots: pool}}); !v.OK() || v.Level != attest.LevelStrongBox {
		t.Fatalf("attested: %+v", v)
	}
	// With the built-in roots the test root is untrusted: the signature step fails.
	if v := Verify(context.Background(), file, r, l); v.Failed != StepSignature || !strings.Contains(v.Reason, "attestation") {
		t.Fatalf("untrusted: %+v", v)
	}
}
