package embed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/stillproof-labs/stillproof/receipt"
)

func testJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 8))
	for x := range 16 {
		for y := range 8 {
			img.Set(x, y, color.RGBA{uint8(x * 16), uint8(y * 32), 128, 255}) //nolint:gosec // G115: small
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func seg(marker byte, payload []byte) []byte {
	n := len(payload) + 2
	return append([]byte{0xFF, marker, byte(n >> 8), byte(n)}, payload...)
}

var (
	// JFIF 1.1, no density, no thumbnail.
	jfif = seg(markerAPP0, append([]byte("JFIF"), 0, 1, 1, 0, 0, 1, 0, 1, 0, 0))
	// Exif with a big-endian TIFF header and one empty IFD.
	exif = seg(markerAPP1, append([]byte("Exif"), 0, 0, 'M', 'M', 0, 42, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0))
)

// withHeaders puts headers right after SOI.
func withHeaders(j []byte, headers ...[]byte) []byte {
	out := append([]byte{}, j[:2]...)
	for _, h := range headers {
		out = append(out, h...)
	}
	return append(out, j[2:]...)
}

func testReceipt(proofs int) receipt.Receipt {
	r := receipt.Receipt{
		V: 1, Claim: `{"v":0,"sha256":"00"}`, Index: 2, Size: 3, Root: strings.Repeat("ab", 32),
		Anchor: receipt.Anchor{Network: "testnet", Account: "GABC", Tx: "aa", Ledger: 100, ClosedAt: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
	}
	for i := range proofs {
		r.Proof = append(r.Proof, strings.Repeat(string(rune('a'+i%6)), 64))
	}
	return r
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := SelfSigned(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, chain
}

func TestRoundTrip(t *testing.T) {
	plain := testJPEG(t)
	k, chain := testKey(t)
	for _, tc := range []struct {
		name    string
		file    []byte
		proofs  int
		segs    int
		insertX int // expected insertion offset
	}{
		{"bare", plain, 2, 1, 2},
		{"jfif", withHeaders(plain, jfif), 2, 1, 2 + len(jfif)},
		{"exif", withHeaders(plain, exif), 2, 1, 2 + len(exif)},
		{"jfif+exif", withHeaders(plain, jfif, exif), 2, 1, 2 + len(jfif) + len(exif)},
		{"multi-segment", withHeaders(plain, jfif, exif), 3000, 4, 2 + len(jfif) + len(exif)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testReceipt(tc.proofs)
			out, err := Embed(tc.file, r, k, chain)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out[:tc.insertX], tc.file[:tc.insertX]) || out[tc.insertX] != 0xFF || out[tc.insertX+1] != markerAPP11 {
				t.Fatalf("APP11 not at offset %d", tc.insertX)
			}
			segs, _ := segments(out)
			idx, _, _ := c2paSegments(out, segs)
			if len(idx) != tc.segs {
				t.Fatalf("%d APP11 segments, want %d", len(idx), tc.segs)
			}
			if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
				t.Fatalf("output doesn't decode: %v", err)
			}
			got, orig, err := Extract(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(orig, tc.file) {
				t.Fatal("Extract didn't return the original bytes")
			}
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("receipt\n got %+v\nwant %+v", got, r)
			}
			checkSignature(t, out, chain[0])
		})
	}
}

// checkSignature verifies the claim's COSE_Sign1 against cert.
func checkSignature(t *testing.T, file []byte, cert *x509.Certificate) {
	t.Helper()
	segs, _ := segments(file)
	_, store, _ := c2paSegments(file, segs)
	boxes, _ := parseBoxes(store)
	top, _ := parseSuperbox(boxes[0])
	ms, _ := top.children()
	parts, err := ms[0].children()
	if err != nil || len(parts) != 3 {
		t.Fatalf("manifest parts: %v", err)
	}
	claimBytes, _ := parts[1].data("cbor")
	coseBytes, _ := parts[2].data("cbor")
	if parts[1].label != "c2pa.claim.v2" || parts[2].label != "c2pa.signature" {
		t.Fatalf("labels %q %q", parts[1].label, parts[2].label)
	}
	var tag cbor.RawTag
	if err := cbor.Unmarshal(coseBytes, &tag); err != nil || tag.Number != 18 {
		t.Fatalf("COSE tag: %v %d", err, tag.Number)
	}
	var sign1 struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected map[any]any
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(tag.Content, &sign1); err != nil {
		t.Fatal(err)
	}
	var hdr map[int]any
	if err := cbor.Unmarshal(sign1.Protected, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != int64(-7) || !bytes.Equal(hdr[33].([]byte), cert.Raw) {
		t.Fatalf("protected header %v", hdr)
	}
	tbs, _ := enc.Marshal([]any{"Signature1", sign1.Protected, []byte{}, claimBytes})
	d := sha256.Sum256(tbs)
	rr, ss := new(big.Int).SetBytes(sign1.Signature[:32]), new(big.Int).SetBytes(sign1.Signature[32:])
	if !ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), d[:], rr, ss) {
		t.Fatal("bad claim signature")
	}
}

func TestSelfSigned(t *testing.T) {
	_, chain := testKey(t)
	c := chain[0]
	switch {
	case c.Version != 3, c.IsCA, c.KeyUsage != x509.KeyUsageDigitalSignature,
		!reflect.DeepEqual(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}),
		len(c.SubjectKeyId) == 0, !bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId):
		t.Fatalf("certificate profile: %+v", c)
	}
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestExtractErrors(t *testing.T) {
	plain := withHeaders(testJPEG(t), exif)
	k, chain := testKey(t)
	out, err := Embed(plain, testReceipt(2), k, chain)
	if err != nil {
		t.Fatal(err)
	}
	app11At := 2 + len(exif)
	edit := func(f func(b []byte)) []byte {
		b := append([]byte{}, out...)
		f(b)
		return b
	}
	for _, tc := range []struct {
		name string
		file []byte
		want error // nil: any error
	}{
		{"no manifest", plain, ErrNoManifest},
		{"not a JPEG", []byte("hello, world"), ErrNotJPEG},
		{"empty", nil, ErrNotJPEG},
		{"truncated", out[:app11At+40], ErrNotJPEG},
		{"bad segment length", edit(func(b []byte) { b[app11At+2], b[app11At+3] = 0xFF, 0xFF }), ErrNotJPEG},
		{"image changed", edit(func(b []byte) { b[len(b)-3] ^= 1 }), nil},
		{"exif changed", edit(func(b []byte) { b[20] ^= 1 }), nil},
		{"bad JUMBF", edit(func(b []byte) { b[app11At+12] = 0xFF }), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Extract(tc.file)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestEmbedErrors(t *testing.T) {
	plain := testJPEG(t)
	k, chain := testKey(t)
	other, _ := testKey(t)
	out, err := Embed(plain, testReceipt(1), k, chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		file   []byte
		signer *ecdsa.PrivateKey
		chain  []*x509.Certificate
	}{
		{"not a JPEG", []byte("GIF89a"), k, chain},
		{"already embedded", out, k, chain},
		{"wrong key", plain, other, chain},
		{"no chain", plain, k, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Embed(tc.file, testReceipt(1), tc.signer, tc.chain); err == nil {
				t.Fatal("no error")
			}
		})
	}
}
