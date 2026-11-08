package attest

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const appID = "ABCDE12345.org.stillproof.app"

type appleCase struct {
	issuer   ca
	fmt      string
	appID    string
	counter  uint32
	aaguid   []byte
	nonceFor []byte // the key the nonce binds
	keyID    []byte // nil: SHA-256 of the credential key
	credID   []byte // nil: keyID
	until    time.Time
}

// build makes an App Attest object the way a device would.
func (c appleCase) build(t *testing.T) Attestation {
	t.Helper()
	cred := newKey(t)
	kh := sha256.Sum256(pubBytes(t, &cred.PublicKey))
	keyID := c.keyID
	if keyID == nil {
		keyID = kh[:]
	}
	credID := c.credID
	if credID == nil {
		credID = keyID
	}
	rp := sha256.Sum256([]byte(c.appID))
	ad := append(rp[:], 0x40)
	ad = binary.BigEndian.AppendUint32(ad, c.counter)
	ad = append(ad, c.aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(credID)))
	ad = append(ad, credID...)
	ad = append(ad, 0xa0) // credential public key (COSE), unused

	cdh := sha256.Sum256(c.nonceFor)
	nonce := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	ext, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"explicit,tag:1"`
	}{nonce[:]})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustB64(t, c.issuer.issue(t, &cred.PublicKey, oidAppleNonce, ext, c.until))

	var obj appleObject
	obj.Fmt, obj.AuthData = c.fmt, ad
	obj.AttStmt.X5C = [][]byte{leaf, c.issuer.cert.Raw}
	raw, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return Attestation{Kind: KindAppleAppAttest, KeyID: base64.StdEncoding.EncodeToString(keyID), Object: base64.StdEncoding.EncodeToString(raw)}
}

func TestAppleSynthetic(t *testing.T) {
	root, other := newCA(t), newCA(t)
	claimKey := pubBytes(t, &newKey(t).PublicKey)
	ok := appleCase{issuer: root, fmt: "apple-appattest", appID: appID, aaguid: aaguidProduction, nonceFor: claimKey, until: now.AddDate(1, 0, 0)}
	edit := func(f func(*appleCase)) appleCase { c := ok; f(&c); return c }

	cases := map[string]struct {
		c    appleCase
		dev  bool
		want string // "level:" and a level, or part of the error
	}{
		"production":       {ok, false, "level:" + LevelSecureEnclave},
		"development":      {edit(func(c *appleCase) { c.aaguid = aaguidDevelopment }), true, "level:" + LevelSecureEnclave},
		"development, off": {edit(func(c *appleCase) { c.aaguid = aaguidDevelopment }), false, "development"},
		"unknown aaguid":   {edit(func(c *appleCase) { c.aaguid = []byte("0123456789abcdef") }), true, "aaguid"},
		"wrong format":     {edit(func(c *appleCase) { c.fmt = "packed" }), false, "format"},
		"untrusted root":   {edit(func(c *appleCase) { c.issuer = other }), false, "unknown authority"},
		"expired":          {edit(func(c *appleCase) { c.until = now.Add(-time.Hour) }), false, "expired"},
		"other claim key":  {edit(func(c *appleCase) { c.nonceFor = []byte("another key") }), false, "nonce"},
		"wrong key_id":     {edit(func(c *appleCase) { c.keyID = make([]byte, 32) }), false, "key_id"},
		"wrong credential": {edit(func(c *appleCase) { c.credID = make([]byte, 32) }), false, "credential id"},
		"other app":        {edit(func(c *appleCase) { c.appID = "ABCDE12345.org.example" }), false, "app id"},
		"counter not zero": {edit(func(c *appleCase) { c.counter = 1 }), false, "counter"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Verify(c.c.build(t), claimKey, Options{Now: now, AppIDs: []string{"X.other", appID}, AppleRoots: root.pool, AllowDevelopment: c.dev})
			check(t, got, err, c.want)
		})
	}
	if _, err := Verify(ok.build(t), claimKey, Options{Now: now, AppleRoots: root.pool}); err == nil {
		t.Fatal("verified with no app ids")
	}
}

// TestAppleReal checks a real development-environment object from
// github.com/veehaitch/devicecheck-appattest (Apache-2.0) against Apple's root.
func TestAppleReal(t *testing.T) {
	raw, err := os.ReadFile("testdata/apple-ios-14.4.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AppID          string    `json:"app_id"`
		Timestamp      time.Time `json:"timestamp"`
		KeyID          string    `json:"key_id"`
		ClientDataHash string    `json:"client_data_hash"`
		Object         string    `json:"object"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	a := Attestation{Kind: KindAppleAppAttest, KeyID: s.KeyID, Object: s.Object}
	cdh := mustB64(t, s.ClientDataHash)
	o := Options{Now: s.Timestamp, AppIDs: []string{s.AppID}, AllowDevelopment: true}

	got, err := verifyAppleHash(a, cdh, o)
	check(t, got, err, "level:"+LevelSecureEnclave)

	cases := map[string]struct {
		o    func(*Options)
		want string
	}{
		"development off": {func(o *Options) { o.AllowDevelopment = false }, "development"},
		"other app":       {func(o *Options) { o.AppIDs = []string{"6MURL8TA57.org.example"} }, "app id"},
		"expired":         {func(o *Options) { o.Now = now }, "expired"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := o
			c.o(&o)
			_, err := verifyAppleHash(a, cdh, o)
			check(t, "", errors.Join(ErrAttestation, err), c.want)
		})
	}
	// Through Verify the object is genuine but doesn't bind this key.
	got, err = Verify(a, make([]byte, 65), o)
	check(t, got, err, "nonce")
}
