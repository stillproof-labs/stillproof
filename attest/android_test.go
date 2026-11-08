package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubBytes(t *testing.T, k *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newCA(t *testing.T) ca {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	p := x509.NewCertPool()
	p.AddCert(c)
	return ca{c, k, p}
}

// issue signs a leaf for pub with one extension, valid until notAfter.
func (c ca) issue(t *testing.T, pub *ecdsa.PublicKey, oid asn1.ObjectIdentifier, ext []byte, notAfter time.Time) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: notAfter,
		ExtraExtensions: []pkix.Extension{{Id: oid, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func authList(t *testing.T, purposes ...int) asn1.RawValue {
	t.Helper()
	var fields []byte
	if purposes != nil {
		set, err := asn1.MarshalWithParams(purposes, "set")
		if err != nil {
			t.Fatal(err)
		}
		f, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagPurpose, IsCompound: true, Bytes: set})
		if err != nil {
			t.Fatal(err)
		}
		fields = f
	}
	// An unrelated high tag first (701, creationDateTime), as real lists have.
	other, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 701, IsCompound: true, Bytes: []byte{2, 1, 0}})
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(other, fields...)}
}

func TestAndroidSynthetic(t *testing.T) {
	root, other := newCA(t), newCA(t)
	claimKey := newKey(t)
	desc := func(level int, challenge string, hw, sw asn1.RawValue) []byte {
		b, err := asn1.Marshal(keyDescription{
			AttestationVersion: 300, AttestationSecurityLevel: asn1.Enumerated(level),
			KeyMintVersion: 300, KeyMintSecurityLevel: asn1.Enumerated(level),
			AttestationChallenge: []byte(challenge), UniqueID: []byte{},
			SoftwareEnforced: sw, HardwareEnforced: hw,
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sign, none := authList(t, 2, 3), authList(t)
	good := func(level int) []byte { return desc(level, Challenge, sign, none) }
	later := now.AddDate(1, 0, 0)

	cases := map[string]struct {
		issuer ca
		pub    *ecdsa.PublicKey
		ext    []byte
		until  time.Time
		want   string // "level:" and a level, or part of the error
	}{
		"tee":              {root, &claimKey.PublicKey, good(1), later, "level:" + LevelTEE},
		"strongbox":        {root, &claimKey.PublicKey, good(2), later, "level:" + LevelStrongBox},
		"software":         {root, &claimKey.PublicKey, good(0), later, "level 0"},
		"unknown level":    {root, &claimKey.PublicKey, good(3), later, "level 3"},
		"wrong challenge":  {root, &claimKey.PublicKey, desc(1, "stillproof/key/v0", sign, none), later, "challenge"},
		"no sign purpose":  {root, &claimKey.PublicKey, desc(1, Challenge, authList(t, 3), none), later, "sign"},
		"sign in software": {root, &claimKey.PublicKey, desc(1, Challenge, none, sign), later, "sign"},
		"wrong key":        {root, &newKey(t).PublicKey, good(1), later, "not the claim key"},
		"expired":          {root, &claimKey.PublicKey, good(1), now.Add(-time.Hour), "expired"},
		"untrusted root":   {other, &claimKey.PublicKey, good(1), later, "unknown authority"},
		"bad description":  {root, &claimKey.PublicKey, []byte{0x30, 0x01}, later, "key description"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := Attestation{Kind: KindAndroidKey, Chain: []string{
				c.issuer.issue(t, c.pub, oidKeyDescription, c.ext, c.until),
				base64.StdEncoding.EncodeToString(c.issuer.cert.Raw),
			}}
			got, err := Verify(a, pubBytes(t, &claimKey.PublicKey), Options{Now: now, AndroidRoots: root.pool})
			check(t, got, err, c.want)
		})
	}
}

// TestAndroidReal checks real chains from github.com/android/keyattestation
// (Apache-2.0) against the built-in roots.
func TestAndroidReal(t *testing.T) {
	cases := map[string]struct {
		at   time.Time
		want string
	}{
		"testdata/android-tegu-tee.pem":         {time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), LevelTEE},        // ECDSA root
		"testdata/android-caiman-strongbox.pem": {time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), LevelStrongBox}, // RSA root
	}
	for file, c := range cases {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			m := regexp.MustCompile(`Challenge \(base64\): (\S+)`).FindSubmatch(raw)
			challenge, _ := base64.StdEncoding.DecodeString(string(m[1]))
			var a Attestation
			a.Kind = KindAndroidKey
			for b, rest := pem.Decode(raw); b != nil; b, rest = pem.Decode(rest) {
				a.Chain = append(a.Chain, base64.StdEncoding.EncodeToString(b.Bytes))
			}
			leaf, _ := x509.ParseCertificate(mustB64(t, a.Chain[0]))
			key := pubBytes(t, leaf.PublicKey.(*ecdsa.PublicKey))

			got, err := verifyAndroid(a, key, challenge, Options{Now: c.at})
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
			// Through Verify the chain is fine but the challenge isn't ours.
			if _, err := Verify(a, key, Options{Now: c.at}); err == nil || !strings.Contains(err.Error(), "challenge") {
				t.Fatalf("Verify: %v; want a challenge error", err)
			}
			// Later, the short-lived intermediates have expired.
			if _, err := verifyAndroid(a, key, challenge, Options{Now: now}); err == nil {
				t.Fatal("verified with expired intermediates")
			}
		})
	}
}

// check fails t unless want is "level:" and got, or err is an ErrAttestation
// that mentions want.
func check(t *testing.T, got string, err error, want string) {
	t.Helper()
	if lvl, ok := strings.CutPrefix(want, "level:"); ok {
		if err != nil || got != lvl {
			t.Fatalf("got %q, %v; want %s", got, err, want)
		}
	} else if !errors.Is(err, ErrAttestation) || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %q, %v; want an error with %q", got, err, want)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnknownKind(t *testing.T) {
	if _, err := Verify(Attestation{Kind: "tpm"}, nil, Options{}); !errors.Is(err, ErrAttestation) {
		t.Fatal(err)
	}
}
