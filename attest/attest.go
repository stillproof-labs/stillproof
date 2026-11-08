// Package attest verifies that a claim key is held in hardware (SPEC.md §8.1).
package attest

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Kinds of attestation.
const (
	KindAndroidKey     = "android-key"
	KindAppleAppAttest = "apple-app-attest"
)

// Protection levels, as verdicts report them.
const (
	LevelSoftware      = "software"
	LevelTEE           = "tee"
	LevelStrongBox     = "strongbox"
	LevelSecureEnclave = "secure-enclave"
)

// Challenge is the Android attestation challenge for claim keys.
const Challenge = "stillproof/key/v1"

// Attestation is a receipt's attestation field.
type Attestation struct {
	Kind   string   `json:"kind"`
	Chain  []string `json:"chain,omitempty"`  // android-key: base64 DER, leaf first
	KeyID  string   `json:"key_id,omitempty"` // apple-app-attest
	Object string   `json:"object,omitempty"` // apple-app-attest: base64 CBOR
}

// Options configures Verify. The zero value uses the built-in roots and the
// current time.
type Options struct {
	Now          time.Time
	AppIDs       []string       // apple-app-attest: accepted "TEAMID.bundle" ids
	AndroidRoots *x509.CertPool // nil: Google's hardware attestation roots
	AppleRoots   *x509.CertPool // nil: Apple's App Attestation root

	// AllowDevelopment accepts App Attest objects from the development
	// environment.
	AllowDevelopment bool
}

// ErrAttestation means an attestation doesn't show that key is in hardware.
var ErrAttestation = errors.New("attestation")

// Verify checks that a attests key (65 bytes, SEC1 uncompressed) and returns
// its protection level.
//
// Neither kind is checked for revocation: Google's attestation status list
// and Apple's fraud metric are out of scope.
func Verify(a Attestation, key []byte, o Options) (level string, err error) {
	switch a.Kind {
	case KindAndroidKey:
		level, err = verifyAndroid(a, key, []byte(Challenge), o)
	case KindAppleAppAttest:
		level, err = verifyApple(a, key, o)
	default:
		err = fmt.Errorf("unknown kind %q", a.Kind)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	return level, nil
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// verifyChain parses certs (leaf first) and checks that they chain to roots
// at now. It returns the leaf.
func verifyChain(certs [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	inter := x509.NewCertPool()
	var leaf *x509.Certificate
	for i, der := range certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		if i == 0 {
			leaf = c
		} else {
			inter.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return leaf, err
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
