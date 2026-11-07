// Package attest verifies that a claim key is held in hardware (SPEC.md §8.1).
package attest

import (
	"crypto/x509"
	"errors"
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
}

// ErrAttestation means an attestation doesn't show that key is in hardware.
var ErrAttestation = errors.New("attestation")

// Verify checks that a attests key (65 bytes, SEC1 uncompressed) and returns
// its protection level.
func Verify(a Attestation, key []byte, o Options) (string, error) {
	return "", errors.Join(ErrAttestation, errors.New("not implemented"))
}
