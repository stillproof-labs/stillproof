// Package claim builds, signs, parses and verifies Stillproof claims (SPEC.md §1–2).
package claim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const header = "stillproof/claim/v0"

// Claim is what a device asserts about a file.
type Claim struct {
	SHA256   [32]byte
	Type     string
	Captured int64 // unix milliseconds, device clock
	Key      *ecdsa.PublicKey
}

// Signed is a claim with its device signature.
type Signed struct {
	Claim
	Sig [64]byte // r‖s, low s
}

var (
	// ErrFormat means the text is not a v0 claim.
	ErrFormat = errors.New("claim: malformed")
	// ErrSignature means the signature does not verify.
	ErrSignature = errors.New("claim: bad signature")
)

var mediaType = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)

// Bytes is the exact text the device signs.
func (c Claim) Bytes() []byte {
	return fmt.Appendf(nil, "%s\nsha256 %x\ntype %s\ncaptured %d\nkey %x\n",
		header, c.SHA256, c.Type, c.Captured, publicKeyBytes(c.Key))
}

// Bytes is the signed claim: the claim plus its sig line.
func (s Signed) Bytes() []byte {
	return fmt.Appendf(s.Claim.Bytes(), "sig %x\n", s.Sig)
}

// ID is the hex leaf hash, SHA-256(0x00 ‖ signed claim).
func (s Signed) ID() string {
	h := LeafHash(s.Bytes())
	return hex.EncodeToString(h[:])
}

// LeafHash is SHA-256(0x00 ‖ signed claim bytes).
func LeafHash(signed []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, signed...))
}

// Sign signs c with key, normalising s to the lower half of the order.
func Sign(c Claim, key *ecdsa.PrivateKey) (Signed, error) {
	if err := c.check(); err != nil {
		return Signed{}, err
	}
	digest := sha256.Sum256(c.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return Signed{}, err
	}
	n := key.Curve.Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	var out Signed
	out.Claim = c
	r.FillBytes(out.Sig[:32])
	s.FillBytes(out.Sig[32:])
	return out, nil
}

// Verify checks the signature, rejecting high s.
func (s Signed) Verify() error {
	if err := s.check(); err != nil {
		return err
	}
	r := new(big.Int).SetBytes(s.Sig[:32])
	sv := new(big.Int).SetBytes(s.Sig[32:])
	if sv.Cmp(new(big.Int).Rsh(elliptic.P256().Params().N, 1)) > 0 {
		return ErrSignature
	}
	digest := sha256.Sum256(s.Claim.Bytes())
	if !ecdsa.Verify(s.Key, digest[:], r, sv) {
		return ErrSignature
	}
	return nil
}

// Parse reads a signed claim and checks it is byte-for-byte canonical.
// It does not verify the signature.
func Parse(text []byte) (Signed, error) {
	lines := strings.Split(string(text), "\n")
	if len(lines) != 7 || lines[6] != "" || lines[0] != header {
		return Signed{}, ErrFormat
	}
	field := func(i int, name string) (string, error) {
		v, ok := strings.CutPrefix(lines[i], name+" ")
		if !ok {
			return "", fmt.Errorf("%w: line %d is not %q", ErrFormat, i+1, name)
		}
		return v, nil
	}
	var s Signed
	v, err := field(1, "sha256")
	if err != nil {
		return Signed{}, err
	}
	if err := decodeHex(v, s.SHA256[:]); err != nil {
		return Signed{}, err
	}
	if s.Type, err = field(2, "type"); err != nil {
		return Signed{}, err
	}
	if v, err = field(3, "captured"); err != nil {
		return Signed{}, err
	}
	if s.Captured, err = strconv.ParseInt(v, 10, 64); err != nil {
		return Signed{}, fmt.Errorf("%w: captured", ErrFormat)
	}
	if v, err = field(4, "key"); err != nil {
		return Signed{}, err
	}
	var kb [65]byte
	if err := decodeHex(v, kb[:]); err != nil {
		return Signed{}, err
	}
	if s.Key, err = parsePublicKey(kb[:]); err != nil {
		return Signed{}, err
	}
	if v, err = field(5, "sig"); err != nil {
		return Signed{}, err
	}
	if err := decodeHex(v, s.Sig[:]); err != nil {
		return Signed{}, err
	}
	if err := s.check(); err != nil {
		return Signed{}, err
	}
	// Re-encoding must give back the input: one text per claim.
	if string(s.Bytes()) != string(text) {
		return Signed{}, fmt.Errorf("%w: not canonical", ErrFormat)
	}
	return s, nil
}

func (c Claim) check() error {
	switch {
	case !mediaType.MatchString(c.Type):
		return fmt.Errorf("%w: type %q", ErrFormat, c.Type)
	case c.Captured < 0:
		return fmt.Errorf("%w: captured is negative", ErrFormat)
	case c.Key == nil || c.Key.Curve != elliptic.P256():
		return fmt.Errorf("%w: key must be P-256", ErrFormat)
	}
	return nil
}

func decodeHex(s string, dst []byte) error {
	if len(s) != 2*len(dst) || strings.ToLower(s) != s {
		return fmt.Errorf("%w: want %d lowercase hex characters", ErrFormat, 2*len(dst))
	}
	_, err := hex.Decode(dst, []byte(s))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return nil
}

func publicKeyBytes(k *ecdsa.PublicKey) []byte {
	if k == nil {
		return nil
	}
	b, err := k.Bytes()
	if err != nil {
		return nil
	}
	return b
}

func parsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	if err != nil {
		return nil, fmt.Errorf("%w: key: %w", ErrFormat, err)
	}
	return k, nil
}
