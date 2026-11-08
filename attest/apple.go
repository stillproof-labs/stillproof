package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// oidAppleNonce is the App Attest nonce extension.
var oidAppleNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
)

type appleObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C [][]byte `cbor:"x5c"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

// verifyApple checks an App Attest attestation object whose client data is
// key, as in "Validating apps that connect to your server":
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
func verifyApple(a Attestation, key []byte, o Options) (string, error) {
	h := sha256.Sum256(key)
	return verifyAppleHash(a, h[:], o)
}

func verifyAppleHash(a Attestation, clientDataHash []byte, o Options) (string, error) {
	keyID, err := decodeB64(a.KeyID)
	if err != nil {
		return "", fmt.Errorf("key_id: %w", err)
	}
	raw, err := decodeB64(a.Object)
	if err != nil {
		return "", fmt.Errorf("object: %w", err)
	}
	var obj appleObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return "", fmt.Errorf("object: %w", err)
	}
	if obj.Fmt != "apple-appattest" {
		return "", fmt.Errorf("object format is %q", obj.Fmt)
	}

	// 1. The chain reaches Apple's root.
	roots := o.AppleRoots
	if roots == nil {
		roots = appleRoots
	}
	cred, err := verifyChain(obj.AttStmt.X5C, roots, o.now())
	if err != nil {
		return "", err
	}

	// 2–4. The nonce is SHA-256(authData ‖ clientDataHash).
	nonce := sha256.Sum256(append(bytes.Clone(obj.AuthData), clientDataHash...))
	var ext []byte
	for _, e := range cred.Extensions {
		if e.Id.Equal(oidAppleNonce) {
			ext = e.Value
		}
	}
	var n struct {
		Nonce []byte `asn1:"explicit,tag:1"`
	}
	if ext == nil {
		return "", errors.New("no nonce extension")
	}
	if _, err := asn1.Unmarshal(ext, &n); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	if !bytes.Equal(n.Nonce, nonce[:]) {
		return "", errors.New("nonce is not for this key")
	}

	// 5. The credential certificate's key is the key id.
	pub, ok := cred.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("credential key is not ECDSA")
	}
	pb, err := pub.Bytes()
	if err != nil {
		return "", err
	}
	if kh := sha256.Sum256(pb); !bytes.Equal(kh[:], keyID) {
		return "", errors.New("credential key does not match key_id")
	}

	// 6–9. Authenticator data: rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credentialId.
	ad := obj.AuthData
	if len(ad) < 55 {
		return "", errors.New("authenticator data too short")
	}
	rp := ad[:32]
	if !slices.ContainsFunc(o.AppIDs, func(id string) bool { h := sha256.Sum256([]byte(id)); return bytes.Equal(h[:], rp) }) {
		return "", errors.New("app id is not accepted")
	}
	if binary.BigEndian.Uint32(ad[33:37]) != 0 {
		return "", errors.New("counter is not 0")
	}
	switch aaguid := ad[37:53]; {
	case bytes.Equal(aaguid, aaguidProduction):
	case bytes.Equal(aaguid, aaguidDevelopment):
		if !o.AllowDevelopment {
			return "", errors.New("development environment")
		}
	default:
		return "", errors.New("unknown aaguid")
	}
	idLen := int(binary.BigEndian.Uint16(ad[53:55]))
	if len(ad) < 55+idLen || !bytes.Equal(ad[55:55+idLen], keyID) {
		return "", errors.New("credential id does not match key_id")
	}
	return LevelSecureEnclave, nil
}
