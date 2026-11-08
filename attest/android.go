package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// oidKeyDescription is the Android key attestation extension.
var oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// keyDescription is the start of the KeyDescription sequence, see
// https://source.android.com/docs/security/features/keystore/attestation#schema
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

const (
	tagPurpose  = 1 // AuthorizationList purpose [1] EXPLICIT SET OF INTEGER
	purposeSign = 2
)

// verifyAndroid checks an Android Keystore attestation chain. The chain is
// not checked against Google's revocation list.
func verifyAndroid(a Attestation, key, challenge []byte, o Options) (string, error) {
	certs := make([][]byte, len(a.Chain))
	for i, s := range a.Chain {
		var err error
		if certs[i], err = decodeB64(s); err != nil {
			return "", fmt.Errorf("chain[%d]: %w", i, err)
		}
	}
	roots := o.AndroidRoots
	if roots == nil {
		roots = androidRoots
	}
	leaf, err := verifyChain(certs, roots, o.now())
	if err != nil {
		return "", err
	}
	if !sameKey(leaf, key) {
		return "", errors.New("the attested key is not the claim key")
	}
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidKeyDescription) {
			ext = e.Value
		}
	}
	if ext == nil {
		return "", errors.New("no key description")
	}
	var kd keyDescription
	if rest, err := asn1.Unmarshal(ext, &kd); err != nil {
		return "", fmt.Errorf("key description: %w", err)
	} else if len(rest) > 0 {
		return "", errors.New("key description: trailing data")
	}
	if !bytes.Equal(kd.AttestationChallenge, challenge) {
		return "", errors.New("wrong attestation challenge")
	}
	purposes, err := authPurposes(kd.HardwareEnforced)
	if err != nil {
		return "", fmt.Errorf("key description: %w", err)
	}
	if !slices.Contains(purposes, purposeSign) {
		return "", errors.New("the key's hardware-enforced purposes don't include sign")
	}
	switch kd.AttestationSecurityLevel {
	case 1:
		return LevelTEE, nil
	case 2:
		return LevelStrongBox, nil
	default:
		return "", fmt.Errorf("attestation security level %d is not hardware", kd.AttestationSecurityLevel)
	}
}

// authPurposes returns the purpose tag of an AuthorizationList.
func authPurposes(list asn1.RawValue) ([]int, error) {
	if list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence {
		return nil, errors.New("authorization list is not a sequence")
	}
	for rest := list.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, err
		}
		if f.Class != asn1.ClassContextSpecific || f.Tag != tagPurpose {
			continue
		}
		var p []int
		if _, err := asn1.UnmarshalWithParams(f.Bytes, &p, "set"); err != nil {
			return nil, fmt.Errorf("purpose: %w", err)
		}
		return p, nil
	}
	return nil, nil
}

// sameKey reports whether c's public key is the P-256 key with SEC1 bytes key.
func sameKey(c *x509.Certificate, key []byte) bool {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	b, err := pub.Bytes()
	return err == nil && bytes.Equal(b, key)
}
