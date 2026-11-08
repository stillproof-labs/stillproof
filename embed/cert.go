package embed

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 5280 key identifier, not a signature
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// SelfSigned returns a one-certificate chain for key, shaped like a C2PA
// signing certificate: v3, end entity, digitalSignature, EKU
// emailProtection, subject and authority key ids. C2PA validators accept it
// and report the signer as untrusted.
func SelfSigned(key *ecdsa.PrivateKey) ([]*x509.Certificate, error) {
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	ski := sha1.Sum(pub) //nolint:gosec // G401: see import
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	name := pkix.Name{CommonName: "Stillproof embedder", Organization: []string{"Stillproof"}}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		Issuer:                name,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{c}, nil
}
