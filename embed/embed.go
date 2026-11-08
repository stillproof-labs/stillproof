// Package embed carries a receipt inside a JPEG as a C2PA manifest store
// (SPEC.md §8.3).
//
// The manifest has a v2 claim (c2pa.claim.v2) and three assertions:
// c2pa.actions.v2 (c2pa.created), c2pa.hash.data (a hard binding over the
// whole file, excluding the inserted APP11 segments) and
// org.stillproof.receipt (the receipt JSON). The claim is signed with
// COSE_Sign1, ES256, x5chain in the protected header.
package embed

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"

	"github.com/stillproof-labs/stillproof/receipt"
)

// Assertion labels.
const (
	LabelReceipt  = "org.stillproof.receipt"
	labelActions  = "c2pa.actions.v2"
	labelDataHash = "c2pa.hash.data"
)

// ErrNoManifest means the JPEG has no C2PA manifest store.
var ErrNoManifest = errors.New("no C2PA manifest in the JPEG")

const digitalCapture = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"

var enc = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

type hashedURI struct {
	URL  string `cbor:"url"`
	Hash []byte `cbor:"hash"`
}

type generatorInfo struct {
	Name string `cbor:"name"`
}

type claimV2 struct {
	InstanceID string        `cbor:"instanceID"`
	Generator  generatorInfo `cbor:"claim_generator_info"`
	Signature  string        `cbor:"signature"`
	Created    []hashedURI   `cbor:"created_assertions"`
	Alg        string        `cbor:"alg"`
}

type hashRange struct {
	Start  int `cbor:"start"`
	Length int `cbor:"length"`
}

type dataHash struct {
	Exclusions []hashRange `cbor:"exclusions"`
	Name       string      `cbor:"name,omitempty"`
	Alg        string      `cbor:"alg"`
	Hash       []byte      `cbor:"hash"`
	Pad        []byte      `cbor:"pad"`
}

type action struct {
	Action            string `cbor:"action"`
	DigitalSourceType string `cbor:"digitalSourceType"`
}

type actions struct {
	Actions []action `cbor:"actions"`
}

// Embed returns jpeg with r inserted as a C2PA manifest store, signed by
// signer (an ECDSA P-256 key) with certificate chain chain, leaf first. The
// APP11 segments go after the leading APP0 and APP1 segments; no other byte
// changes.
func Embed(jpeg []byte, r receipt.Receipt, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	segs, err := segments(jpeg)
	if err != nil {
		return nil, err
	}
	idx, _, err := c2paSegments(jpeg, segs)
	if err != nil {
		return nil, err
	}
	if len(idx) > 0 {
		return nil, errors.New("the JPEG already has a C2PA manifest")
	}
	if err := checkSigner(signer, chain); err != nil {
		return nil, err
	}
	rj, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	pos := 2
	for _, s := range segs {
		if s.marker != markerAPP0 && s.marker != markerAPP1 {
			break
		}
		pos = s.end
	}

	label, err := uuidURN("urn:c2pa:")
	if err != nil {
		return nil, err
	}
	iid, err := uuidURN("xmp:iid:")
	if err != nil {
		return nil, err
	}
	protected, err := enc.Marshal(map[int]any{1: -7, 33: x5chain(chain)})
	if err != nil {
		return nil, err
	}
	// Everything outside the exclusion is the input itself.
	fileHash := sha256.Sum256(jpeg)

	// The exclusion length depends on the store's size, which depends on how
	// the length encodes: grow it until it is stable.
	build := func(n int, sign bool) ([]byte, error) {
		return manifestStore(label, iid, rj, dataHash{
			Exclusions: []hashRange{{Start: pos, Length: n}},
			Name:       "jumbf manifest",
			Alg:        "sha256",
			Hash:       fileHash[:],
			Pad:        []byte{},
		}, protected, signer, sign)
	}
	n := 0
	for range 8 {
		store, err := build(n, false)
		if err != nil {
			return nil, err
		}
		if m := len(app11(store)); m != n {
			n = m
			continue
		}
		store, err = build(n, true)
		if err != nil {
			return nil, err
		}
		seg := app11(store)
		if len(seg) != n {
			return nil, errors.New("manifest size changed when signed")
		}
		out := make([]byte, 0, len(jpeg)+n)
		out = append(out, jpeg[:pos]...)
		out = append(out, seg...)
		return append(out, jpeg[pos:]...), nil
	}
	return nil, errors.New("manifest size did not settle")
}

func checkSigner(signer crypto.Signer, chain []*x509.Certificate) error {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("signer must be an ECDSA P-256 key")
	}
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}
	if !pub.Equal(chain[0].PublicKey) {
		return errors.New("the leaf certificate is not for the signer's key")
	}
	return nil
}

func x5chain(chain []*x509.Certificate) any {
	if len(chain) == 1 {
		return chain[0].Raw
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return ders
}

func uuidURN(prefix string) (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}
	u[6], u[8] = u[6]&0x0f|0x40, u[8]&0x3f|0x80
	h := hex.EncodeToString(u[:])
	return prefix + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// manifestStore builds the JUMBF manifest store. Unless sign is set, the
// signature is a placeholder of the same size.
func manifestStore(label, iid string, receiptJSON []byte, dh dataHash, protected []byte, signer crypto.Signer, sign bool) ([]byte, error) {
	ac, err := enc.Marshal(actions{[]action{{Action: "c2pa.created", DigitalSourceType: digitalCapture}}})
	if err != nil {
		return nil, err
	}
	hc, err := enc.Marshal(dh)
	if err != nil {
		return nil, err
	}
	assertions := []struct {
		label string
		box   []byte
	}{
		{labelActions, superbox(uuidCBOR, labelActions, isoBox("cbor", ac))},
		{labelDataHash, superbox(uuidCBOR, labelDataHash, isoBox("cbor", hc))},
		{LabelReceipt, superbox(uuidJSON, LabelReceipt, isoBox("json", receiptJSON))},
	}
	manifestURI := "self#jumbf=/c2pa/" + label
	cl := claimV2{
		InstanceID: iid,
		Generator:  generatorInfo{Name: "stillproof"},
		Signature:  manifestURI + "/c2pa.signature",
		Alg:        "sha256",
	}
	boxes := make([][]byte, len(assertions))
	for i, a := range assertions {
		h := sha256.Sum256(a.box[8:]) // the superbox's content, without its header
		cl.Created = append(cl.Created, hashedURI{URL: manifestURI + "/c2pa.assertions/" + a.label, Hash: h[:]})
		boxes[i] = a.box
	}
	claimBytes, err := enc.Marshal(cl)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	if sign {
		if sig, err = es256(signer, protected, claimBytes); err != nil {
			return nil, err
		}
	}
	cose, err := enc.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, nil, sig}})
	if err != nil {
		return nil, err
	}
	return superbox(uuidStore, "c2pa",
		superbox(uuidManifest, label,
			superbox(uuidAssertions, "c2pa.assertions", boxes...),
			superbox(uuidClaim, "c2pa.claim.v2", isoBox("cbor", claimBytes)),
			superbox(uuidSignature, "c2pa.signature", isoBox("cbor", cose)),
		),
	), nil
}

// es256 signs the COSE Sig_structure for a detached payload and returns r||s.
func es256(signer crypto.Signer, protected, payload []byte) ([]byte, error) {
	tbs, err := enc.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(tbs)
	der, err := signer.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 || rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return nil, errors.New("signer returned a malformed ECDSA signature")
	}
	sig := make([]byte, 64)
	rs.R.FillBytes(sig[:32])
	rs.S.FillBytes(sig[32:])
	return sig, nil
}

// Extract reads the receipt from jpeg's C2PA manifest and returns it with the
// original bytes: jpeg without its C2PA APP11 segments. It checks the
// manifest's c2pa.hash.data binding but not its C2PA signature; the receipt
// is the proof. It returns ErrNoManifest if there is no manifest store.
func Extract(jpeg []byte) (receipt.Receipt, []byte, error) {
	var r receipt.Receipt
	segs, err := segments(jpeg)
	if err != nil {
		return r, nil, err
	}
	idx, store, err := c2paSegments(jpeg, segs)
	if err != nil {
		return r, nil, err
	}
	if len(idx) == 0 {
		return r, nil, ErrNoManifest
	}
	rj, dh, err := readManifest(store)
	if err != nil {
		return r, nil, err
	}
	if err := checkDataHash(jpeg, dh); err != nil {
		return r, nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(rj))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, nil, fmt.Errorf("%s: %w", LabelReceipt, err)
	}

	orig := make([]byte, 0, len(jpeg))
	from := 0
	for _, i := range idx {
		orig = append(orig, jpeg[from:segs[i].start]...)
		from = segs[i].end
	}
	return r, append(orig, jpeg[from:]...), nil
}

// readManifest returns the receipt JSON and data hash of the active (last)
// manifest in store.
func readManifest(store []byte) ([]byte, dataHash, error) {
	var dh dataHash
	boxes, err := parseBoxes(store)
	if err != nil {
		return nil, dh, err
	}
	if len(boxes) != 1 {
		return nil, dh, errBox
	}
	top, err := parseSuperbox(boxes[0])
	if err != nil {
		return nil, dh, err
	}
	manifests, err := top.children()
	if err != nil {
		return nil, dh, err
	}
	if top.uuid != uuidStore || len(manifests) == 0 {
		return nil, dh, errBox
	}
	active := manifests[len(manifests)-1]
	parts, err := active.children()
	if err != nil {
		return nil, dh, err
	}
	var rj, hc []byte
	for _, p := range parts {
		if p.uuid != uuidAssertions {
			continue
		}
		as, err := p.children()
		if err != nil {
			return nil, dh, err
		}
		for _, a := range as {
			switch a.label {
			case LabelReceipt:
				rj, _ = a.data("json")
			case labelDataHash:
				hc, _ = a.data("cbor")
			}
		}
	}
	if rj == nil {
		return nil, dh, fmt.Errorf("the C2PA manifest has no %s assertion", LabelReceipt)
	}
	if hc == nil {
		return nil, dh, fmt.Errorf("the C2PA manifest has no %s assertion", labelDataHash)
	}
	if err := cbor.Unmarshal(hc, &dh); err != nil {
		return nil, dh, fmt.Errorf("%s: %w", labelDataHash, err)
	}
	return rj, dh, nil
}

// checkDataHash hashes jpeg without dh's exclusions and compares.
func checkDataHash(jpeg []byte, dh dataHash) error {
	if dh.Alg != "" && dh.Alg != "sha256" {
		return fmt.Errorf("%s: unsupported alg %q", labelDataHash, dh.Alg)
	}
	h := sha256.New()
	from := 0
	for _, x := range dh.Exclusions {
		if x.Start < from || x.Length < 0 || x.Start > len(jpeg)-x.Length {
			return fmt.Errorf("%s: bad exclusion", labelDataHash)
		}
		h.Write(jpeg[from:x.Start])
		from = x.Start + x.Length
	}
	h.Write(jpeg[from:])
	if !bytes.Equal(h.Sum(nil), dh.Hash) {
		return errors.New("the JPEG does not match its C2PA hard binding (c2pa.hash.data)")
	}
	return nil
}
