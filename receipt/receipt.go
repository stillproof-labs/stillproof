// Package receipt defines Stillproof receipts and verifies a file against
// one (SPEC.md §5–6).
package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/stillproof-labs/stillproof/attest"
	"github.com/stillproof-labs/stillproof/claim"
	"github.com/stillproof-labs/stillproof/merkle"
)

// Caveat goes with every verdict.
const Caveat = "This proves the file is unchanged and when it existed. It does not prove the scene is genuine."

// Receipt ties a signed claim to an anchored tree root.
type Receipt struct {
	V      int      `json:"v"`
	Claim  string   `json:"claim"`
	Index  int      `json:"index"`
	Size   int      `json:"size"`
	Proof  []string `json:"proof"`
	Root   string   `json:"root"`
	Anchor Anchor   `json:"anchor"`

	Attestation *attest.Attestation `json:"attestation,omitempty"` // v1, §8.1
}

// Anchor locates the transaction that recorded the root.
type Anchor struct {
	Network  string    `json:"network"`
	Account  string    `json:"account"`
	Tx       string    `json:"tx"`
	Ledger   uint32    `json:"ledger"`
	ClosedAt time.Time `json:"closed_at"`

	Proof json.RawMessage `json:"proof,omitempty"` // v1, §8.2: an Externalize bundle
}

// Tx is what the network says about an anchor transaction.
type Tx struct {
	Successful bool
	Source     string
	MemoHash   *[32]byte // nil unless the memo is MEMO_HASH
	Ledger     uint32
	ClosedAt   time.Time
}

// ErrNotFound means the network has no such transaction.
var ErrNotFound = errors.New("transaction not found")

// Lookup reads a transaction from a network.
type Lookup interface {
	Transaction(ctx context.Context, network, hash string) (*Tx, error)
}

// Step names a verification step, in order.
type Step string

// The steps of SPEC.md §6.
const (
	StepClaim     Step = "claim"
	StepFile      Step = "file"
	StepSignature Step = "signature"
	StepTree      Step = "tree"
	StepAnchor    Step = "anchor"
)

// Verdict is the outcome of Verify. When Failed is empty, every check passed.
type Verdict struct {
	Failed   Step          `json:"failed,omitempty"`
	Reason   string        `json:"reason,omitempty"`
	Key      string        `json:"key,omitempty"`
	Level    string        `json:"level,omitempty"`
	Captured time.Time     `json:"captured,omitzero"` // device clock
	NotAfter time.Time     `json:"not_after,omitzero"`
	Ledger   uint32        `json:"ledger,omitempty"`
	Network  string        `json:"network,omitempty"`
	Caveat   string        `json:"caveat"`
	Signed   *claim.Signed `json:"-"`
}

// OK reports whether every check passed.
func (v Verdict) OK() bool { return v.Failed == "" }

// Verify checks file against r, reading the anchor transaction through l.
func Verify(ctx context.Context, file []byte, r Receipt, l Lookup) Verdict {
	v := Verdict{Caveat: Caveat}
	fail := func(s Step, format string, a ...any) Verdict {
		v.Failed, v.Reason = s, fmt.Sprintf(format, a...)
		return v
	}
	if r.V != 0 && r.V != 1 {
		return fail(StepClaim, "unsupported receipt version %d", r.V)
	}
	s, err := claim.Parse([]byte(r.Claim))
	if err != nil {
		return fail(StepClaim, "%v", err)
	}
	v.Signed = &s
	pub, _ := s.Key.Bytes()
	v.Key, v.Level = hex.EncodeToString(pub), "software"
	v.Captured = time.UnixMilli(s.Captured).UTC()

	if sha256.Sum256(file) != s.SHA256 {
		return fail(StepFile, "the file's SHA-256 is not the one in the claim")
	}
	if err := s.Verify(); err != nil {
		return fail(StepSignature, "%v", err)
	}

	root, err := hash32(r.Root)
	if err != nil {
		return fail(StepTree, "root: %v", err)
	}
	proof := make([]merkle.Hash, len(r.Proof))
	for i, p := range r.Proof {
		if proof[i], err = hash32(p); err != nil {
			return fail(StepTree, "proof[%d]: %v", i, err)
		}
	}
	if err := merkle.Verify(claim.LeafHash([]byte(r.Claim)), r.Index, r.Size, proof, root); err != nil {
		return fail(StepTree, "%v", err)
	}

	tx, err := l.Transaction(ctx, r.Anchor.Network, r.Anchor.Tx)
	switch {
	case err != nil:
		return fail(StepAnchor, "transaction %s on %s: %v", r.Anchor.Tx, r.Anchor.Network, err)
	case !tx.Successful:
		return fail(StepAnchor, "transaction %s failed", r.Anchor.Tx)
	case tx.Source != r.Anchor.Account:
		return fail(StepAnchor, "transaction source is %s, not %s", tx.Source, r.Anchor.Account)
	case tx.MemoHash == nil || *tx.MemoHash != root:
		return fail(StepAnchor, "transaction memo is not the receipt's root")
	case tx.Ledger != r.Anchor.Ledger || !tx.ClosedAt.Equal(r.Anchor.ClosedAt):
		return fail(StepAnchor, "receipt says ledger %d at %s, the network says %d at %s",
			r.Anchor.Ledger, r.Anchor.ClosedAt.Format(time.RFC3339), tx.Ledger, tx.ClosedAt.Format(time.RFC3339))
	}
	v.NotAfter, v.Ledger, v.Network = tx.ClosedAt.UTC(), tx.Ledger, r.Anchor.Network
	return v
}

func hash32(s string) (merkle.Hash, error) {
	var h merkle.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, errors.New("want 64 hex characters")
	}
	copy(h[:], b)
	return h, nil
}
