// Package webverify checks a photo the way the browser verifier does: against
// a given receipt, a receipt embedded in the photo (SPEC.md §8.3), or every
// receipt the anchoring service holds for the photo's hash (§8.4).
package webverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stillproof-labs/stillproof/receipt"
)

// Options configures Verify.
type Options struct {
	Anchor  string         // anchoring service base URL, for hash lookups
	HTTP    *http.Client   // nil: a client with a 20 s timeout
	Horizon receipt.Lookup // nil: receipt.Horizon{}

	// Extract reads a receipt embedded in a JPEG and returns it with the
	// original, signed bytes. nil: photos carry no receipts.
	Extract func(jpeg []byte) (receipt.Receipt, []byte, error)

	// Validators verifies an Externalize bundle against the built-in trust
	// set for its network and returns Externalize's report as JSON. An error
	// means the bundle couldn't be checked, never that it is bad. nil:
	// validator proofs are not checked and the anchor is read from Horizon.
	Validators func(ctx context.Context, bundle []byte) (report []byte, err error)
}

// Sources of the receipts checked.
const (
	SourceGiven    = "given"
	SourceEmbedded = "embedded"
	SourceLookup   = "lookup"
)

// Statuses of a Result.
const (
	StatusVerified = "verified" // at least one receipt verified
	StatusFailed   = "failed"   // every receipt failed
	StatusNone     = "none"     // no receipt for this photo
	StatusPending  = "pending"  // receipts exist but none is anchored yet
	StatusError    = "error"    // the lookup itself failed
)

// Ways step 5 was checked.
const (
	CheckedValidators = "validators"
	CheckedHorizon    = "horizon"
)

// Result is what Verify found.
type Result struct {
	SHA256 string  `json:"sha256"`                  // of the file as given
	Signed string  `json:"signed_sha256,omitempty"` // with an embedded receipt: of the file without it
	Source string  `json:"source"`
	Status string  `json:"status"`
	Checks []Check `json:"checks"`
	Error  string  `json:"error,omitempty"`
}

// Check is the verdict for one receipt.
type Check struct {
	receipt.Verdict
	AnchorChecked string `json:"anchor_checked,omitempty"`
	Tx            string `json:"tx,omitempty"`
	Account       string `json:"account,omitempty"`
	Note          string `json:"note,omitempty"`
}

// Verify checks file. With a non-nil receiptJSON it checks that receipt.
// Otherwise it tries a receipt embedded in the file, then a lookup by hash.
// A file with an embedded receipt is checked without it, whichever receipt
// is used. Extract errors, including a malformed manifest, count as no
// embedded receipt.
func Verify(ctx context.Context, file, receiptJSON []byte, o Options) Result {
	sum := sha256.Sum256(file)
	res := Result{SHA256: hex.EncodeToString(sum[:]), Checks: []Check{}}
	// A photo with an embedded receipt was signed without it (SPEC.md §8.3).
	var embedded *receipt.Receipt
	if o.Extract != nil {
		if r, orig, err := o.Extract(file); err == nil {
			s := sha256.Sum256(orig)
			embedded, file, res.Signed = &r, orig, hex.EncodeToString(s[:])
		}
	}
	switch {
	case receiptJSON != nil:
		res.Source = SourceGiven
		res.Checks = append(res.Checks, o.checkJSON(ctx, file, receiptJSON))
	case embedded != nil:
		res.Source = SourceEmbedded
		res.Checks = append(res.Checks, o.check(ctx, file, *embedded))
	default:
		res.Source = SourceLookup
		raws, status, err := o.lookup(ctx, res.SHA256)
		if err != nil {
			res.Status, res.Error = StatusError, err.Error()
			return res
		}
		if status != "" {
			res.Status = status
			return res
		}
		for _, raw := range raws {
			res.Checks = append(res.Checks, o.checkJSON(ctx, file, raw))
		}
	}
	res.Status = StatusNone
	for _, c := range res.Checks {
		if c.OK() {
			res.Status = StatusVerified
			break
		}
		res.Status = StatusFailed
	}
	return res
}

// ParseReceipt decodes a receipt, rejecting fields SPEC.md doesn't define.
func ParseReceipt(b []byte) (receipt.Receipt, error) {
	var r receipt.Receipt
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, fmt.Errorf("receipt: %w", err)
	}
	if d.More() {
		return r, errors.New("receipt: trailing data")
	}
	return r, nil
}

func (o Options) checkJSON(ctx context.Context, file, b []byte) Check {
	r, err := ParseReceipt(b)
	if err != nil {
		return Check{Verdict: receipt.Verdict{Failed: receipt.StepClaim, Reason: err.Error(), Caveat: receipt.Caveat}}
	}
	return o.check(ctx, file, r)
}

// check runs SPEC.md §6 on one receipt. Step 5 uses the validator proof
// when there is one and it can be checked here, and Horizon otherwise.
func (o Options) check(ctx context.Context, file []byte, r receipt.Receipt) Check {
	c := Check{Tx: r.Anchor.Tx, Account: r.Anchor.Account}
	var l receipt.Lookup = receipt.Horizon{HTTP: o.HTTP}
	if o.Horizon != nil {
		l = o.Horizon
	}
	how := CheckedHorizon
	if len(r.Anchor.Proof) > 0 {
		p, note, err := o.proven(ctx, r.Anchor)
		switch {
		case err != nil:
			l, how = failed{fmt.Errorf("validator proof: %w", err)}, CheckedValidators
		case p == nil:
			c.Note = note
		case p.SourceMemo:
			l, how = fixed{&p.Tx}, CheckedValidators
		default:
			// The proof covers the ledger and success only: those must
			// match the receipt, and Horizon supplies source and memo.
			if err := matchProven(&p.Tx, r.Anchor); err != nil {
				l, how = failed{fmt.Errorf("validator proof: %w", err)}, CheckedValidators
			} else {
				c.Note = note
			}
		}
	}
	c.Verdict = receipt.Verify(ctx, file, r, l)
	c.Network = r.Anchor.Network
	if c.OK() {
		c.AnchorChecked = how
	}
	return c
}

// Network passphrases, by receipt network name.
var passphrases = map[string]string{
	"testnet": "Test SDF Network ; September 2015",
	"mainnet": "Public Global Stellar Network ; September 2015",
}

// bundle is the part of an Externalize bundle read here. Externalize checks
// all of it.
type bundle struct {
	Network      string `json:"network"`
	Transactions string `json:"transactions"`
}

// report is Externalize's verification report (its VerifyReport or
// Rejection): it proves the ledger and, per transaction, that it was applied
// and whether it succeeded. It does not report source or memo.
type report struct {
	Verified bool   `json:"verified"`
	Error    string `json:"error"`
	Ledger   struct {
		Sequence  uint32 `json:"sequence"`
		CloseTime int64  `json:"close_time"`
	} `json:"ledger"`
	Claims []struct {
		Kind      string `json:"kind"`
		TxHash    string `json:"tx_hash"`
		Succeeded bool   `json:"succeeded"`
	} `json:"claims"`
}

// provenTx is what a validator proof establishes about the anchor
// transaction. Source and MemoHash are set only with SourceMemo.
type provenTx struct {
	receipt.Tx
	SourceMemo bool
}

// proven checks a's validator proof (SPEC.md §8.2). It returns what the
// proof establishes; or nil and a note when the proof can't be checked here,
// so step 5 falls back to Horizon; or an error when the proof is wrong.
//
// Externalize proves the ledger and that a.Tx succeeded in it. Source and
// memo are read from the bundle's transaction set: the transaction hash
// commits to both, so the envelope that hashes to a.Tx carries them. Without
// a transaction set, the result has SourceMemo unset and a note.
func (o Options) proven(ctx context.Context, a receipt.Anchor) (*provenTx, string, error) {
	const fallback = " The anchor was read from Horizon instead."
	if o.Validators == nil {
		return nil, "This receipt has a validator proof, but this verifier can't check proofs." + fallback, nil
	}
	var b bundle
	if err := json.Unmarshal(a.Proof, &b); err != nil {
		return nil, "", fmt.Errorf("bundle: %w", err)
	}
	passphrase, ok := passphrases[a.Network]
	if !ok {
		return nil, "", fmt.Errorf("unknown network %q", a.Network)
	}
	if b.Network != passphrase {
		return nil, "", fmt.Errorf("bundle is for network %q, not %s", b.Network, a.Network)
	}
	txHash, err := hex32(a.Tx)
	if err != nil {
		return nil, "", fmt.Errorf("tx: %w", err)
	}
	raw, err := o.Validators(ctx, a.Proof)
	if err != nil {
		return nil, fmt.Sprintf("The validator proof couldn't be checked here (%v).", err) + fallback, nil
	}
	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, "", fmt.Errorf("unreadable report: %w", err)
	}
	if !rep.Verified {
		return nil, "", fmt.Errorf("rejected: %s", rep.Error)
	}
	p := &provenTx{}
	found := false
	for _, cl := range rep.Claims {
		if cl.Kind == "transaction" && strings.EqualFold(cl.TxHash, a.Tx) {
			found, p.Successful = true, cl.Succeeded
		}
	}
	if !found {
		return nil, "", fmt.Errorf("the bundle doesn't prove transaction %s", a.Tx)
	}
	p.Ledger, p.ClosedAt = rep.Ledger.Sequence, time.Unix(rep.Ledger.CloseTime, 0).UTC()
	if b.Transactions == "" {
		return p, "The validator proof has no transaction set, so it proves the ledger but not the source and memo: those were read from Horizon.", nil
	}
	set, err := base64.StdEncoding.DecodeString(b.Transactions)
	if err != nil {
		return nil, "", fmt.Errorf("bundle transactions: %w", err)
	}
	key, err := accountKey(a.Account)
	if err != nil {
		return nil, "", fmt.Errorf("account: %w", err)
	}
	memo, err := findMemo(set, passphrase, txHash, key)
	if err != nil {
		return nil, "", err
	}
	p.Source, p.MemoHash, p.SourceMemo = a.Account, memo, true
	return p, "", nil
}

// matchProven compares what a proof without a transaction set establishes
// with the receipt.
func matchProven(tx *receipt.Tx, a receipt.Anchor) error {
	switch {
	case !tx.Successful:
		return fmt.Errorf("transaction %s failed", a.Tx)
	case tx.Ledger != a.Ledger || !tx.ClosedAt.Equal(a.ClosedAt):
		return fmt.Errorf("receipt says ledger %d at %s, the validators signed %d at %s",
			a.Ledger, a.ClosedAt.Format(time.RFC3339), tx.Ledger, tx.ClosedAt.Format(time.RFC3339))
	}
	return nil
}

func hex32(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, errors.New("not 32 bytes of hex")
	}
	copy(h[:], b)
	return h, nil
}

type fixed struct{ tx *receipt.Tx }

func (f fixed) Transaction(context.Context, string, string) (*receipt.Tx, error) { return f.tx, nil }

type failed struct{ err error }

func (f failed) Transaction(context.Context, string, string) (*receipt.Tx, error) { return nil, f.err }

// lookup fetches the receipts for a hash (SPEC.md §8.4). It returns them, or
// a status when there are none to check.
func (o Options) lookup(ctx context.Context, hexsum string) ([]json.RawMessage, string, error) {
	if o.Anchor == "" {
		return nil, "", errors.New("no anchoring service to look the photo up in")
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	u := strings.TrimRight(o.Anchor, "/") + "/v1/receipts?sha256=" + url.QueryEscape(hexsum)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("lookup: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusAccepted:
		return nil, StatusPending, nil
	case http.StatusNotFound:
		return nil, StatusNone, nil
	default:
		return nil, "", fmt.Errorf("lookup: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&body); err != nil {
		return nil, "", fmt.Errorf("lookup: %w", err)
	}
	if len(body.Receipts) == 0 {
		return nil, StatusNone, nil
	}
	return body.Receipts, "", nil
}
