// Package webverify checks a photo the way the browser verifier does: against
// a given receipt, a receipt embedded in the photo (SPEC.md §8.3), or every
// receipt the anchoring service holds for the photo's hash (§8.4).
package webverify

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// set for its network and returns Externalize's report as JSON, as for
	// receipt.Validators. An error means the bundle couldn't be checked,
	// never that it is bad. nil: validator proofs are not checked and the
	// anchor is read from Horizon.
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

// Result is what Verify found.
type Result struct {
	SHA256 string  `json:"sha256"`                  // of the file as given
	Signed string  `json:"signed_sha256,omitempty"` // with an embedded receipt: of the file without it
	Source string  `json:"source"`
	Status string  `json:"status"`
	Checks []Check `json:"checks"`
	Error  string  `json:"error,omitempty"`
}

// Check is the verdict for one receipt. Verdict.Anchored says how step 5
// was checked, and Verdict.Note why a validator proof wasn't.
type Check struct {
	receipt.Verdict
	Tx      string `json:"tx,omitempty"`
	Account string `json:"account,omitempty"`
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
	var l receipt.Lookup = receipt.Horizon{HTTP: o.HTTP}
	if o.Horizon != nil {
		l = o.Horizon
	}
	var vo receipt.VerifyOptions
	if o.Validators != nil {
		vo.Proofs = receipt.Validators(o.Validators)
	}
	return Check{Verdict: receipt.VerifyWith(ctx, file, r, l, vo), Tx: r.Anchor.Tx, Account: r.Anchor.Account}
}

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
