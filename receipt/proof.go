package receipt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Passphrases are the Stellar network passphrases by network name.
var Passphrases = map[string]string{
	"testnet": "Test SDF Network ; September 2015",
	"mainnet": "Public Global Stellar Network ; September 2015",
}

// BundleFormat is the only Externalize bundle format checked (SPEC.md §8.2).
// Earlier formats don't certify the whole ledger header.
const BundleFormat = "externalize/bundle/v2"

// ErrUnchecked means a proof could not be checked, for example because no
// verifier is installed or the bundle is an older format. It never means
// the proof is bad.
var ErrUnchecked = errors.New("the validator proof was not checked")

// ProofChecker checks anchor.proof against the validators' signatures
// (SPEC.md §8.2) and returns what it proves about a.Tx: ledger, close time,
// success, source and memo. It returns an error wrapping ErrUnchecked if it
// can't check the proof, and any other error if the proof is invalid or
// isn't about a.Tx.
type ProofChecker interface {
	Check(ctx context.Context, a Anchor) (*Tx, error)
}

// Validators is a ProofChecker built on an Externalize verifier: a function
// that verifies a bundle against the trust set for its network and returns
// Externalize's report as JSON (a VerifyReport, or a Rejection with
// "verified": false). An error means the bundle couldn't be checked, never
// that it is bad.
type Validators func(ctx context.Context, bundle []byte) (report []byte, err error)

// bundle holds the fields of an Externalize bundle read here. The verifier
// checks the whole bundle.
type bundle struct {
	Format       string `json:"format"`
	Network      string `json:"network"`
	Transactions string `json:"transactions"`
}

// report is Externalize's verification report.
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

// Check implements ProofChecker.
//
// A v2 bundle verifies only if validators satisfying the trust set
// externalized ledger N's StellarValue and ledger N+1's, whose transaction
// set commits to the hash of header N. So the whole header is certified,
// and with it the result set: the report's ledger, close time and success
// are proven. The verifier also checks the bundle's transaction set against
// the header and that a.Tx is in it. Source and memo are then read from the
// transaction set here: a.Tx is the hash of the transaction's XDR, so the
// bytes that hash to it are that transaction.
func (f Validators) Check(ctx context.Context, a Anchor) (*Tx, error) {
	var b bundle
	if err := json.Unmarshal(a.Proof, &b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if b.Format != BundleFormat {
		return nil, fmt.Errorf("%w: it is %q, and only %s certifies the whole ledger header", ErrUnchecked, b.Format, BundleFormat)
	}
	passphrase, ok := Passphrases[a.Network]
	if !ok {
		return nil, fmt.Errorf("unknown network %q", a.Network)
	}
	if b.Network != passphrase {
		return nil, fmt.Errorf("bundle is for network %q, not %s", b.Network, a.Network)
	}
	if b.Transactions == "" {
		return nil, fmt.Errorf("%w: it has no transaction set, so it doesn't prove the source and memo", ErrUnchecked)
	}
	set, err := base64.StdEncoding.DecodeString(b.Transactions)
	if err != nil {
		return nil, fmt.Errorf("bundle transactions: %w", err)
	}
	hash, err := hash32(a.Tx)
	if err != nil {
		return nil, fmt.Errorf("tx: %w", err)
	}
	key, err := accountKey(a.Account)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}

	raw, err := f(ctx, a.Proof)
	if err != nil {
		if errors.Is(err, ErrUnchecked) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrUnchecked, err)
	}
	var rep report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("unreadable report: %w", err)
	}
	if !rep.Verified {
		if rep.Error == "" {
			return nil, errors.New("rejected")
		}
		return nil, fmt.Errorf("rejected: %s", rep.Error)
	}
	tx := &Tx{Ledger: rep.Ledger.Sequence, ClosedAt: time.Unix(rep.Ledger.CloseTime, 0).UTC()}
	found := false
	for _, c := range rep.Claims {
		if c.Kind == "transaction" && strings.EqualFold(c.TxHash, a.Tx) {
			found, tx.Successful = true, c.Succeeded
		}
	}
	if !found {
		return nil, fmt.Errorf("bundle does not claim transaction %s", a.Tx)
	}
	memo, err := findMemo(set, passphrase, hash, key)
	if err != nil {
		return nil, err
	}
	tx.Source, tx.MemoHash = a.Account, memo
	return tx, nil
}

// Externalize checks proofs with the externalize CLI
// (github.com/Externalize-Labs/externalize, v0.3.0 or later).
type Externalize struct {
	Path  string // the CLI; "" means externalize on PATH
	Trust string // trust set file; "" means the CLI's built-in set for the network
}

// Check implements ProofChecker; see Validators.Check.
func (e Externalize) Check(ctx context.Context, a Anchor) (*Tx, error) {
	return Validators(e.verify).Check(ctx, a)
}

func (e Externalize) path() string {
	if e.Path == "" {
		return "externalize"
	}
	return e.Path
}

// minVersion is the first externalize release that reads BundleFormat.
var minVersion = [2]int{0, 3}

// version checks that the CLI runs and reads BundleFormat. Older releases
// reject v2 bundles, which must not fail a receipt.
func (e Externalize) version(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, e.path(), "--version").Output() //nolint:gosec // G204: the verifier the caller chose
	if err != nil {
		return fmt.Errorf("%w: externalize: %w", ErrUnchecked, err)
	}
	s := strings.TrimSpace(string(out)) // "externalize 0.3.0"
	v := strings.Split(strings.TrimPrefix(s, "externalize "), ".")
	var n [2]int
	for i := range n {
		if i < len(v) {
			n[i], err = strconv.Atoi(v[i])
		}
		if i >= len(v) || err != nil {
			return fmt.Errorf("%w: unrecognized externalize version %q", ErrUnchecked, s)
		}
	}
	if n[0] < minVersion[0] || n[0] == minVersion[0] && n[1] < minVersion[1] {
		return fmt.Errorf("%w: %s can't read %s; v%d.%d.0 or later is needed", ErrUnchecked, s, BundleFormat, minVersion[0], minVersion[1])
	}
	return nil
}

// verify runs `externalize verify --json` on bundle and returns its report.
// Exit status 0 is verified and 1 rejected; anything else, or a CLI too old
// for the format, is unchecked.
func (e Externalize) verify(ctx context.Context, bundle []byte) ([]byte, error) {
	if err := e.version(ctx); err != nil {
		return nil, err
	}
	args := []string{"verify", "--json"}
	if e.Trust != "" {
		args = append(args, "--trust", e.Trust)
	}
	cmd := exec.CommandContext(ctx, e.path(), append(args, "-")...) //nolint:gosec // G204: the verifier the caller chose
	cmd.Stdin = bytes.NewReader(bundle)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		if !json.Valid(stdout.Bytes()) {
			return []byte(`{"verified":false}`), nil
		}
	case err != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%w: externalize: %s", ErrUnchecked, msg)
	default:
		var rep report
		if json.Unmarshal(stdout.Bytes(), &rep) != nil || !rep.Verified {
			return nil, fmt.Errorf("%w: externalize exited 0 without a verified report", ErrUnchecked)
		}
	}
	return stdout.Bytes(), nil
}
