package receipt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Passphrases are the Stellar network passphrases by network name.
var Passphrases = map[string]string{
	"testnet": "Test SDF Network ; September 2015",
	"mainnet": "Public Global Stellar Network ; September 2015",
}

// ErrUnchecked means a proof could not be checked, for example because no
// verifier is installed. It never means the proof is bad.
var ErrUnchecked = errors.New("the validator proof was not checked")

// ProofChecker checks anchor.proof against the validators' signatures
// (SPEC.md §8.2) and returns what it proves about a.Tx. It returns an error
// wrapping ErrUnchecked if it can't run, and any other error if the proof is
// invalid or isn't about a.Tx.
//
// Ledger, ClosedAt, Source and MemoHash are proven by the signatures.
// Successful comes from the bundle's result set, which they don't cover.
type ProofChecker interface {
	Check(ctx context.Context, a Anchor) (*Tx, error)
}

// Externalize checks proofs with the externalize CLI
// (github.com/Externalize-Labs/externalize, v0.2.0 or later).
type Externalize struct {
	Path  string // the CLI; "" means externalize on PATH
	Trust string // trust set file; "" means the CLI's built-in set for the network
}

// bundle holds the fields of an Externalize bundle read here. The CLI
// checks the whole bundle.
type bundle struct {
	Network      string `json:"network"`
	Transactions string `json:"transactions"`
}

// report is the CLI's `verify --json` output.
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
// The CLI certifies the ledger: validators satisfying the trust set signed
// EXTERNALIZE for its StellarValue, which holds the close time and the
// transaction set's hash. It checks the bundle's transaction set against
// that hash and that a.Tx is in it. Source and memo are then read from the
// transaction set here: a.Tx is the hash of the transaction's XDR, so the
// bytes that hash to it are that transaction.
func (e Externalize) Check(ctx context.Context, a Anchor) (*Tx, error) {
	var b bundle
	if err := json.Unmarshal(a.Proof, &b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	passphrase, ok := Passphrases[a.Network]
	if !ok {
		return nil, fmt.Errorf("unknown network %q", a.Network)
	}
	if b.Network != passphrase {
		return nil, fmt.Errorf("bundle is for network %q, not %s", b.Network, a.Network)
	}
	if b.Transactions == "" {
		// Without it, the bundle proves nothing about the transaction: the
		// result set is committed only by the header, not the signatures.
		return nil, errors.New("bundle has no transaction set")
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

	rep, err := e.run(ctx, a.Proof)
	if err != nil {
		return nil, err
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

// run runs `externalize verify --json` on proof. Exit status 0 is verified,
// 1 rejected, anything else (or no CLI) unchecked.
func (e Externalize) run(ctx context.Context, proof []byte) (*report, error) {
	path := e.Path
	if path == "" {
		path = "externalize"
	}
	args := []string{"verify", "--json"}
	if e.Trust != "" {
		args = append(args, "--trust", e.Trust)
	}
	cmd := exec.CommandContext(ctx, path, append(args, "-")...) //nolint:gosec // G204: the verifier the caller chose
	cmd.Stdin = bytes.NewReader(proof)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var rep report
	parseErr := json.Unmarshal(stdout.Bytes(), &rep)
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		if parseErr != nil || rep.Error == "" {
			return nil, errors.New("rejected by externalize")
		}
		return nil, fmt.Errorf("rejected: %s", rep.Error)
	case err != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%w: externalize: %s", ErrUnchecked, msg)
	case parseErr != nil:
		return nil, fmt.Errorf("%w: externalize output: %w", ErrUnchecked, parseErr)
	case !rep.Verified:
		return nil, fmt.Errorf("%w: externalize exited 0 without verifying", ErrUnchecked)
	}
	return &rep, nil
}
