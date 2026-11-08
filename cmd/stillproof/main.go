// Command stillproof signs and verifies Stillproof claims.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stillproof-labs/stillproof/attest"
	"github.com/stillproof-labs/stillproof/claim"
	"github.com/stillproof-labs/stillproof/embed"
	"github.com/stillproof-labs/stillproof/receipt"
)

const usage = `stillproof signs and verifies Stillproof claims.

Usage:
  stillproof verify [--json] [--app-id ID]... [--externalize PATH] FILE [RECEIPT]
                                              check FILE against RECEIPT (SPEC.md §6), or a
                                              JPEG against its embedded receipt (§8.3);
                                              --app-id: accepted App Attest TEAMID.bundle;
                                              a validator proof (§8.2) is checked with the
                                              externalize CLI (--externalize, default PATH)
  stillproof embed --key KEYFILE PHOTO RECEIPT
                                              print PHOTO with RECEIPT embedded as C2PA (§8.3)
  stillproof keygen KEYFILE                   write a new software P-256 key (hex)
  stillproof sign --key KEYFILE FILE          print a signed claim for FILE

embed signs the C2PA manifest with KEYFILE and a self-signed certificate.
keygen and sign are for development: the app keeps its key on the phone.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "verify":
		err = verify(os.Args[2:], os.Stdout)
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:], os.Stdout)
	case "embed":
		err = embedReceipt(os.Args[2:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

var errFailed = errors.New("verification failed")

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	var o receipt.VerifyOptions
	fs.Func("app-id", "accepted App Attest app id, TEAMID.bundle (repeatable)", func(s string) error {
		o.Attest.AppIDs = append(o.Attest.AppIDs, s)
		return nil
	})
	ex := fs.String("externalize", "", "externalize CLI that checks validator proofs (default: externalize on PATH)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 && fs.NArg() != 2 {
		return errors.New("usage: stillproof verify [--json] [--app-id ID]... [--externalize PATH] FILE [RECEIPT]")
	}
	o.Proofs = receipt.Externalize{Path: *ex}
	file, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var r receipt.Receipt
	if fs.NArg() == 1 {
		if r, file, err = embed.Extract(file); err != nil {
			return fmt.Errorf("embedded receipt: %w", err)
		}
	} else if r, err = readReceipt(fs.Arg(1)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v := receipt.VerifyWith(ctx, file, r, receipt.Horizon{}, o)
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	} else {
		printVerdict(out, v)
	}
	if !v.OK() {
		return errFailed
	}
	return nil
}

func printVerdict(out io.Writer, v receipt.Verdict) {
	if !v.OK() {
		fmt.Fprintf(out, "FAILED at %s: %s\n", v.Failed, v.Reason)
		return
	}
	fmt.Fprintf(out, "VERIFIED\n")
	kind := "software key, not attested"
	if v.Level != attest.LevelSoftware {
		kind = "hardware key, attested " + v.Level
	}
	fmt.Fprintf(out, "  unchanged since signed by key %s… (%s)\n", v.Key[:18], kind)
	fmt.Fprintf(out, "  existed no later than %s (ledger %d, %s)\n", v.NotAfter.Format(time.RFC3339), v.Ledger, v.Network)
	if v.Anchored == receipt.CheckedValidators {
		fmt.Fprintf(out, "  anchor checked against the validators' signatures\n")
	} else {
		fmt.Fprintf(out, "  anchor checked through Horizon\n")
	}
	if v.Note != "" {
		fmt.Fprintf(out, "  note: %s\n", v.Note)
	}
	fmt.Fprintf(out, "  device says captured %s\n", v.Captured.Format(time.RFC3339))
	fmt.Fprintf(out, "  %s\n", v.Caveat)
}

func keygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: stillproof keygen KEYFILE")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	b, err := k.Bytes()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the path the user asked for
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, hex.EncodeToString(b))
	return err
}

func sign(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "key file from stillproof keygen")
	typ := fs.String("type", "", "media type (default: from the file extension)")
	_ = fs.Parse(args)
	if *keyPath == "" || fs.NArg() != 1 {
		return errors.New("usage: stillproof sign --key KEYFILE FILE")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	file, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if *typ == "" {
		*typ, _, _ = strings.Cut(mime.TypeByExtension(strings.ToLower(filepath.Ext(fs.Arg(0)))), ";")
		if *typ == "" {
			*typ = "application/octet-stream"
		}
	}
	s, err := claim.Sign(claim.Claim{SHA256: sha256.Sum256(file), Type: *typ, Captured: time.Now().UnixMilli(), Key: &key.PublicKey}, key)
	if err != nil {
		return err
	}
	_, err = out.Write(s.Bytes())
	return err
}

func embedReceipt(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("embed", flag.ExitOnError)
	keyPath := fs.String("key", "", "key file from stillproof keygen")
	_ = fs.Parse(args)
	if *keyPath == "" || fs.NArg() != 2 {
		return errors.New("usage: stillproof embed --key KEYFILE PHOTO RECEIPT > OUT.jpg")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	photo, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := readReceipt(fs.Arg(1))
	if err != nil {
		return err
	}
	chain, err := embed.SelfSigned(key)
	if err != nil {
		return err
	}
	b, err := embed.Embed(photo, r, key, chain)
	if err != nil {
		return err
	}
	_, err = out.Write(b)
	return err
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path the user asked for
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return key, nil
}

func readReceipt(path string) (receipt.Receipt, error) {
	var r receipt.Receipt
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path the user asked for
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("receipt: %w", err)
	}
	return r, nil
}
