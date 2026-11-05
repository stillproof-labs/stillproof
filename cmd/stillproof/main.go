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

	"github.com/stillproof-labs/stillproof/claim"
	"github.com/stillproof-labs/stillproof/receipt"
)

const usage = `stillproof signs and verifies Stillproof claims.

Usage:
  stillproof verify [--json] FILE RECEIPT     check FILE against RECEIPT (SPEC.md §6)
  stillproof keygen KEYFILE                   write a new software P-256 key (hex)
  stillproof sign --key KEYFILE FILE          print a signed claim for FILE

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
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("usage: stillproof verify [--json] FILE RECEIPT")
	}
	file, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return err
	}
	var r receipt.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v := receipt.Verify(ctx, file, r, receipt.Horizon{})
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
	fmt.Fprintf(out, "  unchanged since signed by key %s… (%s key)\n", v.Key[:18], v.Level)
	fmt.Fprintf(out, "  existed no later than %s (ledger %d, %s)\n", v.NotAfter.Format(time.RFC3339), v.Ledger, v.Network)
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
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	d, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return fmt.Errorf("key: %w", err)
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
