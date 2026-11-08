package main

import (
	"strings"
	"testing"

	"github.com/stillproof-labs/stillproof/attest"
	"github.com/stillproof-labs/stillproof/receipt"
)

func TestPrintVerdictShowsTheLevel(t *testing.T) {
	for level, want := range map[string]string{
		attest.LevelSoftware:      "(software key, not attested)",
		attest.LevelStrongBox:     "(hardware key, attested strongbox)",
		attest.LevelSecureEnclave: "(hardware key, attested secure-enclave)",
	} {
		var b strings.Builder
		printVerdict(&b, receipt.Verdict{Key: strings.Repeat("04", 65), Level: level})
		if !strings.Contains(b.String(), want) {
			t.Errorf("%s: %q lacks %q", level, b.String(), want)
		}
	}
}
