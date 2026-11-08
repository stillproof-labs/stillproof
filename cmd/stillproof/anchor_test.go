package main

import (
	"strings"
	"testing"

	"github.com/stillproof-labs/stillproof/receipt"
)

func TestPrintVerdictSaysHowTheAnchorWasChecked(t *testing.T) {
	for _, c := range []struct {
		v    receipt.Verdict
		want []string
	}{
		{receipt.Verdict{Anchored: receipt.CheckedValidators}, []string{"anchor checked against the validators' signatures"}},
		{receipt.Verdict{Anchored: receipt.CheckedHorizon}, []string{"anchor checked through Horizon"}},
		{receipt.Verdict{Anchored: receipt.CheckedHorizon, Note: "the validator proof was not checked: x"},
			[]string{"anchor checked through Horizon", "note: the validator proof was not checked: x"}},
	} {
		c.v.Key, c.v.Level = strings.Repeat("04", 65), "software"
		var b strings.Builder
		printVerdict(&b, c.v)
		for _, w := range c.want {
			if !strings.Contains(b.String(), w) {
				t.Errorf("%q lacks %q", b.String(), w)
			}
		}
		if c.v.Anchored == receipt.CheckedHorizon && strings.Contains(b.String(), "validators") {
			t.Errorf("%q mentions the validators", b.String())
		}
	}
}
