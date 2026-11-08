package embed

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestC2patool runs the official C2PA tool on an embedded JPEG. It needs
// C2PATOOL set to a c2patool binary; CI pins one.
func TestC2patool(t *testing.T) {
	tool := os.Getenv("C2PATOOL")
	if tool == "" {
		t.Skip("C2PATOOL not set")
	}
	k, chain := testKey(t)
	out, err := Embed(withHeaders(testJPEG(t), jfif, exif), testReceipt(3000), k, chain)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "embedded.jpg")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := exec.Command(tool, path).Output()
	if err != nil {
		t.Fatalf("c2patool: %v", err)
	}
	type status struct {
		Code string `json:"code"`
	}
	type assertion struct {
		Label string `json:"label"`
	}
	var rep struct {
		Active    string `json:"active_manifest"`
		Manifests map[string]struct {
			ClaimVersion int         `json:"claim_version"`
			Assertions   []assertion `json:"assertions"`
		} `json:"manifests"`
		State   string   `json:"validation_state"`
		Status  []status `json:"validation_status"`
		Results struct {
			Active struct {
				Success []status `json:"success"`
			} `json:"activeManifest"`
		} `json:"validation_results"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("c2patool output: %v\n%s", err, b)
	}
	m := rep.Manifests[rep.Active]
	codes := func(s []status) (c []string) {
		for _, x := range s {
			c = append(c, x.Code)
		}
		return c
	}
	switch {
	case rep.State != "Valid", m.ClaimVersion != 2,
		!slices.Equal(codes(rep.Status), []string{"signingCredential.untrusted"}),
		!slices.Contains(codes(rep.Results.Active.Success), "assertion.dataHash.match"),
		!slices.Contains(m.Assertions, assertion{LabelReceipt}):
		t.Fatalf("c2patool report:\n%s", b)
	}
}
