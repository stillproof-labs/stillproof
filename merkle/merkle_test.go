package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func leaf(data []byte) Hash { return sha256.Sum256(append([]byte{0}, data...)) }

// The eight leaves and root from Certificate Transparency's RFC 6962 tests.
var ctLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}

func TestRootMatchesRFC6962Vectors(t *testing.T) {
	var leaves []Hash
	for _, h := range ctLeaves {
		b, _ := hex.DecodeString(h)
		leaves = append(leaves, leaf(b))
	}
	one, all := Root(leaves[:1]), Root(leaves)
	if got := hex.EncodeToString(one[:]); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Errorf("one leaf: %s", got)
	}
	if got := hex.EncodeToString(all[:]); got != "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328" {
		t.Errorf("eight leaves: %s", got)
	}
}

func TestEveryProofVerifiesAndTamperingFails(t *testing.T) {
	for size := 1; size <= 33; size++ {
		leaves := make([]Hash, size)
		for i := range leaves {
			leaves[i] = leaf([]byte{byte(i), byte(size)})
		}
		root := Root(leaves)
		for i := range leaves {
			p := Proof(leaves, i)
			if err := Verify(leaves[i], i, size, p, root); err != nil {
				t.Fatalf("size %d index %d: %v", size, i, err)
			}
			if Verify(leaves[i], (i+1)%size, size, p, root) == nil && size > 1 {
				t.Fatalf("size %d index %d: accepted at the wrong index", size, i)
			}
			if Verify(leaf([]byte("other")), i, size, p, root) == nil {
				t.Fatalf("size %d index %d: accepted another leaf", size, i)
			}
			if len(p) > 0 && Verify(leaves[i], i, size, p[:len(p)-1], root) == nil {
				t.Fatalf("size %d index %d: accepted a short proof", size, i)
			}
		}
	}
}
