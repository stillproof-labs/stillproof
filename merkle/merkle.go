// Package merkle is the RFC 6962 Merkle tree hash with inclusion proofs
// (SPEC.md §3). Leaves are leaf hashes, SHA-256(0x00 ‖ data).
package merkle

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

// Hash is a 32-byte tree node.
type Hash = [32]byte

// ErrProof means an inclusion proof does not lead to the root.
var ErrProof = errors.New("merkle: proof does not match root")

func node(l, r Hash) Hash {
	b := make([]byte, 0, 65)
	b = append(append(append(b, 1), l[:]...), r[:]...)
	return sha256.Sum256(b)
}

// split is the largest power of two smaller than n (n >= 2).
func split(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// Root is the tree hash of leaves. The empty tree is SHA-256("").
func Root(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return node(Root(leaves[:k]), Root(leaves[k:]))
}

// Proof is the audit path for leaves[i], leaf side first.
func Proof(leaves []Hash, i int) []Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if i < k {
		return append(Proof(leaves[:k], i), Root(leaves[k:]))
	}
	return append(Proof(leaves[k:], i-k), Root(leaves[:k]))
}

// Verify checks that leaf is at index in a tree of size leaves with root,
// as in RFC 9162 §2.1.3.2.
func Verify(leaf Hash, index, size int, proof []Hash, root Hash) error {
	if index < 0 || index >= size {
		return ErrProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrProof
		}
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrProof
	}
	return nil
}
