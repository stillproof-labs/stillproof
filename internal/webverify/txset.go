package webverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// accountKey decodes a G… account address to its Ed25519 key.
func accountKey(addr string) ([]byte, error) {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(addr)
	if err != nil || len(b) != 35 || b[0] != 6<<3 {
		return nil, errors.New("not a G… address")
	}
	if crc16(b[:33]) != binary.LittleEndian.Uint16(b[33:]) {
		return nil, errors.New("bad address checksum")
	}
	return b[1:33], nil
}

// crc16 is CRC-16/XMODEM, the strkey checksum.
func crc16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c ^= uint16(x) << 8
		for range 8 {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}

// findMemo finds, in the XDR of a transaction set, the transaction from key
// whose hash under passphrase is txHash, and returns its MEMO_HASH (nil for
// any other memo). The hash commits to the source and memo, so whatever
// bytes hash to txHash are that transaction. Only plain (not fee-bump)
// v1 envelopes with an Ed25519 source are found.
func findMemo(set []byte, passphrase string, txHash [32]byte, key []byte) (*[32]byte, error) {
	netID := sha256.Sum256([]byte(passphrase))
	// ENVELOPE_TYPE_TX, then the source as KEY_TYPE_ED25519.
	pattern := append([]byte{0, 0, 0, 2, 0, 0, 0, 0}, key...)
	for from := 0; ; {
		i := bytes.Index(set[from:], pattern)
		if i < 0 {
			return nil, fmt.Errorf("the bundle's transaction set has no transaction %x from that account", txHash)
		}
		start := from + i + 4 // the Transaction, after the envelope type
		from = start
		memo, pre, ok := memoOf(set[start:])
		if !ok {
			continue
		}
		h := sha256.New()
		h.Write(netID[:])
		h.Write([]byte{0, 0, 0, 2})
		tx := set[start:]
		h.Write(tx[:pre])
		for n := pre; n+4 <= len(tx); n += 4 {
			h.Write(tx[n : n+4])
			c, err := h.(hash.Cloner).Clone()
			if err != nil {
				return nil, err
			}
			if bytes.Equal(c.Sum(nil), txHash[:]) {
				return memo, nil
			}
		}
	}
}

// memoOf reads a Transaction's XDR up to its memo. It returns the MEMO_HASH
// (nil for another memo) and how many bytes come before the operation count.
func memoOf(tx []byte) (memo *[32]byte, n int, ok bool) {
	r := xdrReader{b: tx, off: 36 + 4 + 8} // source, fee, seqNum
	switch r.u32() {
	case 0:
	case 1:
		r.skip(16)
	case 2:
		if r.u32() == 1 {
			r.skip(16) // timeBounds
		}
		if r.u32() == 1 {
			r.skip(8) // ledgerBounds
		}
		if r.u32() == 1 {
			r.skip(8) // minSeqNum
		}
		r.skip(8 + 4) // minSeqAge, minSeqLedgerGap
		signers := r.u32()
		if signers > 2 {
			return nil, 0, false
		}
		for range signers {
			switch r.u32() {
			case 0, 1, 2:
				r.skip(32)
			case 3:
				r.skip(32)
				if !r.opaque(64) {
					return nil, 0, false
				}
			default:
				return nil, 0, false
			}
		}
	default:
		return nil, 0, false
	}
	switch r.u32() {
	case 0:
	case 1:
		if !r.opaque(28) {
			return nil, 0, false
		}
	case 2:
		r.skip(8)
	case 3:
		if r.off+32 <= len(r.b) {
			memo = new([32]byte)
			copy(memo[:], r.b[r.off:])
		}
		r.skip(32)
	case 4:
		r.skip(32)
	default:
		return nil, 0, false
	}
	return memo, r.off, !r.bad
}

type xdrReader struct {
	b   []byte
	off int
	bad bool
}

func (r *xdrReader) skip(n int) {
	if r.off+n > len(r.b) {
		r.bad = true
	}
	r.off += n
}

func (r *xdrReader) u32() uint32 {
	if r.bad || r.off+4 > len(r.b) {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

// opaque skips a variable-length opaque or string of at most max bytes.
func (r *xdrReader) opaque(max uint32) bool {
	n := r.u32()
	if n > max {
		return false
	}
	r.skip(int(n+3) &^ 3)
	return !r.bad
}
