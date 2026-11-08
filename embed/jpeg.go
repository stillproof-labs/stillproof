package embed

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	markerAPP0  = 0xE0
	markerAPP1  = 0xE1
	markerAPP11 = 0xEB
	markerSOS   = 0xDA
	markerEOI   = 0xD9

	// maxChunk is the most JUMBF bytes per APP11 segment, as c2pa-rs writes.
	maxChunk = 64000
)

// ErrNotJPEG means the input isn't a well-formed JPEG header.
var ErrNotJPEG = errors.New("not a well-formed JPEG")

// segment is a marker segment: b[start:end], payload at b[data:end].
type segment struct {
	marker           byte
	start, data, end int
}

// segments parses the marker segments from SOI up to and including SOS.
func segments(b []byte) ([]segment, error) {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return nil, ErrNotJPEG
	}
	var out []segment
	for i := 2; ; {
		if i >= len(b) || b[i] != 0xFF {
			return nil, ErrNotJPEG
		}
		start := i
		for i < len(b) && b[i] == 0xFF { // fill bytes
			i++
		}
		if i >= len(b) {
			return nil, ErrNotJPEG
		}
		m := b[i]
		i++
		switch {
		case m == markerEOI:
			return out, nil
		case m == 0x01 || m >= 0xD0 && m <= 0xD7: // TEM, RSTn: no length
			out = append(out, segment{m, start, i, i})
			continue
		}
		if i+2 > len(b) {
			return nil, ErrNotJPEG
		}
		n := int(binary.BigEndian.Uint16(b[i:]))
		if n < 2 || i+n > len(b) {
			return nil, ErrNotJPEG
		}
		out = append(out, segment{m, start, i + 2, i + n})
		i += n
		if m == markerSOS {
			return out, nil
		}
	}
}

// c2paSegments finds the APP11 segments of the C2PA manifest store, the way
// c2pa-rs does: the first has CI "JP" and a jumb whose jumd type starts with
// "c2pa"; the rest share its En and continue its sequence number Z. It
// returns the indexes into segs and the reassembled JUMBF.
func c2paSegments(b []byte, segs []segment) ([]int, []byte, error) {
	var (
		idx   []int
		store []byte
		en    []byte
		z     uint32
	)
	for i, s := range segs {
		p := b[s.data:s.end]
		if s.marker != markerAPP11 || len(p) < 16 || p[0] != 'J' || p[1] != 'P' {
			continue
		}
		seq := binary.BigEndian.Uint32(p[4:8])
		if en != nil && bytes.Equal(p[2:4], en) {
			if seq != z+1 {
				return nil, nil, errors.New("C2PA APP11 segments out of sequence")
			}
			z = seq
			idx = append(idx, i)
			store = append(store, p[16:]...) // drop the repeated LBox and TBox
			continue
		}
		if len(p) >= 28 && string(p[12:16]) == "jumb" && string(p[24:28]) == "c2pa" {
			if en != nil {
				return nil, nil, errors.New("more than one C2PA manifest store")
			}
			if seq != 1 {
				return nil, nil, errors.New("C2PA APP11 segments out of sequence")
			}
			en, z = p[2:4], seq
			idx = append(idx, i)
			store = append(store, p[8:]...)
		}
	}
	if en != nil && binary.BigEndian.Uint32(store) == 1 {
		return nil, nil, errors.New("C2PA manifest store too large")
	}
	return idx, store, nil
}

// app11 splits a JUMBF box into APP11 segments (ISO/IEC 19566-5 / JPEG XT):
// each holds CI "JP", En, Z, and every one after the first repeats the box's
// LBox and TBox.
func app11(store []byte) []byte {
	var out []byte
	for z, off := uint32(1), 0; off < len(store); z++ {
		n := min(maxChunk, len(store)-off)
		hdr := 8
		if z > 1 {
			hdr += 8
		}
		out = append(out, 0xFF, markerAPP11)
		out = binary.BigEndian.AppendUint16(out, uint16(2+hdr+n)) //nolint:gosec // G115: at most 2+16+maxChunk
		out = append(out, 'J', 'P', 0x02, 0x11)
		out = binary.BigEndian.AppendUint32(out, z)
		if z > 1 {
			out = append(out, store[:8]...)
		}
		out = append(out, store[off:off+n]...)
		off += n
	}
	return out
}
