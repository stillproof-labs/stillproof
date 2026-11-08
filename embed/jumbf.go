package embed

import (
	"encoding/binary"
	"errors"
)

// JUMBF (ISO/IEC 19566-5) superbox types used by C2PA: four ASCII bytes
// followed by the ISO suffix 0011-0010-8000-00AA00389B71.
var (
	uuidStore      = c2paUUID("c2pa")
	uuidManifest   = c2paUUID("c2ma")
	uuidAssertions = c2paUUID("c2as")
	uuidClaim      = c2paUUID("c2cl")
	uuidSignature  = c2paUUID("c2cs")
	uuidCBOR       = c2paUUID("cbor")
	uuidJSON       = c2paUUID("json")
)

func c2paUUID(s string) (u [16]byte) {
	copy(u[:], s)
	copy(u[4:], []byte{0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71})
	return u
}

// isoBox encodes a box: LBox, TBox, payload.
func isoBox(typ string, payload ...[]byte) []byte {
	n := 8
	for _, p := range payload {
		n += len(p)
	}
	b := binary.BigEndian.AppendUint32(make([]byte, 0, n), uint32(n)) //nolint:gosec // G115: bounded by the JPEG segment limit
	b = append(b, typ...)
	for _, p := range payload {
		b = append(b, p...)
	}
	return b
}

// superbox encodes a requestable, labelled JUMBF superbox.
func superbox(uuid [16]byte, label string, content ...[]byte) []byte {
	desc := isoBox("jumd", uuid[:], []byte{0x03}, []byte(label), []byte{0})
	return isoBox("jumb", append([][]byte{desc}, content...)...)
}

// box is a parsed ISO box.
type box struct {
	typ     string
	payload []byte
	raw     []byte // header and payload
}

var errBox = errors.New("malformed JUMBF")

// parseBoxes splits b into consecutive boxes.
func parseBoxes(b []byte) ([]box, error) {
	var out []box
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errBox
		}
		n, hdr := uint64(binary.BigEndian.Uint32(b)), uint64(8)
		switch n {
		case 0:
			n = uint64(len(b))
		case 1:
			if len(b) < 16 {
				return nil, errBox
			}
			n, hdr = binary.BigEndian.Uint64(b[8:]), 16
		}
		if n < hdr || n > uint64(len(b)) {
			return nil, errBox
		}
		out = append(out, box{typ: string(b[4:8]), payload: b[hdr:n], raw: b[:n]})
		b = b[n:]
	}
	return out, nil
}

// jumb is a parsed JUMBF superbox.
type jumb struct {
	uuid    [16]byte
	label   string
	content []box
}

func parseSuperbox(bx box) (jumb, error) {
	var j jumb
	if bx.typ != "jumb" {
		return j, errBox
	}
	boxes, err := parseBoxes(bx.payload)
	if err != nil {
		return j, err
	}
	if len(boxes) == 0 || boxes[0].typ != "jumd" || len(boxes[0].payload) < 17 {
		return j, errBox
	}
	d := boxes[0].payload
	copy(j.uuid[:], d)
	if d[16]&0x02 != 0 {
		rest := d[17:]
		end := 0
		for end < len(rest) && rest[end] != 0 {
			end++
		}
		if end == len(rest) {
			return j, errBox
		}
		j.label = string(rest[:end])
	}
	j.content = boxes[1:]
	return j, nil
}

// children returns the superboxes in j's content.
func (j jumb) children() ([]jumb, error) {
	var out []jumb
	for _, c := range j.content {
		if c.typ != "jumb" {
			continue
		}
		s, err := parseSuperbox(c)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// data returns the payload of j's first content box of type typ.
func (j jumb) data(typ string) ([]byte, bool) {
	for _, c := range j.content {
		if c.typ == typ {
			return c.payload, true
		}
	}
	return nil, false
}
