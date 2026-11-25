package gitobj

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Pack is a pack file and its version 2 index.
type Pack struct {
	data    []byte
	idLen   int
	ids     []byte // sorted, idLen each
	offsets []uint64
}

// LoadPack checks a pack's and its index's headers and trailers and loads the index.
func LoadPack(pack, idx []byte, idLen int) (*Pack, error) {
	if len(pack) < 12+idLen || string(pack[:4]) != "PACK" {
		return nil, errors.New("not a pack")
	}
	if v := binary.BigEndian.Uint32(pack[4:8]); v != 2 && v != 3 {
		return nil, fmt.Errorf("pack version %d", v)
	}
	h := hasher(idLen)
	h.Write(pack[:len(pack)-idLen])
	if !bytes.Equal(h.Sum(nil), pack[len(pack)-idLen:]) {
		return nil, errors.New("pack checksum mismatch")
	}
	n := int(binary.BigEndian.Uint32(pack[8:12]))
	if len(idx) < 8+256*4 || !bytes.Equal(idx[:4], []byte{0xff, 't', 'O', 'c'}) || binary.BigEndian.Uint32(idx[4:8]) != 2 {
		return nil, errors.New("not a version 2 pack index")
	}
	h = hasher(idLen)
	h.Write(idx[:len(idx)-idLen])
	if !bytes.Equal(h.Sum(nil), idx[len(idx)-idLen:]) {
		return nil, errors.New("pack index checksum mismatch")
	}
	if int(binary.BigEndian.Uint32(idx[8+255*4:8+256*4])) != n {
		return nil, errors.New("pack index and pack disagree on the object count")
	}
	need := 8 + 256*4 + n*(idLen+4+4) + 2*idLen
	if len(idx) < need {
		return nil, errors.New("pack index truncated")
	}
	if !bytes.Equal(idx[len(idx)-2*idLen:len(idx)-idLen], pack[len(pack)-idLen:]) {
		return nil, errors.New("pack index names another pack")
	}
	p := &Pack{data: pack, idLen: idLen}
	o := 8 + 256*4
	p.ids = idx[o : o+n*idLen]
	o += n*idLen + n*4 // ids, then CRCs
	off32 := idx[o : o+n*4]
	large := idx[o+n*4 : len(idx)-2*idLen]
	prev := []byte(nil)
	for i := 0; i < n; i++ {
		id := p.ids[i*idLen : (i+1)*idLen]
		if prev != nil && bytes.Compare(prev, id) >= 0 {
			return nil, errors.New("pack index is not sorted")
		}
		prev = id
		v := uint64(binary.BigEndian.Uint32(off32[i*4:]))
		if v&0x80000000 != 0 {
			j := int(v &^ 0x80000000)
			if (j+1)*8 > len(large) {
				return nil, errors.New("pack index large offset out of range")
			}
			v = binary.BigEndian.Uint64(large[j*8:])
		}
		if v < 12 || v >= uint64(len(pack)-idLen) {
			return nil, errors.New("pack index offset out of range")
		}
		p.offsets = append(p.offsets, v)
	}
	return p, nil
}

func (p *Pack) find(id []byte) (uint64, bool) {
	n := len(p.offsets)
	lo, hi := 0, n
	for lo < hi {
		m := (lo + hi) / 2
		c := bytes.Compare(p.ids[m*p.idLen:(m+1)*p.idLen], id)
		if c == 0 {
			return p.offsets[m], true
		}
		if c < 0 {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return 0, false
}

// header parses the object header at off: type, inflated size, and where the data starts.
func (p *Pack) header(off uint64) (int, uint64, uint64, error) {
	d := p.data[:len(p.data)-p.idLen]
	if off >= uint64(len(d)) {
		return 0, 0, 0, errors.New("offset out of range")
	}
	c := d[off]
	typ := int(c>>4) & 7
	size := uint64(c & 15)
	shift := 4
	off++
	for c&0x80 != 0 {
		if off >= uint64(len(d)) || shift > 56 {
			return 0, 0, 0, errors.New("bad object header")
		}
		c = d[off]
		size |= uint64(c&0x7f) << shift
		shift += 7
		off++
	}
	return typ, size, off, nil
}

// readAt resolves the object at off (following deltas) to its kind and body. base is used for
// REF_DELTA bases outside this pack, which a non-thin pack never has.
func (p *Pack) readAt(off uint64, depth int, base *Store) (string, []byte, error) {
	if depth > MaxDeltaDepth {
		return "", nil, errors.New("delta chain too deep")
	}
	typ, size, data, err := p.header(off)
	if err != nil {
		return "", nil, err
	}
	if size > MaxObjectBytes {
		return "", nil, errors.New("object too large")
	}
	d := p.data[:len(p.data)-p.idLen]
	switch typ {
	case 1, 2, 3, 4:
		b, err := inflate(bytes.NewReader(d[data:]), int64(size))
		if err != nil || uint64(len(b)) != size {
			return "", nil, errors.New("object data does not inflate to its size")
		}
		return kindNames[typ], b, nil
	case 6, 7:
		var kind string
		var src []byte
		if typ == 6 {
			c := d[data]
			rel := uint64(c & 0x7f)
			data++
			for c&0x80 != 0 {
				if data >= uint64(len(d)) {
					return "", nil, errors.New("bad delta offset")
				}
				c = d[data]
				rel = (rel+1)<<7 | uint64(c&0x7f)
				data++
			}
			if rel == 0 || rel > off {
				return "", nil, errors.New("delta base offset out of range")
			}
			kind, src, err = p.readAt(off-rel, depth+1, base)
		} else {
			if data+uint64(p.idLen) > uint64(len(d)) {
				return "", nil, errors.New("truncated delta base id")
			}
			bid := d[data : data+uint64(p.idLen)]
			data += uint64(p.idLen)
			if o, ok := p.find(bid); ok {
				kind, src, err = p.readAt(o, depth+1, base)
			} else if base != nil {
				kind, src, err = base.Read(hex.EncodeToString(bid))
			} else {
				err = errors.New("delta base not in the pack")
			}
		}
		if err != nil {
			return "", nil, err
		}
		delta, err := inflate(bytes.NewReader(d[data:]), int64(size))
		if err != nil || uint64(len(delta)) != size {
			return "", nil, errors.New("delta does not inflate to its size")
		}
		out, err := applyDelta(src, delta)
		return kind, out, err
	}
	return "", nil, fmt.Errorf("unknown pack object type %d", typ)
}

func deltaSize(b []byte) (uint64, []byte, error) {
	var v uint64
	shift := 0
	for i, c := range b {
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b[i+1:], nil
		}
		shift += 7
		if shift > 63 {
			break
		}
	}
	return 0, nil, errors.New("bad delta size")
}

// applyDelta is git's delta format: source size, target size, then copy and insert instructions.
func applyDelta(src, delta []byte) ([]byte, error) {
	ss, rest, err := deltaSize(delta)
	if err != nil || ss != uint64(len(src)) {
		return nil, errors.New("delta source size mismatch")
	}
	ts, rest, err := deltaSize(rest)
	if err != nil || ts > MaxObjectBytes {
		return nil, errors.New("bad delta target size")
	}
	out := make([]byte, 0, ts)
	for len(rest) > 0 {
		op := rest[0]
		rest = rest[1:]
		if op&0x80 != 0 {
			var off, n uint64
			for i := 0; i < 4; i++ {
				if op&(1<<i) != 0 {
					if len(rest) == 0 {
						return nil, errors.New("truncated delta")
					}
					off |= uint64(rest[0]) << (8 * i)
					rest = rest[1:]
				}
			}
			for i := 0; i < 3; i++ {
				if op&(0x10<<i) != 0 {
					if len(rest) == 0 {
						return nil, errors.New("truncated delta")
					}
					n |= uint64(rest[0]) << (8 * i)
					rest = rest[1:]
				}
			}
			if n == 0 {
				n = 0x10000
			}
			if off+n > uint64(len(src)) || uint64(len(out))+n > ts {
				return nil, errors.New("delta copy out of range")
			}
			out = append(out, src[off:off+n]...)
		} else if op != 0 {
			n := int(op)
			if n > len(rest) || uint64(len(out)+n) > ts {
				return nil, errors.New("delta insert out of range")
			}
			out = append(out, rest[:n]...)
			rest = rest[n:]
		} else {
			return nil, errors.New("reserved delta opcode")
		}
	}
	if uint64(len(out)) != ts {
		return nil, errors.New("delta result size mismatch")
	}
	return out, nil
}

// VerifyPack checks a VM-origin pack and its index as git index-pack would: both trailers, and
// every object the index lists resolves (within the pack: a thin pack is refused) and hashes to
// the id the index gives it. It returns the ids.
func VerifyPack(pack, idx []byte, idLen int) ([]string, error) {
	p, err := LoadPack(pack, idx, idLen)
	if err != nil {
		return nil, err
	}
	if int(binary.BigEndian.Uint32(pack[8:12])) != len(p.offsets) {
		return nil, errors.New("object count mismatch")
	}
	var ids []string
	for i, off := range p.offsets {
		kind, body, err := p.readAt(off, 0, nil)
		if err != nil {
			return nil, fmt.Errorf("object at %d: %w", off, err)
		}
		want := hex.EncodeToString(p.ids[i*idLen : (i+1)*idLen])
		if got := ID(kind, body, idLen); got != want {
			return nil, fmt.Errorf("object at %d hashes to %s, index says %s", off, got, want)
		}
		ids = append(ids, want)
	}
	return ids, nil
}
