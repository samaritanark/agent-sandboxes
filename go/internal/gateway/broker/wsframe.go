package broker

import (
	"encoding/binary"
	"errors"
)

// FrameScrubber scrubs the server-to-client half of a WebSocket connection (RFC 6455), which Envoy
// hands the broker as raw bytes after the upgrade, in chunks that need not line up with frames.
// Replacing bytes in place would break each frame's length, and a value split across fragments
// would pass, so it parses the frames, runs each message's payload through one Scrubber across
// all its fragments, and re-frames what comes out. A message may come out in more or fewer
// fragments than it went in: an intermediary may refragment when no extension is in use (RFC
// 6455 5.4), and the broker strips the extensions offer and refuses a server that accepts one.
// Control frames (close, ping, pong) are scrubbed whole and kept within 125 bytes. Anything it
// cannot frame (a masked or reserved-bit frame, an unknown opcode, an oversized or fragmented
// control frame) is an error, and the connection is cut.
type FrameScrubber struct {
	reps []Replacement
	buf  []byte // input not yet consumed

	// the frame being read
	inFrame bool
	fin     bool
	op      byte
	left    uint64 // payload bytes of the current data frame still to come

	// the message being relayed
	msg     *Scrubber
	msgOp   byte // the message's opcode (text or binary)
	started bool // a fragment of it has been sent, so later ones are continuations

	Hits int
}

const (
	opCont  = 0x0
	opText  = 0x1
	opBin   = 0x2
	opClose = 0x8
	opPing  = 0x9
	opPong  = 0xA
)

// ErrUnframeable is returned for a stream the scrubber cannot safely relay.
var ErrUnframeable = errors.New("a WebSocket frame the broker cannot scrub")

func NewFrameScrubber(reps []Replacement) *FrameScrubber { return &FrameScrubber{reps: reps} }

// frame encodes one unmasked server frame.
func frame(fin bool, op byte, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	h := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		h = append(h, byte(n))
	case n < 1<<16:
		h = append(h, 126, byte(n>>8), byte(n))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	return append(h, payload...)
}

// header parses a frame header at the start of b: its first byte, payload length, and header
// size, or ok=false when more bytes are needed.
func header(b []byte) (b0 byte, n uint64, size int, ok bool, err error) {
	if len(b) < 2 {
		return 0, 0, 0, false, nil
	}
	b0 = b[0]
	if b[1]&0x80 != 0 || b0&0x70 != 0 {
		return 0, 0, 0, false, ErrUnframeable // masked (a server never masks) or an extension's bits
	}
	n, size = uint64(b[1]&0x7f), 2
	switch n {
	case 126:
		if len(b) < 4 {
			return 0, 0, 0, false, nil
		}
		n, size = uint64(binary.BigEndian.Uint16(b[2:4])), 4
	case 127:
		if len(b) < 10 {
			return 0, 0, 0, false, nil
		}
		n, size = binary.BigEndian.Uint64(b[2:10]), 10
		if n>>63 != 0 {
			return 0, 0, 0, false, ErrUnframeable
		}
	}
	return b0, n, size, true, nil
}

// Write takes the next chunk of the server's bytes and returns the frames to send on.
func (f *FrameScrubber) Write(chunk []byte) ([]byte, error) {
	f.buf = append(f.buf, chunk...)
	var out []byte
	for {
		if !f.inFrame {
			b0, n, size, ok, err := header(f.buf)
			if err != nil {
				return nil, err
			}
			if !ok {
				break
			}
			op := b0 & 0x0f
			fin := b0&0x80 != 0
			switch op {
			case opClose, opPing, opPong:
				if !fin || n > 125 {
					return nil, ErrUnframeable
				}
				if uint64(len(f.buf)-size) < n {
					return out, nil // a control frame is relayed whole
				}
				out = append(out, f.control(op, f.buf[size:size+int(n)])...)
				f.buf = f.buf[size+int(n):]
				continue
			case opText, opBin:
				if f.msg != nil {
					return nil, ErrUnframeable // a new message inside a fragmented one
				}
				f.msg, f.msgOp, f.started = NewScrubber(f.reps), op, false
			case opCont:
				if f.msg == nil {
					return nil, ErrUnframeable
				}
			default:
				return nil, ErrUnframeable
			}
			f.inFrame, f.fin, f.op, f.left = true, fin, op, n
			f.buf = f.buf[size:]
		}
		// a data frame's payload, as far as it has arrived
		take := uint64(len(f.buf))
		if take > f.left {
			take = f.left
		}
		piece := f.msg.Write(f.buf[:take])
		f.buf, f.left = f.buf[take:], f.left-take
		if f.left > 0 {
			if len(piece) > 0 {
				out = append(out, f.fragment(false, piece)...)
			}
			break
		}
		f.inFrame = false
		if !f.fin {
			if len(piece) > 0 {
				out = append(out, f.fragment(false, piece)...)
			}
			continue
		}
		piece = append(piece, f.msg.Close()...)
		out = append(out, f.fragment(true, piece)...)
		f.Hits += f.msg.Hits
		f.msg = nil
	}
	// what is left is part of a header: keep it, compacted
	f.buf = append([]byte(nil), f.buf...)
	return out, nil
}

// fragment sends part of the current message: its own opcode first, continuations after.
func (f *FrameScrubber) fragment(fin bool, payload []byte) []byte {
	op := byte(opCont)
	if !f.started {
		op, f.started = f.msgOp, true
	}
	return frame(fin, op, payload)
}

// control scrubs a control frame's payload whole. A close frame that carried a value keeps its
// status code and loses its reason; any other that grew past 125 bytes is cut to 125.
func (f *FrameScrubber) control(op byte, payload []byte) []byte {
	s := NewScrubber(f.reps)
	p := append(s.Write(payload), s.Close()...)
	f.Hits += s.Hits
	if s.Hits > 0 && op == opClose && len(payload) >= 2 {
		p = append([]byte(nil), payload[:2]...)
	}
	if len(p) > 125 {
		p = p[:125]
	}
	return frame(true, op, p)
}

// Close ends the stream: a frame cut off in the middle is an error (its bytes are not sent).
func (f *FrameScrubber) Close() error {
	if f.inFrame || len(f.buf) > 0 {
		return ErrUnframeable
	}
	return nil
}
