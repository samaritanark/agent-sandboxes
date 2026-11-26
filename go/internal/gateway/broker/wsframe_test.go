package broker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

// serverFrame encodes a frame as a server would send it (independent of the scrubber's encoder).
func serverFrame(fin bool, op byte, p []byte) []byte {
	var b bytes.Buffer
	b0 := op
	if fin {
		b0 |= 0x80
	}
	b.WriteByte(b0)
	switch {
	case len(p) <= 125:
		b.WriteByte(byte(len(p)))
	case len(p) <= 0xffff:
		b.WriteByte(126)
		binary.Write(&b, binary.BigEndian, uint16(len(p)))
	default:
		b.WriteByte(127)
		binary.Write(&b, binary.BigEndian, uint64(len(p)))
	}
	b.Write(p)
	return b.Bytes()
}

type wsMsg struct {
	op      byte
	payload []byte
}

// parseClient reads frames as a strict client would and reassembles messages; control frames are
// returned in place, in order.
func parseClient(t *testing.T, b []byte) []wsMsg {
	t.Helper()
	var out []wsMsg
	var cur *wsMsg
	for len(b) > 0 {
		if len(b) < 2 {
			t.Fatalf("a truncated header")
		}
		b0, b1 := b[0], b[1]
		if b1&0x80 != 0 || b0&0x70 != 0 {
			t.Fatalf("masked or reserved bits: %x %x", b0, b1)
		}
		n, i := uint64(b1&0x7f), 2
		switch n {
		case 126:
			n, i = uint64(binary.BigEndian.Uint16(b[2:])), 4
			if n < 126 {
				t.Fatalf("a non-minimal length")
			}
		case 127:
			n, i = binary.BigEndian.Uint64(b[2:]), 10
			if n <= 0xffff {
				t.Fatalf("a non-minimal length")
			}
		}
		if uint64(len(b)-i) < n {
			t.Fatalf("a truncated payload")
		}
		p := b[i : i+int(n)]
		b = b[i+int(n):]
		op, fin := b0&0x0f, b0&0x80 != 0
		switch op {
		case opClose, opPing, opPong:
			if !fin || n > 125 {
				t.Fatalf("a bad control frame")
			}
			out = append(out, wsMsg{op, append([]byte(nil), p...)})
		case opText, opBin:
			if cur != nil {
				t.Fatalf("a message inside a message")
			}
			cur = &wsMsg{op, append([]byte(nil), p...)}
		case opCont:
			if cur == nil {
				t.Fatalf("a continuation outside a message")
			}
			cur.payload = append(cur.payload, p...)
		default:
			t.Fatalf("opcode %x", op)
		}
		if fin && cur != nil && op != opClose && op != opPing && op != opPong {
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		t.Fatalf("an unfinished message")
	}
	return out
}

func TestFrameScrubberRandom(t *testing.T) {
	const secret = "s3cr3t-VALUE-0123456789"
	const ph = "sbxph_placeholder_that_is_longer_than_the_value"
	reps := []Replacement{{From: []byte(secret), To: []byte(ph)}}
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 400; round++ {
		var stream []byte
		var want []wsMsg
		hits := 0
		for m := rng.Intn(5) + 1; m > 0; m-- {
			// a message with the value at random places, sometimes none, sometimes long
			var body []byte
			for k := rng.Intn(4); k >= 0; k-- {
				filler := bytes.Repeat([]byte{byte('a' + rng.Intn(26))}, rng.Intn([]int{10, 200, 70000}[rng.Intn(3)]))
				body = append(body, filler...)
				if rng.Intn(2) == 0 {
					body = append(body, secret...)
					hits++
				}
			}
			op := byte(opText)
			if rng.Intn(3) == 0 {
				op = opBin
			}
			want = append(want, wsMsg{op, bytes.ReplaceAll(body, []byte(secret), []byte(ph))})
			// fragment it at random cuts, with pings between fragments
			for first, rest := true, body; ; first = false {
				cut := len(rest)
				if rng.Intn(2) == 0 && len(rest) > 0 {
					cut = rng.Intn(len(rest) + 1)
				}
				o := byte(opCont)
				if first {
					o = op
				}
				fin := cut == len(rest)
				stream = append(stream, serverFrame(fin, o, rest[:cut])...)
				rest = rest[cut:]
				if fin {
					break
				}
				if rng.Intn(3) == 0 {
					stream = append(stream, serverFrame(true, opPing, []byte("hb"))...)
				}
			}
		}
		// pings between fragments are delivered in place; compare the messages alone
		f := NewFrameScrubber(reps)
		var out []byte
		for rest := stream; len(rest) > 0; {
			n := 1 + rng.Intn([]int{3, 50, 5000}[rng.Intn(3)])
			if n > len(rest) {
				n = len(rest)
			}
			o, err := f.Write(rest[:n])
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			out = append(out, o...)
			rest = rest[n:]
		}
		if err := f.Close(); err != nil {
			t.Fatalf("round %d: close: %v", round, err)
		}
		var got []wsMsg
		for _, m := range parseClient(t, out) {
			if m.op != opPing {
				got = append(got, m)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("round %d: %d messages, want %d", round, len(got), len(want))
		}
		for i := range want {
			if got[i].op != want[i].op || !bytes.Equal(got[i].payload, want[i].payload) {
				t.Fatalf("round %d message %d: op %x len %d, want op %x len %d", round, i, got[i].op, len(got[i].payload), want[i].op, len(want[i].payload))
			}
		}
		if bytes.Contains(out, []byte(secret)) || f.Hits != hits {
			t.Fatalf("round %d: leaked %v, hits %d want %d", round, bytes.Contains(out, []byte(secret)), f.Hits, hits)
		}
	}
}

func TestFrameScrubberControl(t *testing.T) {
	reps := []Replacement{{From: []byte("secret-value"), To: []byte("PLACEHOLDER-THAT-IS-LONGER")}}
	f := NewFrameScrubber(reps)
	in := append(serverFrame(true, opPing, []byte("ping secret-value")), serverFrame(true, opClose, append([]byte{0x03, 0xe8}, "bye secret-value"...))...)
	out, err := f.Write(in)
	if err != nil {
		t.Fatal(err)
	}
	ms := parseClient(t, out)
	if len(ms) != 2 || string(ms[0].payload) != "ping PLACEHOLDER-THAT-IS-LONGER" || !bytes.Equal(ms[1].payload, []byte{0x03, 0xe8}) || f.Hits != 2 {
		t.Errorf("%q hits %d", ms, f.Hits)
	}
	// a ping whose scrubbed payload would pass 125 bytes is cut to 125
	f = NewFrameScrubber([]Replacement{{From: []byte("v-12345678"), To: bytes.Repeat([]byte("P"), 100)}})
	out, _ = f.Write(serverFrame(true, opPing, []byte("v-12345678v-12345678")))
	if ms := parseClient(t, out); len(ms) != 1 || len(ms[0].payload) != 125 {
		t.Errorf("%d", len(ms[0].payload))
	}
	// exactly 126 bytes after scrubbing: one too many
	f = NewFrameScrubber([]Replacement{{From: []byte("v-12345678"), To: bytes.Repeat([]byte("P"), 100)}})
	out, _ = f.Write(serverFrame(true, opPong, append([]byte("v-12345678"), bytes.Repeat([]byte("."), 26)...)))
	if ms := parseClient(t, out); len(ms) != 1 || len(ms[0].payload) != 125 {
		t.Errorf("%d", len(ms[0].payload))
	}
	// a clean close passes untouched
	f = NewFrameScrubber(reps)
	c := serverFrame(true, opClose, append([]byte{0x03, 0xe8}, "normal"...))
	if out, _ := f.Write(c); !bytes.Equal(out, c) {
		t.Errorf("%x", out)
	}
}

func TestFrameScrubberRefuses(t *testing.T) {
	reps := []Replacement{{From: []byte("secret-value"), To: []byte("P")}}
	// an empty masked text frame whose mask bytes would read as two empty text frames, so a
	// scrubber that ignored the mask bit would find nothing else wrong
	masked := []byte{0x81, 0x80, 0x81, 0x00, 0x81, 0x00}
	for name, in := range map[string][]byte{
		"masked":                    masked,
		"reserved bits":             {0xC1, 0x01, 'a'},
		"unknown opcode":            serverFrame(true, 0x3, []byte("x")),
		"fragmented control":        serverFrame(false, opPing, []byte("x")),
		"oversized control":         serverFrame(true, opPong, bytes.Repeat([]byte("x"), 126)),
		"orphan continuation":       serverFrame(true, opCont, []byte("x")),
		"a message in a message":    append(serverFrame(false, opText, []byte("a")), serverFrame(true, opText, []byte("b"))...),
		"a 64-bit length's top bit": {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1},
	} {
		f := NewFrameScrubber(reps)
		if out, err := f.Write(in); !errors.Is(err, ErrUnframeable) {
			t.Errorf("%s: %x %v", name, out, err)
		}
	}
	// a stream cut inside a frame: nothing of the cut frame's value is sent, and Close says so
	f := NewFrameScrubber(reps)
	out, err := f.Write(serverFrame(true, opText, []byte("x secret-val"))[:12])
	if err != nil || bytes.Contains(out, []byte("secret-val")) || f.Close() == nil {
		t.Errorf("%q %v", out, err)
	}
	f = NewFrameScrubber(reps)
	f.Write([]byte{0x81})
	if f.Close() == nil {
		t.Error("half a header")
	}
}

// TestFrameScrubberStreams: a long frame is relayed as it arrives, not held until it ends.
func TestFrameScrubberStreams(t *testing.T) {
	f := NewFrameScrubber([]Replacement{{From: []byte("secret-value"), To: []byte("P")}})
	big := serverFrame(true, opBin, bytes.Repeat([]byte("z"), 100000))
	out, err := f.Write(big[:50000])
	if err != nil || len(out) < 49000 {
		t.Fatalf("held %d of 50000", 50000-len(out))
	}
	rest, _ := f.Write(big[50000:])
	if ms := parseClient(t, append(out, rest...)); len(ms) != 1 || len(ms[0].payload) != 100000 {
		t.Fatal(fmt.Sprint(len(ms)))
	}
}
