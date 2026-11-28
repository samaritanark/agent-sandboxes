package envoyconf

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"time"
)

// The WebSocket half of the fake API server: kubectl exec's v5.channel.k8s.io stream, reduced to
// raw frames. The server says whether the credential reached it in a first text message, then by
// mode: "down" sends a long binary transfer in frames of every length encoding, "slow" sends a
// trickle with a pause that outlasts the broker's timeouts, and "up" counts what the client sends
// and reports it when the client closes.

// wsChunk is one server frame of a download, sent after a pause.
type wsChunk struct {
	pause time.Duration
	size  int
}

func wsPlan(mode string) []wsChunk {
	var plan []wsChunk
	switch mode {
	case "down":
		sizes := []int{100, 125, 126, 30000, 65535, 65536, 70000, 1 << 20}
		for total, i := 0, 0; total < 64<<20; i++ {
			n := min(sizes[i%len(sizes)], 64<<20-total)
			plan = append(plan, wsChunk{size: n})
			total += n
		}
	case "slow":
		for i := 0; i < 20; i++ {
			pause := 300 * time.Millisecond
			if i == 10 {
				pause = 7 * time.Second
			}
			plan = append(plan, wsChunk{pause: pause, size: 2000})
		}
	}
	return plan
}

// wsPattern is the transfer's bytes: not all one value, so a dropped or reordered piece shows.
func wsPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ byte(i>>9)
	}
	return b
}

func wsSum(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

// wsExpect is what the client should receive for a download mode.
func wsExpect(mode string) (want struct {
	n   int
	sum uint32
}) {
	total := 0
	for _, c := range wsPlan(mode) {
		total += c.size
	}
	b := wsPattern(total)
	want.n, want.sum = len(b), wsSum(b)
	return
}

func wsServerFrame(op byte, p []byte) []byte {
	h := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		h = append(h, byte(n))
	case n < 1<<16:
		h = append(h, 126, byte(n>>8), byte(n))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	return append(h, p...)
}

func wsClientFrame(op byte, p []byte) []byte {
	h := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 1<<16:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	h = append(h, mask[:]...)
	for i, c := range p {
		h = append(h, c^mask[i%4])
	}
	return h
}

// wsRead reads one frame, unmasking a client's.
func wsRead(r *bufio.Reader) (op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	op = h[0] & 0x0f
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, err = io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, err = io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	if err != nil {
		return
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// wsReadAll reads a server's frames up to its close: the binary bytes' count and checksum, and the
// last text message.
func wsReadAll(r *bufio.Reader) (n int, sum uint32, text string, err error) {
	for {
		op, p, e := wsRead(r)
		if e != nil {
			return n, sum, text, fmt.Errorf("after %d bytes: %w", n, e)
		}
		switch op {
		case 0x1:
			text = string(p)
		case 0x2, 0x0:
			n += len(p)
			sum = crc32.Update(sum, crc32.IEEETable, p)
		case 0x8:
			return n, sum, text, nil
		}
	}
}

func wsExecServer(w http.ResponseWriter, r *http.Request) {
	h := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	auth := "auth=none"
	if r.Header.Get("Authorization") == "Bearer "+kubeToken {
		auth = "auth=token"
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n"+
		"Sec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n", base64.StdEncoding.EncodeToString(h[:]))
	closeFrame := wsServerFrame(0x8, []byte{0x03, 0xe8})
	mode := r.URL.Query().Get("mode")
	if mode == "up" {
		rw.Flush()
		got, sum := 0, uint32(0)
		for {
			op, p, err := wsRead(rw.Reader)
			if err != nil {
				return
			}
			if op == 0x8 {
				break
			}
			got += len(p)
			sum = crc32.Update(sum, crc32.IEEETable, p)
		}
		rw.Write(wsServerFrame(0x1, []byte(fmt.Sprintf("%s got=%d sum=%x", auth, got, sum))))
		rw.Write(closeFrame)
		rw.Flush()
		return
	}
	rw.Write(wsServerFrame(0x1, []byte(auth)))
	plan := wsPlan(mode)
	total := 0
	for _, ch := range plan {
		total += ch.size
	}
	data, off := wsPattern(total), 0
	for _, ch := range plan {
		if ch.pause > 0 {
			rw.Flush()
			time.Sleep(ch.pause)
		}
		if _, err := rw.Write(wsServerFrame(0x2, data[off:off+ch.size])); err != nil {
			return
		}
		off += ch.size
	}
	// and closes at once, as an API server does when the command ends
	rw.Write(closeFrame)
	rw.Flush()
}
