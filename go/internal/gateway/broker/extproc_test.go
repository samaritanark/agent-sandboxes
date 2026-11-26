package broker

import (
	"bytes"
	"io"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

// fakeStream plays Envoy's side of one ext_proc stream: it hands Process the requests in order
// and keeps its responses.
type fakeStream struct {
	grpc.ServerStream
	in  []*extprocv3.ProcessingRequest
	out []*extprocv3.ProcessingResponse
}

func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(f.in) == 0 {
		return nil, io.EOF
	}
	r := f.in[0]
	f.in = f.in[1:]
	return r, nil
}

func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.out = append(f.out, r)
	return nil
}

func headers(kv ...string) *corev3.HeaderMap {
	m := &corev3.HeaderMap{}
	for i := 0; i < len(kv); i += 2 {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return m
}

func reqHeaders(kv ...string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: headers(kv...)}}}
}

func respHeaders(kv ...string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: headers(kv...)}}}
}

func respBody(b []byte, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: b, EndOfStream: end}}}
}

func bodyOut(r *extprocv3.ProcessingResponse) []byte {
	return r.GetResponseBody().GetResponse().GetBodyMutation().GetBody()
}

const ghReal = "ghp_realtoken1234567890"

var wsRequest = []string{":authority", "api.github.com", ":path", "/ws", ":method", "GET", "authorization", "Bearer " + phGH,
	"connection", "Upgrade", "upgrade", "websocket"}

func process(t *testing.T, reqs ...*extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, []Event) {
	t.Helper()
	var evs []Event
	s := &Server{Record: func(e Event) { evs = append(evs, e) }}
	s.SetBindings(set(t))
	st := &fakeStream{in: reqs}
	if err := s.Process(st); err != nil {
		t.Fatal(err)
	}
	return st.out, evs
}

// TestProcessWebSocket: after a 101 the body is WebSocket frames, scrubbed as frames.
func TestProcessWebSocket(t *testing.T) {
	msg := []byte("token=" + ghReal)
	f := serverFrame(true, opText, msg)
	out, evs := process(t, reqHeaders(wsRequest...), respHeaders(":status", "101", "upgrade", "websocket"),
		respBody(f[:9], false), respBody(f[9:], false))
	if len(out) != 4 || out[0].GetImmediateResponse() != nil || out[1].GetImmediateResponse() != nil {
		t.Fatalf("%v", out)
	}
	got := append(bodyOut(out[2]), bodyOut(out[3])...)
	ms := parseClient(t, got)
	if len(ms) != 1 || string(ms[0].payload) != "token="+phGH {
		t.Errorf("%q", got)
	}
	kinds := map[string]int{}
	for _, e := range evs {
		kinds[e.Type]++
	}
	if kinds["credential_injected"] != 1 || kinds["credential_reflection"] != 1 {
		t.Errorf("%v", kinds)
	}
}

// TestProcessNotWebSocket: a body that is not after a 101 is scrubbed as bytes, never parsed as frames.
func TestProcessNotWebSocket(t *testing.T) {
	out, _ := process(t, reqHeaders(wsRequest...), respHeaders(":status", "200"), respBody([]byte("x "+ghReal), true))
	if string(bodyOut(out[2])) != "x "+phGH {
		t.Errorf("%q", bodyOut(out[2]))
	}
}

func TestProcessWebSocketRefusals(t *testing.T) {
	// a server that accepts an extension anyway
	out, evs := process(t, reqHeaders(wsRequest...), respHeaders(":status", "101", "sec-websocket-extensions", "permessage-deflate"))
	if out[1].GetImmediateResponse() == nil || evs[len(evs)-1].Type != "refused" {
		t.Errorf("an extension: %v", out[1])
	}
	// a frame with an extension's bit: the stream is cut, and nothing of it is sent
	bad := []byte{0xC1, byte(len(ghReal))}
	bad = append(bad, ghReal...)
	out, _ = process(t, reqHeaders(wsRequest...), respHeaders(":status", "101"), respBody(bad, false))
	if out[2].GetImmediateResponse() == nil || bytes.Contains(bodyOut(out[2]), []byte(ghReal)) {
		t.Errorf("a reserved bit: %v", out[2])
	}
	// the stream ending inside a frame
	f := serverFrame(true, opText, []byte("x"+ghReal))
	out, _ = process(t, reqHeaders(wsRequest...), respHeaders(":status", "101"), respBody(f[:5], true))
	if out[2].GetImmediateResponse() == nil {
		t.Errorf("a cut frame: %v", out[2])
	}
}
