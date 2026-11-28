package broker

import (
	"bytes"
	"io"
	"strings"
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

// TestProcessRateLimited: a spent credential answers 429, not 403, and records why.
func TestProcessRateLimited(t *testing.T) {
	var evs []Event
	srv := &Server{Record: func(e Event) { evs = append(evs, e) }}
	set, err := NewSet([]Binding{{Ref: "github", Hosts: []string{"api.github.com"}, Inject: "bearer", Placeholder: phGH, Value: ghReal, Burst: 1, RatePerMinute: 1}})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetBindings(set)
	req := reqHeaders(":authority", "api.github.com", ":path", "/", ":method", "GET", "authorization", "Bearer "+phGH)
	for i, want := range []int32{0, 429} {
		st := &fakeStream{in: []*extprocv3.ProcessingRequest{req}}
		srv.Process(st)
		got := int32(st.out[0].GetImmediateResponse().GetStatus().GetCode())
		if got != want {
			t.Errorf("request %d: status %d", i, got)
		}
	}
	if e := evs[len(evs)-1]; e.Type != "credential_rate_limited" || e.Ref != "github" {
		t.Errorf("%+v", e)
	}
}

// TestRawStream: kubectl exec over SPDY to a cluster has its token injected and its response
// headers scrubbed, and Envoy is told not to send its stream, which the broker does not parse.
func TestRawStream(t *testing.T) {
	req := reqHeaders(":authority", "kube-0.gw.sandbox.internal", ":path", "/api/v1/namespaces/a/pods/p/exec", ":method", "POST",
		"authorization", "Bearer "+phK, "connection", "Upgrade", "upgrade", "SPDY/3.1")
	out, _ := process(t, req, respHeaders(":status", "101", "x-echo", "eyJkubetoken"))
	if len(out) != 2 || out[0].GetImmediateResponse() != nil {
		t.Fatalf("%v", out)
	}
	if m := out[0].GetModeOverride(); m == nil || m.GetResponseBodyMode().String() != "NONE" || m.GetResponseHeaderMode().String() != "SEND" {
		t.Errorf("mode %v", m)
	}
	set := out[1].GetResponseHeaders().GetResponse().GetHeaderMutation().GetSetHeaders()
	if len(set) != 1 || string(set[0].GetHeader().GetRawValue()) != phK {
		t.Errorf("headers %v", set)
	}
	// a WebSocket upgrade is still read as frames
	out, _ = process(t, reqHeaders(wsRequest...), respHeaders(":status", "101"))
	if out[0].GetModeOverride() != nil {
		t.Errorf("a WebSocket upgrade's stream skipped: %v", out[0].GetModeOverride())
	}
}

func reqBody(b string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{Body: []byte(b), EndOfStream: true}}}
}

// TestWorkloadBody (design 5.9.5): a write to a cluster has its body buffered and checked before it
// goes on, keeping the response scrubbed; a privileged or node-namespace workload is refused (403,
// recorded); an ordinary one passes; reads, and writes to other hosts, are not buffered.
func TestWorkloadBody(t *testing.T) {
	pod := func(spec string) string { return `{"kind":"Pod","spec":` + spec + `}` }
	write := reqHeaders(":authority", "kube-0.gw.sandbox.internal", ":path", "/api/v1/namespaces/a/pods", ":method", "POST",
		"authorization", "Bearer "+phK, "content-type", "application/json")
	out, evs := process(t, write, reqBody(pod(`{"hostNetwork":true,"containers":[{"name":"x"}]}`)))
	if len(out) != 2 {
		t.Fatalf("%v", out)
	}
	if m := out[0].GetModeOverride(); m.GetRequestBodyMode().String() != "BUFFERED" || m.GetResponseBodyMode().String() != "STREAMED" || m.GetResponseHeaderMode().String() != "SEND" {
		t.Errorf("mode %v", m)
	}
	if ir := out[1].GetImmediateResponse(); ir == nil || ir.GetStatus().GetCode().String() != "Forbidden" {
		t.Errorf("not refused: %v", out[1])
	}
	if len(evs) != 2 || evs[1].Type != "refused" || !strings.Contains(evs[1].Reason, "hostNetwork") || evs[1].Path != "/api/v1/namespaces/a/pods" {
		t.Errorf("events %+v", evs)
	}
	out, evs = process(t, write, reqBody(pod(`{"containers":[{"name":"x","image":"nginx"}]}`)))
	if len(out) != 2 || out[1].GetRequestBody() == nil || len(evs) != 1 {
		t.Errorf("an ordinary pod: %v %+v", out, evs)
	}
	// a read is not buffered
	out, _ = process(t, reqHeaders(":authority", "kube-0.gw.sandbox.internal", ":path", "/api/v1/namespaces/a/pods", ":method", "GET", "authorization", "Bearer "+phK))
	if out[0].GetModeOverride().GetRequestBodyMode().String() == "BUFFERED" {
		t.Error("a read was buffered")
	}
	// another host's write is not either
	out, _ = process(t, reqHeaders(":authority", "api.github.com", ":path", "/repos", ":method", "POST", "authorization", "Bearer "+phGH))
	if out[0].GetModeOverride().GetRequestBodyMode().String() == "BUFFERED" {
		t.Error("a write to another host was buffered")
	}
}
