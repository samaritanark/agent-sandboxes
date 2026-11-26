package broker

// The broker as Envoy's external processor (ext_proc, design 5.9.3): Envoy sends each intercepted
// request's headers; the broker refuses it, passes it, or injects the credential (overwriting the
// header or rewriting the query parameter, removing hop-by-hop headers, asking for an uncompressed
// response). For a request it injected into, it scrubs the response headers and streams the body
// through a Scrubber, chunk by chunk (Envoy's STREAMED mode, each chunk returned as a body
// mutation), and refuses a compressed response it could not scrub. Everything else skips the
// response. Envoy is configured to fail closed when the broker does not answer.

import (
	"strings"
	"sync/atomic"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	procmodev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// Event is an audit record of the broker: what happened, to which binding, for which request
// (path without its query). It never carries a value or a placeholder.
type Event struct {
	Type   string // credential_injected, credential_missing, credential_misuse, credential_reflection, refused
	Ref    string
	Host   string
	Method string
	Path   string
	Reason string
}

// Server is the ext_proc service for one session.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	set    atomic.Pointer[Set]
	Record func(Event)
}

// SetBindings replaces the session's bindings.
func (s *Server) SetBindings(set *Set) { s.set.Store(set) }

func (s *Server) record(e Event) {
	if s.Record != nil {
		s.Record(e)
	}
}

var refusedBody = []byte("refused by the sandbox credential broker\n")

func immediate(code typev3.StatusCode, details string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extprocv3.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: code}, Body: refusedBody, Details: details,
	}}}
}

func headerValue(h *corev3.HeaderValue) string {
	if len(h.RawValue) > 0 {
		return string(h.RawValue)
	}
	return h.Value
}

func overwrite(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: name, RawValue: []byte(value)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD}
}

// skipResponse tells Envoy not to send this request's response.
var skipResponse = &procmodev3.ProcessingMode{ResponseHeaderMode: procmodev3.ProcessingMode_SKIP, ResponseBodyMode: procmodev3.ProcessingMode_NONE}

// Process handles one HTTP request's exchange.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var scrub *Scrubber
	var frames *FrameScrubber // after a WebSocket upgrade
	var reps []Replacement
	var ev Event
	reflected := func() {
		hits := 0
		if scrub != nil {
			hits, scrub.Hits = scrub.Hits, 0
		}
		if frames != nil {
			hits, frames.Hits = hits+frames.Hits, 0
		}
		if hits > 0 {
			e := ev
			e.Type, e.Reason = "credential_reflection", "the response carried an injected value; replaced with its placeholder"
			s.record(e)
		}
	}
	unscrubbable := func(why string) *extprocv3.ProcessingResponse {
		e := ev
		e.Type, e.Reason = "refused", why
		s.record(e)
		return immediate(typev3.StatusCode_BadGateway, "broker_unscrubbable")
	}
	for {
		req, err := stream.Recv()
		if err != nil {
			reflected()
			return nil // the request is over (or Envoy went away)
		}
		var resp *extprocv3.ProcessingResponse
		switch r := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			var in Request
			for _, h := range r.RequestHeaders.GetHeaders().GetHeaders() {
				v := headerValue(h)
				switch h.Key {
				case ":authority":
					in.Host = v
				case ":path":
					in.Path = v
				case ":method":
					ev.Method = v
				}
				if !strings.HasPrefix(h.Key, ":") {
					in.Headers = append(in.Headers, Header{Name: strings.ToLower(h.Key), Value: v})
				}
			}
			ev.Host = in.Host
			ev.Path, _, _ = strings.Cut(in.Path, "?")
			bs := s.set.Load()
			if bs == nil {
				resp = immediate(typev3.StatusCode_BadGateway, "broker_not_ready")
				break
			}
			o := bs.Decide(in)
			if o.Refuse {
				e := ev
				e.Type, e.Ref, e.Reason = o.Event, o.Ref, o.Reason
				if e.Type == "" {
					e.Type = "refused"
				}
				s.record(e)
				if o.TooMany {
					resp = immediate(typev3.StatusCode_TooManyRequests, "broker_limited")
				} else {
					resp = immediate(typev3.StatusCode_Forbidden, "broker_refused")
				}
				break
			}
			mut := &extprocv3.HeaderMutation{RemoveHeaders: o.RemoveHeaders}
			for _, h := range o.SetHeaders {
				mut.SetHeaders = append(mut.SetHeaders, overwrite(h.Name, h.Value))
			}
			if o.Path != "" {
				mut.SetHeaders = append(mut.SetHeaders, overwrite(":path", o.Path))
			}
			hr := &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{HeaderMutation: mut}}}
			resp = &extprocv3.ProcessingResponse{Response: hr}
			if o.Injected {
				// the response must arrive as sent so it can be scrubbed
				mut.SetHeaders = append(mut.SetHeaders, overwrite("accept-encoding", "identity"))
				reps = bs.Reflections()
				scrub = NewScrubber(reps)
				ev.Ref = o.Ref
				e := ev
				e.Type = "credential_injected"
				s.record(e)
			} else {
				resp.ModeOverride = skipResponse
			}
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			mut := &extprocv3.HeaderMutation{}
			if scrub != nil {
				hs := r.ResponseHeaders.GetHeaders().GetHeaders()
				for _, h := range hs {
					if h.Key == ":status" && headerValue(h) == "101" {
						// the connection becomes WebSocket frames (Decide lets no other upgrade by)
						frames = NewFrameScrubber(reps)
					}
				}
				for _, h := range hs {
					v := headerValue(h)
					if h.Key == "content-encoding" && !strings.EqualFold(v, "identity") {
						resp = unscrubbable("a compressed response to an injected request cannot be scrubbed")
						break
					}
					if frames != nil && h.Key == "sec-websocket-extensions" {
						// the offer was stripped; a server that accepts an extension anyway
						// (compression) sends frames the broker cannot read
						resp = unscrubbable("a WebSocket extension on an injected connection cannot be scrubbed")
						break
					}
					if !strings.HasPrefix(h.Key, ":") {
						if sv := scrub.String(v); sv != v {
							mut.SetHeaders = append(mut.SetHeaders, overwrite(h.Key, sv))
						}
					}
				}
				// the scrubbed body's length differs from the upstream's
				mut.RemoveHeaders = append(mut.RemoveHeaders, "content-length")
			}
			if resp == nil {
				resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{HeaderMutation: mut}}}}
			}
		case *extprocv3.ProcessingRequest_ResponseBody:
			body := r.ResponseBody.GetBody()
			if frames != nil {
				out, err := frames.Write(body)
				if err == nil && r.ResponseBody.GetEndOfStream() {
					err = frames.Close()
				}
				if err != nil {
					// cut the connection: what was sent so far was whole frames, scrubbed
					resp = unscrubbable(err.Error())
					break
				}
				body = out
			} else if scrub != nil {
				body = scrub.Write(body)
				if r.ResponseBody.GetEndOfStream() {
					body = append(body, scrub.Close()...)
				}
			}
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: body}}}}}}
		default:
			// trailers and anything else pass unchanged
			resp = &extprocv3.ProcessingResponse{}
			switch req.Request.(type) {
			case *extprocv3.ProcessingRequest_RequestTrailers:
				resp.Response = &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}
			case *extprocv3.ProcessingRequest_ResponseTrailers:
				resp.Response = &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}
			case *extprocv3.ProcessingRequest_RequestBody:
				resp.Response = &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}
			}
		}
		if err := stream.Send(resp); err != nil {
			reflected()
			return err
		}
	}
}
