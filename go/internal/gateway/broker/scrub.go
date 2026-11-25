package broker

import "bytes"

// Replacement is one value the scrubber takes out of a response and what it puts in its place.
type Replacement struct{ From, To []byte }

// Scrubber replaces values in a stream that arrives in chunks (design 5.9.3): a value split
// across chunks is still caught, because each chunk's output keeps back the longest suffix that
// could begin a value, and only that, so a live event stream is not delayed by more than a
// partial match. Hits counts the replacements made.
type Scrubber struct {
	reps []Replacement
	held []byte
	Hits int
}

// NewScrubber scrubs the given values; the longest is tried first where several start at one place.
func NewScrubber(reps []Replacement) *Scrubber {
	rs := append([]Replacement(nil), reps...)
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && len(rs[j].From) > len(rs[j-1].From); j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
	return &Scrubber{reps: rs}
}

// Write takes the next chunk and returns what may be sent now.
func (s *Scrubber) Write(chunk []byte) []byte { return s.scan(chunk, false) }

func (s *Scrubber) scan(chunk []byte, final bool) []byte {
	buf := append(s.held, chunk...)
	var out []byte
	i := 0
	for i < len(buf) {
		// a longer value that could still complete here wins over a shorter one that has: wait
		// (at the end of the stream nothing more comes, so the longest complete value is taken)
		if !final && s.partial(buf[i:]) {
			break
		}
		matched := false
		for _, r := range s.reps { // longest first
			if bytes.HasPrefix(buf[i:], r.From) {
				out = append(out, r.To...)
				i += len(r.From)
				s.Hits++
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, buf[i])
			i++
		}
	}
	s.held = append([]byte(nil), buf[i:]...)
	return out
}

// partial reports whether rest is a proper prefix of some value (more data could complete it).
func (s *Scrubber) partial(rest []byte) bool {
	for _, r := range s.reps {
		if len(rest) < len(r.From) && bytes.HasPrefix(r.From, rest) {
			return true
		}
	}
	return false
}

// Close returns what was held back at the end of the stream.
func (s *Scrubber) Close() []byte {
	out := s.scan(nil, true)
	s.held = nil
	return out
}

// String scrubs one whole value (a header).
func (s *Scrubber) String(v string) string {
	t := NewScrubber(s.reps)
	out := append(t.Write([]byte(v)), t.Close()...)
	s.Hits += t.Hits
	return string(out)
}
