// Package bashcompat reproduces the behaviour of bash and its tools that the v2 policy layer
// depends on, so the Go port can match it exactly while the bash is the oracle (spike S8). Each
// helper here marks a quirk: when a quirk is fixed in the port, its callers stop using the helper.
package bashcompat

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var digits = regexp.MustCompile(`^[0-9]+$`)

// SplitRecords splits data into awk records (RS="\n"): a trailing newline does not start a new
// record, an empty file has none.
func SplitRecords(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := string(data)
	parts := strings.Split(s, "\n")
	if strings.HasSuffix(s, "\n") {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// Glob reports whether name matches a bash [[ == pattern ]] glob (*, ?, [set], backslash
// escape; no extglob, no [:class:]; bytes).
func Glob(pat, name string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			for len(pat) > 0 && pat[0] == '*' {
				pat = pat[1:]
			}
			if pat == "" {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if Glob(pat, name[i:]) {
					return true
				}
			}
			return false
		case '?':
			if name == "" {
				return false
			}
			pat, name = pat[1:], name[1:]
		case '[':
			if name == "" {
				return false
			}
			end, ok, matched := bracket(pat, name[0])
			if !ok { // no closing ]: '[' is literal
				if name[0] != '[' {
					return false
				}
				pat, name = pat[1:], name[1:]
				continue
			}
			if !matched {
				return false
			}
			pat, name = pat[end:], name[1:]
		case '\\':
			if len(pat) < 2 {
				return name == "\\" && len(pat) == 1 && len(name) == 1
			}
			if name == "" || name[0] != pat[1] {
				return false
			}
			pat, name = pat[2:], name[1:]
		default:
			if name == "" || name[0] != pat[0] {
				return false
			}
			pat, name = pat[1:], name[1:]
		}
	}
	return name == ""
}

// bracket parses a [...] expression at the start of pat and tests c. end is the index after the
// closing ']'; ok is false when there is no closing bracket.
func bracket(pat string, c byte) (end int, ok, matched bool) {
	i := 1
	neg := false
	if i < len(pat) && (pat[i] == '!' || pat[i] == '^') {
		neg = true
		i++
	}
	first := true
	for i < len(pat) {
		if pat[i] == ']' && !first {
			return i + 1, true, matched != neg
		}
		first = false
		lo := pat[i]
		if lo == '\\' && i+1 < len(pat) {
			i++
			lo = pat[i]
		}
		hi := lo
		if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
			hi = pat[i+2]
			i += 2
		}
		if c >= lo && c <= hi {
			matched = true
		}
		i++
	}
	return 0, false, false
}

// ReadTab emulates `IFS=$'\t' read -r a b c ...` with n variables: tab is IFS whitespace, so
// leading tabs are dropped and runs of tabs separate fields; the last variable takes the rest.
func ReadTab(line string, n int) []string {
	out := make([]string, n)
	s := strings.TrimLeft(line, "\t")
	for i := 0; i < n-1; i++ {
		if s == "" {
			return out
		}
		j := strings.IndexByte(s, '\t')
		if j < 0 {
			out[i] = s
			return out
		}
		out[i] = s[:j]
		s = strings.TrimLeft(s[j:], "\t")
	}
	out[n-1] = strings.TrimRight(s, "\t")
	return out
}

// QuoteQ is printf '%q' in a UTF-8 locale (bash 5.2): backslash-escaping for shell-special
// characters, $'...' when the string holds a control character or an invalid byte.
func QuoteQ(s string) string {
	if s == "" {
		return "''"
	}
	ansi := false
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			ansi = true
			break
		}
		i += n
	}
	var b strings.Builder
	if ansi {
		b.WriteString("$'")
		for i := 0; i < len(s); {
			r, n := utf8.DecodeRuneInString(s[i:])
			if r >= 0xa0 && !(r == utf8.RuneError && n == 1) {
				b.WriteString(s[i : i+n])
				i += n
				continue
			}
			c := s[i]
			switch {
			case c == '\\':
				b.WriteString(`\\`)
			case c == '\'':
				b.WriteString(`\'`)
			case c == 7:
				b.WriteString(`\a`)
			case c == 8:
				b.WriteString(`\b`)
			case c == 27:
				b.WriteString(`\E`)
			case c == 12:
				b.WriteString(`\f`)
			case c == 10:
				b.WriteString(`\n`)
			case c == 13:
				b.WriteString(`\r`)
			case c == 9:
				b.WriteString(`\t`)
			case c == 11:
				b.WriteString(`\v`)
			case c < 0x20 || c >= 0x7f:
				fmt.Fprintf(&b, `\%03o`, c)
			default:
				b.WriteByte(c)
			}
			i++
		}
		b.WriteString("'")
		return b.String()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		special := strings.IndexByte(" !\"$&'()*,;<>?[\\]^`{|}", c) >= 0
		if c == '~' && (i == 0 || s[i-1] == ':' || s[i-1] == '=') {
			special = true
		}
		if c == '#' && i == 0 {
			special = true
		}
		if special {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func Basename(p string) string {
	if p == "" {
		return ""
	}
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/"
	}
	return filepath.Base(t)
}

// Arith evaluates a string of digits the way bash arithmetic does: a leading 0 means octal
// (digits 8 and 9 are an error), and a value too large wraps modulo 2^64 into a signed integer.
func Arith(s string) (int64, bool) {
	base := uint64(10)
	if len(s) > 1 && s[0] == '0' {
		base = 8
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		d := uint64(s[i] - '0')
		if d >= base {
			return 0, false
		}
		v = v*base + d
	}
	return int64(v), true
}

// ArithLess is `[[ a -lt b ]]` for digit strings; an arithmetic error makes it false.
func ArithLess(a, b string) bool {
	x, ok1 := Arith(a)
	y, ok2 := Arith(b)
	return ok1 && ok2 && x < y
}

// ArithCmp evaluates `[[ a OP b ]]` for -gt / -eq on strings the bash would treat as integers; an
// arithmetic error is false. An empty operand is arithmetic 0, as in `[[ "" -eq 0 ]]`.
func ArithCmp(a, b, op string) bool {
	val := func(s string) (int64, bool) {
		if s == "" {
			return 0, true
		}
		if !digits.MatchString(s) {
			return 0, false
		}
		return Arith(s)
	}
	x, ok1 := val(a)
	y, ok2 := val(b)
	if !ok1 || !ok2 {
		return false
	}
	if op == "gt" {
		return x > y
	}
	return x == y
}
