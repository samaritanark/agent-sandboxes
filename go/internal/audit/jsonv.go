package audit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The audit record is written and edited with jq in the bash, and jq keeps an object's keys in
// insertion order, keeps a number's literal text, and pretty-prints in its own style. Value,
// parseValues and encode reproduce exactly that much of jq (1.7), so the record is byte-identical.

// Kind is a JSON value's type.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Value is a JSON value; an object keeps its keys in order.
type Value struct {
	Kind  Kind
	B     bool
	Num   string // the number's literal text
	Str   string
	Arr   []Value
	Keys  []string
	Props map[string]Value
}

func Str(s string) Value    { return Value{Kind: String, Str: s} }
func Int(n int) Value       { return Value{Kind: Number, Num: strconv.Itoa(n)} }
func BoolV(b bool) Value    { return Value{Kind: Bool, B: b} }
func Arr(vs ...Value) Value { return Value{Kind: Array, Arr: append([]Value{}, vs...)} }
func NewObject() Value      { return Value{Kind: Object, Props: map[string]Value{}} }
func (v Value) Get(k string) Value {
	if v.Kind != Object {
		return Value{}
	}
	return v.Props[k]
}

// Set is jq's `.k = x`: on an object it replaces the value in place or appends the key; null
// becomes a one-key object; any other type is an error.
func (v Value) Set(k string, x Value) (Value, error) {
	switch v.Kind {
	case Null:
		v = NewObject()
	case Object:
		p := make(map[string]Value, len(v.Props)+1)
		for kk, vv := range v.Props {
			p[kk] = vv
		}
		v.Props, v.Keys = p, append([]string(nil), v.Keys...)
	default:
		return v, fmt.Errorf("cannot index %s with %q", kindName(v.Kind), k)
	}
	if _, ok := v.Props[k]; !ok {
		v.Keys = append(v.Keys, k)
	}
	v.Props[k] = x
	return v, nil
}

// Merge is jq's object addition `a + b`: b's keys replace a's in place, new keys are appended.
func (v Value) Merge(b Value) Value {
	out := v
	for _, k := range b.Keys {
		out, _ = out.Set(k, b.Props[k])
	}
	return out
}

func kindName(k Kind) string {
	return [...]string{"null", "boolean", "number", "string", "array", "object"}[k]
}

// ---- parsing (jq's input: a stream of JSON texts) ----

type parser struct {
	s string
	i int
}

var errSyntax = errors.New("invalid JSON")

// parseValues parses every JSON text in s, as jq reads its input file.
func parseValues(s string) ([]Value, error) {
	p := &parser{s: s}
	var out []Value
	for {
		p.ws()
		if p.i == len(p.s) {
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

// parseOne parses exactly one JSON text (jq's --argjson).
func parseOne(s string) (Value, error) {
	vs, err := parseValues(s)
	if err != nil || len(vs) != 1 {
		return Value{}, errSyntax
	}
	return vs[0], nil
}

func (p *parser) ws() {
	for p.i < len(p.s) && strings.IndexByte(" \t\n\r", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *parser) value() (Value, error) {
	p.ws()
	if p.i >= len(p.s) {
		return Value{}, errSyntax
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		o := NewObject()
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return Value{}, errSyntax
			}
			k, err := p.str()
			if err != nil {
				return Value{}, err
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return Value{}, errSyntax
			}
			p.i++
			v, err := p.value()
			if err != nil {
				return Value{}, err
			}
			o, _ = o.Set(k, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			return Value{}, errSyntax
		}
	case c == '[':
		p.i++
		a := Arr()
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		for {
			v, err := p.value()
			if err != nil {
				return Value{}, err
			}
			a.Arr = append(a.Arr, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return a, nil
			}
			return Value{}, errSyntax
		}
	case c == '"':
		s, err := p.str()
		return Str(s), err
	case c == '-' || (c >= '0' && c <= '9'):
		j := p.i
		if p.s[j] == '-' {
			j++
		}
		k := j
		for j < len(p.s) && strings.IndexByte("0123456789.eE+-", p.s[j]) >= 0 {
			j++
		}
		lit := p.s[p.i:j]
		if j == k {
			return Value{}, errSyntax
		}
		if _, err := strconv.ParseFloat(lit, 64); err != nil && !errors.Is(err, strconv.ErrRange) {
			return Value{}, errSyntax
		}
		p.i = j
		return Value{Kind: Number, Num: lit}, nil
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return BoolV(true), nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return BoolV(false), nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return Value{}, nil
	}
	return Value{}, errSyntax
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			if p.i+1 >= len(p.s) {
				return "", errSyntax
			}
			e := p.s[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				if p.i+4 > len(p.s) {
					return "", errSyntax
				}
				n, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 32)
				if err != nil {
					return "", errSyntax
				}
				p.i += 4
				b.WriteRune(rune(n))
			default:
				return "", errSyntax
			}
		case c < 0x20: // jq rejects a raw control character inside a string
			return "", errSyntax
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", errSyntax
}

// ---- encoding (jq's default pretty output) ----

func encode(v Value) string {
	var b strings.Builder
	enc(&b, v, 0)
	b.WriteByte('\n')
	return b.String()
}

func enc(b *strings.Builder, v Value, depth int) {
	ind := func(d int) { b.WriteString(strings.Repeat("  ", d)) }
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		b.WriteString(strconv.FormatBool(v.B))
	case Number:
		b.WriteString(v.Num)
	case String:
		quote(b, v.Str)
	case Array:
		if len(v.Arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, x := range v.Arr {
			ind(depth + 1)
			enc(b, x, depth+1)
			if i < len(v.Arr)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		ind(depth)
		b.WriteByte(']')
	case Object:
		if len(v.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range v.Keys {
			ind(depth + 1)
			quote(b, k)
			b.WriteString(": ")
			enc(b, v.Props[k], depth+1)
			if i < len(v.Keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		ind(depth)
		b.WriteByte('}')
	}
}

func quote(b *strings.Builder, s string) {
	s = strings.ToValidUTF8(s, "�")
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
