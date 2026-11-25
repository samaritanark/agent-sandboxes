package proxycert

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// shortNames are OpenSSL's short names for the attribute types a CA subject uses; any other type
// prints as its dotted OID, as OpenSSL does for an OID it has no name for.
var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
	"2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
	"2.5.4.13": "description", "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
	"2.5.4.42": "GN", "2.5.4.43": "initials", "2.5.4.44": "generationQualifier", "2.5.4.46": "dnQualifier",
	"2.5.4.65": "pseudonym", "2.5.4.97": "organizationIdentifier",
	"1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
}

// dumpable are the other types OpenSSL accepts in a name and prints as #hex of their DER:
// VideotexString, GraphicString, GeneralString, and SEQUENCE.
var dumpable = map[int]bool{21: true, 25: true, 27: true, 16: true}

// codePoints decodes a string value by its ASN.1 type, as OpenSSL's do_buf does: BMPString is
// UCS-2, UniversalString UCS-4, UTF8String UTF-8, and the 8-bit types one byte per character.
// ok is false for a type OpenSSL would dump as hex instead.
func codePoints(v asn1.RawValue) ([]rune, bool) {
	if v.Class != asn1.ClassUniversal {
		return nil, false
	}
	b := v.Bytes
	switch v.Tag {
	case asn1.TagUTF8String:
		var out []rune
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r == utf8.RuneError && n <= 1 {
				return nil, false
			}
			out, b = append(out, r), b[n:]
		}
		return out, true
	case 30: // BMPString
		if len(b)%2 != 0 {
			return nil, false
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		return []rune(string(utf16.Decode(u))), true
	case 28: // UniversalString
		if len(b)%4 != 0 {
			return nil, false
		}
		out := make([]rune, len(b)/4)
		for i := range out {
			out[i] = rune(uint32(b[4*i])<<24 | uint32(b[4*i+1])<<16 | uint32(b[4*i+2])<<8 | uint32(b[4*i+3]))
		}
		return out, true
	case asn1.TagNumericString, asn1.TagPrintableString, asn1.TagT61String, asn1.TagIA5String, 26 /* VisibleString */ :
		out := make([]rune, len(b))
		for i, c := range b {
			out[i] = rune(c)
		}
		return out, true
	}
	return nil, false
}

// escapeValue is OpenSSL's escaping under `-nameopt oneline` with UTF-8 conversion (the x509
// command's default): the value is converted to UTF-8, a byte above 0x7f or a control byte is
// printed as \XX, a backslash or double quote is escaped with a backslash, and a value holding
// one of ,+<>; (or a leading space or #, or a trailing space) is wrapped in double quotes, those
// characters printed as they are.
func escapeValue(runes []rune) string {
	var b []byte
	for _, r := range runes {
		b = utf8.AppendRune(b, r)
	}
	var out strings.Builder
	quote := false
	for i, c := range b {
		switch {
		case c > 0x7f || c < 0x20 || c == 0x7f:
			fmt.Fprintf(&out, "\\%02X", c)
		case c == '\\' || c == '"':
			out.WriteByte('\\')
			out.WriteByte(c)
		case strings.IndexByte(`,+<>;`, c) >= 0:
			quote = true
			out.WriteByte(c)
		case (c == ' ' || c == '#') && i == 0, c == ' ' && i == len(b)-1:
			quote = true
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	if quote {
		return `"` + out.String() + `"`
	}
	return out.String()
}

// OneLine is `openssl x509 -noout -subject` (OpenSSL 3) without its "subject=" prefix, for a raw
// DER name: RDNs in certificate order joined by ", ", the attributes of a multi-valued RDN by
// " + ", each as "NAME = value". It is what the vendor pattern is matched against and what
// setup-proxy-cert shows.
func OneLine(rawName []byte) (string, error) {
	var seq []asn1.RawValue
	if rest, err := asn1.Unmarshal(rawName, &asn1.RawValue{}); err != nil || len(rest) != 0 {
		return "", fmt.Errorf("malformed name")
	}
	var outer asn1.RawValue
	asn1.Unmarshal(rawName, &outer)
	b := outer.Bytes
	for len(b) > 0 {
		var set asn1.RawValue
		rest, err := asn1.Unmarshal(b, &set)
		if err != nil {
			return "", err
		}
		seq, b = append(seq, set), rest
	}
	var rdns []string
	for _, set := range seq {
		var atvs []string
		sb := set.Bytes
		for len(sb) > 0 {
			var atv struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			rest, err := asn1.Unmarshal(sb, &atv)
			if err != nil {
				return "", err
			}
			sb = rest
			name, ok := shortNames[atv.Type.String()]
			if !ok {
				name = atv.Type.String()
			}
			var val string
			if r, ok := codePoints(atv.Value); ok {
				val = escapeValue(r)
			} else if dumpable[atv.Value.Tag] && atv.Value.Class == asn1.ClassUniversal {
				val = "#" + strings.ToUpper(hex.EncodeToString(atv.Value.FullBytes))
			} else {
				// OpenSSL cannot read a name whose value is not a string type, so it prints
				// nothing for the certificate, and v2 skipped it
				return "", fmt.Errorf("unsupported value type %d in name", atv.Value.Tag)
			}
			atvs = append(atvs, name+" = "+val)
		}
		rdns = append(rdns, strings.Join(atvs, " + "))
	}
	return strings.Join(rdns, ", "), nil
}

// Subject and Issuer are OneLine of a certificate's names.
func Subject(c *x509.Certificate) string { s, _ := OneLine(c.RawSubject); return s }
func Issuer(c *x509.Certificate) string  { s, _ := OneLine(c.RawIssuer); return s }
