// Package proxycert is `sandbox setup-proxy-cert` (design 5.1.3, 5.10): find a corporate
// TLS-intercept proxy's root CA in the host trust store (or on the wire) and save it where the
// host binary pushes extra CAs into the VM. It is a port of lib/certs.sh with no openssl: the
// subject text that is shown and matched is OpenSSL 3's one-line format, reproduced in OneLine.
package proxycert

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Vendors are SANDBOX_PROXY_CA_VENDORS: subject fragments of common TLS-intercept proxies.
var Vendors = []string{"Zscaler", "Netskope", "Forcepoint", "Cisco Umbrella", "Palo Alto", "Symantec", "Blue Coat", "Prisma", "iboss", "Menlo"}

// VendorList is proxy_ca_vendor_regex's text: the extra vendor first, then the built-in ones,
// joined by "|". It is what the search line shows.
func VendorList(extra string) string {
	v := Vendors
	if extra != "" {
		v = append([]string{extra}, Vendors...)
	}
	return strings.Join(v, "|")
}

// Matcher matches a subject case-insensitively against any vendor. v2 pasted --vendor into an
// extended regular expression unescaped; here every vendor is a literal substring, as the help
// text has always described it.
func Matcher(extra string) *regexp.Regexp {
	v := Vendors
	if extra != "" {
		v = append([]string{extra}, Vendors...)
	}
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = regexp.QuoteMeta(s)
	}
	return regexp.MustCompile("(?i)" + strings.Join(q, "|"))
}

// SplitPEM is the awk splitter lib/certs.sh uses everywhere: a chunk starts at each line holding
// "-----BEGIN CERTIFICATE-----" and runs to the next such line; lines before the first are
// dropped, and every line ends with "\n" (awk's print), including a last line that had none.
func SplitPEM(b []byte) [][]byte {
	var chunks [][]byte
	lines := strings.Split(string(b), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		if strings.Contains(l, "-----BEGIN CERTIFICATE-----") {
			chunks = append(chunks, nil)
		}
		if len(chunks) > 0 {
			chunks[len(chunks)-1] = append(chunks[len(chunks)-1], l+"\n"...)
		}
	}
	return chunks
}

// firstCert is the certificate `openssl x509 -in FILE` (OpenSSL 3) reads: the first PEM block of
// type CERTIFICATE, X509 CERTIFICATE, or TRUSTED CERTIFICATE (whose DER carries trust settings
// after the certificate); failing any, the file itself as DER, which OpenSSL 3 detects too.
func firstCert(b []byte) *x509.Certificate {
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" && blk.Type != "X509 CERTIFICATE" && blk.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		return parseFirst(blk.Bytes)
	}
	return parseFirst(b)
}

// parseFirst parses the first DER element of b as a certificate.
func parseFirst(b []byte) *x509.Certificate {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return nil
	}
	c, err := x509.ParseCertificate(raw.FullBytes)
	if err != nil {
		return nil
	}
	return c
}

// Glob is a bash glob of one directory: filepath.Glob without the names starting with a dot,
// which bash's * does not match, in bytewise order (bash under the C locale).
func Glob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	out := m[:0]
	for _, p := range m {
		if !strings.HasPrefix(filepath.Base(p), ".") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// names is the subject and issuer openssl would print for the first certificate in b, or two
// empty strings when it cannot read one.
func names(b []byte) (string, string) {
	c := firstCert(b)
	if c == nil {
		return "", ""
	}
	s, err1 := OneLine(c.RawSubject)
	i, err2 := OneLine(c.RawIssuer)
	if err1 != nil || err2 != nil {
		return "", ""
	}
	return s, i
}

// LinuxStore is extract_proxy_cert_linux over the given per-file paths (the expansion of
// /usr/local/share/ca-certificates/*.crt and /etc/ssl/certs/*.pem) and the system bundle: each
// file whose first certificate's subject matches is taken whole; only when none matches is the
// bundle split and searched. ok is false when nothing matched.
func LinuxStore(files []string, bundle string, m *regexp.Regexp) (out []byte, ok bool) {
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		subj, _ := names(b)
		if subj != "" && m.MatchString(subj) {
			out, ok = append(out, b...), true
		}
	}
	if ok {
		return out, true
	}
	if st, err := os.Stat(bundle); err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := os.ReadFile(bundle)
	if err != nil {
		return nil, false
	}
	return matchChunks(b, m)
}

// matchChunks splits a PEM stream and keeps the chunks whose subject matches.
func matchChunks(b []byte, m *regexp.Regexp) ([]byte, bool) {
	var out []byte
	ok := false
	for _, c := range SplitPEM(b) {
		if subj, _ := names(c); m.MatchString(subj) {
			out, ok = append(out, c...), true
		}
	}
	return out, ok
}

// Describe is describe_pems: subject and issuer of each certificate in out.
func Describe(out []byte) string {
	var b bytes.Buffer
	for i, c := range SplitPEM(out) {
		s, is := names(c)
		b.WriteString("  [" + itoa(i+1) + "] Subject: " + s + "\n")
		b.WriteString("      Issuer:  " + is + "\n")
	}
	return b.String()
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}
