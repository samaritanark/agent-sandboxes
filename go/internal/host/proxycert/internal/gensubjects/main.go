// gensubjects writes testdata/subjects.pem: one self-signed certificate per test subject,
// deterministic (Ed25519 signing, fixed key, serial, and dates), each subject DER built by hand so
// it can hold any string type and character.
//
// Usage: go run ./internal/host/proxycert/internal/gensubjects -base internal/host/proxycert/testdata
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
	"unicode/utf16"
)

type atv struct {
	oid string
	tag int
	val []byte
}

func oid(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	var n int
	for _, c := range s + "." {
		if c == '.' {
			o, n = append(o, n), 0
			continue
		}
		n = n*10 + int(c-'0')
	}
	return o
}

func name(rdns ...[]atv) []byte {
	var seq []byte
	for _, rdn := range rdns {
		var set []byte
		for _, a := range rdn {
			v := asn1.RawValue{Class: asn1.ClassUniversal, Tag: a.tag, Bytes: a.val}
			b, err := asn1.Marshal(struct {
				T asn1.ObjectIdentifier
				V asn1.RawValue
			}{oid(a.oid), v})
			if err != nil {
				panic(err)
			}
			set = append(set, b...)
		}
		s, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: set})
		seq = append(seq, s...)
	}
	b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: seq})
	return b
}

func u8(o, s string) atv { return atv{o, asn1.TagUTF8String, []byte(s)} }
func ps(o, s string) atv { return atv{o, asn1.TagPrintableString, []byte(s)} }
func bmp(o, s string) atv {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u>>8), byte(u))
	}
	return atv{o, 30, b}
}
func one(a ...atv) []atv { return a }

const (
	cn = "2.5.4.3"
	o  = "2.5.4.10"
	ou = "2.5.4.11"
	c  = "2.5.4.6"
)

func main() {
	base := flag.String("base", "internal/host/proxycert/testdata", "testdata directory")
	flag.Parse()
	subjects := [][]byte{
		name(one(ps(c, "US")), one(u8(o, "Zscaler Inc.")), one(u8(cn, "Zscaler Root CA"))),
		name(one(u8(cn, "Netskope Certificate Authority")), one(u8(o, "Netskope"))),
		name(one(u8(cn, "Palo Alto Networks Decryption CA"))),
		name(one(u8(cn, "a,b"))), name(one(u8(cn, "a+b"))), name(one(u8(cn, `a"b`))), name(one(u8(cn, `a\b`))),
		name(one(u8(cn, "a<b>c"))), name(one(u8(cn, "a;b"))), name(one(u8(cn, "a=b"))),
		name(one(u8(cn, " lead"))), name(one(u8(cn, "trail "))), name(one(u8(cn, "#hash"))), name(one(u8(cn, "mid#dle"))),
		name(one(u8(cn, "a b"))), name(one(u8(cn, " "))), name(one(u8(cn, ""))),
		name(one(u8(cn, "café"))), name(one(u8(cn, "日本"))), name(one(u8(cn, "€"))), name(one(u8(cn, "😀"))),
		name(one(bmp(cn, "café €"))), name(one(atv{cn, 28, []byte{0, 0, 0, 'A', 0, 1, 0xf6, 0}})),
		name(one(atv{cn, asn1.TagT61String, []byte{'a', 0xe9}})), name(one(atv{cn, asn1.TagIA5String, []byte("x@y")})),
		name(one(u8(cn, "tab\there"))), name(one(u8(cn, "nl\nhere"))), name(one(u8(cn, "del\x7f"))),
		name(one(u8(cn, "x"), u8(ou, "y")), one(u8(o, "z"))),
		name(one(atv{"1.2.840.113549.1.9.1", asn1.TagIA5String, []byte("a@b.c")}), one(atv{"0.9.2342.19200300.100.1.25", asn1.TagIA5String, []byte("com")}),
			one(u8("0.9.2342.19200300.100.1.1", "u1")), one(ps("2.5.4.5", "42"))),
		name(one(u8("1.2.3.4.5", "private"))), name(one(atv{cn, asn1.TagInteger, []byte{1}})),
		name(one(u8("2.5.4.8", "Texas")), one(u8("2.5.4.7", "Austin")), one(u8("2.5.4.12", "t")), one(u8("2.5.4.97", "VATUS-1"))),
		name(one(u8(cn, `"quoted"`))), name(one(u8(cn, `\`))), name(one(u8(cn, "Blue Coat, Inc. + Symantec"))),
	}
	seed := make([]byte, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	var out []byte
	for i, s := range subjects {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)), RawSubject: s, RawIssuer: s,
			NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(2000000000, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(nil, tmpl, tmpl, key.Public(), key)
		if err != nil {
			panic(fmt.Sprintf("subject %d: %v", i, err))
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	os.WriteFile(filepath.Join(*base, "subjects.pem"), out, 0o644)
	fmt.Printf("%d subjects\n", len(subjects))
}
