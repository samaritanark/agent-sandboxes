// genstores writes testdata/stores/cases.tsv for the trust-store corpus: "id vendor tree", where
// tree is steps (one per line, fields "=" + base64): "f PATH CONTENT", "d PATH", "l PATH TARGET".
// PATH starts with U/ (/usr/local/share/ca-certificates), E/ (/etc/ssl/certs), or is B (the
// bundle /etc/ssl/certs/ca-certificates.crt). Certificates come from ../subjects.pem.
//
// Usage: go run ./internal/host/proxycert/internal/genstores -base internal/host/proxycert/testdata
package main

import (
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func e(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

type tree []string

func (t tree) add(op string, f ...string) tree {
	p := []string{e(op)}
	for _, x := range f {
		p = append(p, e(x))
	}
	return append(append(tree(nil), t...), strings.Join(p, " "))
}
func (t tree) f(p, c string) tree  { return t.add("f", p, c) }
func (t tree) d(p string) tree     { return t.add("d", p) }
func (t tree) l(p, to string) tree { return t.add("l", p, to) }

func main() {
	base := flag.String("base", "internal/host/proxycert/testdata", "testdata directory")
	n := flag.Int("n", 40, "random cases")
	flag.Parse()
	raw, err := os.ReadFile(filepath.Join(*base, "subjects.pem"))
	if err != nil {
		panic(err)
	}
	var certs []string // PEM text, one per certificate
	var ders []string
	for b := raw; ; {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		certs = append(certs, string(pem.EncodeToMemory(blk)))
		ders = append(ders, string(blk.Bytes))
	}
	zs, ns, pa, bc, plain, cafe := certs[0], certs[1], certs[2], certs[35], certs[14], certs[17]
	trusted := strings.Replace(strings.Replace(zs, "BEGIN CERTIFICATE", "BEGIN TRUSTED CERTIFICATE", 1), "END CERTIFICATE", "END TRUSTED CERTIFICATE", 1)
	x509old := strings.Replace(strings.Replace(zs, "BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE", 1), "END CERTIFICATE", "END X509 CERTIFICATE", 1)
	type cs struct {
		vendor string
		t      tree
	}
	cases := []cs{
		{"", tree{}},
		{"", tree{}.f("U/zs.crt", zs)},
		{"", tree{}.f("U/plain.crt", plain).f("B", plain+ns+cafe)},
		{"", tree{}.f("U/b.crt", ns).f("U/a.crt", zs).f("E/c.pem", pa).f("E/z.pem", plain)},
		{"", tree{}.f("U/two.crt", plain+zs)},
		{"", tree{}.f("U/two.crt", plain+zs).f("B", "junk before\n"+plain+"between\n"+zs+"after")},
		{"", tree{}.f("U/der.crt", ders[0]).f("U/empty.crt", "").d("U/dir.crt").l("U/broken.crt", "nowhere")},
		{"", tree{}.f("other/zs.pem", zs).l("U/link.crt", "../other/zs.pem")},
		{"", tree{}.f("U/zs.CRT", zs).f("U/.hidden.crt", zs).f("E/zs.crt", zs)},
		{"Example", tree{}.f("U/plain.crt", plain).f("B", cafe+zs)},
		{"a b", tree{}.f("U/plain.crt", plain)},
		{"ZSCALER", tree{}.f("B", zs)},
		{"", tree{}.f("B", strings.ReplaceAll(zs+ns, "\n", "\r\n"))},
		{"", tree{}.f("B", "x -----BEGIN CERTIFICATE----- y\n"+zs)},
		{"", tree{}.f("B", strings.TrimSuffix(zs, "\n"))},
		{"", tree{}.f("B", zs+"note: -----BEGIN CERTIFICATE----- here\n"+plain)},
		{"", tree{}.f("U/t.crt", trusted)},
		{"", tree{}.f("U/o.crt", x509old)},
		{"", tree{}.f("B", trusted+x509old)},
		{"", tree{}.f("U/bc.crt", bc).f("B", ns)},
		{"", tree{}.d("B")},
		{"", tree{}.f("E/ca-certificates.crt", zs)},
		{"Netskope", tree{}.f("E/x.pem", "garbage").f("B", "garbage\n")},
	}
	rnd := rand.New(rand.NewSource(7))
	pool := []string{zs, ns, pa, bc, plain, cafe, certs[5], certs[20], "junk\n", ""}
	vendors := []string{"", "", "", "Example", "Root", "Decryption"}
	for i := 0; i < *n; i++ {
		t := tree{}
		for j := rnd.Intn(4); j > 0; j-- {
			dir := []string{"U/", "E/"}[rnd.Intn(2)]
			ext := map[string]string{"U/": ".crt", "E/": ".pem"}[dir]
			t = t.f(fmt.Sprintf("%sf%d%s", dir, rnd.Intn(5), ext), pool[rnd.Intn(len(pool))]+pool[rnd.Intn(len(pool))])
		}
		if rnd.Intn(3) > 0 {
			var b string
			for j := rnd.Intn(5); j > 0; j-- {
				b += pool[rnd.Intn(len(pool))]
			}
			t = t.f("B", b)
		}
		cases = append(cases, cs{vendors[rnd.Intn(len(vendors))], t})
	}
	var rows []string
	for i, c := range cases {
		rows = append(rows, fmt.Sprintf("p%04d\t%s\t%s", i, e(c.vendor), e(strings.Join(c.t, "\n"))))
	}
	os.WriteFile(filepath.Join(*base, "stores", "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}
