// genchecks writes the corpus for lib/checks.sh: block-list fixtures (testdata/fx/*) and
// testdata/cases.tsv, one case per line, "id op layout arg1 arg2", each arg "=" + base64.
// layout names the fixtures in play: o= org list ("-" missing), b= overlay
// blocked-destinations.yaml, u= user config, c= overlay config.yaml (see oracle.sh).
//
// Usage: go run ./internal/checks/internal/genchecks -base internal/checks/testdata -seed 1 -n 200
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var fixtures = map[string]string{
	"org-a": `blocked_domains:
  - evil.com
  - "*.prod.example.com"
  - smtp.*
  - "*corp.internal"
  - EXACT.UPPER.COM
  - trailing.dot.com.
  - metadata.google.internal
  # a comment
  - "*.github.io"
blocked_cidrs:
  - 10.0.0.0/8
  - 169.254.0.0/16
  - fd00::/8
  - 192.168.1.0/24
  - 172.16.0.0/012
  - 100.64.0.0/08
  - 10.0.0.0/8
`,
	"org-b":     "blocked_domains:\n  - \"*\"\nblocked_cidrs:\n  - 0.0.0.0/0\n",
	"org-c":     "blocked_domains:\n  - \"*.\"\n  - \".*\"\n  - \"*.*\"\n  - a.b.*\nblocked_cidrs:\n  - 10.0.0.0/33\n  - 999.1.1.1/8\n  - :::/8\n  - 1:2/200\n  - 10.0.0.0/08\n  - fd00::/8\n  - 10.0.0.0\n  - host.example.com/8\n",
	"org-empty": "",
	"ov-a":      "blocked_domains:\n  - ov-blocked.com\n  - \"*.ovwild.net\"\nblocked_cidrs:\n  - 203.0.113.0/24\n  - 10.0.0.0/8\n",
	"uc-a":      "extra_allowed_domains:\n  - fine.com\nblocked_domains:\n  - user-blocked.org\n  - \"*.EVIL.org.\"\nblocked_cidrs:\n  - 198.51.100.0/24\n",
	"ovcfg-a":   "trusted_inference_endpoints:\n  - llm.internal\n  - LLM2.internal\n  - \"*.wild\"\n  - 10.1.2.3\n",
}

var layouts = []string{
	"o=org-a", "o=org-a,b=ov-a,u=uc-a", "o=-", "o=-,u=uc-a", "o=-,b=ov-a", "o=org-b", "o=org-c",
	"o=org-empty,u=uc-a", "o=org-a,c=ovcfg-a", "o=org-c,b=ov-a,u=uc-a",
}

var (
	domains = []string{
		"evil.com", "EVIL.COM", "evil.com.", "evil.com..", "Evil.Com.", "sub.evil.com", "notevil.com", "evil.com.au",
		"db.prod.example.com", "prod.example.com", "example.com", "xprod.example.com", "smtp", "smtp.example.com",
		"smtpx.example.com", "mycorp.internal", "corp.internal", "exact.upper.com", "trailing.dot.com",
		"ov-blocked.com", "a.ovwild.net", "ovwild.net", "user-blocked.org", "x.evil.org", "evil.org",
		"fine.com", "github.io", "me.github.io", "*.github.io", "*.example.com", "*.com", "*", "*.", "**.x.com",
		"*.co.uk", "*.example.co.uk", "a.*.example.com", "*.a..b", "*.s3.amazonaws.com", "*.b.s3.amazonaws.com",
		"10.0.0.1", "10.0.0.1.", "010.0.0.1", "11.0.0.1", "169.254.169.254", "192.168.1.7", "192.168.2.7",
		"172.16.5.5", "172.24.0.1", "100.64.0.1", "203.0.113.9", "198.51.100.1", "256.1.1.1", "1.2.3",
		"::1", "fd00::1", "[::1]", "evil\\x2ecom", "db.prod\\x2eexample.com", "evil.com ", " evil.com",
		"ev\"il.com", "evil.com\n", "a b.com", "_svc.example.com", "-lead.com", "xn--caf-dma.com", "café.com",
		"", "a.b", "a.b.c.d", "UPPER.Example.COM", "x.metadata.google.internal",
		"evil.com.\n", "Zz.Example.ORG", "EVIL.COMZ", "*.*.example.com", "*.a*b.example.com", "*.example.*",
	}
	patterns = []string{
		"evil.com", "EVIL.COM.", "*.example.com", "*example.com", "smtp.*", "*.", ".*", "*", "*.*", "a.b.*",
		"*.co.uk", "x", "", "*corp", "corp.*", "*.EVIL.org.",
	}
	ips    = []string{"1.2.3.1234", "10.0.0.1", "10.255.255.255", "11.0.0.0", "0.0.0.0", "255.255.255.255", "192.168.1.255", "192.168.2.0", "010.0.0.1", "1.2.3", "1.2.3.4.", "a.b.c.d", "300.1.1.1", "::1", "", "1..2.3"}
	cidrs  = []string{"10.0.0.0/8", "10.0.0.0/08", "10.0.0.0/010", "0.0.0.0/0", "192.168.1.0/24", "192.168.1.0/32", "192.168.1.0/33", "10.0.0.0", "10.0.0.0/", "10.0.0.0/8/9", "a/8", "fd00::/8", "10.0.0.0/x", "300.0.0.0/8", "10.0.0.0/00", "10.0.0.0/0032"}
	ip2s   = []string{"1.2.3.4", "01.02.03.004", "255.255.255.255", "256.0.0.0", "1.2.3", "1.2.3.4.", "1..2.3", "1.2.3.4.5", "", "a.b.c.d", "1.2.3.-1", "18446744073709551617.0.0.0", "9223372036854775808.0.0.0", "1 .2.3.4"}
	names  = []string{"co.uk", "example.co.uk", "a.example.co.uk", "example.com", "aws.amazon.com", "com", "", "github.io", "me.github.io", "a.me.github.io", "s3.amazonaws.com", "b.s3.amazonaws.com", "x.", ".x", "a..b"}
	hosts  = []string{"llm.internal", "LLM.internal", "llm2.internal", "LLM2.internal", "*.wild", "x.wild", "10.1.2.3", "", "llm.internal."}
	labels = []string{"evil", "com", "prod", "example", "smtp", "corp", "internal", "EVIL", "Com", "x", "a-b", "_x",
		"co", "uk", "github", "io", "s3", "amazonaws", "1", "10", "010", "255", "256", "ovwild", "net", "org", "user-blocked"}
)

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func main() {
	base := flag.String("base", "internal/checks/testdata", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 200, "random cases per random op")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	fx := filepath.Join(*base, "fx")
	os.RemoveAll(fx)
	os.MkdirAll(fx, 0o755)
	var keys []string
	for k := range fixtures {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		os.WriteFile(filepath.Join(fx, k), []byte(fixtures[k]), 0o644)
	}
	var rows []string
	add := func(op, layout string, args ...string) {
		for len(args) < 2 {
			args = append(args, "")
		}
		rows = append(rows, fmt.Sprintf("k%04d\t%s\t%s\t%s\t%s", len(rows), op, layout, enc(args[0]), enc(args[1])))
	}
	pick := func(s []string) string { return s[rng.Intn(len(s))] }
	randDomain := func() string {
		var l []string
		for i, k := 0, 1+rng.Intn(4); i < k; i++ {
			l = append(l, pick(labels))
		}
		d := strings.Join(l, ".")
		switch rng.Intn(8) {
		case 0:
			d = "*." + d
		case 1:
			d += "."
		case 2:
			d = strings.ToUpper(d)
		}
		return d
	}
	for _, d := range domains {
		add("norm", "-", d)
		add("wtb", "-", d)
		add("cetnb", "o=org-a,b=ov-a,u=uc-a", d)
	}
	for _, l := range layouts {
		for _, d := range domains {
			add("cdnb", l, d)
			add("dib", l, d)
		}
		add("gbc", l)
		add("cbcv", l)
		for _, ip := range ips {
			add("cinb", l, ip)
		}
		for _, h := range hosts {
			add("iet", l, h)
		}
	}
	for _, d := range []string{"evil.com", "fine.com", "10.0.0.1", "203.0.113.9", "*.example.com"} {
		for _, l := range layouts {
			add("cetnb", l, d)
		}
	}
	for _, d := range domains {
		for _, p := range patterns {
			add("match", "-", NormalizeForMatch(d), p)
		}
	}
	for _, c := range append(append([]string{}, cidrs...), "fd00::/129", "fe80::1%eth0/64", "::/0", "1:2:3:4:5:6:7:8/128", "gg::/8") {
		add("vcidr", "-", c)
	}
	for _, s := range append(append([]string{}, ips...), ip2s...) {
		add("ip4", "-", s)
		add("ip2int", "-", s)
	}
	for _, ip := range ips {
		for _, c := range cidrs {
			add("iic", "-", ip, c)
		}
	}
	for _, nm := range names {
		add("mps", "-", nm)
		add("apex", "-", nm)
	}
	for i := 0; i < *n; i++ {
		add("cetnb", pick(layouts), randDomain())
		add("match", "-", NormalizeForMatch(randDomain()), pick(patterns))
		d := strings.TrimPrefix(NormalizeForMatch(randDomain()), "*.")
		add("apex", "-", d)
		add("wtb", "-", NormalizeForMatch(randDomain()))
		ip := fmt.Sprintf("%d.%d.%d.%d", rng.Intn(260), rng.Intn(260), rng.Intn(4), rng.Intn(260))
		add("iic", "-", ip, fmt.Sprintf("%d.%d.0.0/%d", rng.Intn(260), rng.Intn(260), rng.Intn(34)))
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d cases\n", len(rows))
}

// NormalizeForMatch lowercases ASCII and strips trailing dots, as the callers of
// _domain_matches_block_pattern do before calling it.
func NormalizeForMatch(d string) string {
	return strings.TrimRight(strings.ToLower(d), ".")
}
