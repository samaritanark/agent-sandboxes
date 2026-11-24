// genentries writes the corpus for lib/catalogue.sh: testdata/cases.tsv, one case per line,
// "id op arg1 arg2 arg3", each arg "=" + base64. A catalogue entry travels inside its case (the
// oracle writes it to the case directory), so the corpus adds no fixture files.
// Ops (see oracle.sh): name, resolve, validate, field, haskey.
//
// Usage: go run ./internal/catalogue/internal/genentries -base internal/catalogue/testdata -seed 1 -n 200
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

const digest = "ghcr.io/x/y@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Each field's alternatives; "" means the field is absent. Values are YAML text after "key: "
// (or the list body for list fields).
var fields = []struct {
	key  string
	vals []string
}{
	{"kind", []string{"service", "mcp", "MCP", "", "-n", "web", "'mcp'"}},
	{"image", []string{digest, "ghcr.io/x/y:latest", strings.Replace(digest, "abcdef", "ABCDEF", 1), digest[:len(digest)-1], digest + "x",
		"x:tag@sha256:" + strings.Repeat("a", 64), strings.Replace(digest, "0123", "0G23", 1), "", "-n"}},
	{"port", []string{"80", "0", "1", "65535", "65536", "08", "0080", "010", "abc", "", "-1", "99999999999999999999", "18446744073709551617", "'443'", "80 # c"}},
	{"run_as_user", []string{"", "0", "00", "1000", "08", "x", "-1", "18446744073709551616", "010"}},
	{"egress", []string{"", "  - api.example.com\n", "  - \"*\"\n", "  - \"*.com\"\n", "  - evil.com\n", "  - sub.evil.com\n",
		"  - evil\\x2ecom\n", "  - 10.1.2.3\n", "  - 11.1.2.3\n", "  - ok.com\n  - \"*\"\n", "  - \"*.github.io\"\n", "  - \"*.internal.example.com\"\n", "  - EVIL.COM.\n"}},
	{"secrets", []string{"", "  - GOOD_NAME\n", "  - bad-name\n", "  - _X\n", "  - lower\n", "  - A1\n  - 1A\n"}},
	{"mcp_transport", []string{"", "http", "sse", "ws", "-n", "SSE"}},
	{"forbid", []string{"", "cap_add:\n  - SYS_ADMIN\n", "privileged: true\n", "hostPID: true\n", "# privileged: true\n", "  privileged: true\n",
		"host_network: false\n", "capabilities: []\n", "hostIPC:\n", "privileged_mode: x\n"}},
	{"sig", []string{"", "class: browser\n", "class: browser\nverify_signature: true\n", "verify_signature: true\n", "class: Browser\n",
		"verify_signature: True\n", "class: browser\nverify_signature: True\n"}},
	{"cosign", []string{"", "cosign_key: /k.pub\n", "cosign_identity: https://x/.*\ncosign_issuer: https://iss\n", "cosign_identity: only\n",
		"cosign_key: /k.pub\ncosign_identity: i\ncosign_issuer: s\n"}},
}

func render(pick []int) string {
	var b strings.Builder
	for i, f := range fields {
		v := f.vals[pick[i]]
		if v == "" {
			continue
		}
		switch f.key {
		case "egress", "secrets":
			b.WriteString(f.key + ":\n" + v)
		case "forbid", "sig", "cosign":
			b.WriteString(v)
		default:
			b.WriteString(f.key + ": " + v + "\n")
		}
	}
	return b.String()
}

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func main() {
	base := flag.String("base", "internal/catalogue/testdata", "testdata directory")
	seed := flag.Int64("seed", 1, "seed")
	n := flag.Int("n", 200, "random entries")
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))
	entries := map[string]string{}
	// the valid base: a service with a digest, port 80, every optional field absent
	baseline := make([]int, len(fields))
	for i := range fields {
		if fields[i].vals[0] == "" {
			baseline[i] = 0
		}
	}
	entries["e-base"] = render(baseline)
	mcp := append([]int(nil), baseline...)
	mcp[0] = 1
	entries["e-mcp"] = render(mcp)
	for i, f := range fields { // one field varied at a time, over both kinds
		for j := range f.vals {
			for k, b := range [][]int{baseline, mcp} {
				p := append([]int(nil), b...)
				p[i] = j
				entries[fmt.Sprintf("e-%s-%d-%d", f.key, j, k)] = render(p)
			}
		}
	}
	for i := 0; i < *n; i++ {
		p := make([]int, len(fields))
		for k, f := range fields {
			p[k] = rng.Intn(len(f.vals))
			if k <= 2 && rng.Intn(3) > 0 { // mostly valid kind, image, port so later checks run
				p[k] = []int{0, 1, 0}[k]
			}
		}
		entries[fmt.Sprintf("r-%03d", i)] = render(p)
	}
	var names []string
	for k := range entries {
		names = append(names, k)
	}
	sort.Strings(names)

	var rows []string
	add := func(op string, args ...string) {
		for len(args) < 3 {
			args = append(args, "")
		}
		rows = append(rows, fmt.Sprintf("g%04d\t%s\t%s\t%s\t%s", len(rows), op, enc(args[0]), enc(args[1]), enc(args[2])))
	}
	for _, nm := range []string{"everything-mcp", "x", "1", "a.b", "..x", "a/b", ".h", "", "café", "a b", "-n", "A_Z-09", "a..b", "a.b.c"} {
		add("name", nm)
		for _, l := range []string{"", "O", "V", "OV", "Vd", "E", "EO", "Ed"} {
			add("resolve", l, nm)
		}
	}
	for _, e := range names {
		cos := []string{"absent", "ok", "fail"}[rng.Intn(3)]
		if strings.HasPrefix(e, "e-sig-") || strings.HasPrefix(e, "e-cosign-") {
			for _, m := range []string{"absent", "ok", "fail"} {
				add("validate", entries[e], m, e)
			}
			continue
		}
		add("validate", entries[e], cos, e)
	}
	// the signature path: every class/verify combination with every cosign setting and stub mode
	sigIdx, cosIdx := len(fields)-2, len(fields)-1
	for si := range fields[sigIdx].vals {
		for ci := range fields[cosIdx].vals {
			p := make([]int, len(fields))
			p[sigIdx], p[cosIdx] = si, ci
			for _, m := range []string{"absent", "ok", "fail"} {
				add("validate", render(p), m, fmt.Sprintf("sig-%d-%d", si, ci))
			}
		}
	}
	for _, e := range []string{"e-base", "e-kind-4-0", "e-port-14-0", "e-mcp_transport-4-1", "e-egress-9-0"} {
		for _, k := range []string{"kind", "port", "mcp_transport", "absent", "egress", "image"} {
			add("field", entries[e], k, "dflt")
			add("haskey", entries[e], k)
		}
	}
	os.WriteFile(filepath.Join(*base, "cases.tsv"), []byte(strings.Join(rows, "\n")+"\n"), 0o644)
	fmt.Printf("%d entries, %d cases\n", len(names), len(rows))
}
