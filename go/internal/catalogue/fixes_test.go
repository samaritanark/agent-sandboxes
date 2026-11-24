package catalogue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

const pinned = "ghcr.io/x/y@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func entryCtx(t *testing.T, body string) (Ctx, string) {
	t.Helper()
	c := t.TempDir()
	var log strings.Builder
	x := newCtx(c, "absent", &log)
	p := filepath.Join(c, "e.yaml")
	os.WriteFile(p, []byte("kind: service\nimage: "+pinned+"\n"+body), 0o644)
	return x, p
}

func TestFixCatalogueEgressFullCheck(t *testing.T) {
	bad := []string{`"*.com"`, "10.1.2.3", `evil\x2ecom`, `"*.github.io"`}
	for _, d := range bad {
		x, p := entryCtx(t, "port: 80\negress:\n  - "+d+"\n")
		if err := x.ValidateEntry(p, "e"); err != nil {
			t.Fatalf("legacy: egress %s refused: %v", d, err)
		}
	}
	defer deviation.Force(deviation.CatalogueEgressFullCheck)()
	defer deviation.Force(deviation.StrictEgressSyntax)()
	for _, d := range bad {
		x, p := entryCtx(t, "port: 80\negress:\n  - "+d+"\n")
		if err := x.ValidateEntry(p, "e"); err == nil {
			t.Errorf("fixed: egress %s accepted", d)
		}
	}
	x, p := entryCtx(t, "port: 80\negress:\n  - api.example.com\n  - \"*.internal.example.com\"\n")
	if err := x.ValidateEntry(p, "e"); err != nil {
		t.Errorf("fixed: a bounded egress list refused: %v", err)
	}
}

func TestFixDecimalNumbersCatalogue(t *testing.T) {
	cases := []struct {
		body          string
		legacy, fixed bool // accepted?
	}{
		{"port: 08\n", true, true},                    // legacy: octal error passes; fixed: 8
		{"port: 0080\n", true, true},                  // fixed: 80
		{"port: 18446744073709551617\n", true, false}, // legacy wraps to 1
		{"port: 80\nrun_as_user: 08\n", true, true},
		{"port: 80\nrun_as_user: 18446744073709551616\n", false, true}, // legacy wraps to 0
	}
	for _, c := range cases {
		x, p := entryCtx(t, c.body)
		if got := x.ValidateEntry(p, "e") == nil; got != c.legacy {
			t.Errorf("legacy %q: accepted=%v", c.body, got)
		}
	}
	defer deviation.Force(deviation.DecimalNumbers)()
	for _, c := range cases {
		x, p := entryCtx(t, c.body)
		if got := x.ValidateEntry(p, "e") == nil; got != c.fixed {
			t.Errorf("fixed %q: accepted=%v", c.body, got)
		}
	}
}

func TestFixEchoOptionField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.yaml")
	os.WriteFile(p, []byte("mcp_transport: -n\n"), 0o644)
	if Field(p, "mcp_transport", "http") != "" {
		t.Fatal("legacy: -n should vanish into echo")
	}
	defer deviation.Force(deviation.EchoOptionItems)()
	if got := Field(p, "mcp_transport", "http"); got != "-n" {
		t.Errorf("fixed: got %q", got)
	}
}
