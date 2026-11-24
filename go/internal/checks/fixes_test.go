package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func ctxWith(t *testing.T, org string) Ctx {
	t.Helper()
	d := t.TempDir()
	x := Ctx{Env: config.Env{Home: d, UserConfig: filepath.Join(d, "none.yaml")}, OrgFile: filepath.Join(d, "org.yaml")}
	if org != "" {
		os.WriteFile(x.OrgFile, []byte(org), 0o644)
	}
	return x
}

const org = "blocked_domains:\n  - evil.com\n  - \"*.prod.example.com\"\nblocked_cidrs:\n  - 10.0.0.0/8\n"

func TestFixStrictEgressSyntax(t *testing.T) {
	x := ctxWith(t, org)
	escaped := []string{`evil\x2ecom`, `db.prod\x2eexample.com`, "evil\\" + "u002ecom", `"evil.com"`, "evil.com ", " evil.com", "evil.com\t"}
	for _, d := range escaped {
		if _, err := x.CheckEgressTargetNotBlocked(d); err != nil {
			t.Fatalf("legacy: %q was refused (%v); the bash let it through", d, err)
		}
	}
	if _, err := x.CheckEgressTargetNotBlocked("10.0.0.1."); err != nil {
		t.Fatal("legacy: a trailing dot skipped the CIDR check")
	}
	defer deviation.Force(deviation.StrictEgressSyntax)()
	for _, d := range append(escaped, "010.0.0.1", "1.2.3", "256.1.1.1", "", "*", "a b.com", "café.com", "[::1]", "fe80::1%eth0", "-") {
		if _, err := x.CheckEgressTargetNotBlocked(d); err == nil {
			t.Errorf("fixed: %q accepted", d)
		}
	}
	if _, err := x.CheckEgressTargetNotBlocked("10.0.0.1."); err == nil {
		t.Error("fixed: 10.0.0.1. must reach the CIDR check and be refused")
	}
	for _, d := range []string{"fine.com", "API.Example.COM.", "*.internal.example.com", "_svc.example.com", "xn--caf-dma.com", "192.0.2.10", "2001:db8::1", "a-b.c_d.io", "host1.example.com"} {
		if _, err := x.CheckEgressTargetNotBlocked(d); err != nil {
			t.Errorf("fixed: %q refused: %v", d, err)
		}
	}
}

func TestFixStrictCIDRs(t *testing.T) {
	loose := []string{"10.0.0.0/33", "999.1.1.1/8", ":::/8", "1:2/200", "10.0.0.0/08"}
	for _, c := range loose {
		if !ValidateCIDR(c) {
			t.Fatalf("legacy: %q rejected", c)
		}
	}
	defer deviation.Force(deviation.StrictCIDRs)()
	for _, c := range loose {
		if ValidateCIDR(c) {
			t.Errorf("fixed: %q accepted", c)
		}
	}
	for _, c := range []string{"10.0.0.0/8", "169.254.0.0/16", "fd00::/8", "0.0.0.0/0", "10.1.2.3/8", "::/0"} {
		if !ValidateCIDR(c) {
			t.Errorf("fixed: %q rejected", c)
		}
	}
}

func TestFixMissingOrgBlockListFailsClosed(t *testing.T) {
	x := ctxWith(t, "")
	os.WriteFile(x.UserConfig, []byte("blocked_domains:\n  - evil.com\n"), 0o644)
	if w, err := x.CheckDomainNotBlocked("evil.com"); err != nil || len(w) != 1 {
		t.Fatalf("legacy: expected a warning and a pass, got %q %v", w, err)
	}
	if !x.DomainIsBlocked("evil.com") || x.DomainIsBlocked("fine.com") {
		t.Fatal("legacy: domain_is_blocked reads the user list without the org list")
	}
	defer deviation.Force(deviation.MissingOrgBlockListFailsClosed)()
	if _, err := x.CheckDomainNotBlocked("fine.com"); err == nil {
		t.Error("fixed: a missing org list must refuse")
	}
	if !x.DomainIsBlocked("fine.com") {
		t.Error("fixed: a missing org list must count as blocked")
	}
}

func TestFixDecimalNumbersCIDR(t *testing.T) {
	if IPInCIDR("10.0.0.1", "10.0.0.0/08") || !IPInCIDR("10.200.0.1", "10.0.0.0/010") {
		t.Fatal("legacy: /08 is an error (not inside), /010 is octal /8")
	}
	if _, ok := IPv4ToInt("18446744073709551617.0.0.0"); !ok {
		t.Fatal("legacy: an octet past 64 bits wraps into range")
	}
	defer deviation.Force(deviation.DecimalNumbers)()
	if !IPInCIDR("10.0.0.1", "10.0.0.0/08") || IPInCIDR("10.200.0.1", "10.0.0.0/010") {
		t.Error("fixed: prefixes are decimal (/08 is /8, /010 is /10)")
	}
	if _, ok := IPv4ToInt("18446744073709551617.0.0.0"); ok {
		t.Error("fixed: an oversized octet must not wrap")
	}
}
