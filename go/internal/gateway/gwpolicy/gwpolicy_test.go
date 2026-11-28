package gwpolicy

import (
	"net/netip"
	"testing"
)

// TestSameShape: a reload may change only the links' allowlists and blocked names.
func TestSameShape(t *testing.T) {
	base := func() *Policy {
		return &Policy{Resolvers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}, Links: []Link{{Name: "agent",
			Listen: netip.MustParseAddr("10.200.0.1"), Ports: []int{443}, Allow: []string{"a.example"}}}}
	}
	ok := base()
	ok.Links[0].Allow = append(ok.Links[0].Allow, "b.example")
	ok.Links[0].BlockDomains = []string{"c.example"}
	ok.Generation = 3
	if err := base().SameShape(ok); err != nil {
		t.Errorf("allowlist change refused: %v", err)
	}
	for name, f := range map[string]func(*Policy){
		"ports":     func(p *Policy) { p.Links[0].Ports = []int{443, 22} },
		"links":     func(p *Policy) { p.Links = append(p.Links, p.Links[0]) },
		"resolvers": func(p *Policy) { p.Resolvers = nil },
		"listen":    func(p *Policy) { p.Links[0].Listen = netip.MustParseAddr("10.200.0.5") },
		"bindings":  func(p *Policy) { p.Links[0].Bindings = []Binding{{Ref: "x"}} },
		"deps":      func(p *Policy) { p.Deps = []Dep{{Name: "db", Port: 5432}} },
	} {
		q := base()
		f(q)
		if base().SameShape(q) == nil || q.SameShape(base()) == nil {
			t.Errorf("%s change accepted", name)
		}
	}
}
