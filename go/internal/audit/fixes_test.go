package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
)

func TestFixAuditDomainsAsData(t *testing.T) {
	domains := []string{`x","injected.com`, `a.b.com`, "tab\there", `evil\x2ecom`}
	record := func() (jqjson.Value, error) {
		d := t.TempDir()
		_, err := WriteSessionJSON(d, Session{ID: "s", Agent: "a", Tier: "2", Domains: domains[:2]})
		b, _ := os.ReadFile(filepath.Join(d, "session.json"))
		vs, perr := jqjson.ParseValues(string(b))
		if err != nil || perr != nil || len(vs) != 1 {
			return jqjson.Value{}, err
		}
		return vs[0].Get("allowed_domains"), nil
	}
	got, _ := record()
	if len(got.Arr) != 3 || got.Arr[1].Str != "injected.com" || got.Arr[2].Str != "a.b.com" {
		t.Fatalf("legacy: expected the quote to add an entry and the escape to decode, got %+v", got.Arr)
	}
	for _, d := range domains[2:] {
		dir := t.TempDir()
		if _, err := WriteSessionJSON(dir, Session{ID: "s", Agent: "a", Tier: "2", Domains: []string{d}}); err == nil {
			t.Errorf("legacy: %q should leave an empty record", d)
		}
	}
	defer deviation.Force(deviation.AuditDomainsAsData)()
	for _, d := range domains {
		dir := t.TempDir()
		if _, err := WriteSessionJSON(dir, Session{ID: "s", Agent: "a", Tier: "2", Domains: []string{d}}); err != nil {
			t.Fatalf("fixed: %q: %v", d, err)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "session.json"))
		vs, err := jqjson.ParseValues(string(b))
		if err != nil || len(vs[0].Get("allowed_domains").Arr) != 1 || vs[0].Get("allowed_domains").Arr[0].Str != d {
			t.Errorf("fixed: %q recorded as %s", d, b)
		}
	}
}
