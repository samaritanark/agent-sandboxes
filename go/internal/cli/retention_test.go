package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
)

// TestRetentionMinimum (deviation.RetentionMinimum, OQ-08): a session's record claims no
// retention unless the overlay sets a minimum for its tier, and cleanup keeps every session
// younger than its tier's minimum (an unreadable record gets the largest), removes the rest past
// --older-than, and refuses to remove anything when a minimum is not a whole number of days.
func TestRetentionMinimum(t *testing.T) {
	defer deviation.Force(deviation.RetentionMinimum)()
	e, fs, home := launchEnv(t)
	var out bytes.Buffer
	if rc := Run([]string{"run"}, e, &out, &bytes.Buffer{}); rc != 0 {
		t.Fatal(out.String())
	}
	rec, _ := sessionRecord(filepath.Join(e.LogsDir, fs.started[0].ID, "session.json"))
	if v := rec.Get("retention_days"); v.Kind != jqjson.Null {
		t.Errorf("no overlay: retention_days %v", v)
	}
	ov := filepath.Join(home, "overlay")
	os.MkdirAll(ov, 0o755)
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("log_retention_min_days_tier1: 10\nlog_retention_min_days_tier3: 60\n"), 0o644)
	e.SandboxOverlay = ov
	fs = &fakeSessions{}
	e.Launch.Sessions = fs
	if rc := Run([]string{"run"}, e, &out, &bytes.Buffer{}); rc != 0 {
		t.Fatal(out.String())
	}
	rec, _ = sessionRecord(filepath.Join(e.LogsDir, fs.started[0].ID, "session.json"))
	if got := jqRawField(rec, "retention_days", ""); got != "10" {
		t.Errorf("tier 1 under the overlay: retention_days %q", got)
	}

	// cleanup
	logs := t.TempDir()
	e.LogsDir = logs
	old := time.Now().Add(-40 * 24 * time.Hour)
	mk := func(id, tier string) {
		d := filepath.Join(logs, id)
		os.MkdirAll(d, 0o755)
		if tier != "" {
			audit.WriteSessionJSON(d, audit.Session{ID: id, Agent: "claude", Tier: tier})
		}
		os.Chtimes(d, old, old)
	}
	mk("ses-20261001-000000-0001", "1") // past tier 1's 10 days: removed
	mk("ses-20261001-000000-0003", "3") // within tier 3's 60 days: kept
	mk("ses-20261001-000000-0002", "2") // tier 2 has no minimum: removed
	mk("ses-20261001-000000-0009", "")  // no record: the largest minimum, kept
	out.Reset()
	if rc := Run([]string{"cleanup", "--older-than", "30"}, e, &out, &bytes.Buffer{}); rc != 0 {
		t.Fatal(out.String())
	}
	for id, want := range map[string]bool{"ses-20261001-000000-0001": false, "ses-20261001-000000-0002": false,
		"ses-20261001-000000-0003": true, "ses-20261001-000000-0009": true} {
		if _, err := os.Stat(filepath.Join(logs, id)); (err == nil) != want {
			t.Errorf("%s kept %v, want %v\n%s", id, err == nil, want, out.String())
		}
	}
	if !strings.Contains(out.String(), "Removed 2 session(s).") || !strings.Contains(out.String(), "Kept 2 session(s)") ||
		!strings.Contains(out.String(), "Keeping:  ses-20261001-000000-0003 (the overlay keeps tier 3 logs for 60 days)") {
		t.Errorf("%s", out.String())
	}

	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("log_retention_min_days_tier3: 6O\n"), 0o644)
	var errb bytes.Buffer
	if rc := Run([]string{"cleanup", "--older-than", "0"}, e, &bytes.Buffer{}, &errb); rc != 1 ||
		!strings.Contains(errb.String(), "log_retention_min_days_tier3 must be a whole number of days, got '6O'; nothing was removed.") {
		t.Errorf("%d %s", rc, errb.String())
	}
	if _, err := os.Stat(filepath.Join(logs, "ses-20261001-000000-0003")); err != nil {
		t.Error("an invalid minimum removed a session")
	}
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("log_retention_min_days_tier3: 010\n"), 0o644)
	if rc := Run([]string{"cleanup", "--older-than", "0"}, e, &bytes.Buffer{}, &bytes.Buffer{}); rc != 1 {
		t.Error("a minimum with a leading zero was accepted")
	}
}
