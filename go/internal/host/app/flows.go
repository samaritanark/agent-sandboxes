package app

// `sandbox flows ID` and `sandbox status` on the host (design 5.12: the gateway's request log
// replaces v2's Hubble flows.json; status reports the VM). flows pulls the session's records from
// the VM when it can, then prints those the host holds, one line each.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

var flowSessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (a *app) flows(args []string) int {
	if len(args) != 1 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(a.env.Stdout, "Usage: sandbox flows <SESSION_ID>")
		if len(args) == 1 {
			return 0
		}
		return 1
	}
	id := args[0]
	if !flowSessionRE.MatchString(id) {
		a.die("Session not found: %s", id)
	}
	if st, err := a.env.Driver.Status(a.ctx); err == nil && st == driver.Running {
		if ep, err := a.env.Driver.Endpoint(a.ctx); err == nil {
			a.pullAudit(ep)
		}
	}
	dir := filepath.Join(a.env.StateDir, "logs", id)
	f, err := os.Open(filepath.Join(dir, "flows.jsonl"))
	if err != nil {
		if _, derr := os.Stat(dir); derr != nil {
			a.die("Session not found: %s (looked in %s)", id, dir)
		}
		fmt.Fprintln(a.env.Stdout, "(no flows recorded for this session)")
		return 0
	}
	defer f.Close()
	fmt.Fprintf(a.env.Stdout, "=== Gateway flows for %s ===\n", id)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r map[string]any
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		fmt.Fprintln(a.env.Stdout, flowLine(r))
	}
	return 0
}

// flowLine is one record: time, decision, destination, and for an intercepted request its method,
// path, status, and deciding rule.
func flowLine(r map[string]any) string {
	str := func(k string) string {
		switch v := r[k].(type) {
		case string:
			return v
		case float64:
			return fmt.Sprint(int64(v))
		}
		return ""
	}
	dest := str("authority")
	if dest == "" {
		dest = str("sni")
	}
	if dest == "" {
		dest = str("dependency")
	}
	if dest == "" {
		dest = str("upstream")
	}
	if p := str("port"); p != "" && p != "443" && !strings.Contains(dest, ":") {
		dest += ":" + p
	}
	fields := []string{str("start"), fmt.Sprintf("%-10s", str("decision")), dest}
	if m := str("method"); m != "" {
		fields = append(fields, m, str("path"), str("status"), str("rule"))
	} else if reason := str("reason"); reason != "" {
		fields = append(fields, "("+reason+")")
	}
	return strings.TrimRight(strings.Join(fields, "  "), " ")
}
