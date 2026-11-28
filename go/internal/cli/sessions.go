package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
)

// The session commands read the local session logs. Their v2 halves that query the cluster (the
// active-pod table in list, warn_untorndown_sessions) are replaced by sandboxd in v3; until then
// they print what v2 prints when no cluster is reachable.

// jqAlt is `jq -r '.KEY // "DEF"' FILE 2>/dev/null || echo DEF` under command substitution: one
// line per JSON text in the file (strings raw, other values in jq's layout), DEF for a missing,
// null, or false field; a JSON text that is not an object, or invalid JSON, ends the output with
// DEF.
func jqAlt(path, key, def string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	vals, err := jqjson.ParseValues(string(b))
	if err != nil {
		return def
	}
	var out []string
	for _, v := range vals {
		var x jqjson.Value
		switch v.Kind {
		case jqjson.Object:
			x = v.Get(key)
		case jqjson.Null:
		default:
			// $(...) strips trailing newlines on this exit too (an empty DEF leaves none)
			return strings.TrimRight(strings.Join(append(out, def), "\n"), "\n")
		}
		switch {
		case x.Kind == jqjson.Null || (x.Kind == jqjson.Bool && !x.B):
			out = append(out, def)
		case x.Kind == jqjson.String:
			out = append(out, x.Str)
		default:
			out = append(out, strings.TrimSuffix(jqjson.Encode(x), "\n"))
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// sessionDirs is "${SANDBOX_LOGS_DIR}"/ses-*/ with the [[ -d ]] test: sorted names of directories
// (or links to them) named ses-*.
func sessionDirs(logs string) []string {
	ents, err := os.ReadDir(logs)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "ses-") && isDir(filepath.Join(logs, e.Name())) {
			out = append(out, e.Name())
		}
	}
	return out
}

// cmdList is cmd_list: the active sessions (v2 asked the cluster; see above) and the recent
// session logs.
func cmdList(c *cmdCtx, args []string) {
	c.out("Active pods in namespace 'sandbox':")
	c.out("")
	c.activeSessions()
	c.out("")
	logs := c.env.LogsDir
	c.out("Recent sessions (%s):", logs)
	c.out("")
	if !isDir(logs) {
		c.out("  (log directory does not exist: %s)", logs)
		return
	}
	found := false
	for _, sid := range sessionDirs(logs) {
		found = true
		sj := filepath.Join(logs, sid) + "//session.json" // "${session_dir}/session.json", the glob's trailing slash kept
		if !isRegularFile(sj) {
			fmt.Fprintf(c.stdout, "  %s  (no session.json)\n", padRight(sid, 36))
			continue
		}
		agent, tier := jqAlt(sj, "agent", "?"), jqAlt(sj, "tier", "?")
		name, start, end := jqAlt(sj, "name", ""), jqAlt(sj, "start_time", "?"), jqAlt(sj, "end_time", "running")
		fmt.Fprintf(c.stdout, "  %s  %s  tier%s  %s  %s → %s\n", padRight(sid, 36), padRight(agent, 10), padRight(tier, 2),
			padRight(name, 24), start, end)
	}
	if !found {
		c.out("  (no sessions found)")
	}
}

func isRegularFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }

// cmdLogs is cmd_logs: one session's record, transcript files, and workspace change log.
func cmdLogs(c *cmdCtx, args []string) {
	if len(args) == 0 || args[0] == "" {
		c.missingArg("1", "Usage: sandbox logs <SESSION_ID>")
	}
	sid := args[0]
	dir := c.env.LogsDir + "/" + sid
	if !isDir(dir) {
		c.die("Session not found: %s (looked in %s)", sid, dir)
	}
	c.out("=== Session: %s ===", sid)
	c.out("")
	if sj := dir + "/session.json"; isRegularFile(sj) {
		c.out("--- session.json ---")
		b, _ := os.ReadFile(sj)
		if vals, err := jqjson.ParseValues(string(b)); err == nil {
			for _, v := range vals {
				fmt.Fprint(c.stdout, jqjson.Encode(v))
			}
		}
		c.out("")
	}
	if td := dir + "/transcript"; isDir(td) {
		c.out("--- transcript (agent conversation) ---")
		var files []string
		filepath.WalkDir(td, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		for _, f := range files {
			fmt.Fprintf(c.stdout, "  %s\n", f)
		}
		c.out("")
	}
	if fl := dir + "/files.log"; isRegularFile(fl) {
		c.out("--- files.log (workspace changes) ---")
		b, _ := os.ReadFile(fl)
		c.stdout.Write(b)
		c.out("")
	}
}

// cmdCleanup is cmd_cleanup: remove session directories older than --older-than days (default 90),
// by `find -maxdepth 1 -name 'ses-*' -type d -mtime +N` (a malformed N matches nothing).
func cmdCleanup(c *cmdCtx, args []string) {
	days := "90"
	for i := 0; i < len(args); i++ {
		if v, ok := flagValue(c, args, &i, "--older-than"); ok {
			days = v
			continue
		}
		c.die("Unknown option: %s", args[i])
	}
	// With CleanupDaysValidated anything but a non-negative whole number of days is refused before
	// anything is removed. The bash handed it to `find -mtime +N`, which treats "-5" as "older than
	// minus five days" and so removed every session.
	if deviation.Fixed(deviation.CleanupDaysValidated) && !lineDigits.MatchString(days) {
		c.die("cleanup: --older-than must be a whole number of days, got '%s'", days)
	}
	c.out("==> Cleaning sessions older than %s days...", days)
	logs := c.env.LogsDir
	if !isDir(logs) {
		c.out("No log directory found.")
		return
	}
	// find -mtime +N: N is decimal digits, optionally after a '-'; anything else is a find error
	// (reported to /dev/null) that matches nothing.
	n, ok := int64(0), false
	if d := strings.TrimPrefix(days, "-"); lineDigits.MatchString(d) {
		ok = true
		var v int64
		fmt.Sscan(strings.TrimLeft(d, "0")+"0", &v)
		n = v / 10
		if d != days {
			n = -n
		}
	}
	var mins map[string]int
	if deviation.Fixed(deviation.RetentionMinimum) {
		var err error
		if mins, err = config.RetentionMinDays(c.env.Env); err != nil {
			c.die("%v; nothing was removed.", err)
		}
	}
	count, kept := 0, 0
	if ok {
		ents, _ := os.ReadDir(logs)
		now := time.Now()
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), "ses-") || !e.IsDir() {
				continue
			}
			st, err := os.Lstat(filepath.Join(logs, e.Name()))
			if err != nil {
				continue
			}
			if age := now.Sub(st.ModTime()); age > 0 && int64(age/(24*time.Hour)) > n {
				if min, t := keepFor(mins, filepath.Join(logs, e.Name())); min >= 0 && int64(age/(24*time.Hour)) <= int64(min) {
					c.out("  Keeping:  %s (the overlay keeps tier %s logs for %d days)", e.Name(), t, min)
					kept++
					continue
				}
				c.out("  Removing: %s", e.Name())
				os.RemoveAll(filepath.Join(logs, e.Name()))
				count++
			}
		}
	}
	c.out("Removed %d session(s).", count)
	if kept > 0 {
		c.out("Kept %d session(s) the overlay's minimum retention still covers.", kept)
	}
}

// keepFor is the overlay's minimum retention for the session logged in dir (-1 for none), and the
// tier it applies to. A session whose tier cannot be read gets the largest minimum the overlay
// sets, so an unreadable record is never what lets its logs go early.
func keepFor(mins map[string]int, dir string) (int, string) {
	if len(mins) == 0 {
		return -1, ""
	}
	if rec, ok := sessionRecord(filepath.Join(dir, "session.json")); ok {
		t := jqRawField(rec, "tier", "")
		if d, ok := mins[t]; ok {
			return d, t
		}
		if t == "1" || t == "2" || t == "3" {
			return -1, t
		}
	}
	max, tier := -1, "unknown"
	for t, d := range mins {
		if d > max {
			max, tier = d, t+" (its record unreadable; the largest minimum)"
		}
	}
	return max, tier
}

// phases are v2's pod phases for sandboxd's session states.
var phases = map[string]string{"REQUESTED": "Pending", "ADMITTED": "Pending", "STARTING": "Pending",
	"RUNNING": "Running", "STOPPING": "Terminating", "FAILED": "Failed"}

// activeSessions is cmd_list's `kubectl get pods -o custom-columns=...` over sandboxd's sessions:
// the session, and from its record the agent, tier, name, and start time; nothing when there are
// none (kubectl said so on stderr), "(could not reach cluster)" when sandboxd cannot be asked.
func (c *cmdCtx) activeSessions() {
	s := c.env.Launch.Sessions
	if s == nil {
		c.out("(could not reach cluster)")
		return
	}
	live, err := s.List()
	if err != nil {
		c.out("(could not reach cluster)")
		return
	}
	if len(live) == 0 {
		return
	}
	none := func(v string) string {
		if v == "" {
			return "<none>"
		}
		return v
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 8, 3, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tAGENT\tTIER\tNAME\tSTATUS\tAGE")
	for _, l := range live {
		sj := filepath.Join(c.env.LogsDir, l.ID, "session.json")
		phase, ok := phases[l.State]
		if !ok {
			phase = "Unknown"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", l.ID, none(jqAlt(sj, "agent", "")), none(jqAlt(sj, "tier", "")),
			none(jqAlt(sj, "name", "")), phase, none(jqAlt(sj, "start_time", "")))
	}
	tw.Flush()
}
