// Package audit is the session-record half of lib/audit.sh: session.json (written at launch,
// then edited in place by the teardown and event writers), the deferred override events, and the
// session list. Transcript capture (audit_capture_transcript) copies files out of a Kubernetes
// pod and is not ported; v3 captures transcripts in sandboxd.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

// Override is one accepted launch-time waiver (record_override).
type Override struct {
	Mechanism, What string
	Repos           []string // basenames
}

// RecordOverride is record_override: repos are stored as basenames, empty ones skipped.
func RecordOverride(mechanism, what string, repos ...string) Override {
	o := Override{Mechanism: mechanism, What: what, Repos: []string{}}
	for _, r := range repos {
		if r != "" {
			o.Repos = append(o.Repos, bashcompat.Basename(r))
		}
	}
	return o
}

func (o Override) value() Value {
	v := NewObject()
	v, _ = v.Set("mechanism", Str(o.Mechanism))
	v, _ = v.Set("what", Str(o.What))
	r := Arr()
	for _, x := range o.Repos {
		r.Arr = append(r.Arr, Str(x))
	}
	v, _ = v.Set("repos", r)
	return v
}

// update is the bash's `jq FILTER session.json > tmp && mv tmp session.json`: nothing happens if
// the file is absent or the filter fails on any JSON text in it; on success the file is replaced
// by a mktemp file, so it ends up mode 0600.
func update(logDir string, f func(Value) (Value, error)) {
	p := filepath.Join(logDir, "session.json")
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	vs, err := parseValues(string(b))
	if err != nil {
		return
	}
	var out strings.Builder
	for _, v := range vs {
		nv, err := f(v)
		if err != nil {
			return
		}
		out.WriteString(encode(nv))
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(out.String()), 0o600); err != nil {
		return
	}
	os.Chmod(tmp, 0o600)
	os.Rename(tmp, p)
}

// appendEvent is jq's `.events += [e]`.
func appendEvent(v Value, e Value) (Value, error) {
	if v.Kind != Object && v.Kind != Null {
		return v, fmt.Errorf("cannot index %s", kindName(v.Kind))
	}
	ev := v.Get("events")
	switch ev.Kind {
	case Null:
		ev = Arr(e)
	case Array:
		ev = Arr(append(append([]Value{}, ev.Arr...), e)...)
	default:
		return v, fmt.Errorf("%s and array cannot be added", kindName(ev.Kind))
	}
	return v.Set("events", ev)
}

// FlushOverrides is audit_flush_overrides: each override becomes an "override" event stamped now.
func FlushOverrides(logDir string, overrides []Override, now string) {
	if len(overrides) == 0 {
		return
	}
	for _, o := range overrides {
		ev := o.value().Merge(mustObj("time", Str(now), "type", Str("override")))
		update(logDir, func(v Value) (Value, error) { return appendEvent(v, ev) })
	}
}

func mustObj(kv ...interface{}) Value {
	v := NewObject()
	for i := 0; i < len(kv); i += 2 {
		v, _ = v.Set(kv[i].(string), kv[i+1].(Value))
	}
	return v
}

// Session is what audit_write_session_json records. The bash reads Profile through
// InfraKubeconfig from SESSION_* variables; InfraToken and InfraKubeconfig are recorded as whether
// the variable was non-empty.
type Session struct {
	ID, Agent, Tier, User string
	Repos                 []string
	Name, PodName         string
	StartTime             string
	CredentialType        string // get_agent_credential_type <agent>
	Domains               []string
	Profile, Overlay      string
	KubeAPICIDR           string
	KubeAPIPort           string
	KubeAPIContexts       string
	KubeHostEntity        string
	InfraToken            bool
	InfraKubeconfig       bool
}

// WriteSessionJSON is audit_write_session_json: it writes <logDir>/session.json and returns the
// line the bash prints. On an error (in legacy mode, a domain that does not make a valid JSON
// string) the file is left empty, as the bash's truncating redirect leaves it.
//
// In legacy mode each domain is pasted between quotes into JSON text, so a quote in a domain adds
// entries to the record and an escape (A) is recorded as the character it names; with
// AuditDomainsAsData each domain is recorded exactly as given.
func WriteSessionJSON(logDir string, s Session) (string, error) {
	p := filepath.Join(logDir, "session.json")
	line := "  Wrote session.json: " + p
	var domains Value
	if deviation.Fixed(deviation.AuditDomainsAsData) {
		domains = Arr()
		for _, d := range s.Domains {
			domains.Arr = append(domains.Arr, Str(d))
		}
	} else {
		raw := "["
		for i, d := range s.Domains {
			if i > 0 {
				raw += ","
			}
			raw += `"` + d + `"`
		}
		var err error
		if domains, err = parseOne(raw + "]"); err != nil {
			os.WriteFile(p, nil, 0o666)
			return line, err
		}
	}
	tierV, err := parseOne(s.Tier) // --argjson tier
	if err != nil {
		os.WriteFile(p, nil, 0o666)
		return line, err
	}
	repos := Arr()
	for _, r := range s.Repos {
		repos.Arr = append(repos.Arr, Str(r))
	}
	v := mustObj(
		"id", Str(s.ID), "agent", Str(s.Agent), "tier", tierV, "user", Str(s.User), "repos", repos,
		"name", Str(s.Name), "pod_name", Str(s.PodName), "start_time", Str(s.StartTime),
		"end_time", Value{}, "agent_session_id", Value{}, "credential_type", Str(s.CredentialType),
		"profile", Str(s.Profile), "overlay", Str(s.Overlay), "kube_api_cidr", Str(s.KubeAPICIDR),
		"kube_api_port", Str(s.KubeAPIPort), "kube_api_contexts", Str(s.KubeAPIContexts),
		"kube_host_entity", Str(s.KubeHostEntity), "infra_token", BoolV(s.InfraToken),
		"infra_kubeconfig", BoolV(s.InfraKubeconfig), "allowed_domains", domains,
		"retention_days", Int(tier.RetentionDays(s.Tier)))
	return line, os.WriteFile(p, []byte(encode(v)), 0o666)
}

func setter(k string, x Value) func(Value) (Value, error) {
	return func(v Value) (Value, error) { return v.Set(k, x) }
}

// UpdateEndTime is audit_update_end_time.
func UpdateEndTime(logDir, endTime string) { update(logDir, setter("end_time", Str(endTime))) }

// RecordEndReason is audit_record_end_reason; an empty reason records nothing.
func RecordEndReason(logDir, reason, detail string) {
	if reason == "" {
		return
	}
	update(logDir, func(v Value) (Value, error) {
		v, err := v.Set("end_reason", Str(reason))
		if err != nil {
			return v, err
		}
		return v.Set("end_detail", Str(detail))
	})
}

// RecordAgentSessionID is audit_record_agent_session_id.
func RecordAgentSessionID(logDir, id string) { update(logDir, setter("agent_session_id", Str(id))) }

// RecordDependencies is audit_record_dependencies; depsJSON is a JSON array (it is not checked to
// be one, as in the bash); invalid JSON records nothing.
func RecordDependencies(logDir, depsJSON string) {
	deps, err := parseOne(depsJSON)
	if err != nil {
		return
	}
	update(logDir, setter("dependencies", deps))
}

// RecordDependenciesDown is audit_record_dependencies_down: stamp down_time on every recorded
// dependency, when .dependencies is an array.
func RecordDependenciesDown(logDir, downTime string) {
	update(logDir, func(v Value) (Value, error) {
		if v.Kind != Object && v.Kind != Null {
			return v, fmt.Errorf("cannot index %s", kindName(v.Kind))
		}
		deps := v.Get("dependencies")
		if deps.Kind != Array {
			return v, nil
		}
		out := Arr()
		for _, d := range deps.Arr {
			nd, err := d.Set("down_time", Str(downTime))
			if err != nil {
				return v, err
			}
			out.Arr = append(out.Arr, nd)
		}
		return v.Set("dependencies", out)
	})
}

// LogEvent is audit_log_event: append {time, type, message}, stamped now.
func LogEvent(logDir, eventType, message, now string) {
	ev := mustObj("time", Str(now), "type", Str(eventType), "message", Str(message))
	update(logDir, func(v Value) (Value, error) { return appendEvent(v, ev) })
}

// ListSessions is audit_list_sessions: the ses-* directories in logDir, sorted.
func ListSessions(logDir string) []string {
	ents, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "ses-") {
			continue
		}
		if st, err := os.Stat(filepath.Join(logDir, n)); err == nil && st.IsDir() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
