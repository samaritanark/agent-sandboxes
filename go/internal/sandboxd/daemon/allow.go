package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// Allow adds names to a running session's allowlist (`sandbox allow`; the policy layer has already
// checked them against the block lists). The session's spec is checked again with them, the agent
// link's allowlist in its gateway's policy is replaced, and the gateway reloads it: its resolver
// and connection check at once, and its Envoy by a restart, which resets the agent's connections
// open through it. The session, its terminal, and its brokers stay. It returns how many names were
// new.
func (d *Daemon) Allow(ctx context.Context, id string, names []string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.live[id]; !ok {
		return 0, fmt.Errorf("session %s is not running", id)
	}
	s, err := d.Journal.Load(id)
	if err != nil {
		return 0, err
	}
	spec := *s.Spec
	spec.Egress.Allow = append([]string(nil), s.Spec.Egress.Allow...)
	var added []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" && !slices.Contains(spec.Egress.Allow, n) {
			spec.Egress.Allow = append(spec.Egress.Allow, n)
			added = append(added, n)
		}
	}
	if len(added) == 0 {
		return 0, nil
	}
	if err := spec.Validate(sessionspec.Options{}); err != nil {
		return 0, fmt.Errorf("the widened allowlist is refused: %w", err)
	}
	slot := -1
	for _, r := range s.Live() {
		if r.Kind == KindUplink {
			slot, _ = strconv.Atoi(r.Name)
		}
	}
	if slot < 0 {
		return 0, errors.New("the session has no gateway")
	}
	gwDir := filepath.Join(d.SessionRoot, id, "gateway")
	b, err := os.ReadFile(filepath.Join(gwDir, "policy.json"))
	if err != nil {
		return 0, err
	}
	pol, err := gwpolicy.Decode(b)
	if err != nil {
		return 0, err
	}
	pol.Links[0].Allow = spec.Egress.Allow
	pol.Generation++
	nb, _ := json.Marshal(pol)
	if err := d.Gateways.Reload(ctx, id, gwDir, slot, pol.Generation, nb); err != nil {
		return 0, fmt.Errorf("gateway: %w", err)
	}
	if err := d.Journal.SetSpec(id, &spec, "allowlist extended: "+strings.Join(added, ",")); err != nil {
		return 0, err
	}
	d.audit(id, auditlog.Events, "allowlist_extended", map[string]any{"added": added})
	return len(added), nil
}
