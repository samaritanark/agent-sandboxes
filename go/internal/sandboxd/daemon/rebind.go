package daemon

// Rebind hands a running session's gateway its credentials again (design 5.9.5, the exec-plugin
// token pump): the host has stored a renewed credential in the broker store, and the gateway's
// brokers take the new values whole. Only a running session; its bindings are its policy's.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
)

func (d *Daemon) Rebind(ctx context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.Journal.Load(id)
	if err != nil {
		return err
	}
	if s.State != journal.Running {
		return fmt.Errorf("session %s is %s, not running", id, s.State)
	}
	if d.Broker == nil {
		return errors.New("sandboxd has no broker store")
	}
	gwDir := filepath.Join(d.SessionRoot, id, "gateway")
	b, err := os.ReadFile(filepath.Join(gwDir, "policy.json"))
	if err != nil {
		return fmt.Errorf("the session's gateway policy: %w", err)
	}
	var pol gwpolicy.Policy
	if err := json.Unmarshal(b, &pol); err != nil {
		return fmt.Errorf("the session's gateway policy: %w", err)
	}
	refs := make([][]Use, len(pol.Links))
	any := false
	for i, l := range pol.Links {
		for _, bd := range l.Bindings {
			refs[i] = append(refs[i], Use{Ref: bd.Ref, Hosts: bd.Hosts, Inject: bd.Inject})
			any = true
		}
	}
	if !any {
		return fmt.Errorf("session %s binds no credentials", id)
	}
	if err := d.Broker.HandOver(ctx, id, filepath.Join(gwDir, gwpolicy.HandoverSocket), refs); err != nil {
		return fmt.Errorf("credential handover: %w", err)
	}
	d.logf("session %s: credentials handed over again", id)
	return nil
}
