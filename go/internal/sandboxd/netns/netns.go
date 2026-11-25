// Package netns creates and removes sandboxd's named network namespaces (/var/run/netns/<name>)
// with iproute2's `ip netns`, which the appliance image ships. Namespaces are single-use (design
// 5.8.2, S1): a namespace is never reused for a second microVM.
package netns

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Dir is where named namespaces are bound.
const Dir = "/var/run/netns"

// Prefix marks sandboxd's namespaces; nothing else in the VM uses it.
const Prefix = "sbx-"

var nameRE = regexp.MustCompile(`^` + Prefix + `[a-z0-9-]{1,240}$`)

// Path is the file a microVM joins.
func Path(name string) string { return filepath.Join(Dir, name) }

// Manager runs ip (Tool, default /usr/sbin/ip).
type Manager struct {
	Tool string
}

func (m Manager) ip(ctx context.Context, args ...string) error {
	tool := m.Tool
	if tool == "" {
		tool = "/usr/sbin/ip"
	}
	out, err := exec.CommandContext(ctx, tool, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func check(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("netns: invalid name %q", name)
	}
	return nil
}

// Create makes the namespace name with only its loopback interface, up.
func (m Manager) Create(ctx context.Context, name string) error {
	if err := check(name); err != nil {
		return err
	}
	if _, err := os.Stat(Path(name)); err == nil {
		return fmt.Errorf("netns: %s already exists (namespaces are single-use)", name)
	}
	if err := m.ip(ctx, "netns", "add", name); err != nil {
		return err
	}
	return m.ip(ctx, "-n", name, "link", "set", "lo", "up")
}

// Delete removes the namespace; one already gone is not an error.
func (m Manager) Delete(ctx context.Context, name string) error {
	if err := check(name); err != nil {
		return err
	}
	if _, err := os.Stat(Path(name)); os.IsNotExist(err) {
		return nil
	}
	return m.ip(ctx, "netns", "delete", name)
}

// List is every sandboxd namespace present, for reconciliation.
func (m Manager) List(context.Context) ([]string, error) {
	ents, err := os.ReadDir(Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if nameRE.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
