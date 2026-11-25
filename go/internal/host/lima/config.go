package lima

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// SeedPath is where the seed lands in the guest (design 5.3.3): Lima writes it with a `mode: data`
// provision, after its boot scripts and before any other provisioning, root-owned and 0600. The
// appliance image reads it before sshd starts, so the guest's SSH host key is the one the host
// generated and pinned, and neither Lima's first-connect scan nor our transport ever trusts a key
// it has not seen before. The file holds KEY=VALUE lines; multi-line values are base64. Nothing goes
// in Lima's `env:`, which Lima also copies into /etc/environment for every user to read.
const SeedPath = "/etc/sandbox/seed.env"

// The seed's keys (see driver.SeedEnv).
const (
	SeedHostname      = driver.SeedHostname
	SeedHostKey       = driver.SeedHostKey
	SeedHostKeyPub    = driver.SeedHostKeyPub
	SeedAuthorizedKey = driver.SeedAuthorizedKey
	SeedCABundle      = driver.SeedCABundle
	SeedDNS           = driver.SeedDNS
	SeedProxy         = driver.SeedProxy
)

func limaArch(goarch string) (string, error) {
	switch goarch {
	case "arm64":
		return "aarch64", nil
	case "amd64":
		return "x86_64", nil
	}
	return "", fmt.Errorf("unsupported architecture %s", goarch)
}

// Config renders the instance configuration as JSON, which Lima reads as YAML. Every setting
// design 5.2.5 depends on is written out rather than left to Lima's defaults, which change
// between releases:
//
//   - no mounts, no agent forwarding, no X11, no ~/.ssh keys, no containerd, no Rosetta, no
//     host proxy environment, no display or audio;
//   - plain mode (no guest agent, so no automatic port forwarding; S7 confirmed it closes the
//     guest-loopback fallback rule), plus an ignore-everything portForwards rule in case a later
//     Lima applies rules in plain mode;
//   - on vz, hostLoopback false (S7) and nested virtualization.
func Config(goos, goarch string, img driver.ImageRef, res driver.Resources, seed driver.SeedConfig) ([]byte, error) {
	arch, err := limaArch(goarch)
	if err != nil {
		return nil, err
	}
	vmType := "qemu"
	if goos == "darwin" {
		vmType = "vz"
	}
	if img.Path == "" || !strings.HasPrefix(img.Path, "/") {
		return nil, fmt.Errorf("image path must be absolute: %q", img.Path)
	}
	if res.CPUs < 1 || res.MemoryMiB < 512 || res.DiskGiB < 1 {
		return nil, fmt.Errorf("invalid VM resources %+v", res)
	}
	for _, v := range append([]string{seed.Hostname, seed.HostKeyPublic, seed.AuthorizedKey, seed.Proxy}, seed.DNS...) {
		if strings.Contains(v, "{{") { // Lima evaluates a data provision's content as a template
			return nil, fmt.Errorf("seed value holds a template marker")
		}
	}
	env, err := driver.SeedEnv(seed)
	if err != nil {
		return nil, err
	}
	c := map[string]interface{}{
		"vmType": vmType,
		"arch":   arch,
		"images": []map[string]string{{"location": img.Path, "arch": arch}},
		"cpus":   res.CPUs,
		"memory": fmt.Sprintf("%dMiB", res.MemoryMiB),
		"disk":   fmt.Sprintf("%dGiB", res.DiskGiB),
		"mounts": []interface{}{},
		"ssh": map[string]interface{}{
			"localPort": 0, "loadDotSSHPubKeys": false, "forwardAgent": false,
			"forwardX11": false, "forwardX11Trusted": false,
		},
		"containerd":        map[string]bool{"system": false, "user": false},
		"plain":             true,
		"portForwards":      []map[string]interface{}{{"guestIP": "0.0.0.0", "proto": "any", "ignore": true}},
		"propagateProxyEnv": false,
		"upgradePackages":   false,
		"video":             map[string]string{"display": "none"},
		"audio":             map[string]string{"device": ""},
		"hostResolver":      map[string]bool{"enabled": true},
		"provision": []map[string]interface{}{{
			"mode": "data", "path": SeedPath, "content": env,
			"owner": "root:root", "permissions": 600, "overwrite": true,
		}},
	}
	if vmType == "vz" {
		c["nestedVirtualization"] = true
		c["networkOpts"] = map[string]bool{"hostLoopback": false}
		c["vmOpts"] = map[string]interface{}{"vz": map[string]interface{}{"rosetta": map[string]bool{"enabled": false, "binfmt": false}}}
	} else if arch == "aarch64" {
		c["nestedVirtualization"] = true
	}
	return json.MarshalIndent(c, "", "  ")
}
