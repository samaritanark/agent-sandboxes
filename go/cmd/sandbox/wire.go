package main

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/lima"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sizing"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sshx"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/vfkit"
)

// wire picks the VM driver and transport for this host.
func wire(home string) (driver.Driver, app.Transport, error) {
	state := filepath.Join(home, ".sandbox", "vm")
	var d driver.Driver
	switch {
	case runtime.GOOS == "darwin" && vfkit.Recorded(state):
		vd, err := vfkit.Open(state)
		if err != nil {
			return nil, nil, err
		}
		d = vd
	case runtime.GOOS == "darwin" || runtime.GOOS == "linux":
		ld, err := lima.Open(state)
		switch {
		case errors.Is(err, driver.ErrNotCreated):
			d = driver.Absent{}
		case err != nil:
			return nil, nil, err
		default:
			d = ld
		}
	default:
		d = driver.Absent{Reason: "no VM driver for " + runtime.GOOS + " yet (design 5.2.2: decided by spike S3)"}
	}
	ssh, err := sshx.DefaultSSH()
	if err != nil {
		return d, nil, err
	}
	return d, &sshx.Client{SSH: ssh, Identity: filepath.Join(state, "id_ed25519"), KnownHosts: filepath.Join(state, "known_hosts")}, nil
}

// installDeps are install's real host parts: vfkit (the default) or Lima on macOS, Lima on Linux,
// ssh-keygen for keys.
func installDeps(home string) app.InstallDeps {
	state := filepath.Join(home, ".sandbox", "vm")
	return app.InstallDeps{
		RecordDriver: func(kind, tool string) (driver.Driver, error) {
			if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
				return nil, errors.New("no VM driver for " + runtime.GOOS + " yet (design 5.2.2: decided by spike S3)")
			}
			if kind == "" {
				kind = map[bool]string{true: "vfkit", false: "lima"}[runtime.GOOS == "darwin"]
			}
			switch kind {
			case "vfkit":
				if tool == "" {
					tool = "vfkit"
				}
				if _, err := vfkit.Record(state, tool); err != nil {
					return nil, err
				}
				return vfkit.Open(state)
			case "lima":
			default:
				return nil, errors.New("unknown VM driver '" + kind + "' (vfkit or lima)")
			}
			if tool == "" {
				tool = "limactl"
			}
			if _, err := lima.Record(state, tool); err != nil {
				return nil, err
			}
			return lima.Open(state)
		},
		GenerateKey: func(comment string) (string, string, error) {
			ssh, err := sshx.DefaultSSH()
			if err != nil {
				return "", "", err
			}
			k, err := sshx.GenerateKey(context.Background(), sshx.DefaultKeygen(ssh), comment)
			return k.Private, k.Public, err
		},
		HostCPUs:   runtime.NumCPU(),
		HostMemGiB: int(sizing.HostMemory() >> 30),
	}
}
