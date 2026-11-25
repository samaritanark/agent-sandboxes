package main

import (
	"errors"
	"path/filepath"
	"runtime"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/lima"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sshx"
)

// wire picks the VM driver and transport for this host.
func wire(home string) (driver.Driver, app.Transport, error) {
	state := filepath.Join(home, ".sandbox", "vm")
	var d driver.Driver
	switch runtime.GOOS {
	case "darwin", "linux":
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
