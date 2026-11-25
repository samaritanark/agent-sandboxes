package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/lima"
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
	return d, noTransport{}, nil
}

type noTransport struct{}

var errNoTransport = errors.New("this build of the v3 host binary cannot reach the VM yet")

func (noTransport) Run(context.Context, driver.SSHEndpoint, []string, io.Reader, io.Writer, io.Writer, bool) (int, error) {
	return 1, errNoTransport
}

func (noTransport) Output(context.Context, driver.SSHEndpoint, []string, int) ([]byte, error) {
	return nil, errNoTransport
}
