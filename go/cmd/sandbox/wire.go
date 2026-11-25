package main

import (
	"errors"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// wire picks the VM driver and transport for this host.
func wire(home string) (driver.Driver, app.Transport, error) {
	return nil, nil, errors.New("this build of the v3 host binary has no VM driver yet")
}
