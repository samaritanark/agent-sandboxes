package driver

import (
	"context"
	"fmt"
)

// Mock is an in-memory driver for tests (5.1.2: unit tests run on every OS without
// virtualization). It records the calls made to it.
type Mock struct {
	State    State
	Caps     Capabilities
	EP       SSHEndpoint
	Reach    HostReachControl
	Fail     map[string]error // method name -> error to return
	Calls    []string
	Created  *SeedConfig
	Resource Resources
}

func (m *Mock) call(name string) error {
	m.Calls = append(m.Calls, name)
	return m.Fail[name]
}

func (m *Mock) Name() string { return "mock" }

func (m *Mock) Probe(context.Context) (Capabilities, error) { return m.Caps, m.call("Probe") }

func (m *Mock) Create(_ context.Context, _ ImageRef, res Resources, seed SeedConfig) error {
	if err := m.call("Create"); err != nil {
		return err
	}
	if m.State != NotCreated {
		return fmt.Errorf("the sandbox VM already exists")
	}
	m.State, m.Created, m.Resource = Stopped, &seed, res
	return nil
}

func (m *Mock) Start(context.Context) error {
	if err := m.call("Start"); err != nil {
		return err
	}
	if m.State == NotCreated {
		return ErrNotCreated
	}
	m.State = Running
	return nil
}

func (m *Mock) Stop(context.Context) error {
	if err := m.call("Stop"); err != nil {
		return err
	}
	if m.State == NotCreated {
		return ErrNotCreated
	}
	m.State = Stopped
	return nil
}

func (m *Mock) Delete(context.Context) error {
	if err := m.call("Delete"); err != nil {
		return err
	}
	m.State = NotCreated
	return nil
}

func (m *Mock) Status(context.Context) (State, error) { return m.State, m.call("Status") }

func (m *Mock) Endpoint(context.Context) (SSHEndpoint, error) {
	if err := m.call("Endpoint"); err != nil {
		return SSHEndpoint{}, err
	}
	if m.State != Running {
		return SSHEndpoint{}, fmt.Errorf("the sandbox VM is %s", m.State)
	}
	return m.EP, nil
}

func (m *Mock) HostReach(context.Context) (HostReachControl, error) {
	return m.Reach, m.call("HostReach")
}
