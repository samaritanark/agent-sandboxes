package app

// The host half of the broker store (design 5.9.2, D-32): the key lives in the host's keeper
// (package brokerkey), reaches sandboxd only on stdin over the control channel, and is held there
// in memory; credentials are sealed here, so the VM stores entries it cannot read without the key.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// SandboxdCommand is the in-VM supervisor's control command, by its full path: the image installs
// it off PATH (image/mkosi.extra's sandboxd.service).
const SandboxdCommand = "/usr/lib/sandbox/bin/sandboxd"

// brokerKey returns the store key, making it the first time.
func (a *app) brokerKey() ([]byte, error) {
	k, created, err := brokerkey.Get(a.env.BrokerKey)
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Fprintf(a.env.Stdout, "==> Made the credential broker's store key (kept in %s)\n", a.env.BrokerKey.Where())
	}
	return k, nil
}

// keyPushTries is how many times a start pushes the key before warning.
const keyPushTries = 15

// pushBrokerKey gives sandboxd the store key. sandboxd keeps it in memory only, so it is pushed
// at every VM start (and by `sandbox vm start` on a running VM, which is how a restarted sandboxd
// gets it back).
func (a *app) pushBrokerKey(ep driver.SSHEndpoint) error {
	if a.env.BrokerKey == nil {
		return nil
	}
	k, err := a.brokerKey()
	if err != nil {
		return err
	}
	defer brokerseal.Wipe(k)
	return a.sandboxd(ep, bytes.NewReader(k), "broker-key")
}

// warnBrokerKey is pushBrokerKey for the start paths, where a failure leaves the VM usable except
// for sessions with credential bindings.
// Right after boot it is retried for a while: the guest's sshd can restart once as the seed unit
// applies the host key, and sandboxd may not be listening yet (both seen on vfkit).
func (a *app) warnBrokerKey(ep driver.SSHEndpoint) {
	poll := a.env.Install.Poll
	if poll == 0 {
		poll = 2 * time.Second
	}
	err := a.pushBrokerKey(ep)
	for i := 1; err != nil && transient(err) && i < keyPushTries; i++ {
		time.Sleep(poll)
		err = a.pushBrokerKey(ep)
	}
	if err != nil {
		fmt.Fprintf(a.env.Stderr, "WARNING: could not give the credential broker its key: %v\n"+
			"  Sessions with credential bindings will be refused until 'sandbox vm start' succeeds.\n", err)
	}
}

func (a *app) sandboxd(ep driver.SSHEndpoint, stdin io.Reader, args ...string) error {
	var errb strings.Builder
	rc, err := a.env.Transport.Run(a.ctx, ep, append([]string{SandboxdCommand, "ctl"}, args...), stdin, io.Discard, &errb, false)
	if err == nil && rc != 0 {
		err = sandboxdError(strings.TrimSpace(errb.String()))
	}
	return err
}

// sandboxdError is sandboxd's own refusal, as against a failure to reach it.
type sandboxdError string

func (e sandboxdError) Error() string { return string(e) }

// transient is whether a failed sandboxd call may succeed if tried again: the SSH connection
// failed, or sandboxd is not listening yet. A refusal from sandboxd itself is final.
func transient(err error) bool {
	var se sandboxdError
	if !errors.As(err, &se) {
		return true
	}
	return strings.Contains(string(se), "sandboxd.sock")
}

// BrokerPut is the hidden `sandbox __broker-put REF`: seal the value on stdin as REF's entry and
// store it in the VM. It stands in until `run` pushes a session's bound secrets itself (5.1.4).
const BrokerPut = "__broker-put"

func (a *app) brokerPut(args []string) int {
	if len(args) != 1 || !brokerseal.ValidRef(args[0]) {
		a.die("usage: sandbox %s REF < VALUE (REF: letters, digits, '.', '_', '-')", BrokerPut)
	}
	if a.env.BrokerKey == nil {
		a.die("this host has no place to keep the credential broker's key")
	}
	v, err := io.ReadAll(io.LimitReader(a.env.Stdin, 64<<10))
	if err != nil {
		a.die("cannot read the value: %v", err)
	}
	defer brokerseal.Wipe(v)
	v = bytes.TrimRight(v, "\r\n")
	if len(v) == 0 {
		a.die("no value on stdin")
	}
	ep := a.running()
	a.handshake(ep)
	k, err := a.brokerKey()
	if err != nil {
		a.die("%v", err)
	}
	sealed, err := brokerseal.Seal(k, args[0], v)
	brokerseal.Wipe(k)
	if err != nil {
		a.die("%v", err)
	}
	if err := a.sandboxd(ep, bytes.NewReader(sealed), "broker-put", args[0]); err != nil {
		a.die("could not store %s in the sandbox VM: %v", args[0], err)
	}
	return 0
}

// doctorBrokerKey reports where the key lives; a plain file is a warning (5.9.2).
func (a *app) doctorBrokerKey(report func(ok bool, what, detail string), warn func(what, detail string)) {
	if a.env.BrokerKey == nil {
		return
	}
	k, err := a.env.BrokerKey.Load()
	brokerseal.Wipe(k)
	what := "credential broker key in " + a.env.BrokerKey.Where()
	switch {
	case errors.Is(err, brokerkey.ErrNoKey):
		report(true, what, "not made yet (made at the next VM start)")
	case err != nil:
		report(false, what, err.Error())
	case a.env.BrokerKey.Weak():
		warn(what, "a plain file: a copy of your home directory carries the key that opens the VM's credential store")
	default:
		report(true, what, "")
	}
}
