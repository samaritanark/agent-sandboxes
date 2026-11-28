package app

// `sandbox upgrade` (design 10), for development images until signed releases are published: the
// VM's state (sessions' records, workspace copies, agent logins and homes, built images, the broker
// store) is on its state disk, so an upgrade replaces only the system disk. Sessions must be
// stopped first. The new image must boot and answer the handshake, and must not be older than the
// one it replaces unless --allow-downgrade is given; otherwise the previous system disk, which is
// kept, is put back. Each upgrade and roll-back is recorded in ~/.sandbox/logs/upgrades.log.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

const upgradeUsage = `Usage: sandbox upgrade --image <path> [--allow-downgrade]
       sandbox upgrade --rollback

  --image <path>       A local appliance image (raw). Signed releases are not published yet.
  --allow-downgrade    Accept an image older than the installed one (recorded).
  --rollback           Put back the system disk the last upgrade replaced.

The VM's state (logins, built images, workspace copies, session records) is kept. Stop running
sessions first (sandbox list, sandbox stop).
`

func (a *app) upgrade(args []string) int {
	image, downgrade, rollback := "", false, false
	for i := 0; i < len(args); i++ {
		switch v := args[i]; {
		case v == "--image" && i+1 < len(args):
			image = args[i+1]
			i++
		case strings.HasPrefix(v, "--image="):
			image = v[len("--image="):]
		case v == "--allow-downgrade":
			downgrade = true
		case v == "--rollback":
			rollback = true
		case v == "-h" || v == "--help":
			fmt.Fprint(a.env.Stdout, upgradeUsage)
			return 0
		case v == "--app" || v == "--infra" || v == "--all":
			a.die("upgrade %s was v2's: in v3 the host binary is updated by its package manager, and the VM with: sandbox upgrade --image <path>", v)
		default:
			fmt.Fprint(a.env.Stderr, upgradeUsage)
			a.die("upgrade: unknown option '%s'", v)
		}
	}
	if (image == "") == !rollback {
		fmt.Fprint(a.env.Stderr, upgradeUsage)
		a.die("upgrade: pass --image <path> (signed releases are not published yet) or --rollback")
	}
	d, ok := a.env.Driver.(driver.SystemDiskReplacer)
	if !ok {
		a.die("the %s driver keeps the VM's state on its system disk; to change its image: sandbox uninstall, then sandbox install", a.env.Driver.Name())
	}
	img := ""
	if image != "" {
		var err error
		if img, err = filepath.Abs(a.expandTilde(image)); err != nil {
			a.die("%v", err)
		}
		if st, err := os.Stat(img); err != nil || !st.Mode().IsRegular() {
			a.die("the image %s is not a file", img)
		}
		if err := checkDiskImage(img); err != nil {
			a.die("%v", err)
		}
	} else if !d.CanRollBack(a.ctx) {
		a.die("no previous system disk is kept: nothing to roll back to")
	}
	before := a.stopForUpgrade()
	if rollback {
		if err := d.RollBack(a.ctx); err != nil {
			a.die("could not roll back: %v", err)
		}
		info := a.bootAfterUpgrade()
		a.recordUpgrade("rollback", before, info.ImageVersion, "")
		fmt.Fprintf(a.env.Stdout, "The sandbox VM is rolled back: image %s → %s.\n", before, info.ImageVersion)
		return 0
	}
	fmt.Fprintf(a.env.Stderr, "WARNING: %s is a development image; its signature is not checked.\n", img)
	fmt.Fprintln(a.env.Stdout, "==> Replacing the sandbox VM's system disk (its state disk is kept)...")
	if err := d.ReplaceSystemDisk(a.ctx, driver.ImageRef{Path: img}); err != nil {
		a.startAgain()
		a.die("could not replace the system disk: %v", err)
	}
	fmt.Fprintln(a.env.Stdout, "==> Starting the sandbox VM...")
	var info releaseInfo
	failed := ""
	if err := a.env.Driver.Start(a.ctx); err != nil {
		failed = "it did not start: " + err.Error()
	} else if i, err := a.waitReady(); err != nil {
		failed = "it did not answer: " + err.Error()
	} else {
		info = releaseInfo{i.ImageVersion, i.ControlAPI}
		if before != "" && olderVersion(info.ImageVersion, before) && !downgrade {
			failed = fmt.Sprintf("image %s is older than the installed %s (pass --allow-downgrade to accept it)", info.ImageVersion, before)
		}
	}
	if failed != "" {
		fmt.Fprintf(a.env.Stderr, "WARNING: the new image was not accepted: %s; putting the previous system disk back.\n", failed)
		a.env.Driver.Stop(a.ctx)
		if err := d.RollBack(a.ctx); err != nil {
			a.die("could not put the previous system disk back: %v", err)
		}
		back := a.bootAfterUpgrade()
		a.recordUpgrade("rolled-back", before, info.ImageVersion, failed)
		a.die("the upgrade was rolled back (image %s): %s", back.ImageVersion, failed)
	}
	a.warnBrokerKey(a.running())
	note := ""
	if olderVersion(info.ImageVersion, before) {
		note = "downgrade allowed"
	}
	a.recordUpgrade("upgrade", before, info.ImageVersion, note)
	fmt.Fprintf(a.env.Stdout, "The sandbox VM is upgraded: image %s → %s (control API %d). The previous system disk is kept: sandbox upgrade --rollback\n",
		or(before, "unknown"), info.ImageVersion, info.ControlAPI)
	return 0
}

type releaseInfo struct {
	ImageVersion string
	ControlAPI   int
}

// stopForUpgrade refuses while sessions run, pulls the audit records, stops the VM, and returns the
// installed image version ("" when the VM was not running and so could not be asked).
func (a *app) stopForUpgrade() string {
	st, err := a.env.Driver.Status(a.ctx)
	if err != nil {
		a.die("cannot read the sandbox VM's state: %v", err)
	}
	if st == driver.NotCreated {
		a.die("the sandbox VM has not been created. Run: sandbox install")
	}
	before := ""
	if st == driver.Running {
		ep := a.running()
		before = a.handshake(ep).ImageVersion
		out, err := a.env.Transport.Output(a.ctx, ep, []string{SandboxdCommand, "ctl", "list"}, 1<<20)
		if err != nil {
			a.die("cannot list the sandbox VM's sessions: %v", err)
		}
		var live []string
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Split(l, "\t"); len(f) >= 3 && f[2] != "TERMINATED" && f[2] != "FAILED" {
				live = append(live, f[0])
			}
		}
		if len(live) > 0 {
			a.die("sessions are running (%s); stop them first: sandbox stop <SESSION_ID>", strings.Join(live, " "))
		}
		a.pullAudit(ep)
		fmt.Fprintln(a.env.Stdout, "==> Stopping the sandbox VM...")
		if err := a.env.Driver.Stop(a.ctx); err != nil {
			a.die("could not stop the sandbox VM: %v", err)
		}
		a.releaseAllEndpoints()
	}
	return before
}

func (a *app) bootAfterUpgrade() releaseInfo {
	if err := a.env.Driver.Start(a.ctx); err != nil {
		a.die("could not start the sandbox VM: %v", err)
	}
	i, err := a.waitReady()
	if err != nil {
		a.die("the sandbox VM started but is not answering: %v\n  See: sandbox vm status", err)
	}
	a.warnBrokerKey(a.running())
	return releaseInfo{i.ImageVersion, i.ControlAPI}
}

func (a *app) startAgain() {
	if err := a.env.Driver.Start(a.ctx); err == nil {
		a.waitReady()
	}
}

// recordUpgrade appends to ~/.sandbox/logs/upgrades.log.
func (a *app) recordUpgrade(what, from, to, note string) {
	dir := filepath.Join(a.env.StateDir, "logs")
	if os.MkdirAll(dir, 0o700) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "upgrades.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s from=%s to=%s %s\n", a.env.Now().UTC().Format(time.RFC3339), what, or(from, "unknown"), or(to, "unknown"), note)
}

// olderVersion reports whether image version a is older than b, comparing runs of digits as
// numbers ("3.0.0-dev.9" < "3.0.0-dev.10"); a release is newer than its pre-releases.
func olderVersion(a, b string) bool {
	if a == "" || b == "" || a == b {
		return false
	}
	ta, tb := versionParts(a), versionParts(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if ta[i] == tb[i] {
			continue
		}
		na, ea := strconv.Atoi(ta[i])
		nb, eb := strconv.Atoi(tb[i])
		if ea == nil && eb == nil {
			return na < nb
		}
		return ta[i] < tb[i]
	}
	// "3.0.0-dev.1" (longer) is older than "3.0.0" (a release)
	return len(ta) > len(tb)
}

func versionParts(v string) []string {
	var out []string
	cur, digit := "", false
	for _, r := range v {
		d := r >= '0' && r <= '9'
		if cur != "" && (d != digit || r == '.' || r == '-' || r == '+') {
			out = append(out, cur)
			cur = ""
		}
		if r == '.' || r == '-' || r == '+' {
			continue
		}
		cur += string(r)
		digit = d
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
