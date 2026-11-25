package proxycert

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Env is what the command touches; the trust-store sources are injected so tests can stand in
// for them.
type Env struct {
	GOOS          string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	StdinTTY      bool
	DefaultOutput string // ~/.sandbox/extra-ca-certs/proxy-ca.crt (design 5.10)

	LinuxFiles   func() []string                                            // the per-file trust store, in glob order
	LinuxBundle  string                                                     // the system bundle
	MacKeychain  func(ctx context.Context) ([]byte, error)                  // the System keychain as PEM
	WindowsStore func(ctx context.Context) ([]byte, error)                  // LocalMachine\Root and CurrentUser\Root as PEM
	Wire         func(ctx context.Context, target string) ([][]byte, error) // DER chain the server presents
}

// System is the real host's sources.
func System(goos string) Env {
	return Env{
		GOOS: goos,
		LinuxFiles: func() []string {
			return append(Glob("/usr/local/share/ca-certificates/*.crt"), Glob("/etc/ssl/certs/*.pem")...)
		},
		LinuxBundle: "/etc/ssl/certs/ca-certificates.crt",
		MacKeychain: func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "/usr/bin/security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain").Output()
		},
		WindowsStore: func(ctx context.Context) ([]byte, error) {
			script := "$ErrorActionPreference = 'Stop'\n" +
				"Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root | ForEach-Object {\n" +
				"  $b64 = [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')\n" +
				"  \"-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----\"\n}\n"
			out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
			return []byte(strings.ReplaceAll(string(out), "\r", "")), err
		},
		Wire: DialChain,
	}
}

// DialChain opens a TLS connection to target (host[:port], port 443 by default) and returns the
// certificates the server presents, without verifying them: on an intercepting network that is
// the proxy's chain, which is the point.
func DialChain(ctx context.Context, target string) ([][]byte, error) {
	host := target
	if !strings.Contains(target, ":") {
		target += ":443"
	} else {
		host, _, _ = net.SplitHostPort(target)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}} // #nosec G402 -- capture only, nothing is sent
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var out [][]byte
	for _, cert := range c.(*tls.Conn).ConnectionState().PeerCertificates {
		out = append(out, cert.Raw)
	}
	return out, nil
}

const usage = `Usage: sandbox setup-proxy-cert [options]

Auto-extract a corporate TLS-intercept proxy's root CA from the host's
trust store and save it for the sandbox VM to trust.

Options:
  --from-wire <host[:port]>  Skip the trust-store scan; instead open a TLS
                             connection to <host> and capture the proxy
                             chain on the wire. Defaults port to 443.
  --vendor <name>            Restrict trust-store matching to a specific
                             subject substring. Default tries common ones
                             (Zscaler, Netskope, Forcepoint, Cisco
                             Umbrella, Palo Alto/Prisma, Symantec/Blue
                             Coat, iboss, Menlo).
  --output <path>            Write the PEM here. Default:
                             ~/.sandbox/extra-ca-certs/proxy-ca.crt
  --list                     Print what was found; don't write the file.
  --force                    Overwrite an existing output file without
                             prompting.

The sandbox trusts the saved cert from the next session; no rebuild is
needed. It is trusted by the agent and by anything it runs.
`

type exitCode int

// Run is the command; args follow "setup-proxy-cert".
func Run(ctx context.Context, args []string, env Env) (rc int) {
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(exitCode)
			if !ok {
				panic(r)
			}
			rc = int(c)
		}
	}()
	die := func(f string, a ...interface{}) {
		fmt.Fprintf(env.Stderr, "ERROR: %s\n", fmt.Sprintf(f, a...))
		panic(exitCode(1))
	}
	var fromWire, vendor string
	out := env.DefaultOutput
	list, force := false, false
	for len(args) > 0 {
		a := args[0]
		args = args[1:]
		next := func(msg string) string {
			if len(args) == 0 {
				die("setup-proxy-cert: %s", msg)
			}
			v := args[0]
			args = args[1:]
			return v
		}
		switch a {
		case "--from-wire":
			fromWire = next("--from-wire needs a host argument")
		case "--vendor":
			vendor = next("--vendor needs a name")
		case "--output", "-o":
			out = next("--output needs a path")
		case "--list":
			list = true
		case "--force", "-f":
			force = true
		case "--help", "-h":
			fmt.Fprint(env.Stdout, usage)
			return 0
		default:
			die("setup-proxy-cert: unknown option '%s' (use --help)", a)
		}
	}
	m := Matcher(vendor)
	var pemOut []byte
	var source string
	say := func(s string) { fmt.Fprintln(env.Stdout, s) }
	switch {
	case fromWire != "":
		say("==> Extracting proxy chain from wire (" + fromWire + ")...")
		chain, err := env.Wire(ctx, fromWire)
		if err != nil || len(chain) == 0 {
			die("Could not extract a cert chain from %s. Check the host is reachable.", fromWire)
		}
		if len(chain) > 1 {
			chain = chain[1:] // the leaf is the proxy's per-site re-signing, not what to trust
		}
		for _, der := range chain {
			pemOut = append(pemOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		source = "wire: " + fromWire
	case env.GOOS == "darwin":
		say("==> Searching macOS System keychain for proxy CA (vendors: " + VendorList(vendor) + ")...")
		b, err := env.MacKeychain(ctx)
		var ok bool
		if err == nil {
			pemOut, ok = matchChunks(b, m)
		}
		if !ok {
			die("No matching cert in /Library/Keychains/System.keychain. If your org's\nMITM uses an unusual name, pass --vendor <substring>, or try\n  sandbox setup-proxy-cert --from-wire deb.nodesource.com")
		}
		source = "macOS System keychain"
	case env.GOOS == "windows":
		say("==> Searching Windows trust store for proxy CA (vendors: " + VendorList(vendor) + ")...")
		b, err := env.WindowsStore(ctx)
		var ok bool
		if err == nil {
			pemOut, ok = matchChunks(b, m)
		}
		if !ok {
			die("No matching cert in the Windows LocalMachine\\Root or CurrentUser\\Root store.\nPass --vendor <substring> if your org uses a non-standard name, or try\n  sandbox setup-proxy-cert --from-wire deb.nodesource.com")
		}
		source = "Windows LocalMachine\\Root and CurrentUser\\Root"
	default:
		say("==> Searching Linux trust store for proxy CA (vendors: " + VendorList(vendor) + ")...")
		var ok bool
		pemOut, ok = LinuxStore(env.LinuxFiles(), env.LinuxBundle, m)
		if !ok {
			die("No matching cert in the host trust store. Pass --vendor <substring>\nif your org uses a non-standard name, or try\n  sandbox setup-proxy-cert --from-wire deb.nodesource.com")
		}
		source = "Linux trust store"
	}
	say("  Source: " + source)
	say("  Cert(s) extracted:")
	fmt.Fprint(env.Stdout, Describe(pemOut))
	if list {
		return 0
	}
	if _, err := os.Lstat(out); err == nil && !force {
		if !env.StdinTTY {
			die("%s already exists and stdin is not a TTY. Re-run with --force to overwrite.", out)
		}
		fmt.Fprintf(env.Stderr, "Overwrite %s? [y/N] ", out)
		reply, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		switch strings.TrimRight(reply, "\r\n") {
		case "y", "Y", "yes", "YES":
		default:
			fmt.Fprintln(env.Stderr, "Aborted; existing file untouched.")
			return 1
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		die("%v", err)
	}
	if err := writeFile(out, pemOut); err != nil {
		die("%v", err)
	}
	say("==> Wrote " + out)
	say("    The sandbox trusts it from the next session; no rebuild is needed.")
	return 0
}

// writeFile replaces out with b through a temporary file in the same directory, so a failure
// never leaves a half-written CA file behind.
func writeFile(out string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(out), ".proxy-ca-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil && !errors.Is(err, os.ErrInvalid) {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), out)
}
