package driver

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// The keys of the guest's seed file, /etc/sandbox/seed.env (design 5.3.3), which the appliance
// image reads before sshd starts. It holds KEY=VALUE lines; multi-line values are base64.
const (
	SeedHostname      = "SANDBOX_SEED_HOSTNAME"
	SeedHostKey       = "SANDBOX_SEED_SSH_HOST_KEY_B64"
	SeedHostKeyPub    = "SANDBOX_SEED_SSH_HOST_KEY_PUB"
	SeedAuthorizedKey = "SANDBOX_SEED_AUTHORIZED_KEY"
	SeedCABundle      = "SANDBOX_SEED_CA_BUNDLE_B64"
	SeedDNS           = "SANDBOX_SEED_DNS"
	SeedProxy         = "SANDBOX_SEED_PROXY"
)

func printable(s string) bool {
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// SeedEnv renders the seed file every driver delivers. Single-line values must hold no control
// character, so no value can add a line of its own.
func SeedEnv(seed SeedConfig) (string, error) {
	for _, v := range append([]string{seed.Hostname, seed.HostKeyPublic, seed.AuthorizedKey, seed.Proxy}, seed.DNS...) {
		if !printable(v) {
			return "", fmt.Errorf("seed value holds a control character")
		}
	}
	for _, d := range seed.DNS {
		if d == "" || strings.ContainsAny(d, " \t") {
			return "", fmt.Errorf("invalid DNS server %q", d)
		}
	}
	if seed.HostKeyPrivate == "" || seed.HostKeyPublic == "" || seed.AuthorizedKey == "" {
		return "", fmt.Errorf("the seed needs the guest host key pair and the client's public key")
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	var env strings.Builder
	for _, kv := range [][2]string{
		{SeedHostname, seed.Hostname},
		{SeedHostKey, b64(seed.HostKeyPrivate)},
		{SeedHostKeyPub, seed.HostKeyPublic},
		{SeedAuthorizedKey, seed.AuthorizedKey},
		{SeedCABundle, b64(seed.CABundle)},
		{SeedDNS, strings.Join(seed.DNS, " ")},
		{SeedProxy, seed.Proxy},
	} {
		env.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	return env.String(), nil
}
