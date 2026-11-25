// Package release reads the appliance image's /etc/sandbox/release and runs the version
// handshake of design 5.1.7: the host binary proxies commands only to an image whose CONTROL_API
// is in the range it supports, and otherwise prints the sandbox upgrade invocation that fixes it.
//
// The file is os-release style: KEY=VALUE lines, a value optionally in double quotes, # comments
// and blank lines ignored. The VM is not trusted, so parsing is strict and bounded: a malformed
// line, a repeated key, or an oversized file is an error, never a guess.
package release

import (
	"fmt"
	"strconv"
	"strings"
)

// The control API versions this binary speaks.
const (
	MinControlAPI = 1
	MaxControlAPI = 1
)

// MaxSize bounds the release file.
const MaxSize = 4096

// Info is the parsed release file.
type Info struct {
	ImageVersion string
	ControlAPI   int
}

func validVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".-+_", r)) {
			return false
		}
	}
	return true
}

// Parse reads a release file.
func Parse(b []byte) (Info, error) {
	if len(b) > MaxSize {
		return Info{}, fmt.Errorf("release file is larger than %d bytes", MaxSize)
	}
	seen := map[string]bool{}
	var info Info
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" || strings.TrimSpace(k) != k {
			return Info{}, fmt.Errorf("release file line %d: not KEY=VALUE", n+1)
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		if strings.ContainsAny(v, "\"\\$`") {
			return Info{}, fmt.Errorf("release file line %d: unsupported quoting", n+1)
		}
		if seen[k] {
			return Info{}, fmt.Errorf("release file line %d: %s repeated", n+1, k)
		}
		seen[k] = true
		switch k {
		case "IMAGE_VERSION":
			if !validVersion(v) {
				return Info{}, fmt.Errorf("release file line %d: invalid IMAGE_VERSION", n+1)
			}
			info.ImageVersion = v
		case "CONTROL_API":
			i, err := strconv.Atoi(v)
			if err != nil || i < 1 || i > 1<<20 || strconv.Itoa(i) != v {
				return Info{}, fmt.Errorf("release file line %d: invalid CONTROL_API", n+1)
			}
			info.ControlAPI = i
		}
	}
	if !seen["IMAGE_VERSION"] || !seen["CONTROL_API"] {
		return Info{}, fmt.Errorf("release file lacks IMAGE_VERSION or CONTROL_API")
	}
	return info, nil
}

// Check is the handshake: nil when this binary may proxy to the image, otherwise an error whose
// text names the upgrade that resolves it.
func Check(info Info) error {
	switch {
	case info.ControlAPI < MinControlAPI:
		return fmt.Errorf("the sandbox VM image %s speaks control API %d, older than this sandbox binary supports (%d-%d).\n  Upgrade the image: sandbox upgrade --image",
			info.ImageVersion, info.ControlAPI, MinControlAPI, MaxControlAPI)
	case info.ControlAPI > MaxControlAPI:
		return fmt.Errorf("the sandbox VM image %s speaks control API %d, newer than this sandbox binary supports (%d-%d).\n  Upgrade the binary: sandbox upgrade --app",
			info.ImageVersion, info.ControlAPI, MinControlAPI, MaxControlAPI)
	}
	return nil
}
