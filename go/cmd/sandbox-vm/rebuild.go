package main

// The image builder `sandbox rebuild` uses in the VM: nerdctl and buildkit (from nerdctl-full in
// the image) building into sandboxd's containerd namespace, and the VM's own agent image map,
// which run reads before the image's baseline (AgentImages).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// BuiltImages is the VM's agent image map: what `sandbox rebuild` built, by tag, pinned by digest.
const BuiltImages = "/var/lib/sandbox/agent-images.json"

// The namespace sessions run from (sandboxd's runtime.Namespace) and the builder's socket.
const (
	imageNamespace = "sandbox"
	buildkitSocket = "/run/buildkit/buildkitd.sock"
)

// builderPath is the fixed PATH the builder runs with: nerdctl calls buildctl by name.
const builderPath = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type nerdctlBuilder struct {
	mapFile string
	run     func(name string, args []string, out io.Writer) error // nil: exec with builderPath
	output  func(name string, args []string) (string, error)
}

func (b nerdctlBuilder) exec(name string, args []string, out io.Writer) error {
	if b.run != nil {
		return b.run(name, args, out)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "PATH="+builderPath)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

func (b nerdctlBuilder) out(name string, args []string) (string, error) {
	if b.output != nil {
		return b.output(name, args)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "PATH="+builderPath)
	o, err := cmd.Output()
	return string(o), err
}

// Build starts buildkit if it is not running, builds tag, and returns its digest.
func (b nerdctlBuilder) Build(tag, dir, dockerfile string, args []string, noCache bool, out io.Writer) (string, error) {
	if _, err := os.Stat(buildkitSocket); err != nil && b.run == nil {
		if err := b.exec("systemctl", []string{"start", "buildkit.service"}, out); err != nil {
			return "", fmt.Errorf("cannot start buildkit: %v", err)
		}
		for i := 0; i < 50; i++ {
			if _, err := os.Stat(buildkitSocket); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	argv := []string{"--namespace", imageNamespace, "build"}
	if noCache {
		argv = append(argv, "--no-cache")
	}
	argv = append(argv, "-t", tag, "-f", filepath.Join(dir, dockerfile))
	argv = append(append(argv, args...), dir)
	if err := b.exec("nerdctl", argv, out); err != nil {
		return "", err
	}
	ls, err := b.out("ctr", []string{"--namespace", imageNamespace, "images", "ls", "name==" + tag})
	if err != nil {
		return "", fmt.Errorf("cannot read the built image: %v", err)
	}
	var digest string
	for _, l := range strings.Split(ls, "\n")[1:] {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == tag {
			digest = f[2]
		}
	}
	if !digestRE.MatchString(digest) {
		return "", fmt.Errorf("no digest for %s", tag)
	}
	return digest, nil
}

// Pin names the image by its digest in the image store (sessions start images by digest) and
// records it in the VM's agent image map under its short tag ("sandbox:claude").
func (b nerdctlBuilder) Pin(tag, digest string) error {
	repo, short, ok := splitTag(tag)
	if !ok || !digestRE.MatchString(digest) {
		return fmt.Errorf("bad image %s@%s", tag, digest)
	}
	ref := repo + "@" + digest
	if err := b.exec("ctr", []string{"--namespace", imageNamespace, "images", "tag", "--force", tag, ref}, io.Discard); err != nil {
		return fmt.Errorf("cannot tag %s: %v", ref, err)
	}
	m := map[string]string{}
	if raw, err := os.ReadFile(b.mapFile); err == nil {
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%s: %v", b.mapFile, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m[short] = ref
	raw, _ := json.MarshalIndent(m, "", "  ")
	tmp := b.mapFile + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, b.mapFile)
}

// splitTag splits "docker.io/library/sandbox:claude" into the repository and the short tag the
// CLI asks for ("sandbox:claude").
func splitTag(tag string) (repo, short string, ok bool) {
	i := strings.LastIndex(tag, ":")
	if i < 0 || strings.Contains(tag[i:], "/") {
		return "", "", false
	}
	repo = tag[:i]
	return repo, strings.TrimPrefix(repo, "docker.io/library/") + tag[i:], true
}
