package gate

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// FetchEnv is what the config fetch reads beyond config.Env.
type FetchEnv struct {
	Timeout  time.Duration // $LINK_FETCH_TIMEOUT_SECONDS (default 10s)
	MinRules string        // $LEAKSCAN_MIN_RULES (default "1")
}

var (
	badURLChar = regexp.MustCompile(`[[:cntrl:][:space:]\\]`)
	okRules    = regexp.MustCompile(`(?m)^OK: ([0-9][0-9]*) rules`)
)

// FetchLeakscanConfig is _leakscan_fetch_config: when the overlay names a leakscan_config_url,
// fetch it (curl), require it to pass `betterleaks config check` with at least MinRules rules, cache
// it, and record its sha256 and source in the user config. Every failure warns and keeps the
// previous state; it never fails the caller.
func FetchLeakscanConfig(e config.Env, f FetchEnv, warn func(string), out io.Writer) {
	url := leakscanConfigURL(e)
	if url == "" {
		return
	}
	if strings.HasPrefix(url, "-") {
		warn("leakscan config: ignoring leakscan_config_url that begins with '-' (looks like a flag).")
		return
	}
	if badURLChar.MatchString(url) {
		warn("leakscan config: ignoring leakscan_config_url containing whitespace, control, or backslash characters.")
		return
	}
	if _, err := exec.LookPath("curl"); err != nil {
		warn("leakscan_config_url is set but 'curl' is not on PATH; the secret gate will use its generated config.")
		return
	}
	if _, err := exec.LookPath("betterleaks"); err != nil {
		return
	}
	os.MkdirAll(e.CacheDir, 0o755)
	cache := e.CacheDir + "/betterleaks.toml"
	tmpf, err := os.CreateTemp(e.CacheDir, "fetch-")
	if err != nil {
		return
	}
	tmp := tmpf.Name()
	tmpf.Close()
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	err = exec.CommandContext(ctx, "curl", "-fsSL", "--max-time", fmt.Sprint(int(timeout.Seconds())), url, "-o", tmp).Run()
	cancel()
	if err != nil {
		os.Remove(tmp)
		if config.IsFile(cache) {
			warn(fmt.Sprintf("leakscan config: could not fetch %s; the secret gate will use the cached copy.", url))
		} else {
			warn(fmt.Sprintf("leakscan config: could not fetch %s and there is no cached copy; the secret gate will use its generated config.", url))
		}
		return
	}
	check, err := exec.Command("betterleaks", "config", "check", "--config", tmp).Output()
	if err != nil {
		os.Remove(tmp)
		warn(fmt.Sprintf("leakscan config: the config fetched from %s failed 'betterleaks config check'; keeping the previous copy (or the generated config).", url))
		return
	}
	count := ""
	if m := okRules.FindStringSubmatch(string(check)); m != nil {
		count = m[1]
	}
	min := f.MinRules
	if min == "" {
		min = "1"
	}
	if count == "" || bashcompat.ArithLess(count, min) {
		os.Remove(tmp)
		shown := count
		if shown == "" {
			shown = "no"
		}
		warn(fmt.Sprintf("leakscan config: the config fetched from %s resolves to %s rule(s); refusing to adopt it. The secret gate will use its generated config.", url, shown))
		return
	}
	newSHA := sha256File(tmp)
	oldSHA := config.ExtractYAMLScalar(e.UserConfig, "leakscan_config_sha256")
	if os.Rename(tmp, cache) != nil {
		os.Remove(tmp)
		return
	}
	os.Chmod(cache, 0o644)
	if newSHA != "" {
		config.UpsertYAMLScalar(e.UserConfig, "leakscan_config_sha256", newSHA)
		config.UpsertYAMLScalar(e.UserConfig, "leakscan_config_source", url)
	}
	short := func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	}
	switch {
	case oldSHA == "":
		fmt.Fprintf(out, "==> Secret-gate config fetched from %s (%s)\n", url, short(newSHA))
	case oldSHA != newSHA:
		fmt.Fprintf(out, "==> Secret-gate config updated from %s (%s -> %s)\n", url, short(oldSHA), short(newSHA))
	}
}
