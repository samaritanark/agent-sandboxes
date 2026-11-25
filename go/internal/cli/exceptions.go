package cli

import (
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
)

// cmdExceptions is cmd_exceptions: add, list, and migrate a repo's secret-gate exceptions.
func cmdExceptions(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_exceptions")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "--help", "-h", "help":
		c.usage("usage_exceptions")
	case "add":
		exceptionsAdd(c, rest)
	case "list":
		exceptionsList(c, rest)
	case "migrate":
		exceptionsMigrate(c, rest)
	default:
		c.die("Unknown 'exceptions' subcommand: %s. Run 'sandbox exceptions --help'.", sub)
	}
}

var lineDigits = regexp.MustCompile(`^[0-9]+$`)

// repoOnlyArgs parses the --repo-only argument lists of list and migrate.
func repoOnlyArgs(c *cmdCtx, args []string, sub, usage string) string {
	repo := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repo = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_exceptions")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'exceptions %s': %s", sub, a)
		default:
			c.die("Unexpected argument for 'exceptions %s': %s", sub, a)
		}
	}
	if repo == "" {
		c.die("%s", usage)
	}
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	return repo
}

func exceptionsAdd(c *cmdCtx, args []string) {
	repo, reason := "", ""
	var specs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repo = v
			continue
		}
		if v, ok := flagValue(c, args, &i, "--reason"); ok {
			reason = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_exceptions")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'exceptions add': %s", a)
		default:
			specs = append(specs, a)
		}
	}
	if repo == "" {
		c.die("Usage: sandbox exceptions add --repo <PATH> <PATH:RULE:LINE>...")
	}
	if len(specs) == 0 {
		c.die("exceptions add: at least one PATH:RULE:LINE is required.")
	}
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	if _, err := exec.LookPath("betterleaks"); err != nil {
		c.die("exceptions add: betterleaks is required to confirm the finding exists, but it was not found on PATH.")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		c.die("exceptions add: jq is required but was not found on PATH.")
	}
	ignoreFile := config.RepoIgnoreFile(repo)
	for _, spec := range specs {
		// With ExceptionSpecOneLine a spec with a line break is refused before anything is
		// scanned: the bash recorded each of its lines as a separate fingerprint, so a file
		// name with a newline (which the gate's suggested command reproduces through $'...')
		// could record a second fingerprint that suppresses a finding elsewhere.
		if deviation.Fixed(deviation.ExceptionSpecOneLine) && strings.ContainsAny(spec, "\n\r") {
			c.die("exceptions add: PATH:RULE:LINE must be a single line (it contains a line break): %q", spec)
		}
		line, rest := spec, ""
		if i := strings.LastIndex(spec, ":"); i >= 0 {
			line, rest = spec[i+1:], spec[:i]
		} else {
			rest = spec
		}
		rule, relpath := rest, rest
		if i := strings.LastIndex(rest, ":"); i >= 0 {
			rule, relpath = rest[i+1:], rest[:i]
		}
		if !strings.Contains(rest, ":") || relpath == "" || rule == "" || !lineDigits.MatchString(line) {
			c.die("exceptions add: expected PATH:RULE:LINE (e.g. deploy/values.yaml:generic-api-key:155), got: %s", spec)
		}
		if strings.HasPrefix(relpath, "/") || strings.HasPrefix(relpath, "../") || strings.Contains(relpath, "/../") {
			c.die("exceptions add: PATH must be relative to the repo root and inside it: %s", relpath)
		}
		fps, rc := gate.FingerprintsFor(c.env.Env, repo, relpath, rule, line)
		switch rc {
		case 0:
		case 1:
			c.die("exceptions add: no %s finding at %s:%s in the current tree. Run 'sandbox run' (or 'sandbox check') to see the gate's findings, and copy the RELPATH:RULE:LINE it prints.", rule, relpath, line)
		case 2:
			c.die("exceptions add: betterleaks failed to scan %s. Nothing was recorded.", repo)
		default:
			c.die("exceptions add: betterleaks/jq unavailable.")
		}
		added := 0
		for _, fp := range fps {
			// `while IFS= read -r fp` over the resolver's output: one fingerprint per line.
			for _, l := range strings.Split(fp, "\n") {
				if l == "" {
					continue
				}
				if err := config.IgnoreFileAddFingerprint(ignoreFile, l, reason); err != nil {
					c.die("exceptions add: %s", err)
				}
				c.out("Accepted %s in %s (%s).", l, bashcompat.Basename(repo), c.tilde(ignoreFile))
				added++
			}
		}
		if added == 0 {
			c.die("exceptions add: could not fingerprint %s.", spec)
		}
	}
	base := ignoreFile[strings.LastIndex(ignoreFile, "/")+1:]
	c.out("")
	c.out("NOTE: commit %s — the gate honours it only once the repo is", base)
	c.out("      vetted ('sandbox vet --repo %s'). Your CI/pre-commit betterleaks", repo)
	c.out("      runs read the same file natively (scan with 'betterleaks dir .' from")
	c.out("      the repo root so its relative fingerprints match).")
}

func exceptionsList(c *cmdCtx, args []string) {
	repo := repoOnlyArgs(c, args, "list", "Usage: sandbox exceptions list --repo <PATH>")
	ignoreFile := config.RepoIgnoreFile(repo)
	c.out("Accepted secret findings for %s (%s):", bashcompat.Basename(repo), c.tilde(ignoreFile))
	any := false
	for _, fp := range config.LoadRepoIgnoreFingerprints(repo) {
		if fp != "" {
			any = true
			c.out("  %s", fp)
		}
	}
	if !any {
		c.out("  (none)")
	}
	legacy := false
	for _, fp := range config.LoadRepoAcceptedSecrets(repo) {
		if fp == "" {
			continue
		}
		if !legacy {
			legacy = true
			c.out("")
			c.out("  LEGACY (no longer honored — run 'sandbox exceptions migrate --repo %s'):", repo)
		}
		c.out("    %s", fp)
	}
}

// migrateReason is `grep -F -- entry config | head -1 | sed -n 's/.*#[[:space:]]*//p'`: on the
// first config line containing entry, the text after its last '#' and the spaces that follow it.
func migrateReason(cfg, entry string) string {
	b, err := os.ReadFile(cfg)
	if err != nil {
		return ""
	}
	for _, l := range bashcompat.SplitRecords(b) {
		if !strings.Contains(l, entry) {
			continue
		}
		i := strings.LastIndex(l, "#")
		if i < 0 {
			return ""
		}
		return strings.TrimLeft(l[i+1:], " \t\n\v\f\r")
	}
	return ""
}

func exceptionsMigrate(c *cmdCtx, args []string) {
	repo := repoOnlyArgs(c, args, "migrate", "Usage: sandbox exceptions migrate --repo <PATH>")
	cfg := repo + "/" + config.RepoConfigName
	entries := config.LoadRepoAcceptedSecrets(repo)
	if len(entries) == 0 {
		c.out("No accepted_secrets: entries in %s — nothing to migrate.", c.tilde(cfg))
		return
	}
	ignoreFile := config.RepoIgnoreFile(repo)
	for _, entry := range entries {
		fp := entry
		if i := strings.LastIndex(entry, ":"); i >= 0 {
			fp = entry[:i]
		}
		if strings.Count(fp, ":") < 2 {
			fp = entry
		}
		if err := config.IgnoreFileAddFingerprint(ignoreFile, fp, migrateReason(cfg, entry)); err != nil {
			c.die("exceptions migrate: %s", err)
		}
		c.out("Migrated %s -> %s", entry, fp)
	}
	config.RemoveYAMLList(cfg, "accepted_secrets")
	c.out("")
	c.out("Wrote %s and removed accepted_secrets: from", c.tilde(ignoreFile))
	c.out("%s. Review the diff, commit BOTH files, then", c.tilde(cfg))
	c.out("re-vet ('sandbox vet --repo %s') so the gate honours the new list.", repo)
}
