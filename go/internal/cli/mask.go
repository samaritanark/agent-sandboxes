package cli

import (
	"os"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/workspace"
)

// cmdMask is cmd_mask: add and list a repo's masked_paths.
func cmdMask(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_mask")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "--help", "-h", "help":
		c.usage("usage_mask")
	case "add":
		maskAdd(c, rest)
	case "list":
		maskList(c, rest)
	default:
		c.die("Unknown 'mask' subcommand: %s. Run 'sandbox mask --help'.", sub)
	}
}

// badMaskPath reports whether rel may not be masked: the bash's check (absolute, or escaping
// through "../"), and with MaskPathComponents an empty path or a "." or ".." component.
func badMaskPath(rel string) bool {
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
		return true
	}
	if !deviation.Fixed(deviation.MaskPathComponents) {
		return false
	}
	bare := strings.TrimSuffix(rel, "/")
	if bare == "" {
		return true
	}
	for _, comp := range strings.Split(bare, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return true
		}
	}
	return false
}

func (c *cmdCtx) expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		return c.env.Home + p[1:]
	}
	return p
}

func maskAdd(c *cmdCtx, args []string) {
	repo := ""
	var rels []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repo = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_mask")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'mask add': %s", a)
		default:
			rels = append(rels, a)
		}
	}
	if repo == "" {
		c.die("Usage: sandbox mask add --repo <PATH> <RELPATH>...")
	}
	if len(rels) == 0 {
		c.die("mask add: at least one RELPATH is required.")
	}
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	cfg := repo + "/" + config.RepoConfigName
	for _, rel := range rels {
		if badMaskPath(rel) {
			c.die("mask add: RELPATH must be relative to the repo root and inside it: %s", rel)
		}
		bare := strings.TrimSuffix(rel, "/")
		var stored string
		if st, err := os.Stat(repo + "/" + bare); err == nil {
			switch {
			case st.IsDir():
				stored = bare + "/"
			case st.Mode().IsRegular():
				stored = bare
			default:
				c.die("mask add: only regular files and directories can be masked (found a non-file/non-dir): %s", bare)
			}
		} else if strings.HasSuffix(rel, "/") {
			stored = bare + "/"
			c.warn("Path does not exist in repo (masking as a directory anyway): %s/", bare)
		} else {
			stored = bare
			c.warn("Path does not exist in repo (masking as a file anyway): %s", bare)
		}
		if err := config.AddMaskedPath(cfg, stored); err != nil {
			c.die("mask add: %s", err)
		}
		if workspace.PathHasTrackedContent(repo, bare) {
			c.warn("'%s' is in git; masking hides the working copy only.", bare)
			c.warn("The agent can still recover it from the mounted .git history (git show / git worktree).")
			c.warn("To keep a committed secret from the agent, rotate it or scrub it from history — do not rely on the mask.")
		}
		c.out("Masked '%s' in %s (%s).", stored, bashcompat.Basename(repo), c.tilde(cfg))
	}
}

func maskList(c *cmdCtx, args []string) {
	repo := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repo = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_mask")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'mask list': %s", a)
		default:
			c.die("Unexpected argument for 'mask list': %s", a)
		}
	}
	if repo == "" {
		c.die("Usage: sandbox mask list --repo <PATH>")
	}
	repo = c.expandHome(repo)
	if err := c.workspace().ValidateRepoPath(repo); err != nil {
		c.fail(err)
	}
	c.out("Built-in masked paths (root-level):")
	for _, p := range gate.MaskedFilePaths {
		c.out("  %s", p)
	}
	c.out("  %s/  (directory)", gate.MaskedDirPath)
	c.out("  %s", gate.MaskedOpenrcPattern)
	c.out("")
	c.out("Configured masked_paths for %s:", bashcompat.Basename(repo))
	any := false
	for _, p := range config.LoadRepoMaskedPaths(repo) {
		if p == "" {
			continue
		}
		any = true
		switch {
		case strings.HasSuffix(p, "/"):
			if isDir(repo + "/" + strings.TrimSuffix(p, "/")) {
				c.out("  %s  (directory)", p)
			} else {
				c.out("  %s  (directory, not present in repo)", p)
			}
		case config.IsFile(repo + "/" + p):
			c.out("  %s", p)
		default:
			c.out("  %s  (not present in repo)", p)
		}
	}
	if !any {
		c.out("  (none)")
		return
	}
	// The bash ends with `[[ "${any}" == false ]] && echo "  (none)"`, so a repo with masked paths
	// made the command exit 1; with MaskListStatus it exits 0.
	if !deviation.Fixed(deviation.MaskListStatus) {
		panic(exit(1))
	}
}
