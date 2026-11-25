package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

// cmdProfile is cmd_profile.
func cmdProfile(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_profile")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "--help", "-h", "help":
		c.usage("usage_profile")
	case "save":
		profileSave(c, rest)
	case "list", "ls":
		profileList(c, rest)
	case "show", "cat":
		profileShow(c, rest)
	case "delete", "rm", "remove":
		profileDelete(c, rest)
	default:
		c.die("Unknown 'profile' subcommand: %s. Run 'sandbox profile --help'.", sub)
	}
}

// flagValue matches --flag VALUE and --flag=VALUE; ok reports a match, and i is advanced past a
// separate value.
func flagValue(c *cmdCtx, args []string, i *int, flag string) (string, bool) {
	a := args[*i]
	if a == flag {
		v := c.needValue(args, *i, flag)
		*i++
		return v, true
	}
	if strings.HasPrefix(a, flag+"=") {
		return a[len(flag)+1:], true
	}
	return "", false
}

func profileSave(c *cmdCtx, args []string) {
	var tierV, agent, name string
	var repos, domains []string
	force, dry := false, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			c.usage("usage_profile")
		}
		if v, ok := flagValue(c, args, &i, "--tier"); ok {
			tierV = v
			continue
		}
		if v, ok := flagValue(c, args, &i, "--agent"); ok {
			agent = v
			continue
		}
		if v, ok := flagValue(c, args, &i, "--repo"); ok {
			repos = append(repos, v)
			continue
		}
		if v, ok := flagValue(c, args, &i, "--allow-domain"); ok {
			domains = append(domains, v)
			continue
		}
		if v, ok := flagValue(c, args, &i, "--name"); ok {
			name = v
			continue
		}
		switch {
		case a == "--force":
			force = true
		case a == "--dry-run":
			dry = true
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'profile save': %s. Run 'sandbox profile --help'.", a)
		default:
			c.die("Unexpected argument: %s. Run 'sandbox profile --help'.", a)
		}
	}
	if tierV == "" {
		c.die("profile save: --tier is required.")
	}
	if err := tier.Validate(tierV); err != nil {
		c.fail(err)
	}
	if agent != "" {
		if err := agents.Validate(agent); err != nil {
			c.fail(err)
		}
	}
	if len(repos) > 1 {
		c.die("profile save: only one --repo is supported (the profile holds a single default_repo). Use 'run --repo ... --repo ...' for multi-repo launches.")
	}
	repo := ""
	if len(repos) == 1 {
		repo = repos[0]
		if strings.HasPrefix(repo, "~") {
			repo = c.env.Home + repo[1:]
		}
		if st, err := os.Stat(repo); err != nil || !st.IsDir() {
			c.warn("repo path '%s' is not a directory here; saving anyway (it may live on another machine).", repo)
		}
	}
	if tierV != "1" && repo == "" {
		c.warn("tier %s usually needs a repo; none set, so 'run --profile' will require --repo.", tierV)
	}
	for _, d := range domains {
		w, err := c.checks().CheckDomainNotBlocked(d)
		for _, l := range w {
			fmt.Fprintln(c.stderr, l)
		}
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			c.die("profile save: domain '%s' is blocked; refusing to save a profile that 'run' would reject.", d)
		}
	}
	if name == "" {
		base := ""
		if repo != "" {
			base = bashcompat.Basename(repo)
		}
		switch {
		case base != "" && agent != "":
			name = base + "-" + agent
		case base != "":
			name = base
		case agent != "":
			name = agent
		default:
			name = "tier" + tierV
		}
	}
	if !config.IsValidProfileName(name) {
		c.die("profile save: invalid name '%s'. Use letters, digits, '.', '_', '-'; no '/', no leading '.', and not a bare tier number (1|2|3).", name)
	}
	yaml, err := config.RenderProfileYAML(name, tierV, agent, repo, domains)
	if err != nil {
		c.die("profile save: %s", err)
	}
	yaml = strings.TrimRight(yaml, "\n") // "$(render_profile_yaml ...)"
	if dry {
		c.out("%s", yaml)
		return
	}
	dir := config.UserProfilesDir(c.env.Env)
	path := dir + "/" + name + ".yaml"
	if config.Exists(path) && !force {
		c.die("profile '%s' already exists at %s. Re-run with --force to overwrite.", name, c.tilde(path))
	}
	os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(path, []byte(yaml+"\n"), 0o666); err != nil {
		c.die("profile save: %s", err)
	}
	os.Chmod(path, 0o644)
	c.out("Saved profile '%s' → %s", name, c.tilde(path))
	c.out("Launch it with: sandbox run --profile %s", name)
}

// yamlFiles is "${dir}"/*.yaml with the `[[ -e ]]` filter: sorted, no dot files.
func yamlFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".yaml") && config.Exists(dir+"/"+n) {
			out = append(out, n)
		}
	}
	return out // os.ReadDir sorts by name, as the C-locale glob does
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

func profileList(c *cmdCtx, args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "--help", "-h":
			c.usage("usage_profile")
		case "":
		default:
			c.die("Unexpected argument: %s", args[0])
		}
	}
	userDir := config.UserProfilesDir(c.env.Env)
	overlay := config.ResolveOverlayPath(c.env.Env)
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	row := func(f, name, source string) string {
		t, a, r := config.ExtractYAMLScalar(f, "tier"), config.ExtractYAMLScalar(f, "agent"), config.ExtractYAMLScalar(f, "default_repo")
		return padRight(name, 24) + "  " + padRight(source, 7) + "  " + padRight(dash(t), 4) + "  " + padRight(dash(a), 8) + "  " + dash(r)
	}
	var rows []string
	if isDir(userDir) {
		for _, f := range yamlFiles(userDir) {
			rows = append(rows, row(userDir+"/"+f, strings.TrimSuffix(f, ".yaml"), "user"))
		}
	}
	if overlay != "" && isDir(overlay+"/profiles") {
		for _, f := range yamlFiles(overlay + "/profiles") {
			name := strings.TrimSuffix(f, ".yaml")
			if config.IsFile(userDir + "/" + name + ".yaml") {
				continue
			}
			rows = append(rows, row(overlay+"/profiles/"+f, name, "overlay"))
		}
	}
	if len(rows) == 0 {
		orOverlay := ""
		if overlay != "" {
			orOverlay = " or the overlay"
		}
		c.out("No profiles found in %s/%s.", c.tilde(userDir), orOverlay)
		c.out("Create one with: sandbox profile save --tier <N> [--agent <A>] [--repo <PATH>] [--name <NAME>]")
		return
	}
	c.out("%s", padRight("NAME", 24)+"  "+padRight("SOURCE", 7)+"  "+padRight("TIER", 4)+"  "+padRight("AGENT", 8)+"  REPO")
	for _, r := range rows {
		c.out("%s", r)
	}
}

func profileShow(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.die("Usage: sandbox profile show <NAME>")
	}
	if args[0] == "--help" || args[0] == "-h" {
		c.usage("usage_profile")
	}
	name := args[0]
	path, ok := config.FindProfilePath(c.env.Env, name)
	if !ok {
		c.die("Profile '%s' not found in ~/.sandbox/profiles/ or the overlay.", name)
	}
	c.out("# %s", c.tilde(path))
	b, _ := os.ReadFile(path)
	c.stdout.Write(b)
}

func profileDelete(c *cmdCtx, args []string) {
	yes, name := false, ""
	for _, a := range args {
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_profile")
		case a == "--yes" || a == "-y":
			yes = true
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'profile delete': %s", a)
		default:
			if name != "" {
				c.die("Unexpected argument: %s", a)
			}
			name = a
		}
	}
	if name == "" {
		c.die("Usage: sandbox profile delete <NAME> [--yes]")
	}
	userDir := config.UserProfilesDir(c.env.Env)
	path := userDir + "/" + name + ".yaml"
	if !config.IsFile(path) {
		if resolved, ok := config.FindProfilePath(c.env.Env, name); ok {
			c.die("Profile '%s' is an overlay profile (%s); 'profile delete' only removes your own profiles under %s/.", name, c.tilde(resolved), c.tilde(userDir))
		}
		c.die("Profile '%s' not found in %s/.", name, c.tilde(userDir))
	}
	if !yes {
		fmt.Fprintf(c.stdout, "Delete profile '%s' (%s)? [y/N] ", name, c.tilde(path))
		switch c.readLine() {
		case "y", "Y", "yes", "YES":
		default:
			c.out("Aborted.")
			return
		}
	}
	os.Remove(path)
	c.out("Deleted profile '%s'.", name)
}
