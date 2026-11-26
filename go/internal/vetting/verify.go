package vetting

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var filterNameRe = regexp.MustCompile(`^filter\.(.*)\.[^.]+$`)

// gitCmd builds a git invocation with environment additions.
func gitCmd(env []string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// VettingGit is _vetting_git: run git inside an UNTRUSTED workspace with everything the repo's
// own config could use to execute a program neutralized (fsmonitor, hooks, and every content
// filter driver the repo declares, pinned to `cat` through GIT_CONFIG_KEY_n/VALUE_n so names
// containing '=' cannot split). It returns the command, ready to run.
func VettingGit(repo string, args ...string) *exec.Cmd {
	// filter names: the repo's own config including [include]d files, with global/system nulled.
	enum := gitCmd([]string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"},
		"-C", repo, "config", "--name-only", "--get-regexp", "^filter\\.")
	out, _ := enum.Output() // stderr dropped, failure tolerated, as `2>/dev/null ... || true`
	seen := map[string]bool{}
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" {
			continue
		}
		if m := filterNameRe.FindStringSubmatch(l); m != nil {
			l = m[1]
		}
		if !seen[l] {
			seen[l] = true
			names = append(names, l)
		}
	}
	sort.Strings(names) // order only numbers the pins; it is not observable
	var env []string
	n := 0
	for _, name := range names {
		for _, sub := range []string{"clean", "smudge", "process", "required"} {
			env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=filter.%s.%s", n, name, sub))
			switch sub {
			case "clean", "smudge":
				env = append(env, fmt.Sprintf("GIT_CONFIG_VALUE_%d=cat", n))
			case "process":
				env = append(env, fmt.Sprintf("GIT_CONFIG_VALUE_%d=", n))
			case "required":
				env = append(env, fmt.Sprintf("GIT_CONFIG_VALUE_%d=false", n))
			}
			n++
		}
	}
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", n))
	full := append([]string{"-C", repo, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null"}, args...)
	return gitCmd(env, full...)
}

// vgit runs VettingGit and returns stdout (stderr discarded) and whether it succeeded.
func vgit(repo string, args ...string) (string, bool) {
	cmd := VettingGit(repo, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err == nil
}

// trimNL is what $(...) does to captured output.
func trimNL(s string) string { return strings.TrimRight(s, "\n") }

func commandV(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// TrustedGit is the git for repositories the CLI made itself. In the VM the CLI runs as root and
// the git on its PATH drops to an unprivileged user (image: /usr/lib/sandbox/gitbin), because a
// workspace's own config reaches every git that runs in it; SANDBOX_TRUSTED_GIT names the git that
// keeps root, for a scratch repository holding nothing of the workspace's but a tag object.
func TrustedGit() string {
	if p := os.Getenv("SANDBOX_TRUSTED_GIT"); p != "" {
		return p
	}
	return "git"
}

// VerifyTag is _vetting_verify_tag: verify one tag against ONE trust root, with every verifier
// program pinned (ssh, openpgp, x509) and the other format's trust source neutralized, so the
// workspace's own git config can neither choose a program nor supply a signer. On success it
// returns the signer principal. The tag object is read from the workspace (by the git on PATH)
// and verified in a scratch repository with TrustedGit, so the git that runs the verifier with the
// trust root never reads the workspace's config.
func VerifyTag(repo, tag, trustRoot, format string) (signer string, ok bool) {
	falseBin := commandV("false")
	if falseBin == "" {
		falseBin = "/bin/false"
	}
	sshKeygen := commandV("ssh-keygen")
	if sshKeygen == "" {
		sshKeygen = falseBin
	}
	gpgBin := commandV("gpg", "gpg2")
	if gpgBin == "" {
		gpgBin = falseBin
	}
	scratch, ok := tagScratch(repo, tag)
	if !ok {
		return "", false
	}
	defer os.RemoveAll(scratch)
	emptyGnupg, err := os.MkdirTemp(os.TempDir(), "sandbox-vet-gnupg-")
	if err != nil {
		return "", false
	}
	defer os.RemoveAll(emptyGnupg)
	os.Chmod(emptyGnupg, 0o700)

	args := []string{"-C", scratch,
		"-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
		"-c", "gpg.ssh.program=" + sshKeygen, "-c", "gpg.program=" + gpgBin,
		"-c", "gpg.x509.program=" + falseBin}
	var env []string
	if format == "gpg" {
		env = []string{"GNUPGHOME=" + trustRoot}
		args = append(args, "-c", "gpg.format=openpgp", "-c", "gpg.ssh.allowedSignersFile=/dev/null")
	} else {
		env = []string{"GNUPGHOME=" + emptyGnupg}
		args = append(args, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+trustRoot)
	}
	args = append(args, "tag", "-v", tag)
	cmd := exec.Command(TrustedGit(), args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf // 2>&1
	if err := cmd.Run(); err != nil {
		return "", false
	}
	return trimNL(ExtractSigner(buf.String(), format)), true
}

// tagScratch is a new bare repository, in the workspace's object format, holding only the
// workspace's tag object under its name. A name that is not an annotated tag yields none.
func tagScratch(repo, tag string) (string, bool) {
	cat := VettingGit(repo, "cat-file", "tag", "refs/tags/"+tag)
	raw, err := cat.Output()
	if err != nil {
		return "", false
	}
	objFormat := "sha1"
	if f, ok := vgit(repo, "rev-parse", "--show-object-format"); ok && trimNL(f) != "" {
		objFormat = trimNL(f)
	}
	dir, err := os.MkdirTemp(os.TempDir(), "sandbox-vet-tag-")
	if err != nil {
		return "", false
	}
	git := func(stdin []byte, args ...string) (string, bool) {
		cmd := exec.Command(TrustedGit(), append([]string{"-C", dir}, args...)...)
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		out, err := cmd.Output()
		return trimNL(string(out)), err == nil
	}
	if _, ok := git(nil, "init", "-q", "--bare", "--object-format="+objFormat); ok {
		if oid, ok := git(raw, "hash-object", "-t", "tag", "-w", "--stdin"); ok {
			if _, ok := git(nil, "update-ref", "refs/tags/"+tag, oid); ok {
				return dir, true
			}
		}
	}
	os.RemoveAll(dir)
	return "", false
}

var allDigits = regexp.MustCompile(`^[0-9]+$`)

// StatusRepo is vetting_status_repo: classify a workspace's vetting state as the one TSV line
// the gate consumes. It never fails; the line carries the status.
func (c Ctx) StatusRepo(repo string) string {
	realRepo, err := physicalDir(repo)
	if err != nil {
		return fmt.Sprintf("error\tcannot access %s", repo)
	}
	if _, ok := vgit(realRepo, "rev-parse", "--git-dir"); !ok {
		return fmt.Sprintf("not-git\t%s is not a git repository", repo)
	}
	headOut, ok := vgit(realRepo, "rev-parse", "HEAD")
	if !ok {
		return fmt.Sprintf("error\t%s has no commits yet (empty repository) — make an initial commit, then attest with: sandbox vet --repo %s", repo, repo)
	}
	head := trimNL(headOut)

	if c.RequireCleanWorktree() == "true" {
		if st, _ := vgit(realRepo, "status", "--porcelain"); trimNL(st) != "" {
			return "dirty\t" + head
		}
	}

	format := c.TrustFormat()
	roots := c.TrustRoots()
	if len(roots) == 0 {
		return fmt.Sprintf("error\tno trust root found (%s; none shipped by the overlay)", c.TrustRoot())
	}

	tagsOut, _ := vgit(realRepo, "tag", "--list", c.TagPrefix+"*")
	var allTags []string
	if tagsOut != "" {
		allTags = strings.Split(strings.TrimSuffix(tagsOut, "\n"), "\n")
	}
	type ranked struct {
		behind string
		tag    string
	}
	var rk []ranked
	for _, t := range allTags {
		if t == "" {
			continue
		}
		if _, ok := vgit(realRepo, "merge-base", "--is-ancestor", t, "HEAD"); !ok {
			continue
		}
		b, _ := vgit(realRepo, "rev-list", "--count", t+"..HEAD")
		b = trimNL(b)
		if !allDigits.MatchString(b) {
			continue
		}
		rk = append(rk, ranked{b, t})
	}

	if len(rk) == 0 {
		ntags := 0
		for _, t := range allTags {
			if t != "" {
				ntags++
			}
		}
		var reason string
		if ntags == 0 {
			if sh, _ := vgit(realRepo, "rev-parse", "--is-shallow-repository"); trimNL(sh) == "true" {
				reason = fmt.Sprintf("no %s* tag present, and this is a shallow clone — if the repo is vetted upstream, 'git fetch --unshallow --tags' may reveal the attestation", c.TagPrefix)
			} else {
				reason = fmt.Sprintf("no %s* tag present — if the repo is vetted upstream, 'git fetch --tags' may reveal the attestation", c.TagPrefix)
			}
		} else {
			reason = fmt.Sprintf("%d %s* tag(s) present but none is an ancestor of HEAD (an older checkout or a divergent branch?) — check out the vetted commit, or attest this HEAD", ntags, c.TagPrefix)
		}
		return fmt.Sprintf("unvetted\t%s\t%s", head, reason)
	}

	// sort -n -k1,1: numeric on the distance, ties broken by the whole line (byte order here).
	sort.SliceStable(rk, func(i, j int) bool {
		a, _ := strconv.ParseUint(rk[i].behind, 10, 64)
		b, _ := strconv.ParseUint(rk[j].behind, 10, 64)
		if a != b {
			return a < b
		}
		return rk[i].behind+"\t"+rk[i].tag < rk[j].behind+"\t"+rk[j].tag
	})
	for _, e := range rk {
		for _, root := range roots {
			if root == "" {
				continue
			}
			if signer, ok := VerifyTag(realRepo, e.tag, root, format); ok {
				td, _ := vgit(realRepo, "for-each-ref", "--format=%(creatordate:unix)", "refs/tags/"+e.tag)
				td = trimNL(td)
				if !allDigits.MatchString(td) {
					td = ""
				}
				if signer == "" {
					signer = "unknown"
				}
				return fmt.Sprintf("vetted\t%s\t%s\t%s\t%s\t%s", head, e.tag, signer, e.behind, td)
			}
		}
	}
	return fmt.Sprintf("unvetted\t%s\t%d reachable tag(s) but none verified against the trust root", head, len(rk))
}

// physicalDir is `cd "$repo" && pwd -P`.
func physicalDir(p string) (string, error) {
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}
