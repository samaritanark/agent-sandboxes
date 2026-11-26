package main

import "strconv"

// gitProtected is the git configuration every git the in-VM CLI runs gets as protected (command)
// configuration, through GIT_CONFIG_COUNT: it overrides a repository's own config. The CLI runs as
// root on workspace copies the sync user owns, which git otherwise refuses ("dubious ownership");
// accepting them must not let a copy's config run code as root, so hooks and fsmonitor are off and
// the programs git would run on its own (pager, ssh, credential helpers, x509 verifier) are the
// system's; the vetting code pins gpg.program and gpg.ssh.program on every verify itself. Filters
// (.gitattributes with filter.<name>.clean in config) are not covered: the CLI's git commands on a
// copy (ls-files, rev-parse, cat-file, tag verification) do not run them.
var gitProtected = [][2]string{{"safe.directory", "*"}, {"core.fsmonitor", "false"}, {"core.hooksPath", "/dev/null"},
	{"core.pager", "cat"}, {"core.sshCommand", "ssh"}, {"credential.helper", ""}, {"gpg.x509.program", "gpgsm"}}

// protectGit appends gitProtected to the process's command-scope git configuration.
func protectGit(getenv func(string) string, setenv func(string, string) error) {
	n, _ := strconv.Atoi(getenv("GIT_CONFIG_COUNT"))
	for _, kv := range gitProtected {
		i := strconv.Itoa(n)
		setenv("GIT_CONFIG_KEY_"+i, kv[0])
		setenv("GIT_CONFIG_VALUE_"+i, kv[1])
		n++
	}
	setenv("GIT_CONFIG_COUNT", strconv.Itoa(n))
}
