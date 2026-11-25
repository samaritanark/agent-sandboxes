// Package secrets is the host-side secret store of lib/secrets.sh: one file per secret, mode
// 0600, in a 0700 directory (~/.sandbox/secrets, or $SANDBOX_SECRETS_DIR). v3 keeps the store on
// the host and pushes only the secrets a session's bindings reference (design 5.1.4); the
// cluster-side injection half of lib/secrets.sh is replaced by the broker and is not ported.
package secrets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Error is a refusal: the lines the bash prints to stderr before `exit 1`.
type Error struct{ Lines []string }

func (e *Error) Error() string { return strings.Join(e.Lines, "\n") }

func fail(lines ...string) error { return &Error{Lines: lines} }

var nameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ValidateName is secret_validate_name: the name is also the agent's env-var name.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fail("ERROR: secret name is empty.")
	case len(name) > 64:
		// ${#name} under LC_ALL=C counts bytes. (A non-ASCII name fails the pattern below either
		// way, so the count only decides which of the two messages it gets.)
		return fail(fmt.Sprintf("ERROR: secret name '%s' is longer than 64 characters.", name))
	case !nameRe.MatchString(name):
		return fail(fmt.Sprintf("ERROR: secret name '%s' must match [A-Z_][A-Z0-9_]* — the", name),
			"       name is also the env-var the agent sees inside the pod.")
	}
	return nil
}

// Store is the directory of secrets.
type Store struct{ Dir string }

// Path is secret_store_path.
func (s Store) Path(name string) string { return s.Dir + "/" + name }

// Exists is secret_exists: [[ -f path ]] (a link to a regular file counts).
func (s Store) Exists(name string) bool {
	st, err := os.Stat(s.Path(name))
	return err == nil && st.Mode().IsRegular()
}

// prepare is `mkdir -p dir; chmod 0700 dir 2>/dev/null || true`.
func (s Store) prepare() error {
	if err := os.MkdirAll(s.Dir, 0o777); err != nil {
		return fail(fmt.Sprintf("mkdir: cannot create directory '%s': %s", s.Dir, errText(err)))
	}
	os.Chmod(s.Dir, 0o700)
	return nil
}

func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	if e, ok := err.(syscall.Errno); ok {
		switch e {
		case syscall.EEXIST:
			return "File exists"
		case syscall.ENOTDIR:
			return "Not a directory"
		case syscall.EACCES:
			return "Permission denied"
		}
	}
	return err.Error()
}

// write is `( umask 0177 && cat > path ); chmod 0600 path`: the file is created 0600 (an
// existing one keeps its mode until the chmod), and like the shell redirect it follows a link.
func write(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fail(fmt.Sprintf("%s: %s", path, errText(err)))
	}
	_, err = f.Write(data)
	f.Close()
	if err != nil {
		return fail(fmt.Sprintf("%s: %s", path, errText(err)))
	}
	os.Chmod(path, 0o600)
	return nil
}

// SetFromReader is secret_set_from_stdin.
func (s Store) SetFromReader(name string, r io.Reader) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := s.prepare(); err != nil {
		return err
	}
	var data []byte
	if r != nil {
		data, _ = io.ReadAll(r)
	}
	return write(s.Path(name), data)
}

// SetFromFile is secret_set_from_file: the source must be a regular file (or a link to one).
func (s Store) SetFromFile(name, src string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {
		return fail("ERROR: source file not found: " + src)
	}
	if err := s.prepare(); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fail(fmt.Sprintf("cp: cannot open '%s' for reading: %s", src, errText(err)))
	}
	return write(s.Path(name), data)
}

// SetFromEnv is secret_set_from_env: the value of the named variable, which must be non-empty.
// getenv is the environment the bash sees (its ${!var}).
func (s Store) SetFromEnv(name, envVar string, getenv func(string) string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if envVar == "" {
		return fail("ERROR: --from-env requires a source variable name.")
	}
	v := getenv(envVar)
	if v == "" {
		return fail(fmt.Sprintf("ERROR: env var $%s is unset or empty in this shell.", envVar),
			fmt.Sprintf("       Export it first, e.g.  export %s=...  then re-run.", envVar))
	}
	if err := s.prepare(); err != nil {
		return err
	}
	return write(s.Path(name), []byte(v))
}

// Delete is secret_delete: rm -f, a missing secret being no error.
func (s Store) Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	p := s.Path(name)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		if st, e := os.Lstat(p); e == nil && st.IsDir() {
			return fail(fmt.Sprintf("rm: cannot remove '%s': Is a directory", p))
		}
		return fail(fmt.Sprintf("rm: cannot remove '%s': %s", p, errText(err)))
	}
	return nil
}

// List is secret_list: one row per regular file (or link to one) whose name does not start with
// a dot, sorted bytewise, as "NAME  SIZE bytes  MTIME". Like `stat -c %s / %y` without -L, a
// link reports its own size and time. loc is the local time zone stat prints in.
func (s Store) List(loc *time.Location) []string {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var rows []string
	for _, n := range names {
		p := filepath.Join(s.Dir, n)
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			continue
		}
		size, mtime := "?", "?"
		if st, err := os.Lstat(p); err == nil {
			size = fmt.Sprint(st.Size())
			mtime = st.ModTime().In(loc).Format("2006-01-02 15:04:05")
		}
		// printf '%-32s' under LC_ALL=C pads to 32 bytes, not characters
		pad := n
		if len(pad) < 32 {
			pad += strings.Repeat(" ", 32-len(pad))
		}
		rows = append(rows, fmt.Sprintf("%s  %6s bytes  %s", pad, size, mtime))
	}
	return rows
}
