package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The writers below reproduce lib/config.sh byte for byte, including the file mode each leaves
// behind: a file rewritten through a temp file and mv gets a new file's mode (0666 less the
// umask); a file appended to keeps its mode.

// replaceFile writes data to path through a temp file in the same directory, as the bash's
// `> "${path}.tmp.$$"; mv` does.
func replaceFile(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	os.Remove(tmp)
	if err := os.WriteFile(tmp, data, 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o666)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// endsWithoutNewline is `[[ -n "$(tail -c1 file)" ]]`: the file is not empty and its last byte is
// neither a newline nor a NUL (command substitution drops both).
func endsWithoutNewline(data []byte) bool {
	return len(data) > 0 && data[len(data)-1] != '\n' && data[len(data)-1] != 0
}

func joinRecords(lines []string) []byte {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// RemoveYAMLScalar is remove_yaml_scalar_from_file: delete every top-level "<key>:" line; the
// file is left with mode 0600. Nothing happens if the file is absent. key must not contain regex
// metacharacters (the bash interpolates it into an awk regex; every caller passes a fixed word).
func RemoveYAMLScalar(path, key string) error {
	if !IsFile(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var keep []string
	for _, l := range bashcompat.SplitRecords(data) {
		if !strings.HasPrefix(l, key+":") {
			keep = append(keep, l)
		}
	}
	if err := replaceFile(path, joinRecords(keep)); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// AddMaskedPath is config_add_masked_path: add relpath to the masked_paths: list in a repo config
// file (created, with its parent directory, if absent), double-quoted, right after the key line.
// A path already listed is a no-op.
//
// In legacy mode the inserted entry goes through awk -v escape processing (see awkUnescape), and
// any path is written; LiteralMaskedPath writes it as is, and WritesReadBack refuses a path that
// extract_yaml_list_from_file would not read back unchanged.
func AddMaskedPath(configFile, relpath string) error {
	for _, existing := range ExtractYAMLList(configFile, "masked_paths") {
		if existing == relpath {
			return nil
		}
	}
	item := `  - "` + relpath + `"`
	if deviation.Fixed(deviation.WritesReadBack) {
		if got, ok := listItem(item); strings.ContainsAny(relpath, "\n\r") || !ok || got != relpath {
			return fmt.Errorf("cannot mask %q: the masked_paths: reader would not read it back as written (quotes, ' #', a leading '#', trailing whitespace, and line breaks are not supported)", relpath)
		}
	}
	if err := os.MkdirAll(filepath.Dir(configFile), 0o755); err != nil {
		return err
	}
	if !IsFile(configFile) {
		return os.WriteFile(configFile, []byte("masked_paths:\n"+item+"\n"), 0o666)
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	lines := bashcompat.SplitRecords(data)
	has := false
	for _, l := range lines {
		if strings.HasPrefix(l, "masked_paths:") {
			has = true
			break
		}
	}
	if !has {
		var add []byte
		if endsWithoutNewline(data) {
			add = append(add, '\n')
		}
		add = append(add, "masked_paths:\n"+item+"\n"...)
		return appendFile(configFile, add)
	}
	ins := item
	if !deviation.Fixed(deviation.LiteralMaskedPath) {
		ins = awkUnescape(item)
	}
	var out []string
	done := false
	for _, l := range lines {
		out = append(out, l)
		if !done && strings.HasPrefix(l, "masked_paths:") {
			out = append(out, ins)
			done = true
		}
	}
	return replaceFile(configFile, joinRecords(out))
}

// awkUnescape is the escape processing awk applies to a -v assignment: \\ \" \/ \a \b \f \n \r \t
// \v and one to three octal digits. Other escapes are kept with their backslash, as mawk does
// (gawk drops the backslash); the corpus avoids them.
func awkUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch d := s[i]; d {
		case '\\', '"', '/':
			b.WriteByte(d)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		default:
			if d >= '0' && d <= '7' {
				v, n := 0, 0
				for n < 3 && i < len(s) && s[i] >= '0' && s[i] <= '7' {
					v = v*8 + int(s[i]-'0')
					i++
					n++
				}
				i--
				b.WriteByte(byte(v))
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(d)
		}
	}
	return b.String()
}

// IgnoreFileAddFingerprint is ignorefile_add_fingerprint: append fingerprint (and, before it, the
// reason as a one-line "# " comment) to a betterleaks ignore file, created if absent. A
// fingerprint already in the file is a no-op.
//
// With WritesReadBack, a fingerprint the ignore-file reader would not read back unchanged (empty,
// starting with '#', with surrounding whitespace or a line break) is refused.
func IgnoreFileAddFingerprint(ignoreFile, fingerprint, reason string) error {
	if deviation.Fixed(deviation.WritesReadBack) {
		got := StripIgnoreFileComments([]byte(fingerprint))
		if len(got) != 1 || got[0] != fingerprint || strings.ContainsAny(fingerprint, "\n\r") {
			return fmt.Errorf("cannot record fingerprint %q: the ignore-file reader would not read it back as written", fingerprint)
		}
	}
	var add []byte
	if IsFile(ignoreFile) {
		data, err := os.ReadFile(ignoreFile)
		if err != nil {
			return err
		}
		for _, existing := range StripIgnoreFileComments(data) {
			if existing == fingerprint {
				return nil
			}
		}
		if endsWithoutNewline(data) {
			add = append(add, '\n')
		}
	}
	if reason != "" {
		r := strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(reason)
		r = strings.TrimPrefix(r, "#")
		r = strings.TrimPrefix(r, " ")
		add = append(add, "# "+r+"\n"...)
	}
	add = append(add, fingerprint+"\n"...)
	return appendFile(ignoreFile, add)
}

// RemoveYAMLList is remove_yaml_list_from_file: remove a "<key>:" block list (the key line and its
// items) from a YAML file. Nothing happens if the file or the key is absent.
//
// In legacy mode the block ends at the first line that is not an indented "-" or "#" line or a
// blank line, so column-0 items are left behind and blank lines after the block are dropped. With
// ListRemovalMatchesReader it ends where extract_yaml_list_from_file's does (the next line that
// starts with a letter or '_'), keeping the run of blank and column-0 comment lines that close it.
func RemoveYAMLList(file, key string) error {
	if !IsFile(file) {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	lines := bashcompat.SplitRecords(data)
	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, key+":") {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	var out []string
	if deviation.Fixed(deviation.ListRemovalMatchesReader) {
		for i := 0; i < len(lines); i++ {
			if !strings.HasPrefix(lines[i], key+":") {
				out = append(out, lines[i])
				continue
			}
			j := i + 1
			for j < len(lines) && !startsTopLevelKey(lines[j]) {
				j++
			}
			k := j // keep the closing run of blank and column-0 comment lines
			for k > i+1 && (isBlank(lines[k-1]) || strings.HasPrefix(lines[k-1], "#")) {
				k--
			}
			out = append(out, lines[k:j]...)
			i = j - 1
		}
		return replaceFile(file, joinRecords(out))
	}
	inblock := false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, key+":"):
			inblock = true
			continue
		case inblock && indentedDashOrHash(l):
			continue
		case inblock && isBlank(l):
			continue
		}
		inblock = false
		out = append(out, l)
	}
	return replaceFile(file, joinRecords(out))
}

// startsTopLevelKey is the reader's block end, /^[A-Za-z_]/.
func startsTopLevelKey(l string) bool {
	if l == "" {
		return false
	}
	c := l[0]
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// isBlank is /^[[:space:]]*$/.
func isBlank(l string) bool {
	for i := 0; i < len(l); i++ {
		if !isSpace(l[i]) {
			return false
		}
	}
	return true
}

// indentedDashOrHash is /^[[:space:]]+(-|#)/.
func indentedDashOrHash(l string) bool {
	i := 0
	for i < len(l) && isSpace(l[i]) {
		i++
	}
	return i > 0 && i < len(l) && (l[i] == '-' || l[i] == '#')
}
