package syncgate

import (
	"fmt"
	"strings"
)

// driverAttr reports whether an attribute token names a driver: filter=, diff=, or merge= with a
// value. A bare "diff" (git's text diff), "-diff", "!diff", and attributes such as text, eol,
// binary, or linguist-* name none.
// To stay on the safe side a token also counts after a leading - or !, and in any case.
func driverAttr(tok string) bool {
	t := strings.ToLower(strings.TrimLeft(tok, "-!"))
	for _, a := range []string{"filter=", "diff=", "merge="} {
		if strings.HasPrefix(t, a) {
			return true
		}
	}
	return false
}

// splitAttrLine splits one .gitattributes line into its pattern and attribute tokens, as git
// reads it: leading whitespace skipped, a pattern in double quotes (C-style escapes) or up to the
// first whitespace, then whitespace-separated attributes. ok is false for a line git would treat
// differently from the way this parser can tell (an unterminated quote).
func splitAttrLine(line string) (pattern string, attrs []string, ok bool) {
	line = strings.TrimLeft(strings.TrimSuffix(line, "\r"), " \t")
	if line == "" || line[0] == '#' {
		return "", nil, true
	}
	if line[0] == '"' {
		i := 1
		for ; i < len(line); i++ {
			if line[i] == '\\' {
				i++
				continue
			}
			if line[i] == '"' {
				break
			}
		}
		if i >= len(line) {
			return "", nil, false
		}
		pattern, line = line[:i+1], line[i+1:]
	} else {
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			return line, nil, true
		}
		pattern, line = line[:end], line[end:]
	}
	return pattern, strings.Fields(line), true
}

// driverLines is every line of a .gitattributes file that assigns a driver or defines a macro,
// normalized to "pattern attr attr...".
func driverLines(b []byte) (map[string]bool, error) {
	out := map[string]bool{}
	for n, line := range strings.Split(string(b), "\n") {
		pattern, attrs, ok := splitAttrLine(line)
		if !ok {
			return nil, fmt.Errorf("line %d: unterminated quoted pattern", n+1)
		}
		if strings.HasPrefix(pattern, "[attr]") {
			out[pattern+" "+strings.Join(attrs, " ")] = true // a macro can carry a driver to any pattern
			continue
		}
		drivers := false
		for _, a := range attrs {
			if driverAttr(a) {
				drivers = true
			}
		}
		if drivers && !lfsTriple(attrs) {
			out[pattern+" "+strings.Join(attrs, " ")] = true
		}
	}
	return out, nil
}

// lfsTriple: the drivers on the line are exactly filter=lfs, diff=lfs, and merge=lfs.
func lfsTriple(attrs []string) bool {
	seen := map[string]bool{}
	for _, a := range attrs {
		if driverAttr(a) {
			if a != "filter=lfs" && a != "diff=lfs" && a != "merge=lfs" {
				return false
			}
			seen[a] = true
		}
	}
	return len(seen) == 3
}

// CheckAttributes is rule 8 for one .gitattributes file (at any depth): nil when the VM's version
// adds or changes no driver assignment and no macro, compared with the host's version (nil when
// the file is new). A deletion, or removing a driver, needs no check.
func CheckAttributes(host, vm []byte) error {
	if vm == nil {
		return nil
	}
	newLines, err := driverLines(vm)
	if err != nil {
		return err
	}
	old := map[string]bool{}
	if host != nil {
		if old, err = driverLines(host); err != nil {
			old = map[string]bool{} // the host's own file is not ours to judge; compare against nothing
		}
	}
	for l := range newLines {
		if !old[l] {
			return fmt.Errorf("adds or changes a driver attribute or macro: %q", l)
		}
	}
	return nil
}
