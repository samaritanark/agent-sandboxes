package syncgate

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// LineDiff is a plain line diff of two texts for `sandbox sync review`: lines only in a prefixed
// "-", only in b "+", common ones "  ". Binary content, or texts too long to compare, get a
// one-line summary instead.
func LineDiff(a, b []byte) string {
	const maxLines = 3000
	if !utf8.Valid(a) || !utf8.Valid(b) || strings.ContainsRune(string(a), 0) || strings.ContainsRune(string(b), 0) {
		return fmt.Sprintf("  (binary: %d bytes on the host, %d bytes held)\n", len(a), len(b))
	}
	al, bl := splitLines(string(a)), splitLines(string(b))
	if len(al) > maxLines || len(bl) > maxLines {
		return fmt.Sprintf("  (too long to show: %d lines on the host, %d held)\n", len(al), len(bl))
	}
	// longest common subsequence, then walk it
	n, m := len(al), len(bl)
	l := make([][]int32, n+1)
	for i := range l {
		l[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				l[i][j] = l[i+1][j+1] + 1
			} else if l[i+1][j] >= l[i][j+1] {
				l[i][j] = l[i+1][j]
			} else {
				l[i][j] = l[i][j+1]
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			out.WriteString("  " + al[i] + "\n")
			i, j = i+1, j+1
		case i < n && (j == m || l[i+1][j] >= l[i][j+1]):
			out.WriteString("- " + al[i] + "\n")
			i++
		default:
			out.WriteString("+ " + bl[j] + "\n")
			j++
		}
	}
	return out.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
