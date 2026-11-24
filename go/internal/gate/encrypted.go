// Package gate is the Go port of the secret gate in lib/filesystem.sh (spike S8, decision D-34).
//
// Behaviour is intentionally identical to the bash it replaces, including quirks, because the
// bash is the oracle until release. Positions are BYTE positions. That matches the oracle under
// mawk, and under gawk in the C locale, and it matches the scanner: betterleaks reports byte
// columns (measured with betterleaks 1.10.0). Under gawk in a UTF-8 locale the bash counts
// characters instead and answers differently on lines with multibyte text (12 of 34,504 mutant
// answers in the S8 corpus); the port deliberately does not reproduce that. Where this file notes
// a quirk, it is a quirk of the original, not a design choice; fixing one is a separate, reviewed
// change after the port is verified.
package gate

import (
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
)

var (
	digitsOnly = regexp.MustCompile(`^[0-9]+$`)

	// grep -Eq '^[[:space:]]*(-[[:space:]]+)?kind:[[:space:]]*SealedSecret[[:space:]]*$'
	sealedKindLine = regexp.MustCompile(`^[[:space:]]*(-[[:space:]]+)?kind:[[:space:]]*SealedSecret[[:space:]]*$`)
	// /^(---|\.\.\.)([[:space:]].*)?$/
	docSeparator = regexp.MustCompile(`^(---|\.\.\.)([[:space:]].*)?$`)
	// /^[^[:space:]#][^:]*:([[:space:]].*)?$/  (. matches any character, as in awk)
	keyLine = regexp.MustCompile(`(?s)^[^[:space:]#][^:]*:([[:space:]].*)?$`)
	// /^SealedSecret[[:space:]]*$/
	sealedKindVal = regexp.MustCompile(`^SealedSecret[[:space:]]*$`)
	apiBitnami    = regexp.MustCompile(`bitnami\.com`)
	leadingSpace  = regexp.MustCompile(`^[[:space:]]+`)
)

const sopsMarker = "ENC[AES256_GCM,"

// FindingIsEncrypted reports whether the secret-scanner finding at file:line (columns
// startcol..endcol, 1-based inclusive over the real file, both as strings so the original's
// "absent or non-numeric means no span" handling is preserved) is a value that is encrypted at
// rest and therefore safe for the agent to read. See finding_is_encrypted in lib/filesystem.sh.
//
// It mirrors the bash return code: true is exit 0 (exempt), false is exit 1 (not exempt).
func FindingIsEncrypted(file, line, startcol, endcol string) bool {
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() { // [[ -f file ]] follows symlinks
		return false
	}
	if !digitsOnly.MatchString(line) {
		return false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	lines := bashcompat.SplitRecords(data)

	// SOPS: the flagged span must lie strictly inside an ENC[AES256_GCM,...] envelope on the line.
	if digitsOnly.MatchString(startcol) && digitsOnly.MatchString(endcol) {
		if sopsContains(lines, awkNum(line), awkNum(startcol), awkNum(endcol)) {
			return true
		}
	}

	// SealedSecret: cheap pre-filter (grep), then the YAML walk.
	pre := false
	for _, l := range lines {
		if sealedKindLine.MatchString(l) {
			pre = true
			break
		}
	}
	if !pre {
		return false
	}
	return sealedSecretEncrypted(lines, awkNum(line))
}

// awkNum converts a digit string the way awk -v does for comparison (a double).
func awkNum(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// sopsContains is the first awk program: NR == n selects the line; the span must sit strictly
// between the '[' and ']' of an ENC[AES256_GCM,...] envelope.
func sopsContains(lines []string, n, sc, ec float64) bool {
	for i, rec := range lines {
		if float64(i+1) != n {
			continue
		}
		s := sc - 1 // legacy: the bash assumed the scanner reports the start one past the real start
		if deviation.Fixed(deviation.ExactColumns) {
			s = sc // betterleaks reports exact 1-based byte columns
		}
		pos := 1
		for {
			sub := awkSubstr(rec, pos)
			idx := strings.Index(sub, sopsMarker) + 1 // awk index(): 1-based, 0 when absent
			if idx <= 0 {
				break
			}
			estart := pos + idx - 1
			bopen := estart + 3
			rest := awkSubstr(rec, bopen)
			closeRel := strings.Index(rest, "]") + 1
			if closeRel == 0 {
				pos = estart + 1
				continue
			}
			bclose := bopen + closeRel - 1
			if s > float64(bopen) && ec < float64(bclose) {
				return true
			}
			pos = estart + 1
		}
	}
	return false
}

// awkSubstr is awk's substr(s, pos) for integer pos >= 1 (bytes).
func awkSubstr(s string, pos int) string {
	if pos < 1 {
		pos = 1
	}
	if pos > len(s) {
		return ""
	}
	return s[pos-1:]
}

type yamlLine struct {
	blank bool
	cind  int
	item  bool
	iskey bool
	key   string
	val   string
}

// sealedSecretEncrypted is the second awk program: the target line must nest directly under
// spec > encryptedData of one object whose own keys include kind: SealedSecret and a bitnami.com
// apiVersion.
func sealedSecretEncrypted(lines []string, target float64) bool {
	nr := len(lines)
	if target < 1 || target > float64(nr) {
		return false
	}
	t := int(target) // target is integral: digits only; an absurdly large value already failed above
	// 1-based indexing to mirror the awk.
	at := func(i int) string { return lines[i-1] }

	ds, de := 1, nr
	for i := 1; i <= nr; i++ {
		if docSeparator.MatchString(at(i)) {
			if i < t {
				ds = i + 1
			} else if i > t {
				de = i - 1
				break
			}
		}
	}

	info := make(map[int]*yamlLine, de-ds+1)
	for i := ds; i <= de; i++ {
		s := at(i)
		tt := leadingSpace.ReplaceAllString(s, "")
		yl := &yamlLine{}
		info[i] = yl
		if tt == "" || tt[0] == '#' {
			yl.blank, yl.cind = true, -1
			continue
		}
		L := len(s)
		pos := 0
		for pos < L && s[pos] == ' ' {
			pos++
		}
		it := false
		for pos < L && s[pos] == '-' && (pos+2 > L || s[pos+1] == ' ') {
			it = true
			pos++
			for pos < L && s[pos] == ' ' {
				pos++
			}
		}
		yl.cind, yl.item = pos, it
		rest := s[pos:]
		if keyLine.MatchString(rest) {
			yl.iskey = true
			k := rest
			if c := strings.Index(k, ":"); c >= 0 {
				k = k[:c]
			}
			yl.key = k
			v := rest
			if c := strings.Index(v, ":"); c >= 0 {
				v = v[c+1:]
				v = leadingSpace.ReplaceAllString(v, "")
			}
			yl.val = v
		}
	}
	if info[t].blank {
		return false
	}

	tInd := info[t].cind
	p := -1
	for j := t - 1; j >= ds; j-- {
		if info[j].blank {
			continue
		}
		if info[j].cind < tInd {
			if info[j].iskey {
				p = j
			}
			break
		}
	}
	if p < 0 || info[p].key != "encryptedData" {
		return false
	}
	gp := -1
	for j := p - 1; j >= ds; j-- {
		if info[j].blank {
			continue
		}
		if info[j].cind < info[p].cind {
			if info[j].iskey {
				gp = j
			}
			break
		}
	}
	if gp < 0 || info[gp].key != "spec" {
		return false
	}
	specInd := info[gp].cind

	start := ds
	for j := gp; j >= ds; j-- {
		if info[j].blank {
			continue
		}
		if info[j].cind > specInd {
			continue
		}
		if info[j].cind < specInd {
			start = j + 1
			break
		}
		start = j
		if info[j].item {
			break
		}
	}
	end := de + 1
	for j := gp + 1; j <= de; j++ {
		if info[j].blank {
			continue
		}
		if info[j].cind < specInd {
			end = j
			break
		}
		if info[j].cind == specInd && info[j].item {
			end = j
			break
		}
	}
	kindOK, apiOK := false, false
	for j := start; j < end; j++ {
		if info[j].blank || info[j].cind != specInd || !info[j].iskey {
			continue
		}
		if info[j].key == "kind" && sealedKindVal.MatchString(info[j].val) {
			kindOK = true
		}
		if info[j].key == "apiVersion" && apiBitnami.MatchString(info[j].val) {
			apiOK = true
		}
	}
	return kindOK && apiOK
}
