// gencorpus writes the differential corpus for finding_is_encrypted: the fixtures' cases, plus a
// seeded set of mutated files and their cases. It does not run the oracle; see go/README.md.
//
//	go run ./internal/gate/internal/gencorpus -base internal/gate/testdata/encrypted -seed 1 -n 300
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var tokRE = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)

const marker = "ENC[AES256_GCM,"

type doc struct {
	lines    []string
	crlf     bool
	noTrail  bool
	ext      string
	basename string
}

func parse(name string, b []byte) doc {
	s := string(b)
	d := doc{ext: filepath.Ext(name), basename: name}
	d.noTrail = !strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	d.lines = strings.Split(s, "\n")
	return d
}

func (d doc) bytes() []byte {
	nl := "\n"
	if d.crlf {
		nl = "\r\n"
	}
	body := strings.Join(d.lines, nl)
	if !d.noTrail {
		body += nl
	}
	return []byte(body)
}

// ---- mutations ----

func mutate(r *rand.Rand, d doc, all []doc) doc {
	d.lines = append([]string(nil), d.lines...)
	n := 1 + r.Intn(3)
	for k := 0; k < n; k++ {
		if len(d.lines) == 0 {
			break
		}
		i := r.Intn(len(d.lines))
		switch r.Intn(24) {
		case 0: // indent a line by 1-3 spaces
			d.lines[i] = strings.Repeat(" ", 1+r.Intn(3)) + d.lines[i]
		case 1: // dedent
			d.lines[i] = strings.TrimPrefix(strings.TrimPrefix(d.lines[i], " "), " ")
		case 2: // insert a blank line
			d.lines = insert(d.lines, i, "")
		case 3: // insert a comment line, flush and indented
			d.lines = insert(d.lines, i, []string{"# note", "    # indented note", "  #"}[r.Intn(3)])
		case 4: // delete a line
			d.lines = append(d.lines[:i], d.lines[i+1:]...)
		case 5: // duplicate a line
			d.lines = insert(d.lines, i, d.lines[i])
		case 6: // swap with the next line
			if i+1 < len(d.lines) {
				d.lines[i], d.lines[i+1] = d.lines[i+1], d.lines[i]
			}
		case 7:
			d.crlf = true
		case 8:
			d.noTrail = true
		case 9: // tab-indent
			d.lines[i] = "\t" + strings.TrimLeft(d.lines[i], " ")
		case 10: // document separator, plain or with trailing text
			d.lines = insert(d.lines, i, []string{"---", "--- # next", "...", "---  ", "----"}[r.Intn(5)])
		case 11: // kind variants
			for j, l := range d.lines {
				if strings.Contains(l, "kind: SealedSecret") {
					v := []string{"kind: \"SealedSecret\"", "kind: sealedsecret", "kind: SealedSecret   ", "kind: SealedSecret # c", "kind:SealedSecret", "kind:   SealedSecret"}[r.Intn(6)]
					d.lines[j] = prefixOf(l) + v
					break
				}
			}
		case 12: // apiVersion variants
			for j, l := range d.lines {
				if strings.Contains(l, "apiVersion:") {
					v := []string{"apiVersion: v1", "apiVersion: bitnami.com", "apiVersion: example.org/bitnami.com/x", "apiVersion: \"bitnami.com/v1alpha1\"", "apiVersion: bitnamixcom/v1"}[r.Intn(5)]
					d.lines[j] = prefixOf(l) + v
					break
				}
			}
		case 13: // damage or relocate an envelope
			for j, l := range d.lines {
				if strings.Contains(l, marker) {
					switch r.Intn(4) {
					case 0:
						d.lines[j] = strings.Replace(l, marker, "ENC[AES256_GCM", 1)
					case 1:
						d.lines[j] = strings.Replace(l, "]", "", 1)
					case 2:
						d.lines[j] = l + " # " + marker + "x]"
					case 3:
						d.lines[j] = marker + "x] " + l
					}
					break
				}
			}
		case 14: // multibyte characters before content (byte vs character positions)
			d.lines[i] = []string{"é", "日本語", "😀", "ü ü"}[r.Intn(4)] + d.lines[i]
		case 15: // list marker prefix
			d.lines[i] = []string{"- ", "-   ", "  - ", "-"}[r.Intn(4)] + d.lines[i]
		case 16: // trailing whitespace
			d.lines[i] += []string{" ", "  ", "\t", " \r"}[r.Intn(4)]
		case 18: // tab variants around the kind value and list marker
			for j, l := range d.lines {
				if strings.Contains(l, "kind: SealedSecret") {
					d.lines[j] = prefixOf(l) + []string{"kind:\tSealedSecret", "kind: SealedSecret\t", "kind:\t SealedSecret"}[r.Intn(3)]
					break
				}
			}
		case 19: // swap two adjacent blocks at the same indent (reorders keys, list elements, documents' parts)
			d.lines = swapBlocks(r, d.lines, i)
		case 20: // tab after a list marker
			d.lines[i] = prefixOf(d.lines[i]) + "-\t" + strings.TrimLeft(d.lines[i], " ")
		case 21: // append another fixture, with or without a document separator
			o := all[r.Intn(len(all))]
			sep := []string{"---", "", "...", "--- "}[r.Intn(4)]
			if sep != "" {
				d.lines = append(d.lines, sep)
			}
			d.lines = append(d.lines, o.lines...)
		case 22: // shift a block right or left by two
			j := i + 1 + r.Intn(4)
			if j > len(d.lines) {
				j = len(d.lines)
			}
			for k := i; k < j; k++ {
				if r.Intn(2) == 0 {
					d.lines[k] = "  " + d.lines[k]
				} else {
					d.lines[k] = strings.TrimPrefix(d.lines[k], "  ")
				}
			}
		case 23: // wrap the whole file as a list element under a parent key, as Helm extraObjects do
			wrapped := []string{"extraObjects:"}
			for k, l := range d.lines {
				if k == 0 {
					wrapped = append(wrapped, "  - "+l)
				} else {
					wrapped = append(wrapped, "    "+l)
				}
			}
			d.lines = wrapped
		case 17: // a plaintext key sibling of encryptedData
			d.lines = insert(d.lines, i, prefixOf(d.lines[i])+"extra: "+"ghp_zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP9oO8n")
		}
	}
	return d
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// swapBlocks swaps the block starting at line i with the block that follows it, where a block runs
// until the next non-blank line at the same or a smaller indent.
func swapBlocks(r *rand.Rand, ls []string, i int) []string {
	ind := indentOf(ls[i])
	end := func(from int) int {
		k := from + 1
		for k < len(ls) && (strings.TrimSpace(ls[k]) == "" || indentOf(ls[k]) > ind) {
			k++
		}
		return k
	}
	j := end(i)
	if j >= len(ls) {
		return ls
	}
	k := end(j)
	out := append([]string(nil), ls[:i]...)
	out = append(out, ls[j:k]...)
	out = append(out, ls[i:j]...)
	return append(out, ls[k:]...)
}

func insert(ls []string, i int, s string) []string {
	ls = append(ls, "")
	copy(ls[i+1:], ls[i:])
	ls[i] = s
	return ls
}

func prefixOf(l string) string { return l[:len(l)-len(strings.TrimLeft(l, " "))] }

// ---- cases ----

type c struct{ line, sc, ec string }

func casesFor(d doc) []c {
	set := map[c]bool{}
	add := func(l int, sc, ec int) { set[c{strconv.Itoa(l), strconv.Itoa(sc), strconv.Itoa(ec)}] = true }
	n := len(d.lines)
	for l := 0; l <= n+2; l++ {
		set[c{strconv.Itoa(l), "", ""}] = true
	}
	for idx, line := range d.lines {
		l := idx + 1
		hit := false
		for _, m := range tokRE.FindAllStringIndex(line, -1) {
			hit = true
			sc, ec := m[0]+2, m[1]+1 // betterleaks reports one past the real positions
			add(l, sc, ec)
			add(l, sc-1, ec)
			add(l, sc+1, ec)
			add(l, sc, ec-1)
			add(l, sc, ec+1)
		}
		for from := 0; ; {
			i := strings.Index(line[from:], marker)
			if i < 0 {
				break
			}
			hit = true
			estart := from + i + 1
			bopen := estart + 3
			cl := strings.Index(line[bopen-1:], "]")
			if cl >= 0 {
				bclose := bopen + cl
				for _, sc := range []int{bopen - 1, bopen, bopen + 1, bopen + 2} {
					for _, ec := range []int{bclose - 2, bclose - 1, bclose, bclose + 1} {
						add(l, sc, ec)
					}
				}
				// Only one column present, the other absent, with the present one inside the
				// envelope: the bash takes the SOPS path only when both are numeric.
				set[c{strconv.Itoa(l), strconv.Itoa(bopen + 1), ""}] = true
				set[c{strconv.Itoa(l), "", strconv.Itoa(bclose - 1)}] = true
			}
			from += i + 1
		}
		if hit {
			add(l, 0, 0)
			add(l, 1, 1)
			set[c{strconv.Itoa(l), "99999999999999999999", "99999999999999999999"}] = true
			set[c{strconv.Itoa(l), "5", ""}] = true
			set[c{strconv.Itoa(l), "", "5"}] = true
			// Non-canonical spellings of this line number: the bash requires digits only, while a
			// float parse would accept them and select the same line.
			for _, ln := range []string{"+" + strconv.Itoa(l), strconv.Itoa(l) + "e0", strconv.Itoa(l) + ".0", fmt.Sprintf("0x%x", l)} {
				set[c{ln, "", ""}] = true
			}
		}
	}
	out := make([]c, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.line != b.line {
			ai, _ := strconv.Atoi(a.line)
			bi, _ := strconv.Atoi(b.line)
			if ai != bi {
				return ai < bi
			}
			return a.line < b.line // non-canonical spellings parse alike; keep the order deterministic
		}
		if a.sc != b.sc {
			return a.sc < b.sc
		}
		return a.ec < b.ec
	})
	return out
}

func writeCases(path string, files map[string][]c, order []string) {
	var sb strings.Builder
	total := 0
	for _, f := range order {
		for _, k := range files[f] {
			fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\n", f, k.line, k.sc, k.ec)
			total++
		}
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%s: %d files, %d cases\n", path, len(order), total)
}

// adversarial returns hand-written files aimed at boundaries the random mutations reach only rarely.
// Each is written to fixtures/adv-<name> so it is also a base for the mutations.
func adversarial() map[string]string {
	const sealed = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z"
	const plain = "ghp_bC4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6a"
	return map[string]string{
		// A plaintext element FIRST, then a real SealedSecret element: the end-of-object scan must stop
		// at the next list item, or the later element's kind/apiVersion would vouch for the first.
		"plaintext-then-sealed.yaml": "extraObjects:\n  - apiVersion: v1\n    kind: Secret\n    spec:\n      encryptedData:\n        token: " + plain + "\n  - apiVersion: bitnami.com/v1alpha1\n    kind: SealedSecret\n    spec:\n      encryptedData:\n        token: " + sealed + "\n",
		// bitnami apiVersion and encryptedData, but kind is Secret, beside a genuine SealedSecret document.
		"wrongkind-beside-sealed.yaml": "apiVersion: bitnami.com/v1alpha1\nkind: Secret\nspec:\n  encryptedData:\n    token: " + plain + "\n---\napiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n    token: " + sealed + "\n",
		// A bare list marker on its own line.
		"bare-dash.yaml": "items:\n  -\n    apiVersion: bitnami.com/v1\n    kind: SealedSecret\n    spec:\n      encryptedData:\n        t: " + sealed + "\n",
		// A tab after the colon of kind:.
		"tab-after-colon.yaml": "apiVersion: bitnami.com/v1alpha1\nkind:\tSealedSecret\nspec:\n  encryptedData:\n    token: " + sealed + "\n",
		// kind/apiVersion repeated at the same indent in one document: no list item bounds the object.
		"duplicate-keys.yaml": "kind: Secret\nspec:\n  encryptedData:\n    a: " + plain + "\nkind: SealedSecret\napiVersion: bitnami.com/v1\n",
		// kind: SealedSecret present only as a nested value of another key, so the prefilter passes but no object owns it.
		"kind-nested-only.yaml": "wrapper:\n  kind: SealedSecret\nspec:\n  encryptedData:\n    token: " + plain + "\n",
		// Windows line endings throughout.
		"crlf-sealed.yaml": "apiVersion: bitnami.com/v1alpha1\r\nkind: SealedSecret\r\nspec:\r\n  encryptedData:\r\n    token: " + sealed + "\r\n",
		// A comment between the key and its value lines, and a document separator carrying trailing text.
		// Colons inside key names: a line whose text before ": " itself contains a colon is not a key
		// line to the bash (its key pattern is [^:]* up to the first colon), so it can neither be the
		// encryptedData/spec parent nor the kind/apiVersion that vouches for the object.
		"colon-in-key.yaml":     "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:x: y\n    token: " + sealed + "\n---\napiVersion: bitnami.com/v1alpha1\nkind:x: SealedSecret\nspec:\n  encryptedData:\n    token: " + plain + "\n---\napiVersion:x: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n    a:b: c\n    token: " + sealed + "\n",
		"comments-and-sep.yaml": "# header\napiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  # note\n  encryptedData:\n    # note\n    token: " + sealed + "\n--- # next doc\nkind: Secret\nstringData:\n  token: " + plain + "\n",
	}
}

func main() {
	base := flag.String("base", "internal/gate/testdata/encrypted", "testdata directory")
	seed := flag.Int64("seed", 1, "random seed")
	n := flag.Int("n", 300, "number of mutated files")
	flag.Parse()

	for name, body := range adversarial() {
		if err := os.WriteFile(filepath.Join(*base, "fixtures", "adv-"+name), []byte(body), 0o644); err != nil {
			panic(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(*base, "fixtures"))
	if err != nil {
		panic(err)
	}
	var names []string
	docs := map[string]doc{}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(*base, "fixtures", e.Name()))
		names = append(names, e.Name())
		docs[e.Name()] = parse(e.Name(), b)
	}
	sort.Strings(names)

	// fixtures
	fcases := map[string][]c{}
	var forder []string
	for _, nm := range names {
		rel := "fixtures/" + nm
		fcases[rel] = casesFor(docs[nm])
		forder = append(forder, rel)
	}
	writeCases(filepath.Join(*base, "cases-fixtures.tsv"), fcases, forder)

	// mutants
	os.RemoveAll(filepath.Join(*base, "mut"))
	os.MkdirAll(filepath.Join(*base, "mut"), 0o755)
	r := rand.New(rand.NewSource(*seed))
	var allDocs []doc
	for _, nm := range names {
		allDocs = append(allDocs, docs[nm])
	}
	mcases := map[string][]c{}
	var morder []string
	for i := 0; i < *n; i++ {
		src := docs[names[r.Intn(len(names))]]
		m := mutate(r, src, allDocs)
		rel := fmt.Sprintf("mut/m%04d%s", i, m.ext)
		os.WriteFile(filepath.Join(*base, rel), m.bytes(), 0o644)
		mcases[rel] = casesFor(m)
		morder = append(morder, rel)
	}
	writeCases(filepath.Join(*base, "cases-mutants.tsv"), mcases, morder)
}
