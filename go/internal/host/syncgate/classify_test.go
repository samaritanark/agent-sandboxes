package syncgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var (
	linux = Host{}
	apfs  = Host{CaseInsensitive: true, NormInsensitive: true}
	ntfs  = Host{CaseInsensitive: true, Windows: true}
)

func TestClassify(t *testing.T) {
	repo := Repo{MaskedPaths: []string{"secrets/", "conf/db.yml", "café.txt"}, HooksPath: ".hooks"}
	cases := []struct {
		path string
		host Host
		want Class
	}{
		{"src/main.go", linux, Apply},
		{"README.md", apfs, Apply},
		{"docs/.gitattributes", linux, Attributes},
		{".gitattributes", apfs, Attributes},
		// rule 1: masked
		{".env", linux, Quarantine}, {".ENV", apfs, Quarantine}, {".env", ntfs, Quarantine}, {".env.", ntfs, Quarantine},
		{"sub/.env", linux, Apply},
		{"prod-openrc.sh", linux, Quarantine}, {".kube/config", linux, Quarantine}, {".KUBE/config", apfs, Quarantine},
		{"secrets/a", linux, Quarantine}, {"Secrets/a", apfs, Quarantine}, {"Secrets/a", linux, Apply},
		{"conf/db.yml", linux, Quarantine}, {"conf/db.yml/x", linux, Quarantine}, {"conf/other.yml", linux, Apply},
		{"café.txt", apfs, Quarantine},
		// rule 2: exec vectors
		{".git/hooks/pre-commit", linux, Quarantine}, {".GIT/hooks/pre-commit", apfs, Quarantine},
		{".git/hooKs/pre-commit", apfs, Quarantine}, {".git/config", linux, Quarantine},
		{".git/info/attributes", linux, Quarantine}, {".git/objects/info/alternates", linux, Quarantine},
		{".git/modules/m/config", linux, Quarantine}, {".git/worktrees/w/config.worktree", linux, Quarantine},
		{".gitmodules", linux, Quarantine}, {".pre-commit-config.yaml", linux, Quarantine}, {"lefthook.yml", linux, Quarantine},
		{".lefthook-local.yml", linux, Quarantine}, {".lfsconfig", linux, Quarantine}, {".envrc", linux, Quarantine},
		{".vscode/settings.json", linux, Quarantine}, {"pkg/.idea/x.xml", linux, Quarantine}, {".devcontainer/devcontainer.json", linux, Quarantine},
		{".husky/pre-commit", linux, Quarantine}, {".hooks/pre-push", linux, Quarantine}, {".HOOKS/pre-push", apfs, Quarantine},
		{".claude/settings.json", linux, Quarantine}, {".claude/settings.local.json", linux, Quarantine}, {".claude/hooks/x.sh", linux, Quarantine},
		{".claude/commands/x.md", linux, Apply},
		{".lfscon\ufb01g", apfs, Quarantine}, {".git/con\ufb01g", apfs, Quarantine}, {"\u00dfecrets/a", apfs, Apply},
		{"\u017Fecrets/a", apfs, Quarantine}, {"se\u00dfrets/a", Host{CaseInsensitive: true}, Apply},
		{"vendor/lib/.git/hooks/post-checkout", linux, Quarantine}, {"vendor/lib/.Git/config", apfs, Quarantine},
		// NTFS aliases
		{"GIT~1/hooks/pre-commit", ntfs, Quarantine}, {"file.txt:stream", ntfs, Quarantine}, {".git./hooks/x", ntfs, Quarantine},
		// git state
		{".git/HEAD", linux, Head}, {".git/index", linux, Index}, {".git/packed-refs", linux, PackedRefs},
		{".git/refs/heads/feature/x", linux, Ref}, {".git/refs/tags/v1", linux, Quarantine}, {".git/refs/remotes/origin/main", linux, Quarantine},
		{".git/refs/heads/café", apfs, Quarantine},
		{".git/index.lock", linux, Local}, {".git/refs/heads/main.lock", linux, Local}, {".git/MERGE_HEAD", linux, Local},
		{".git/rebase-merge/done", linux, Local}, {".git/sequencer/todo", linux, Local},
		{".git/FETCH_HEAD", linux, Quarantine}, {".git/ORIG_HEAD", linux, Quarantine}, {".git/logs/HEAD", linux, Quarantine}, {".git/shallow", linux, Quarantine},
		{".git/objects/ab/" + "0123456789012345678901234567890123456789"[:38], linux, Object},
		{".git/objects/pack/pack-1234.pack", linux, Object}, {".git/objects/pack/pack-1234.idx", linux, Object},
		{".git/objects/ab/short", linux, Quarantine}, {".git/objects/AB/" + "0123456789012345678901234567890123456789"[:38], linux, Quarantine},
		{".git/description", linux, Quarantine}, {".git/COMMIT_EDITMSG", linux, Quarantine},
	}
	for _, c := range cases {
		got, err := Classify(c.path, c.host, repo)
		if got != c.want {
			t.Errorf("%q on %+v: %v (%v), want %v", c.path, c.host, got, err, c.want)
		}
	}
}

func TestCleanPath(t *testing.T) {
	for _, bad := range []string{"", "/etc/passwd", "a/../b", "../x", "a//b", "./a", "a/.", `a\b`, "a\x00b", "a\nb", "\xff", "a/" + string(make([]byte, 256))} {
		if _, err := CleanPath(bad, linux); err == nil {
			t.Errorf("%q accepted", bad)
		}
		if c, _ := Classify(bad, linux, Repo{}); c != Quarantine {
			t.Errorf("%q classified %v", bad, c)
		}
	}
	for _, bad := range []string{"a.", "a ", "a:b", "a?b", `a"b`} {
		if _, err := CleanPath(bad, ntfs); err == nil {
			t.Errorf("%q accepted on NTFS", bad)
		}
	}
	if _, err := CleanPath("dir/file with spaces.txt", ntfs); err != nil {
		t.Error(err)
	}
}

func TestKey(t *testing.T) {
	for _, c := range [][2]string{{"HOOKS", "hooks"}, {"hoo\u212As", "hooks"}, {"\u017Fettings", "settings"}, {"cafe\u0301", "caf\u00e9"}, {"\u1100\u1161", "\uac00"}} {
		if apfs.key(c[0]) != apfs.key(c[1]) {
			t.Errorf("APFS: %q and %q should alias", c[0], c[1])
		}
	}
	if linux.key("HOOKS") == linux.key("hooks") {
		t.Error("ext4 is case-sensitive")
	}
	if !shortName("GIT~1") || !shortName("PROGR~12.TXT") || shortName("a~b") || shortName("~1") {
		t.Error("short names")
	}
}

// TestKeyCoversHostAliases asks the file system the test runs on which spellings it treats as the
// same name, and checks that the key for this kind of host never tells two such spellings apart
// (it may join more). On macOS (APFS) and Windows (NTFS) this tests the real aliasing rules.
func TestKeyCoversHostAliases(t *testing.T) {
	host := map[string]Host{"darwin": apfs, "windows": ntfs, "linux": linux}[runtime.GOOS]
	pairs := [][2]string{{"hooks", "hooKs"}, {"settings", "ſettings"}, {"café", "café"},
		{"가", "가"}, {"semi;", "semi;"}, {"HOOKS", "hooks"}, {"Å", "Å"}, {"k", "K"},
		{"ß", "ss"}, {"İ", "i"}, {"Σ", "ς"}, {"ﬁ", "fi"}, {"git.", "git"}, {"git ", "git"}, {"x́̂", "x̂́"}}
	dir := t.TempDir()
	for i, p := range pairs {
		d := filepath.Join(dir, fmt.Sprint(i))
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(d, p[0]), 0o755); err != nil {
			continue // a name this file system cannot hold
		}
		_, err := os.Stat(filepath.Join(d, p[1]))
		alias := err == nil
		if alias && host.key(p[0]) != host.key(p[1]) {
			t.Errorf("%s: %+q and %+q are the same name here, but their keys differ (%+q, %+q)", runtime.GOOS, p[0], p[1], host.key(p[0]), host.key(p[1]))
		}
		t.Logf("%+q %+q alias=%v", p[0], p[1], alias)
	}
}
