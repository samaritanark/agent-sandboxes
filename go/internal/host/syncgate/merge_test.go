package syncgate

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func id(n byte) []byte { return bytes.Repeat([]byte{n}, 20) }

func ent(p string, n byte) Entry { return Entry{Path: p, Mode: 0o100644, ID: id(n)} }

func TestMergeIndex(t *testing.T) {
	have := map[byte]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true}
	hasObject := func(b []byte) bool { return have[b[0]] }
	base := []Entry{ent("a", 1), ent("b", 1), ent("c", 1), ent("d", 1), ent("e", 1), ent(".env", 1), ent("f", 1), ent("g", 1)}
	host := []Entry{ent("a", 2), ent("b", 1), ent("c", 3), ent("d", 1), ent("e", 1), ent(".env", 1), ent("f", 1), ent("g", 1), ent("h", 5)}
	vm := []Entry{ent("a", 1), ent("b", 2), ent("c", 4), ent("e", 1), ent(".env", 6), ent("f", 9),
		{Path: "g", Mode: 0o120000, ID: id(2)}, ent("h", 5), ent("new", 3), {Path: "sub", Mode: 0o160000, ID: id(1)},
		{Path: "x", Stage: 1, Mode: 0o100644, ID: id(1)}, {Path: "x", Stage: 2, Mode: 0o100644, ID: id(2)},
		{Path: "ita", Mode: 0o100644, ID: id(99), IntentToAdd: true}}
	r := MergeIndex(base, host, vm, Host{}, Repo{}, hasObject)
	got := map[string]string{}
	for _, e := range r.Entries {
		got[fmt.Sprintf("%s/%d", e.Path, e.Stage)] = fmt.Sprintf("%o:%d", e.Mode, e.ID[0])
	}
	want := map[string]string{
		"a/0": "100644:2", // host change kept
		"b/0": "100644:2", // VM change taken
		"c/0": "100644:3", // both changed: host wins
		// d deleted in the VM: taken
		"e/0":    "100644:1",
		".env/0": "100644:1", // masked: withheld
		"f/0":    "100644:1", // object not on the host: withheld
		"g/0":    "100644:1", // type change: withheld
		"h/0":    "100644:5", // both added the same
		"new/0":  "100644:3",
		"x/1":    "100644:1", "x/2": "100644:2", // conflict stages travel
		"ita/0": "100644:99", // intent-to-add carries no content to check
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged %v\n   want %v", got, want)
	}
	var withheld []string
	for _, n := range r.Withheld {
		withheld = append(withheld, n.Path)
	}
	if !reflect.DeepEqual(withheld, []string{".env", "f", "g", "sub"}) {
		t.Errorf("withheld %v", r.Withheld)
	}
	if len(r.Conflicts) != 1 || r.Conflicts[0].Path != "c" {
		t.Errorf("conflicts %v", r.Conflicts)
	}
	if _, err := WriteIndex(r.Entries, 20); err != nil {
		t.Errorf("merged index does not write: %v", err)
	}
	// resolving a conflict in the VM (stages 1-3 to stage 0) is one change to the path
	base2 := []Entry{{Path: "x", Stage: 1, Mode: 0o100644, ID: id(1)}, {Path: "x", Stage: 2, Mode: 0o100644, ID: id(2)}}
	r2 := MergeIndex(base2, base2, []Entry{ent("x", 3)}, Host{}, Repo{}, hasObject)
	if len(r2.Entries) != 1 || r2.Entries[0].Stage != 0 || r2.Entries[0].ID[0] != 3 {
		t.Errorf("resolution: %v", r2.Entries)
	}
	// the flags a VM sets do not count as a change, so they cannot be carried
	sw := ent("b", 1)
	sw.SkipWorktree = true
	r3 := MergeIndex([]Entry{ent("b", 1)}, []Entry{ent("b", 1)}, []Entry{sw}, Host{}, Repo{}, hasObject)
	if r3.Entries[0].SkipWorktree {
		t.Error("skip-worktree from the VM was carried")
	}
}
