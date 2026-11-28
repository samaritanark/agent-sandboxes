package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMirror(t *testing.T) {
	root := t.TempDir()
	cp := "/var/lib/sandbox/workspaces/0123456789abcdef"
	if err := mirror(root, "/Users/op/.sandbox", OperatorDir); err != nil {
		t.Fatal(err)
	}
	if err := mirror(root, "/Users/op/code/app", cp); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(filepath.Join(root, "Users/op/code/app")); got != cp {
		t.Errorf("link %q", got)
	}
	// a Fedora Atomic home in /var/home
	if err := mirror(root, "/var/home/op/code/app", cp); err != nil {
		t.Errorf("/var/home: %v", err)
	}
	// again: kept
	if err := mirror(root, "/Users/op/code/app", cp); err != nil {
		t.Errorf("repeat: %v", err)
	}
	os.MkdirAll(filepath.Join(root, "Users/op/real"), 0o755)
	os.Symlink("/etc", filepath.Join(root, "Users/op/steer"))
	for name, c := range map[string][2]string{
		"a system path":         {"/etc/x", cp},
		"var":                   {"/var/lib/sandbox/operator/x", cp},
		"var/home itself":       {"/var/home", cp},
		"var/home/":             {"/var/home/", cp},
		"root itself":           {"/x", cp},
		"relative":              {"Users/op/x", cp},
		"unclean":               {"/Users/op/../op/x", cp},
		"another target":        {"/Users/op/x", "/etc"},
		"a near-copy":           {"/Users/op/x", cp + "0"},
		"an existing directory": {"/Users/op/real", cp},
		"a link elsewhere":      {"/Users/op/code/app", "/var/lib/sandbox/workspaces/fedcba9876543210"},
		"through a link":        {"/Users/op/steer/x", cp},
	} {
		if err := mirror(root, c[0], c[1]); err == nil {
			t.Errorf("%s: mirrored", name)
		}
	}
	if _, err := os.Lstat(filepath.Join("/etc", "x")); err == nil {
		t.Log("(/etc/x exists on this machine; not ours)")
	}
}
