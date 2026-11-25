package syncengine

import "testing"

func TestPerWorktree(t *testing.T) {
	for rel, want := range map[string]bool{
		"HEAD": true, "index": true, "ORIG_HEAD": true, "MERGE_HEAD": true, "rebase-merge/done": true,
		"logs/HEAD": true, "refs/bisect/bad": true, "refs/worktree/x": true, "refs/rewritten/y": true,
		"info/sparse-checkout": true, "config.worktree": true,
		"objects/ab/cd": false, "refs/heads/main": false, "refs/tags/v1": false, "packed-refs": false,
		"config": false, "hooks/pre-commit": false, "info/exclude": false, "logs/refs/heads/main": false,
		"worktrees/w/HEAD": false, "shallow": false, "refs/bisectx": false,
	} {
		if perWorktree(rel) != want {
			t.Errorf("%s: per-worktree %v, want %v", rel, !want, want)
		}
	}
}
