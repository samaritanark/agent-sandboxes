package syncgate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/samaritanark/agent-sandboxes/go/internal/yamllist"
)

// RepoMaskedPaths reads the masked_paths: list from the host checkout's own .sandbox/config.yaml
// (the owner's decision, 2026-11-25: the host reads it itself, with the same reader the policy
// layer uses, because the VM's report of the list could be falsified). The file is read through
// os.Root without following a symlink; a symlinked, non-regular, or oversized file is an error, so
// the caller fails closed. A missing file is an empty list.
func RepoMaskedPaths(repo string) ([]string, error) {
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	st, err := root.Lstat(yamllist.RepoConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", yamllist.RepoConfig)
	}
	const max = 1 << 20
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", yamllist.RepoConfig, max)
	}
	f, err := root.Open(yamllist.RepoConfig)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	return yamllist.Extract(b, "masked_paths", false), nil
}
