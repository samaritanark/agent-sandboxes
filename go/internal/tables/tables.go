// Package tables holds rule tables shared by the in-VM policy layer and the host binary's sync gate
// (design 5.1.1 lets the host import shared rule tables): plain data, no logic, no imports.
package tables

// The built-in masked paths (MASKED_* in lib/filesystem.sh), relative to the repo root.
var (
	MaskedFilePaths = []string{".env", ".env.local", ".npmrc", "clouds.yaml", "kubeconfig"}
	MaskedDirPath   = ".kube"
)

// MaskedOpenrcSuffix: a file at the repo root named *-openrc.sh is masked.
const MaskedOpenrcSuffix = "-openrc.sh"
