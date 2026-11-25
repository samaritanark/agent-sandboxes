//go:build windows

package hostbin

import "errors"

// Verify: Windows has no driver tool yet; its driver is decided by spike S3 (design 5.2.2).
func Verify(name, p string, uid int) error {
	return errors.New(name + " is not supported on Windows (design 5.2.2: Hyper-V or lima-hcs, spike S3)")
}
