//go:build windows

package lima

import "errors"

// VerifyBinary: Windows has no Lima driver yet; its driver is decided by spike S3 (design 5.2.2).
func VerifyBinary(p string, uid int) error {
	return errors.New("the Lima driver is not supported on Windows (design 5.2.2: Hyper-V or lima-hcs, spike S3)")
}
