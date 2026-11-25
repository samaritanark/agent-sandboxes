//go:build windows

package netd

import (
	"errors"
	"fmt"
	"os"
)

// Windows has no netd yet: its VM driver and link are decided by spike S3 (design 5.2.2).
var errWindows = errors.New("sandbox netd is not supported on Windows yet (design 5.2.2, spike S3)")

const EndpointsName = "endpoints"

func Running(string) (bool, error) { return false, errWindows }
func SSHPort(string) (int, error)  { return 0, errWindows }
func PID(string) (int, error)      { return 0, errWindows }

func WorkerMain([]string) int {
	fmt.Fprintln(os.Stderr, errWindows)
	return 1
}
