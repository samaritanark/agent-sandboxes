package sizing

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// HostMemory is the host's physical memory in bytes, or 0 when unknown.
func HostMemory() uint64 {
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseUint(f[1], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	if out, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.memsize").Output(); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64); err == nil {
			return n
		}
	}
	return 0
}
