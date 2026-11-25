// Package sizing is the appliance VM's CPU, memory, and disk (design 5.3.3: "from host RAM/CPU;
// logic from lib/resources.sh"): lima_vm_cpus, lima_vm_memory_gib, and lima_vm_disk_gib. v2
// applied the host-relative defaults on macOS only; v3 runs its VM on every host, so they apply
// everywhere.
package sizing

import (
	"fmt"
	"strconv"
)

// The defaults of lib/resources.sh.
const (
	DefaultDiskGiB     = 60
	HostReserveCPUs    = 2
	HostReserveMemGiB  = 6
	MinCPUs            = 4
	MinMemGiB          = 8
	hostMemHeadroomGiB = 2 // always left to the host OS
)

// Overrides are the operator's explicit values (install --vm-cpus, --vm-memory, --vm-disk); an
// empty string means "derive from the host".
type Overrides struct{ CPUs, MemoryGiB, DiskGiB string }

// uint parses a whole non-negative decimal at least min, as _resources_require_uint checked it.
func uint(name, v string, min int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || strconv.Itoa(n) != trimZeros(v) {
		return 0, fmt.Errorf("%s must be a whole non-negative integer (got: '%s')", name, v)
	}
	if n < min {
		return 0, fmt.Errorf("%s must be >= %d (got: '%s')", name, min, v)
	}
	return n, nil
}

// trimZeros drops leading zeros (the bash read 010 as 10, with 10#).
func trimZeros(v string) string {
	for len(v) > 1 && v[0] == '0' {
		v = v[1:]
	}
	return v
}

// CPUs is lima_vm_cpus: the override, else host CPUs less the reserve, at least MinCPUs but never
// more than the host has; MinCPUs when the host count is unknown (0).
func CPUs(o Overrides, hostCPUs int) (int, error) {
	if o.CPUs != "" {
		return uint("--vm-cpus", o.CPUs, 1)
	}
	if hostCPUs <= 0 {
		return MinCPUs, nil
	}
	n := hostCPUs - HostReserveCPUs
	if n < MinCPUs {
		n = min(MinCPUs, hostCPUs)
	}
	return min(n, hostCPUs), nil
}

// MemoryGiB is lima_vm_memory_gib: the override, else host RAM less the reserve, at least
// MinMemGiB but always leaving 2 GiB to the host, and at least 1; MinMemGiB when unknown.
func MemoryGiB(o Overrides, hostGiB int) (int, error) {
	if o.MemoryGiB != "" {
		return uint("--vm-memory", o.MemoryGiB, 1)
	}
	if hostGiB <= 0 {
		return MinMemGiB, nil
	}
	n := hostGiB - HostReserveMemGiB
	ceiling := hostGiB - hostMemHeadroomGiB
	if n < MinMemGiB {
		n = min(MinMemGiB, ceiling)
	}
	n = min(n, ceiling)
	return max(n, 1), nil
}

// DiskGiB is lima_vm_disk_gib: the override or 60.
func DiskGiB(o Overrides) (int, error) {
	if o.DiskGiB == "" {
		return DefaultDiskGiB, nil
	}
	return uint("--vm-disk", o.DiskGiB, 1)
}
