package sizing

import "testing"

// The expectations were taken from lib/resources.sh's lima_vm_cpus and lima_vm_memory_gib with
// _host_cpus and _host_mem_gib stubbed (bash 5.2, 2026-11-25).
func TestCPUs(t *testing.T) {
	for host, want := range map[int]int{0: 4, 1: 1, 2: 2, 3: 3, 4: 4, 5: 4, 6: 4, 7: 5, 10: 8, 16: 14, 64: 62} {
		if got, err := CPUs(Overrides{}, host); err != nil || got != want {
			t.Errorf("host %d: %d %v, want %d", host, got, err, want)
		}
	}
}

func TestMemory(t *testing.T) {
	for host, want := range map[int]int{0: 8, 1: 1, 2: 1, 3: 1, 4: 2, 8: 6, 10: 8, 12: 8, 14: 8, 15: 9, 16: 10, 32: 26, 128: 122} {
		if got, err := MemoryGiB(Overrides{}, host); err != nil || got != want {
			t.Errorf("host %d GiB: %d %v, want %d", host, got, err, want)
		}
	}
}

func TestOverrides(t *testing.T) {
	if n, err := CPUs(Overrides{CPUs: "12"}, 4); n != 12 || err != nil {
		t.Errorf("cpus override: %d %v", n, err)
	}
	if n, err := MemoryGiB(Overrides{MemoryGiB: "010"}, 4); n != 10 || err != nil {
		t.Errorf("leading zero: %d %v", n, err)
	}
	if n, err := DiskGiB(Overrides{}); n != 60 || err != nil {
		t.Errorf("disk default: %d %v", n, err)
	}
	for _, bad := range []string{"0", "-1", "x", "1.5", " 2", "2 ", "a[$(id)]", "99999999999999999999999"} {
		if _, err := CPUs(Overrides{CPUs: bad}, 8); err == nil {
			t.Errorf("cpus %q accepted", bad)
		}
		if _, err := DiskGiB(Overrides{DiskGiB: bad}); err == nil {
			t.Errorf("disk %q accepted", bad)
		}
	}
}
