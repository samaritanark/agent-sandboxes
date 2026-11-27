// Package runtime is sandboxd's adapter to containerd and Kata (design 5.4.3 item 1, 5.5): it
// creates, starts, and destroys microVMs (Kata with Cloud Hypervisor, io.containerd.kata.v2)
// through containerd's Go client (owner decision, 2026-11-25), or, for a session that asks for it,
// gVisor sandboxes (io.containerd.runsc.v1; owner decision, 2026-11-27). Every one gets the
// workload hardening of 5.5.2 whatever its description says: a non-root user, no capabilities,
// no_new_privs, the default seccomp profile (applied in the guest: the image's Kata configuration
// sets disable_guest_seccomp = false, and its runsc.toml sets oci-seccomp), and its own network
// namespace.
package runtime
