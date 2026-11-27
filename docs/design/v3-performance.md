# v3 performance on macOS (measured 2026-11-26/27)

[← Design](v3-architecture.md)

The owner's first real v3 session (24 repositories, Claude Code) was unusable: Claude Code took
minutes to start and lagged seconds behind the keyboard. This note records what was measured,
what was changed within the design (no feature or security change), what remains, and the
options that would close the rest of the gap by changing the design. Everything here was
measured on the owner's Apple M6 (macOS 27.3) with v3 test installs (vfkit, 4 CPUs, 8 GiB) and
v2's Lima VM (10 CPUs, 26 GiB), on clones of the owner's own repositories.

## Results

| | v2 (gVisor in Lima) | v3 before (dev.17) | v3 now (dev.20) |
|---|---|---|---|
| 1 repository (narthex, 2.1 GB): launch to attach | 22 s | — | 5.0 s |
| 1 repository: Claude Code's prompt after attach | 0.4 s | minutes | 7.2 s |
| 24 repositories: launch to attach | 32 s | 22.9 s\* | 8.5–9.1 s |
| 24 repositories: Claude Code's prompt after attach | 0.3 s | minutes | 7.1–8.9 s |
| keystroke echo in Claude Code (median) | 8–9 ms | seconds | 39–70 ms |
| host CPU, one idle session | 51% of a core | — | 12.5–15% |
| host CPU, live sync of 24 repositories | (Mutagen) | 88% of a core | a stat walk per pass |

\* Measured on dev.18 with the owner's real narthex, before the secret gate's fix (its scan took 19
s). The v3 numbers are from a 4-CPU, 8 GiB test VM; the owner's VM has 8 CPUs and 16 GiB. Neither
side had a working login (v2's stored token had expired; v3 used a fake one), which adds the same
failed requests to Claude Code's start-up in both. The first launch of a repository into a new VM
copies it (narthex: 20.7 s to attach).

v3 now reaches Claude Code's prompt sooner than v2 (12 s against 22 s for narthex, 16 s against 32 s
for 24 repositories) and idles at a third of its CPU, but the agent itself runs slower: Claude Code
starts in about 7 s instead of 0.4 s, and echoes keys in 39–70 ms instead of 9 ms. v2's gVisor pod,
for comparison: node starts in 36 ms, 300 process starts take 120 ms.

## Why: nested virtualization on Apple silicon

v2 runs the agent under gVisor in the Lima VM: one level of hardware virtualization. v3 runs it
in a Kata microVM inside the appliance VM: two. On this Mac the second level is expensive, and
unevenly so (microVM against a runc container in the same appliance VM):

| | appliance VM (runc) | microVM, stock Kata | microVM, now |
|---|---|---|---|
| start node | ~10 ms | 1.85 s | 0.14–0.28 s |
| fork + exec | 0.5 ms | 37 ms | 1.1–2.3 ms |
| a pure integer loop | 1× | 1.3× | 1.3× |
| a JIT-compiled JS loop (node, default flags) | 1× | 5–7× | 5–7× |
| waking a thread on an idle vCPU (p50) | 0.22 ms | 0.8 ms | 0.06 ms (idle < 5 ms) |
| Claude Code to its prompt | 0.4 s, 1 CPU-s | minutes | ~7 s, ~17 CPU-s |

The stock costs came from three places, each fixed below: every exec re-read the program over
virtio-fs (Kata's `virtio_fs_cache = "auto"` makes the guest drop a file's cache at every open),
the microVM's memory was backed by 4 KiB pages (shared memory never got huge pages), and waking an
idle vCPU went through both hypervisors. What is left is the general cost of nesting for a
JIT-heavy, many-threaded program: Claude Code (Bun) uses about 17 times the CPU it uses in the
appliance VM directly, mostly user time. Turning off Bun's concurrent JIT, pinning it to one CPU,
fewer vCPUs, and the guest's (already minimal) speculation mitigations each changed little.

## Changed (within the design)

None of these changes what a session can reach, read, or do.

1. **virtiofsd keeps a file's cache across opens** (`image/patches/virtiofsd-auto-keep-cache.patch`,
   built by `image/build.sh` from the pinned v1.14.0 source). Under the `auto` policy the guest now
   keeps cached data (`KEEP_CACHE`) and drops it when a file's mtime or size changes
   (`AUTO_INVAL_DATA`, checked after the 1 s attribute timeout); virtiofsd refuses to mount if the
   guest kernel cannot do that. `cache = always` would have been as fast but serves stale data
   after the sync writes a file (measured: an in-place rewrite was never seen). The sync agent
   writes by rename, so the guest sees each synced file as new. Node's start 1.6 s → 23 ms.
2. **Transparent huge pages for the microVMs' memory** (`shmem_enabled = advise`, tmpfiles.d).
   Process start about 5 times faster; no memory is reserved.
3. **KVM halt polling 5 ms** (from 0.5 ms; tmpfiles.d). A thread woken within 5 ms of its vCPU
   idling answers in 0.06 ms instead of 0.8 ms; keystroke echo halved; an idle session costs 0.3%
   more of a host CPU.
4. **The sync's connections no longer fail at a launch, and are made again when they do.** The
   host rewrote its pinned `known_hosts` file in place before every ssh command; with one sync per
   repository starting at once, another ssh could read the file empty, fail host key verification,
   and exit 255 like a dropped connection. In the owner's session 6 of 24 repositories failed that
   way and went unsynced for the whole session. The file is now left alone when it holds the key
   and otherwise replaced by a rename; a sync connection that fails or ends mid-session is made
   again; at most 6 repositories set up a connection at once; and sshd's `MaxStartups` is
   64:30:256 as headroom for overlapping launches (the port is reachable only from the host's
   loopback through netd, and needs the pinned key).
5. **The sync scans faster**: the walk takes each entry's stat data from `ReadDir` (which `os.Root`
   already takes with `fstatat` on the open directory) instead of resolving each path again
   (narthex's walk 950 → 150 ms); the fingerprint cache is kept across runs, on the host in
   `~/.sandbox/sync/<id>/fpcache.json` and in the VM in `/var/lib/sandbox/sync-cache/<id>` (never
   mounted into a microVM), keyed by size, mtime, mode, inode, and change time (no program can set
   the last two); the launch's syncs run at once. A no-change pass over narthex: 4.8 s → 0.4 s.
6. **The secret gate reads each file once per scan** for its encrypted-at-rest check, instead of
   once per finding (a file with many findings cost findings × lines): 24 repositories, 19 → 5 s.
   Output identical (the bash oracle's goldens pass).
7. **Claude Code trusts `/workspace`** when several repositories are mounted under it, as it
   trusts each repository: it asked, and a "no" ended the session.

## Not changed: decisions for the owner

- **A. Scan repositories in parallel in the secret gate.** About 3–4 s off a 24-repository launch.
  The bash stops at the first repository whose scan fails; scanning in parallel makes the later
  repositories' calls and warnings happen anyway (the launch is still refused). A deviation from
  the oracle.
- **B. Run agents under gVisor in the appliance VM on macOS** (Kata stays on Linux, where nesting
  is cheap). v2's speed (prompt 0.4 s, echo 9 ms); the boundary becomes gVisor's user-space kernel
  inside the appliance VM instead of a hardware VM.
- **C. One VM per session on the host** (Virtualization.framework), no nesting. Near the
  appliance-VM numbers with a hardware boundary; the host binary would manage a VM per session, and
  the workspace copies and network would have to reach it.
- **D. runc in the appliance VM.** Fastest, but a container escape reaches the appliance VM (the
  broker, other sessions, the gateway). Not recommended.
- **E. Files over 64 MB are not synced** (`syncproto.MaxBody`): 24 files in narthex (tool binaries
  built for macOS, large logs). v2 showed them. A feature gap, not a performance one.
