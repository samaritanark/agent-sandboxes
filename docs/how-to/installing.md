# Installing

[← Documentation](../index.md)

v3 has two parts: the `sandbox` host binary on your machine, and an appliance
VM that runs everything else (the policy layer, `sandboxd`, the agents' Kata
microVMs, and each session's gateway). `sandbox install` creates the VM from an
appliance image.

There are no signed release images yet, so you build the image yourself and
install it with `--dev-image`. Coming from v2? Read
[Upgrading from v2](upgrading-from-v2.md) first; the install below also carries
a v2 install over.

## 1. Check the requirements

- **macOS 15 or later on Apple M3 or later** with [vfkit](https://github.com/crc-org/vfkit)
  (`brew install vfkit`).
- **Linux on arm64 or x86_64** with `qemu-system-<arch>` and access to
  `/dev/kvm` (your user in the `kvm` group).
- At least 4 CPUs and 8 GiB of memory to give the VM, and 60 GiB of disk.
- Go 1.27 to build the host binary.

Windows is not available in v3 yet. See
[Platform requirements](../reference/platform-requirements.md).

## 2. Build the host binary

```bash
cd go
go build -o ~/bin/sandbox ./cmd/sandbox    # any directory on your PATH
```

`bin/sandbox` in the checkout is v2's bash script, not v3, even on the v3
branch. If v2's setup put the checkout's `bin/` on your PATH, make sure the
binary you just built is the one `sandbox` runs: build it into a directory that
comes first on your PATH, run `hash -r`, and check with
`file "$(command -v sandbox)"` (an executable, not a shell script). Coming from
v2, see [Upgrading from v2](upgrading-from-v2.md#first-make-sandbox-the-v3-command)
first; to keep both, name this one `sandbox3`.

## 3. Build the appliance image

The image is built on Linux, as root, with mkosi v27.1
([image/README.md](../../image/README.md) lists the tools):

```bash
sudo image/build.sh 3.0.0-dev.1
# writes image/mkosi.output/sandbox-appliance.raw (and .qcow2 for --driver lima)
```

On a Mac, build it in a Linux Lima VM set up the same way (mkosi in
`/opt/mkosi`, Go in `/usr/local/go`). `image/build-in-lima.sh` copies the
repository's tracked files into the VM, builds, and copies the image back:

```bash
image/build-in-lima.sh <lima-vm-name> 3.0.0-dev.1 ~/sandbox-appliance.raw
```

The image is built for the build machine's architecture. A build takes about
15 minutes.

## 4. Install

```bash
sandbox install --dev-image ~/sandbox-appliance.raw
```

`install` warns that a development image's signature is not checked. It then:

1. Sizes the VM from the host: CPUs less 2 (at least 4), memory less 6 GiB
   (at least 8 GiB), and a 60 GiB state disk.
2. Makes the VM's SSH keys and its seed in `~/.sandbox/vm/`, including your
   extra CA certificates (`~/.sandbox/extra-ca-certs/`).
3. Creates the credential broker's store key and keeps it in your login
   keychain (macOS, item `agent-sandboxes broker key`) or in
   `~/.sandbox/broker.key`, mode 0600 (Linux).
4. Boots the VM, waits until it answers, and pushes the broker key.
5. Looks for a v2 install and carries it over (see
   [Upgrading from v2](upgrading-from-v2.md)); `--skip-v2-migration` skips this.

Options:

| Option | Effect |
|---|---|
| `--vm-cpus <n>` | VM CPUs |
| `--vm-memory <GiB>` | VM memory (at least 8). A session's agent gets up to 6 GiB; on an 8 GiB VM it gets about 5.25 GiB, and dependencies need more room |
| `--vm-disk <GiB>` | VM state disk |
| `--driver <name>` | `vfkit` (macOS) or `qemu` (Linux), the defaults; or `lima` |
| `--vfkit`, `--qemu`, `--limactl <path>` | The binary to use (default: on PATH) |
| `--skip-v2-migration` | Leave a v2 install for `sandbox migrate` |

With `vfkit` and `qemu` the VM's only network is `sandbox netd`, a part of the
host binary that runs beside the VM: it refuses every connection from the VM to
your machine's own addresses (loopback, LAN, the gateway), and the VM fails
closed if netd stops. `--driver lima` uses Lima's network instead, which cannot
block your machine's LAN address; use it only if the others don't work for you.

Behind a TLS-intercepting proxy? Run `sandbox setup-proxy-cert` before
installing; see [TLS-intercept proxies](tls-intercept-proxies.md).

## 5. Check the install

```bash
sandbox doctor
```

`doctor` checks the driver, netd, that the VM answers and its version, nested
virtualization in the VM (`/dev/kvm`, which Kata needs), and that the VM cannot
reach your machine. Every line should say `ok`.

## 6. Build the agent images

The agents' container images are built in the VM, from the network:

```bash
sandbox rebuild --agent base       # needed by all the others
sandbox rebuild --agent claude     # and codex, opencode as you need them
```

See [Rebuilding images](rebuilding-images.md). Then
[sign the agents in](onboarding-agents.md) and start
[your first session](../tutorials/first-session.md).

## Running the VM

```bash
sandbox vm status    # the VM's state and image version (also: sandbox status)
sandbox vm stop      # stop it (sessions stop with it)
sandbox vm start     # start it again; also restarts netd if it died
sandbox vm shell     # a root shell in the VM, for debugging (recorded in ~/.sandbox/logs/vm-shell.log)
```

Any command that needs the VM tells you when it is stopped. The VM keeps its
state (workspace copies, agent history, the credential broker's store) across
stops; the broker's key is pushed again at every start.

## Related

- [Uninstalling](uninstalling.md)
- [Updating the sandbox](updating-the-cli.md)
- [Platform requirements](../reference/platform-requirements.md)
