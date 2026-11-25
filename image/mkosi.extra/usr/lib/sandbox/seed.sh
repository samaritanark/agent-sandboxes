#!/bin/bash
# Apply /etc/sandbox/seed.env (written by Lima from the host's seed, design 5.3.3): install the
# pinned SSH host key and root's authorized key, add the operator's CAs, then start sshd. Runs on
# every boot (Lima rewrites the seed each time); every step is idempotent.
set -euo pipefail
seed=/etc/sandbox/seed.env
[[ -f "${seed}" && ! -L "${seed}" ]] || { echo "no seed" >&2; exit 1; }

get() { # the value of KEY in the seed, exactly as written; no shell evaluation
  local k="$1" line
  while IFS= read -r line; do
    [[ "${line}" == "${k}="* ]] && { printf '%s' "${line#*=}"; return 0; }
  done < "${seed}"
  return 0
}

umask 077
install -d -m 0700 /etc/sandbox/ssh /root/.ssh
get SANDBOX_SEED_SSH_HOST_KEY_B64 | base64 -d > /etc/sandbox/ssh/ssh_host_ed25519_key.new
get SANDBOX_SEED_SSH_HOST_KEY_PUB > /etc/sandbox/ssh/ssh_host_ed25519_key.pub.new
printf '\n' >> /etc/sandbox/ssh/ssh_host_ed25519_key.pub.new
# refuse a seed whose private and public keys do not belong together
derived="$(ssh-keygen -y -f /etc/sandbox/ssh/ssh_host_ed25519_key.new | cut -d' ' -f1,2)"
given="$(cut -d' ' -f1,2 < /etc/sandbox/ssh/ssh_host_ed25519_key.pub.new)"
[[ -n "${derived}" && "${derived}" == "${given}" ]] || { echo "seed host key pair does not match" >&2; exit 1; }
mv -f /etc/sandbox/ssh/ssh_host_ed25519_key.new /etc/sandbox/ssh/ssh_host_ed25519_key
mv -f /etc/sandbox/ssh/ssh_host_ed25519_key.pub.new /etc/sandbox/ssh/ssh_host_ed25519_key.pub

key="$(get SANDBOX_SEED_AUTHORIZED_KEY)"
[[ "${key}" == ssh-ed25519\ * ]] || { echo "seed has no client key" >&2; exit 1; }
printf '%s\n' "${key}" > /root/.ssh/authorized_keys.new
mv -f /root/.ssh/authorized_keys.new /root/.ssh/authorized_keys

ca="$(get SANDBOX_SEED_CA_BUNDLE_B64)"
if [[ -n "${ca}" ]]; then
  umask 022
  printf '%s' "${ca}" | base64 -d > /usr/local/share/ca-certificates/sandbox-operator.crt
  update-ca-certificates >/dev/null
fi

# Until now every start of sshd failed for want of its host key (cloud-init restarts it during
# boot), which may have tripped systemd's start limit; clear it before the real start.
systemctl reset-failed ssh.service || true
systemctl restart ssh.service
