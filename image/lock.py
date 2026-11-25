#!/usr/bin/env python3
"""The appliance image's package lockfile (owner decision 6, S8): every .deb the build installs,
with its version and SHA-256, for each architecture, installed from a local repository built from
the lock. The lock, not apt's signature, is what the build trusts: a package whose hash differs is
refused, wherever it came from.

  lock.py names DEBDIR > names.txt
      The package names in a build's apt cache (a fresh, unlocked build: image and initrd).
  lock.py resolve --arch ARCH NAMES.txt > packages.ARCH.lock
      Resolve those names for ARCH against Ubuntu's signed indexes (apt verifies them) and write
      the lock: one "name version arch sha256 size path" line per package.
  lock.py repo --lock LOCK --out DIR
      Fetch every locked .deb (the archive, then Launchpad's permanent file URLs once the archive
      drops a superseded version), check its size and SHA-256, and write an unsigned flat
      repository at DIR for mkosi's --local-mirror (suite noble, component main).

Standard library only; resolve also runs apt-get (in a scratch directory, as any user).
"""

import argparse
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

SUITE = "noble"
POCKETS = ["noble", "noble-updates", "noble-security"]
COMPONENTS = ["main", "universe"]
MIRRORS = {"amd64": "http://archive.ubuntu.com/ubuntu", "arm64": "http://ports.ubuntu.com/ubuntu-ports"}
LAUNCHPAD = "https://launchpad.net/ubuntu/+archive/primary/+files/"
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
LINE_RE = re.compile(r"^([a-z0-9][a-z0-9+.-]+) (\S+) (amd64|arm64|all) ([0-9a-f]{64}) ([0-9]+) (pool/[A-Za-z0-9+._/~-]+\.deb)$")


def die(msg):
    sys.exit("lock.py: " + msg)


def cmd_names(args):
    names = set()
    for root, _, files in os.walk(args.debdir):
        for f in files:
            if f.endswith(".deb"):
                n = subprocess.run(["dpkg-deb", "-f", os.path.join(root, f), "Package"],
                                   check=True, capture_output=True, text=True).stdout.strip()
                if not NAME_RE.match(n):
                    die(f"bad package name {n!r} in {f}")
                names.add(n)
    if not names:
        die(f"no .deb files under {args.debdir}")
    for n in sorted(names):
        print(n)


def cmd_resolve(args):
    arch = args.arch
    if arch not in MIRRORS:
        die(f"unsupported architecture {arch}")
    names = [l.strip() for l in open(args.names) if l.strip() and not l.startswith("#")]
    for n in names:
        if not NAME_RE.match(n):
            die(f"bad package name {n!r}")
    tmp = tempfile.mkdtemp(prefix="sandbox-lock-")
    try:
        for d in ["etc/apt/preferences.d", "etc/apt/apt.conf.d", "etc/apt/sources.list.d",
                  "var/lib/apt/lists/partial", "var/cache/apt/archives/partial", "var/lib/dpkg"]:
            os.makedirs(os.path.join(tmp, d))
        open(os.path.join(tmp, "var/lib/dpkg/status"), "w").close()
        with open(os.path.join(tmp, "etc/apt/sources.list.d/ubuntu.sources"), "w") as f:
            f.write(f"Types: deb\nURIs: {MIRRORS[arch]}\nSuites: {' '.join(POCKETS)}\n"
                    f"Components: {' '.join(COMPONENTS)}\nSigned-By: {KEYRING}\n")
        opts = ["-o", f"Dir={tmp}", "-o", f"Dir::State::status={tmp}/var/lib/dpkg/status",
                "-o", f"APT::Architecture={arch}", "-o", f"APT::Architectures::={arch}",
                "-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Debug::NoLocking=true",
                "-o", "APT::Install-Recommends=false", "-o", "Acquire::Languages=none"]
        subprocess.run(["apt-get", *opts, "-qq", "update"], check=True)
        out = subprocess.run(["apt-get", *opts, "-qq", "--print-uris", "-y", "install", *names],
                             check=True, capture_output=True, text=True).stdout
        index = read_indexes(os.path.join(tmp, "var/lib/apt/lists"))
    finally:
        shutil.rmtree(tmp)
    lines = []
    for l in out.splitlines():
        m = re.match(r"^'(\S+)' (\S+) ([0-9]+) \S+$", l)
        if not m:
            continue
        url, fname, size = m.groups()
        path = urllib.parse.unquote(urllib.parse.urlparse(url).path)
        i = path.find("/pool/")
        if i < 0:
            die(f"unexpected URL {url}")
        pool = path[i + 1:]
        if pool not in index:
            die(f"{pool} is not in the signed indexes")
        name, version, a, sha, isize = index[pool]
        if isize != int(size):
            die(f"{pool}: apt and the index disagree on its size")
        lines.append(f"{name} {version} {a} {sha} {size} {pool}")
    if len(lines) < len(names):
        die(f"resolved {len(lines)} packages for {len(names)} names")
    print(f"# The appliance image's packages for {arch} (image/lock.py; design 5.3.2, S8 item 6).")
    print("# name version arch sha256 size path; fetched from " + MIRRORS[arch] + " or " + LAUNCHPAD)
    for l in sorted(lines):
        print(l)


def read_indexes(lists):
    """Filename -> (Package, Version, Architecture, SHA256, Size) from apt's downloaded indexes
    (apt has checked them against the archive's signed Release files)."""
    index = {}
    for f in os.listdir(lists):
        if "_Packages" not in f:
            continue
        p = os.path.join(lists, f)
        opener = gzip.open if f.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for stanza in text.split("\n\n"):
            fields = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", stanza, re.M))
            if all(k in fields for k in ("Filename", "Package", "Version", "Architecture", "SHA256", "Size")):
                index[fields["Filename"]] = (fields["Package"], fields["Version"], fields["Architecture"],
                                             fields["SHA256"], int(fields["Size"]))
    if not index:
        die("no package indexes downloaded")
    return index


def read_lock(path):
    entries = []
    for n, l in enumerate(open(path), 1):
        l = l.rstrip("\n")
        if not l or l.startswith("#"):
            continue
        m = LINE_RE.match(l)
        if not m:
            die(f"{path} line {n}: malformed")
        name, version, arch, sha, size, pool = m.groups()
        if ".." in pool.split("/"):
            die(f"{path} line {n}: bad path")
        entries.append((name, version, arch, sha, int(size), pool))
    if not entries:
        die(f"{path}: empty")
    return entries


def fetch(url, dest, sha, size):
    """Download url to dest; keep it only if its size and SHA-256 match."""
    h = hashlib.sha256()
    n = 0
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=60) as r, open(tmp, "wb") as f:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                n += len(b)
                if n > size:
                    raise ValueError("larger than locked")
                h.update(b)
                f.write(b)
    except Exception as e:  # noqa: BLE001 - try the next source
        if os.path.exists(tmp):
            os.unlink(tmp)
        return str(e)
    if n != size or h.hexdigest() != sha:
        os.unlink(tmp)
        return "size or SHA-256 differs from the lock"
    os.rename(tmp, dest)
    return None


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def cmd_repo(args):
    entries = read_lock(args.lock)
    archs = {e[2] for e in entries} - {"all"}
    if len(archs) != 1:
        die("a lock holds one architecture")
    arch = archs.pop()
    store = os.path.join(args.out, "pool")
    os.makedirs(store, exist_ok=True)
    keep = set()
    stanzas = []
    for name, version, a, sha, size, pool in entries:
        base = os.path.basename(pool)
        dest = os.path.join(store, base)
        keep.add(base)
        if not (os.path.exists(dest) and os.path.getsize(dest) == size and sha256_file(dest) == sha):
            errs = []
            for url in (MIRRORS[arch] + "/" + pool, LAUNCHPAD + urllib.parse.quote(base)):
                err = fetch(url, dest, sha, size)
                if err is None:
                    break
                errs.append(f"{url}: {err}")
            else:
                die(f"cannot fetch {name} {version}:\n  " + "\n  ".join(errs))
        control = subprocess.run(["dpkg-deb", "-f", dest], check=True, capture_output=True, text=True).stdout
        fields = dict(re.findall(r"^(Package|Version|Architecture): (.*)$", control, re.M))
        if (fields.get("Package"), fields.get("Version"), fields.get("Architecture")) != (name, version, a):
            die(f"{base}: its control file does not match the lock")
        stanzas.append(control.rstrip("\n") + f"\nFilename: pool/{base}\nSize: {size}\nSHA256: {sha}\n")
    for f in os.listdir(store):  # nothing but the locked packages
        if f not in keep:
            os.unlink(os.path.join(store, f))
    bdir = os.path.join(args.out, "dists", SUITE, "main", f"binary-{arch}")
    os.makedirs(bdir, exist_ok=True)
    packages = "\n".join(stanzas).encode()
    with open(os.path.join(bdir, "Packages"), "wb") as f:
        f.write(packages)
    with gzip.GzipFile(os.path.join(bdir, "Packages.gz"), "wb", mtime=0) as f:
        f.write(packages)
    rel = [f"Suite: {SUITE}", f"Codename: {SUITE}", "Components: main", f"Architectures: {arch} all", "SHA256:"]
    for fn in ("Packages", "Packages.gz"):
        p = os.path.join(bdir, fn)
        rel.append(f" {sha256_file(p)} {os.path.getsize(p)} main/binary-{arch}/{fn}")
    with open(os.path.join(args.out, "dists", SUITE, "Release"), "w") as f:
        f.write("\n".join(rel) + "\n")
    print(f"lock.py: {len(entries)} locked packages for {arch} in {args.out}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("names")
    s.add_argument("debdir")
    s = sub.add_parser("resolve")
    s.add_argument("--arch", required=True)
    s.add_argument("names")
    s = sub.add_parser("repo")
    s.add_argument("--lock", required=True)
    s.add_argument("--out", required=True)
    a = p.parse_args()
    {"names": cmd_names, "resolve": cmd_resolve, "repo": cmd_repo}[a.cmd](a)


if __name__ == "__main__":
    main()
