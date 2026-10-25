#!/bin/sh
# Package pre-install script for previewd (nfpm.yaml), run as root by dpkg
# (preinst install|upgrade) and rpm (%pre) before any file is unpacked.
# Fail fast: a host that cannot run previewd is refused here, with the
# reason, instead of getting a package whose daemon refuses to start. A
# non-zero exit aborts the apt/dnf transaction and installs nothing.
#
# It checks what the package cannot supply and the daemon cannot run
# without; it installs, starts and changes nothing. The finer host controls
# (build cgroup limits, egress filter, ramfs, clock) are `previewd doctor`.
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin

fail() {
	echo "previewd: $*" >&2
	echo "previewd: installation aborted, nothing was installed." >&2
	exit 1
}

# Docker Engine: the daemon drives it through the Engine API, and
# previewd-proxy.service and the dockerd drop-in need both binaries. The
# package declares no dependency (nfpm.yaml), so the check is here.
command -v dockerd >/dev/null 2>&1 ||
	fail "Docker Engine is not installed (dockerd not found). Install it first, offline if need be: docs/deployment.md, section 1."
command -v docker >/dev/null 2>&1 ||
	fail "the docker command is not installed (docker-ce-cli). Install Docker Engine first: docs/deployment.md, section 1."

# cgroup v2: bounded builds (previewd-builds.slice) and the build probe need
# the unified hierarchy; on cgroup v1 systemd enforces none of the limits.
# Its mount is the only file system of type cgroup2fs at /sys/fs/cgroup.
fstype=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null || true)
[ "$fstype" = cgroup2fs ] ||
	fail "cgroup v2 is required: /sys/fs/cgroup is '${fstype:-missing}', not cgroup2fs. Boot with systemd.unified_cgroup_hierarchy=1 (docs/deployment.md, section 1)."
