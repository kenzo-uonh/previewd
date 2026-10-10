#!/usr/bin/env bash
# Run a command inside a fresh, unprivileged network namespace that holds
# only the loopback interface. The air gap is verified before the command
# starts; if any interface, route, egress path or daemon socket is reachable,
# the script refuses to run the command (fail closed).
#
# A network namespace does not isolate filesystem Unix sockets: through
# /run/docker.sock a test could ask the host daemon, which lives in the host
# namespace, to pull images or reach the network. A private mount namespace
# hides /run behind an empty tmpfs.
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

if [[ "${PREVIEWD_AIRGAP_INNER:-}" != "1" ]]; then
  # --map-root-user grants CAP_NET_ADMIN over the new namespace only, which is
  # needed to bring loopback up. No host privilege is involved.
  exec unshare --user --map-root-user --net --mount --propagation private -- \
    env PREVIEWD_AIRGAP_INNER=1 "$0" "$@"
fi

# Endpoints that could reach a daemon in the host namespace.
unset DOCKER_HOST DOCKER_CONTEXT CONTAINER_HOST SSH_AUTH_SOCK \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
if [[ -d /var/run && ! -L /var/run ]]; then
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /var/run
fi

for sock in /run/docker.sock /var/run/docker.sock /run/containerd/containerd.sock \
  /run/podman/podman.sock /run/buildkit/buildkitd.sock \
  "${HOME}/.docker/run/docker.sock" "${HOME}/.docker/desktop/docker.sock"; do
  if [[ -e "${sock}" ]]; then
    echo "FATAL: air gap not established: daemon socket reachable: ${sock}" >&2
    exit 1
  fi
done

ip link set lo up

# /sys/class/net reflects the parent namespace until sysfs is remounted;
# netlink (ip) reports the namespace the process actually lives in.
ifaces="$(ip -o link show | awk -F': ' '{print $2}')"
if [[ "${ifaces}" != "lo" ]]; then
  echo "FATAL: air gap not established: interfaces present: ${ifaces//$'\n'/ }" >&2
  exit 1
fi

routes="$(ip route show; ip -6 route show | grep -v '^::1 ' || true)"
if [[ -n "${routes}" ]]; then
  echo "FATAL: air gap not established: routes present:" >&2
  echo "${routes}" >&2
  exit 1
fi

# IP literals: the probe must not depend on DNS to detect an egress path.
for target in 1.1.1.1/443 8.8.8.8/53 140.82.112.3/443; do
  if timeout 5 bash -c "exec 3<>/dev/tcp/${target}" 2>/dev/null; then
    echo "FATAL: air gap not established: egress to ${target} succeeded" >&2
    exit 1
  fi
done

echo "air gap verified: loopback only, no route, egress probes refused, /run masked" >&2
exec "$@"
