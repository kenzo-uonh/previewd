#!/usr/bin/env bash
# CI runner preparation (GitHub-hosted Ubuntu 24.04): allow unshare(1), and
# only unshare(1), to create unprivileged user namespaces, then prove that
# scripts/airgap-exec.sh can build its namespace.
#
# Ubuntu 24.04 sets kernel.apparmor_restrict_unprivileged_userns=1: an
# unconfined process may create a user namespace but holds no capability in
# it, so `ip link set lo up` fails inside. A per-binary AppArmor profile with
# the `userns` permission is the narrow fix; the global sysctl stays on.
#
# Runs as the runner user; sudo is used for the profile install only.
set -euo pipefail

unshare_bin="$(readlink -f "$(command -v unshare)")"
profile="/etc/apparmor.d/previewd-unshare"
restrict="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

if [[ -r "${restrict}" && "$(cat "${restrict}")" == "1" ]]; then
  sudo tee "${profile}" >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>

profile previewd-unshare ${unshare_bin} flags=(unconfined) {
  userns,

  include if exists <local/previewd-unshare>
}
EOF
  sudo apparmor_parser --replace "${profile}"
  echo "apparmor: ${profile} loaded for ${unshare_bin}"
else
  echo "apparmor: unprivileged user namespaces not restricted on this kernel"
fi

# Fail closed: the air-gapped steps must not start if the wrapper cannot
# build and verify its namespaces.
"$(dirname "${BASH_SOURCE[0]}")/airgap-exec.sh" true
echo "apparmor: unprivileged air-gap namespace verified"
