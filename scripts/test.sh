#!/usr/bin/env bash
# Deterministic unit run for `make check`.
#
# Packages whose tests import pgregory.net/rapid run with a fixed
# -rapid.seed, so every run generates the same inputs. Those packages run in
# their own invocation because the flag does not exist in other test binaries.
# Random seeding belongs to `make verify` only.
set -euo pipefail

RAPID_SEED="${RAPID_SEED:-1}"

# rapid treats seed 0 as "pick a random seed": refuse it.
if ! [[ "${RAPID_SEED}" =~ ^[1-9][0-9]*$ ]]; then
  echo "FATAL: RAPID_SEED must be a positive integer (0 means random), got '${RAPID_SEED}'" >&2
  exit 2
fi

export CGO_ENABLED=0

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rapid_list="$("${script_dir}/rapid-packages.sh")"
all_list="$(go list ./...)"

mapfile -t rapid_pkgs < <(grep -v '^$' <<<"${rapid_list}" || true)
mapfile -t other_pkgs < <(grep -vxF -f <(printf '%s\n' "${rapid_pkgs[@]}" '') <<<"${all_list}" || true)

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

profiles=()
if [[ ${#other_pkgs[@]} -gt 0 ]]; then
  go test -v -coverprofile="${workdir}/other.out" "${other_pkgs[@]}"
  profiles+=("${workdir}/other.out")
fi
if [[ ${#rapid_pkgs[@]} -gt 0 ]]; then
  echo "==> rapid packages with fixed seed ${RAPID_SEED}"
  go test -v -coverprofile="${workdir}/rapid.out" "${rapid_pkgs[@]}" -rapid.seed="${RAPID_SEED}"
  profiles+=("${workdir}/rapid.out")
fi

if [[ ${#profiles[@]} -eq 0 ]]; then
  echo "FATAL: go list returned no package to test" >&2
  exit 1
fi

# Merge: keep the first mode header, append the bodies.
{
  head -n 1 "${profiles[0]}"
  for p in "${profiles[@]}"; do
    tail -n +2 "${p}"
  done
} >coverage.out
