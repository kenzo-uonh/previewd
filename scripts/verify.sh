#!/usr/bin/env bash
# Deep verification: property-based tests (pgregory.net/rapid) at high check
# counts, then every native Go fuzz target for a bounded duration.
#
# Fails closed: a gate that discovers nothing to verify is a failed gate, not
# a passing one.
set -euo pipefail

RAPID_CHECKS="${RAPID_CHECKS:-10000}"
FUZZTIME="${FUZZTIME:-60s}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-60m}"

export CGO_ENABLED=0

if ! [[ "${RAPID_CHECKS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "FATAL: RAPID_CHECKS must be a positive integer, got '${RAPID_CHECKS}'" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rapid_list="$("${script_dir}/rapid-packages.sh")"
mapfile -t rapid_pkgs < <(grep -v '^$' <<<"${rapid_list}" || true)

if [[ ${#rapid_pkgs[@]} -eq 0 ]]; then
  echo "FATAL: no package imports pgregory.net/rapid; nothing to property-test" >&2
  exit 1
fi

# No -rapid.seed: each run explores a fresh random seed. rapid prints the
# failing seed, which reproduces under `make check RAPID_SEED=<seed>`.
echo "==> property-based tests (-rapid.checks=${RAPID_CHECKS}, random seed)"
for pkg in "${rapid_pkgs[@]}"; do
  echo "--> ${pkg}"
  go test -count=1 -timeout "${VERIFY_TIMEOUT}" "${pkg}" -rapid.checks="${RAPID_CHECKS}"
done

# go test -fuzz accepts exactly one target per invocation.
mapfile -t all_pkgs < <(go list ./...)
fuzz_runs=0
echo "==> native fuzzing (-fuzztime=${FUZZTIME} per target)"
for pkg in "${all_pkgs[@]}"; do
  # Capture first so a compile failure aborts here instead of being masked by
  # the filter's exit status.
  out="$(go test -list '^Fuzz' "${pkg}")"
  mapfile -t targets < <(grep -E '^Fuzz[A-Za-z0-9_]*$' <<<"${out}" || true)
  for target in "${targets[@]}"; do
    echo "--> ${pkg} ${target}"
    go test -count=1 -timeout "${VERIFY_TIMEOUT}" -run '^$' \
      -fuzz "^${target}\$" -fuzztime "${FUZZTIME}" "${pkg}"
    fuzz_runs=$((fuzz_runs + 1))
  done
done

if [[ ${fuzz_runs} -eq 0 ]]; then
  echo "FATAL: no native fuzz target (func FuzzXxx) found; nothing to fuzz" >&2
  exit 1
fi

echo "verify: ${#rapid_pkgs[@]} rapid package(s), ${fuzz_runs} fuzz target(s) passed"
