#!/usr/bin/env bash
# E0 (V1 F2, D-V1-2, D-V1-4): probe the local Docker engine's BuildKit
# isolation with the exact /build request previewd sends (DockerEngine.Build:
# version=2, networkmode=none, nocache=1, forcerm=1, no pull, no session,
# the context as a tar body). Run it on every engine of the supported table,
# on the production host shape (cgroup v2, systemd driver, the BuildKit
# drop-in installed). An engine that fails or skips any case leaves the
# supported table.
#
# Cases:
#   host          cgroup v2 with the systemd driver
#   net-none      networkmode=none: RUN sees lo only, the host listener gets nothing
#   net-control   default network: RUN reaches the listener (proves the probe works)
#   net-host      none + RUN --network=host: refused (network.host entitlement)
#   net-default   none + RUN --network=default: lo only, nothing reached
#   no-session    the context goes as a tar body, no client session
#   stream-error  a failed RUN answers HTTP 200 with the error in the stream
#   nocache       nocache=1: a second identical build re-runs its RUN
#   no-pull       no registry connection for a present pinned base or a missing one
#   offline-base  registry unreachable: a name:tag@digest base loaded locally builds
#   digest-enforced  a local name:tag on another image is refused under the digest
#   limits-ignored  per-build memory, cpuquota and cgroupparent have no effect (D-V1-4)
#   locate        the host cgroup of a BuildKit RUN (shape of the drop-in, PREVIEWD_BUILDKIT_CGROUP)
#   bound-limits  PREVIEWD_BUILDKIT_CGROUP limit files finite, swap 0
#   bound-placement  the RUN runs inside PREVIEWD_BUILDKIT_CGROUP
#   bound-memory  an allocation beyond memory.max is OOM-killed
#   bound-tasks   a fork beyond pids.max fails
#   cgroupns-hidden  a RUN cannot see the subtree's limits (why D-V1-4 checks host side)
#   cancel        closing the /build request stops the solve: no RUN process remains
#
# Inputs (environment):
#   PROBE_BASE                name@sha256:<digest> loaded locally, with busybox
#                             (sh, nc, dd, sleep); default: the local busybox's
#                             repository digest. Never pulled.
#   PREVIEWD_BUILDKIT_CGROUP  the subtree bounded by the drop-in (bound-* cases)
#   DOCKER_SOCK               default /var/run/docker.sock
#   REPORT_DIR                default build/reports/<git describe>
set -euo pipefail

DOCKER_SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"
PREVIEWD_BUILDKIT_CGROUP="${PREVIEWD_BUILDKIT_CGROUP:-}"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
REPORT_DIR="${REPORT_DIR:-build/reports/${VERSION}}"

for tool in docker curl python3 pgrep tar timeout; do
  command -v "$tool" >/dev/null || { echo "FATAL: $tool not found" >&2; exit 2; }
done
[ -S "$DOCKER_SOCK" ] || { echo "FATAL: no Docker socket at $DOCKER_SOCK" >&2; exit 2; }

ENGINE="$(docker version --format '{{.Server.Version}}')"
API="$(docker version --format '{{.Server.APIVersion}}')"
CGROUP_VERSION="$(docker info --format '{{.CgroupVersion}}')"
CGROUP_DRIVER="$(docker info --format '{{.CgroupDriver}}')"

if [ -z "${PROBE_BASE:-}" ]; then
  PROBE_BASE="$(docker image inspect busybox:latest --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
fi
case "${PROBE_BASE:-}" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "FATAL: set PROBE_BASE=name@sha256:<digest> of a busybox image loaded on this host (never pulled)" >&2; exit 2 ;;
esac
docker image inspect "$PROBE_BASE" >/dev/null 2>&1 || { echo "FATAL: $PROBE_BASE is not loaded on this host" >&2; exit 2; }

WORK="$(mktemp -d)"
OUT_DIR="${REPORT_DIR}/buildkit/${ENGINE}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
: >"$SUMMARY"
LISTENER_PID=""
PROBE_TAG="previewd-buildkit-probe"

cleanup() {
  if [ -n "$LISTENER_PID" ]; then kill "$LISTENER_PID" 2>/dev/null || true; fi
  docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '/previewd/probe-(local|offline|swap):pinned$' | xargs -r docker image rm -f >/dev/null 2>&1 || true
  docker image ls --filter "reference=${PROBE_TAG}:*" --format '{{.Repository}}:{{.Tag}}' | xargs -r docker image rm -f >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

FAILED=0
SKIPPED=0
record() { # record STATUS CASE DETAIL
  printf '%-4s %-16s %s\n' "$1" "$2" "$3" | tee -a "$SUMMARY"
  case "$1" in
    FAIL) FAILED=$((FAILED + 1)) ;;
    SKIP) SKIPPED=$((SKIPPED + 1)) ;;
  esac
}

urlencode() { python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# The query DockerEngine.Build sends (internal/orchestrator/docker.go,
# TestBuildRequestIsLockedDown), with a probe tag and label.
query_for() { # query_for TAG [none|default] [EXTRA]
  local q="version=2&nocache=1&forcerm=1&dockerfile=Dockerfile&t=$(urlencode "${PROBE_TAG}:$1")"
  q="${q}&labels=$(urlencode '{"previewd.probe":"1"}')"
  if [ "${2:-none}" = none ]; then q="${q}&networkmode=none"; fi
  if [ -n "${3:-}" ]; then q="${q}&$3"; fi
  echo "$q"
}

# build CTX QUERY OUT: POST the context as a tar body, no session. Prints
# the HTTP status; the response stream goes to OUT.
build() {
  tar -C "$1" -cf - . | curl -sS --unix-socket "$DOCKER_SOCK" -o "$3" -w '%{http_code}' \
    -H 'Content-Type: application/x-tar' --data-binary @- -X POST "http://localhost/v${API}/build?$2"
}

# verdict OUT: "error<TAB>message", "ok<TAB>image-id" or "noid", with the
# rules of readBuildStream (any error or errorDetail fails).
verdict() {
  python3 -I - "$1" <<'PY'
import json, sys
image = ""
with open(sys.argv[1], "rb") as f:
    for raw in f:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            print("error\tmalformed line")
            sys.exit(0)
        if msg.get("error") or msg.get("errorDetail") is not None:
            detail = (msg.get("errorDetail") or {}).get("message") or msg.get("error") or ""
            print("error\t" + detail.replace("\n", " ")[:300])
            sys.exit(0)
        aux = msg.get("aux")
        if isinstance(aux, dict) and msg.get("id", "moby.image.id") == "moby.image.id" and str(aux.get("ID", "")).startswith("sha256:"):
            image = aux["ID"]
print("ok\t" + image if image else "noid")
PY
}

image_file() { # image_file TAG PATH: a file of a built probe image
  docker run --rm --network none --entrypoint cat "${PROBE_TAG}:$1" "$2"
}

new_ctx() { # new_ctx NAME DOCKERFILE-BODY: a context dir with probe scripts
  local dir="$WORK/ctx-$1"
  mkdir -p "$dir"
  cp "$WORK/net.sh" "$WORK/cg.sh" "$dir/"
  printf 'FROM %s\nCOPY net.sh cg.sh /\n%s\n' "$PROBE_BASE" "$2" >"$dir/Dockerfile"
  echo "$dir"
}

# --- probe scripts, run inside RUN steps ---
cat >"$WORK/net.sh" <<'SH'
#!/bin/sh
ifaces=$(awk -F: 'NR > 2 { gsub(/ /, "", $1); print $1 }' /proc/net/dev | sort | tr '\n' ' ')
routes=$(awk 'NR > 1' /proc/net/route | wc -l)
if nc -w 3 "$1" "$2" </dev/null >/dev/null 2>&1; then tcp=reached; else tcp=unreached; fi
printf 'ifaces=%s\nroutes=%s\ntcp=%s\n' "$ifaces" "$routes" "$tcp" | tee /probe.out
SH
cat >"$WORK/cg.sh" <<'SH'
#!/bin/sh
# Inside view: the cgroup and the limits a RUN can read, then a marked sleep.
{
  echo "cgroup=$(tr '\n' ' ' </proc/self/cgroup)"
  for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes \
           /sys/fs/cgroup/cpu.max /sys/fs/cgroup/cpu/cpu.cfs_quota_us /sys/fs/cgroup/pids.max; do
    [ -r "$f" ] && echo "$f=$(cat "$f")"
  done
} | tee /probe.out
[ -n "$1" ] && sleep "$1"
true
SH

# --- host-side helpers ---
await_pid() { # await_pid PATTERN SECONDS: first host PID whose cmdline matches
  local i
  for i in $(seq 1 $(($2 * 5))); do
    if pid="$(pgrep -f -- "$1" | head -n 1)" && [ -n "$pid" ]; then echo "$pid"; return 0; fi
    sleep 0.2
  done
  return 1
}

host_cgroup() { # host_cgroup PID: absolute host path of the PID's cgroup
  if [ "$CGROUP_VERSION" = 2 ]; then
    echo "/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$1/cgroup")"
  else
    echo "/sys/fs/cgroup/memory$(awk -F: '$2 ~ /(^|,)memory(,|$)/ { print $3 }' "/proc/$1/cgroup")"
  fi
}

procs_under() { # procs_under DIR: number of processes in the subtree
  find "$1" -name cgroup.procs -exec cat {} + 2>/dev/null | wc -l
}

marker() { printf '%d.%03d' $((20 + RANDOM % 20)) $((RANDOM % 1000)); }

echo "==> previewd BuildKit probe: Docker ${ENGINE} (API ${API}), cgroup v${CGROUP_VERSION} ${CGROUP_DRIVER}, base ${PROBE_BASE}"
echo "    evidence: ${OUT_DIR}"

# --- host ---
if [ "$CGROUP_VERSION" = 2 ] && [ "$CGROUP_DRIVER" = systemd ]; then
  record PASS host "cgroup v2, systemd driver"
else
  record FAIL host "cgroup v${CGROUP_VERSION}, ${CGROUP_DRIVER} driver: supported engines run cgroup v2 with the systemd driver"
fi

# --- network ---
GATEWAY="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
python3 -I - "$GATEWAY" "$WORK/port" "$WORK/hits" <<'PY' &
import socket, sys
s = socket.socket()
s.bind((sys.argv[1], 0))
s.listen(16)
open(sys.argv[2], "w").write(str(s.getsockname()[1]))
hits = 0
open(sys.argv[3], "w").write("0")
while True:
    c, _ = s.accept()
    c.close()
    hits += 1
    open(sys.argv[3], "w").write(str(hits))
PY
LISTENER_PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
PORT="$(cat "$WORK/port")"
hits() { cat "$WORK/hits"; }
echo "    listener: ${GATEWAY}:${PORT} (host bridge gateway)"

net_case() { # net_case NAME MODE RUN-FLAGS
  local ctx code before after v
  ctx="$(new_ctx "$1" "RUN $3 sh /net.sh $GATEWAY $PORT")"
  before="$(hits)"
  code="$(build "$ctx" "$(query_for "$1" "$2")" "$OUT_DIR/$1.jsonl")"
  after="$(hits)"
  v="$(verdict "$OUT_DIR/$1.jsonl")"
  echo "$code $v listener+$((after - before))" >"$OUT_DIR/$1.result"
  if [ "${v%%$'\t'*}" = ok ]; then image_file "$1" /probe.out >>"$OUT_DIR/$1.result"; fi
  echo "$code|${v%%$'\t'*}|${v#*$'\t'}|$((after - before))"
}

IFS='|' read -r code status detail reached <<<"$(net_case net-none none "")"
probe="$(cat "$OUT_DIR/net-none.result")"
if [ "$code" = 200 ] && [ "$status" = ok ] && grep -qx 'ifaces=lo ' <<<"$probe" && grep -qx 'routes=0' <<<"$probe" && [ "$reached" = 0 ]; then
  record PASS net-none "RUN sees lo only, no route, listener not reached"
  record PASS no-session "context streamed as a tar body, no session, HTTP 200, image ${detail:0:19}"
else
  record FAIL net-none "HTTP $code, $status ${detail:0:120}, listener +$reached, $(tr '\n' ' ' <<<"$probe")"
  record FAIL no-session "the session-less tar build did not succeed (HTTP $code, $status)"
fi

IFS='|' read -r code status detail reached <<<"$(net_case net-control default "")"
if [ "$status" = ok ] && [ "$reached" -ge 1 ]; then
  record PASS net-control "default network reaches the listener: the probe can see a network path"
else
  record FAIL net-control "control build did not reach the listener (HTTP $code, $status): the network cases prove nothing"
fi

IFS='|' read -r code status detail reached <<<"$(net_case net-host none "--network=host")"
if [ "$status" != ok ] && [ "$reached" = 0 ]; then
  record PASS net-host "refused: ${detail:0:120}"
else
  record FAIL net-host "RUN --network=host was not refused (HTTP $code, $status, listener +$reached)"
fi

IFS='|' read -r code status detail reached <<<"$(net_case net-default none "--network=default")"
probe="$(cat "$OUT_DIR/net-default.result")"
if [ "$status" = ok ] && grep -qx 'ifaces=lo ' <<<"$probe" && [ "$reached" = 0 ]; then
  record PASS net-default "none forced on RUN --network=default: lo only, listener not reached"
elif [ "$status" != ok ] && [ "$reached" = 0 ]; then
  record PASS net-default "refused: ${detail:0:120}"
else
  record FAIL net-default "RUN --network=default escaped none (HTTP $code, $status, listener +$reached, $(tr '\n' ' ' <<<"$probe"))"
fi

# --- stream error ---
ctx="$(new_ctx stream-error 'RUN echo about-to-fail && exit 3')"
code="$(build "$ctx" "$(query_for stream-error)" "$OUT_DIR/stream-error.jsonl")"
v="$(verdict "$OUT_DIR/stream-error.jsonl")"
if [ "$code" = 200 ] && [ "${v%%$'\t'*}" = error ]; then
  record PASS stream-error "HTTP 200, error in the stream: ${v#*$'\t'}"
else
  record FAIL stream-error "HTTP $code, stream verdict ${v%%$'\t'*}: previewd reads failures from the stream only"
fi

# --- nocache ---
ctx="$(new_ctx nocache 'RUN cat /proc/sys/kernel/random/uuid > /stamp')"
c1="$(build "$ctx" "$(query_for nocache-1)" "$OUT_DIR/nocache-1.jsonl")"
c2="$(build "$ctx" "$(query_for nocache-2)" "$OUT_DIR/nocache-2.jsonl")"
s1="$(image_file nocache-1 /stamp 2>/dev/null || true)"
s2="$(image_file nocache-2 /stamp 2>/dev/null || true)"
if [ "$c1" = 200 ] && [ "$c2" = 200 ] && [ -n "$s1" ] && [ -n "$s2" ] && [ "$s1" != "$s2" ]; then
  record PASS nocache "the second identical build re-ran its RUN"
else
  record FAIL nocache "RUN output reused across builds (HTTP $c1/$c2, stamps '$s1' '$s2')"
fi

# --- pulls ---
# The base images live under "registries" that are host-bridge ports: the
# counting listener (any connection is a resolution attempt) or a closed
# port (refused, as behind the egress filter). Nothing leaves the host.
DIGEST="${PROBE_BASE#*@}"
CLOSED="$(python3 -I -c 'import socket, sys; s = socket.socket(); s.bind((sys.argv[1], 0)); print(s.getsockname()[1])' "$GATEWAY")"
REG_COUNT="${GATEWAY}:${PORT}/previewd"
REG_DOWN="${GATEWAY}:${CLOSED}/previewd"
docker tag "$PROBE_BASE" "${REG_COUNT}/probe-local:pinned"
docker tag "$PROBE_BASE" "${REG_DOWN}/probe-offline:pinned"
docker tag "${PROBE_TAG}:net-none" "${REG_DOWN}/probe-swap:pinned" # another image under the tag
tagged_cleanup() {
  docker image rm "${REG_COUNT}/probe-local:pinned" "${REG_DOWN}/probe-offline:pinned" "${REG_DOWN}/probe-swap:pinned" >/dev/null 2>&1 || true
}

from_case() { # from_case NAME FROM: build FROM + RUN true; prints status|detail|registry contacts
  local dir="$WORK/ctx-$1" before code v
  mkdir -p "$dir"
  printf 'FROM %s\nRUN true\n' "$2" >"$dir/Dockerfile"
  before="$(hits)"
  code="$(build "$dir" "$(query_for "$1")" "$OUT_DIR/$1.jsonl")"
  v="$(verdict "$OUT_DIR/$1.jsonl")"
  echo "$code ${v%%$'\t'*} contacts+$(( $(hits) - before )) ${v#*$'\t'}" >"$OUT_DIR/$1.result"
  echo "${v%%$'\t'*}|${v#*$'\t'}|$(( $(hits) - before ))"
}

since="$(date +%s)"
IFS='|' read -r st_local det_local contacts_local <<<"$(from_case no-pull-local "${REG_COUNT}/probe-local:pinned@${DIGEST}")"
IFS='|' read -r st_missing det_missing contacts_missing <<<"$(from_case no-pull-missing "${REG_COUNT}/probe-missing:pinned@sha256:0000000000000000000000000000000000000000000000000000000000000000")"
docker events --since "$since" --until "$(( $(date +%s) + 1 ))" --filter type=image --format '{{.Action}} {{.Actor.ID}}' >"$OUT_DIR/no-pull.events"
pulls="$(grep -c '^pull' "$OUT_DIR/no-pull.events" || true)"
if [ "$contacts_local" = 0 ] && [ "$contacts_missing" = 0 ] && [ "$st_missing" != ok ] && [ "$pulls" = 0 ]; then
  record PASS no-pull "no registry contact for a present or a missing base (pull=0 honoured)"
else
  record FAIL no-pull "pull=0 does not stop registry access: present pinned base ${st_local} after ${contacts_local} registry connection(s), missing base ${st_missing} after ${contacts_missing}, ${pulls} pull event(s); only the host egress filter blocks it"
fi

IFS='|' read -r st det _ <<<"$(from_case offline-base "${REG_DOWN}/probe-offline:pinned@${DIGEST}")"
if [ "$st" = ok ]; then
  record PASS offline-base "registry unreachable: the pinned name:tag@digest base builds from the local record"
else
  record FAIL offline-base "registry unreachable: the pinned local base does not build (${det:0:160})"
fi

IFS='|' read -r st det _ <<<"$(from_case digest-enforced "${REG_DOWN}/probe-swap:pinned@${DIGEST}")"
if [ "$st" != ok ]; then
  record PASS digest-enforced "a local tag on another image is refused under the pinned digest"
else
  record FAIL digest-enforced "the local fallback built another image than the pinned digest"
fi
tagged_cleanup

# --- per-build limits, cgroup location, cgroupns view ---
mark="$(marker)"
nonce="previewd-probe-$RANDOM$RANDOM"
ctx="$(new_ctx limits "RUN sh /cg.sh $mark")"
extra="memory=268435456&memswap=268435456&cpuquota=50000&cpuperiod=100000&cgroupparent=$(urlencode "/$nonce")"
build "$ctx" "$(query_for limits none "$extra")" "$OUT_DIR/limits.jsonl" >"$WORK/limits.code" &
build_pid=$!
RUN_CG=""
if pid="$(await_pid "sleep $mark" 60)"; then
  RUN_CG="$(host_cgroup "$pid")"
  {
    echo "pid=$pid"
    echo "host_cgroup=$RUN_CG"
    cat "/proc/$pid/cgroup"
    for f in memory.max memory.swap.max pids.max cpu.max memory.limit_in_bytes; do
      [ -r "$RUN_CG/$f" ] && echo "$f=$(cat "$RUN_CG/$f")"
    done
  } >"$OUT_DIR/locate.txt"
fi
wait "$build_pid" || true
v="$(verdict "$OUT_DIR/limits.jsonl")"
inside="$(image_file limits /probe.out 2>/dev/null || true)"
printf '%s\n' "$inside" >"$OUT_DIR/limits-inside.txt"
if [ -z "$RUN_CG" ]; then
  record FAIL locate "the RUN process never appeared on the host"
  record FAIL limits-ignored "cannot observe the RUN's cgroup"
else
  record PASS locate "RUN cgroup ${RUN_CG}, parent $(dirname "$RUN_CG") (drop-in subtree candidate for PREVIEWD_BUILDKIT_CGROUP)"
  honored=""
  grep -q "$nonce" "$OUT_DIR/locate.txt" && honored="${honored} cgroupparent"
  grep -Eq '^(memory\.max|memory\.limit_in_bytes)=268435456$' "$OUT_DIR/locate.txt" && honored="${honored} memory"
  grep -Eq '268435456' <<<"$inside" && honored="${honored} memory(inside)"
  grep -Eq '^cpu\.max=50000 ' "$OUT_DIR/locate.txt" && honored="${honored} cpuquota"
  grep -Eq '(cpu\.max|cfs_quota_us)=50000' <<<"$inside" && honored="${honored} cpuquota(inside)"
  if [ "${v%%$'\t'*}" = ok ] && [ -z "$honored" ]; then
    record PASS limits-ignored "memory, cpuquota and cgroupparent had no effect (D-V1-4 holds)"
  else
    record FAIL limits-ignored "honored:${honored:- none}, build ${v%%$'\t'*}: D-V1-4 must be revisited for this engine"
  fi
fi

# --- drop-in bounds ---
if [ -z "$PREVIEWD_BUILDKIT_CGROUP" ] || [ "$CGROUP_VERSION" != 2 ]; then
  for c in bound-limits bound-placement bound-memory bound-tasks cgroupns-hidden; do
    record SKIP "$c" "needs cgroup v2 and PREVIEWD_BUILDKIT_CGROUP (the subtree bounded by the drop-in)"
  done
else
  CG="$PREVIEWD_BUILDKIT_CGROUP"
  mem="$(cat "$CG/memory.max" 2>/dev/null || echo missing)"
  swap="$(cat "$CG/memory.swap.max" 2>/dev/null || echo missing)"
  pids="$(cat "$CG/pids.max" 2>/dev/null || echo missing)"
  cpu="$(cut -d' ' -f1 "$CG/cpu.max" 2>/dev/null || echo missing)"
  if [ "$mem" != max ] && [ "$mem" != missing ] && [ "$swap" = 0 ] && [ "$pids" != max ] && [ "$pids" != missing ] && [ "$cpu" != max ] && [ "$cpu" != missing ]; then
    record PASS bound-limits "memory.max=$mem memory.swap.max=$swap pids.max=$pids cpu.max quota=$cpu"
  else
    record FAIL bound-limits "memory.max=$mem memory.swap.max=$swap pids.max=$pids cpu.max quota=$cpu: every limit must be finite, swap 0"
  fi

  case "$RUN_CG/" in
    "$CG"/*) record PASS bound-placement "RUN cgroup $RUN_CG is under $CG" ;;
    *) record FAIL bound-placement "RUN cgroup ${RUN_CG:-unknown} is outside $CG" ;;
  esac

  if grep -q '^/sys/fs/cgroup/memory.max=max$' <<<"$inside" && [ "$mem" != max ]; then
    record PASS cgroupns-hidden "the RUN reads memory.max=max under a limited parent: limits are verified host side"
  else
    record FAIL cgroupns-hidden "the RUN's view: $(grep 'memory.max' <<<"$inside" | tr '\n' ' '): the D-V1-4 rationale changed, review it"
  fi

  if [ "$mem" != max ] && [ "$mem" != missing ]; then
    oom_before="$(awk '$1 == "oom_kill" { print $2 }' "$CG/memory.events")"
    ctx="$(new_ctx bound-memory "RUN dd if=/dev/zero of=/dev/null bs=$((mem + (64 << 20))) count=1")"
    build "$ctx" "$(query_for bound-memory)" "$OUT_DIR/bound-memory.jsonl" >/dev/null
    oom_after="$(awk '$1 == "oom_kill" { print $2 }' "$CG/memory.events")"
    v="$(verdict "$OUT_DIR/bound-memory.jsonl")"
    if [ "${v%%$'\t'*}" = error ] && [ "$oom_after" -gt "$oom_before" ]; then
      record PASS bound-memory "allocation of memory.max + 64 MiB OOM-killed (oom_kill $oom_before -> $oom_after)"
    else
      record FAIL bound-memory "allocation beyond memory.max not killed (build ${v%%$'\t'*}, oom_kill $oom_before -> $oom_after)"
    fi
  else
    record FAIL bound-memory "memory.max=$mem: nothing to exceed"
  fi

  if [ "$pids" != max ] && [ "$pids" != missing ]; then
    max_before="$(awk '$1 == "max" { print $2 }' "$CG/pids.events")"
    ctx="$(new_ctx bound-tasks "RUN i=0; while [ \$i -lt $((pids + 16)) ]; do sleep 5 & i=\$((i + 1)); done; wait")"
    build "$ctx" "$(query_for bound-tasks)" "$OUT_DIR/bound-tasks.jsonl" >/dev/null
    max_after="$(awk '$1 == "max" { print $2 }' "$CG/pids.events")"
    if [ "$max_after" -gt "$max_before" ]; then
      record PASS bound-tasks "forks beyond pids.max=$pids refused (pids.events max $max_before -> $max_after)"
    else
      record FAIL bound-tasks "pids.max=$pids never reached (pids.events max $max_before -> $max_after)"
    fi
  else
    record FAIL bound-tasks "pids.max=$pids: nothing to exceed"
  fi
fi

# --- cancellation ---
mark="$(marker)"
ctx="$(new_ctx cancel "RUN sh /cg.sh $mark")"
build "$ctx" "$(query_for cancel)" "$OUT_DIR/cancel.jsonl" >/dev/null 2>&1 &
build_pid=$!
if pid="$(await_pid "sleep $mark" 60)"; then
  run_cg="$(host_cgroup "$pid")"
  # Closing the request is what PREVIEWD_BUILD_TIMEOUT does: the client's
  # context is cancelled and the connection dropped.
  pkill -TERM -P "$build_pid" curl 2>/dev/null || true
  kill "$build_pid" 2>/dev/null || true
  wait "$build_pid" 2>/dev/null || true
  gone=""
  for _ in $(seq 1 150); do
    if ! kill -0 "$pid" 2>/dev/null; then gone=yes; break; fi
    sleep 0.2
  done
  left=""
  if [ -n "$PREVIEWD_BUILDKIT_CGROUP" ] && [ "$CGROUP_VERSION" = 2 ]; then
    left="$(procs_under "$PREVIEWD_BUILDKIT_CGROUP")"
  fi
  if [ -n "$gone" ] && { [ -z "$left" ] || [ "$left" = 0 ]; }; then
    record PASS cancel "RUN process $pid gone within 30 s of closing the request${left:+, subtree empty}"
  else
    record FAIL cancel "RUN process ${pid} (cgroup ${run_cg}) still alive or subtree holds ${left:-?} processes 30 s after the request closed"
  fi
else
  kill "$build_pid" 2>/dev/null || true
  record FAIL cancel "the RUN process never appeared on the host"
fi

echo
if [ "$FAILED" = 0 ] && [ "$SKIPPED" = 0 ]; then
  echo "==> Docker ${ENGINE}: SUPPORTED (every case passed)" | tee -a "$SUMMARY"
  exit 0
fi
echo "==> Docker ${ENGINE}: NOT SUPPORTED (${FAILED} failed, ${SKIPPED} skipped)" | tee -a "$SUMMARY"
exit 1
