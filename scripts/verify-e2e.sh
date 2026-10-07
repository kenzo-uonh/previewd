#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(pwd)
MOCK_DIR=""
STAGING_DIR=""
ROUTES_DIR=""
# E2E_STAGING=ramfs (default, needs sudo) or tmpfs (no sudo: /dev/shm with
# PREVIEWD_ALLOW_TMPFS_SECRETS=1, accepted by the daemon and logged as an error).
E2E_STAGING="${E2E_STAGING:-ramfs}"
DOMAIN="local.previewd"
AGENT_PID=""
GIT_SERVER_PID=""
E2E_SECRET="e2e-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
WEBHOOK_SECRET="hook-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

fail() {
  echo "E2E FAILED: $*" >&2
  if [ -n "$MOCK_DIR" ] && [ -f "$MOCK_DIR/agent.log" ]; then
    echo "--- last agent log lines ---" >&2
    tail -n 20 "$MOCK_DIR/agent.log" >&2
  fi
  exit 1
}

# uuid1: an RFC 4122 version 1 UUID for the current time, like the
# X-GitHub-Delivery GUIDs previewd orders deliveries by (100-ns ticks since
# 1582-10-15).
uuid1() {
  local ticks
  ticks=$(( $(date +%s%N) / 100 + 0x01B21DD213814000 ))
  printf '%08x-%04x-1%03x-%04x-%04x%08x' \
    $(( ticks & 0xffffffff )) $(( (ticks >> 32) & 0xffff )) $(( (ticks >> 48) & 0xfff )) \
    $(( 0x8000 | (RANDOM & 0x3fff) )) "$RANDOM" $(( (RANDOM << 15) | RANDOM ))
}

# send_webhook EVENT BODY [DELIVERY]: POST a webhook signed exactly as GitHub
# does (the signature covers the body only), with a fresh delivery GUID unless
# one is given.
send_webhook() {
  local sig delivery="${3:-$(uuid1)}"
  sig=$(printf '%s' "$2" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.*= //')
  curl -s -X POST http://localhost:8080/webhooks/github \
    -H "X-GitHub-Event: $1" \
    -H "X-GitHub-Delivery: $delivery" \
    -H "X-Hub-Signature-256: sha256=$sig" \
    -H "Content-Type: application/json" \
    --data-binary "$2"
}

# wait_for SECONDS DESCRIPTION COMMAND...: poll until COMMAND succeeds.
wait_for() {
  local secs="$1" what="$2"
  shift 2
  for _ in $(seq "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out after ${secs}s waiting for $what"
}

cleanup() {
  echo -e "\n\n==> Shutting down and cleaning up..."
  if [ -n "$AGENT_PID" ]; then kill -SIGTERM "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "$GIT_SERVER_PID" ]; then kill -SIGTERM "$GIT_SERVER_PID" 2>/dev/null || true; fi

  cd "$PROJECT_ROOT"
  PREVIEWD_ROUTES_DIR="$ROUTES_DIR" make docker-down >/dev/null 2>&1 || true

  if [ -n "$MOCK_DIR" ] && [ -d "$MOCK_DIR" ]; then rm -rf "$MOCK_DIR"; fi
  if [ -n "$STAGING_DIR" ] && mountpoint -q "$STAGING_DIR"; then
    sudo umount "$STAGING_DIR" || true
  fi
  if [ -n "$STAGING_DIR" ]; then
    # Staged directories are 0555: make them writable again to delete them.
    if [ "$E2E_STAGING" = tmpfs ]; then chmod -R u+w "$STAGING_DIR" 2>/dev/null || true; rm -rf "$STAGING_DIR"; else rmdir "$STAGING_DIR" 2>/dev/null || true; fi
  fi
  if [ -n "$ROUTES_DIR" ]; then rm -rf "$ROUTES_DIR"; fi
  echo "==> E2E Verification Complete."
}

trap cleanup EXIT

echo "==> Setting up local air-gapped Git repository..."
MOCK_DIR=$(mktemp -d)
git init -q --bare "$MOCK_DIR/mock.git"
git clone -q "$MOCK_DIR/mock.git" "$MOCK_DIR/src"

cd "$MOCK_DIR/src"
# Prints its secret once, then serves a page written at build time: the
# container runs on a read-only root with no writable mount.
cat > Dockerfile <<'DOCKERFILE'
FROM busybox:latest
RUN mkdir /www && echo previewd-e2e-ok > /www/index.html
CMD ["sh", "-c", "cat /run/secrets/E2E_TOKEN && echo && exec httpd -f -p 8080 -h /www"]
DOCKERFILE
git config user.name "E2E Test"
git config user.email "test@previewd.local"
git config commit.gpgsign false
git add Dockerfile
git commit -q -m "initial commit"
git push -q origin HEAD
MOCK_SHA=$(git rev-parse HEAD)

cd "$PROJECT_ROOT"

echo "==> Bootstrapping Traefik (file provider, no socket)..."
ROUTES_DIR=$(mktemp -d)
chmod 0755 "$ROUTES_DIR"
PREVIEWD_ROUTES_DIR="$ROUTES_DIR" make docker-up
mounts=$(docker inspect traefik-proxy --format '{{range .Mounts}}{{.Source}} {{.Destination}}{{println}}{{end}}')
case "$mounts" in *.sock*) fail "Traefik mounts a socket: $mounts" ;; esac
case "$(docker inspect traefik-proxy --format '{{json .Args}}')" in *providers.docker*) fail "Traefik Docker provider enabled" ;; esac
echo "    ok: no socket mounted, no Docker provider"

echo "==> Compiling CGO-free static binary..."
make build

ALLOW_TMPFS=""
if [ "$E2E_STAGING" = tmpfs ]; then
  echo "==> Secret staging on tmpfs (/dev/shm, opt-in)..."
  STAGING_DIR=$(mktemp -d -p /dev/shm)
  chmod 0700 "$STAGING_DIR"
  ALLOW_TMPFS=1
else
  echo "==> Mounting ramfs secret staging directory (sudo)..."
  STAGING_DIR=$(mktemp -d)
  sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs "$STAGING_DIR"
  sudo chown "$(id -u):$(id -g)" "$STAGING_DIR"
fi
printf 'E2E_TOKEN=%s\n' "$E2E_SECRET" > "$MOCK_DIR/secrets.env"
chmod 0600 "$MOCK_DIR/secrets.env"

# start_agent: run the daemon in the background on the E2E state (database,
# routes, staging), and wait until it serves (the startup sweep runs first).
start_agent() {
  # Unlocked memory is accepted here (logged as an error): mlockall needs
  # LimitMEMLOCK=infinity, which the dev shell does not have.
  PREVIEWD_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
    PREVIEWD_ALLOW_UNLOCKED_MEMORY=1 \
    PREVIEWD_SECRETS_PATH="$MOCK_DIR/secrets.env" \
    PREVIEWD_SECRETS_STAGING_DIR="$STAGING_DIR" \
    PREVIEWD_ALLOW_TMPFS_SECRETS="$ALLOW_TMPFS" \
    PREVIEWD_ROUTES_DIR="$ROUTES_DIR" \
    PREVIEWD_TRAEFIK_DOMAIN="$DOMAIN" \
    PREVIEWD_DB_PATH="$MOCK_DIR/previewd.sqlite" \
    ./bin/previewd >>"$MOCK_DIR/agent.log" 2>&1 &
  AGENT_PID=$!
  wait_for 30 "the agent to serve" curl -sf http://localhost:8080/healthz
}

echo "==> Starting previewd agent in background..."
start_agent

echo "==> 1. Testing Ping Handshake..."
send_webhook ping '{}'

echo -e "\n\n==> 1b. Unsigned webhook must be rejected..."
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8080/webhooks/github \
  -H "X-GitHub-Event: ping" -H "Content-Type: application/json" -d '{}')
[ "$code" = "401" ] || fail "unsigned webhook answered $code, want 401"
echo "    ok: unsigned webhook rejected (401)"

PR_BODY() {
  printf '{"action":"%s","number":999,"pull_request":{"head":{"ref":"e2e/branch","sha":"%s"}},"repository":{"full_name":"e2e/mock","clone_url":"file://%s/mock.git"}}' \
    "$1" "$MOCK_SHA" "$MOCK_DIR"
}

echo -e "\n==> 1c. Delivery GUIDs that cannot be ordered are rejected..."
for bad in "" "3f1c6b2e-9a7d-4c1b-8e2f-0a1b2c3d4e5f" "not-a-uuid"; do
  sig=$(printf '%s' "$(PR_BODY opened)" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.*= //')
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8080/webhooks/github \
    -H "X-GitHub-Event: pull_request" -H "X-GitHub-Delivery: $bad" \
    -H "X-Hub-Signature-256: sha256=$sig" --data-binary "$(PR_BODY opened)")
  [ "$code" = "400" ] || fail "delivery GUID '$bad' answered $code, want 400"
done
echo "    ok: missing, version 4 and malformed delivery GUIDs rejected (400)"

# A GUID minted now, sent later: older than the deploy below, so stale.
OLD_DELIVERY=$(uuid1)
sleep 0.01

echo -e "\n==> 2. Testing Environment Provisioning (Action: opened)..."
OPENED_DELIVERY=$(uuid1)
reply=$(send_webhook pull_request "$(PR_BODY opened)" "$OPENED_DELIVERY")
echo "$reply"
ENV_ID=$(printf '%s' "$reply" | sed -n 's/.*"environment_id":"\([a-z0-9-]*\)".*/\1/p')
[ -n "$ENV_ID" ] || fail "no environment_id in reply"
case "$reply" in *'"status":"queued"'*) ;; *) fail "opened not queued: $reply" ;; esac

echo -e "\n==> 2d. Replays and stale deliveries change nothing..."
case "$(send_webhook pull_request "$(PR_BODY opened)" "$OPENED_DELIVERY")" in
  *'"status":"duplicate"'*) ;; *) fail "redelivery of the same GUID not a duplicate" ;; esac
case "$(send_webhook pull_request "$(PR_BODY opened)")" in
  *'"status":"duplicate"'*) ;; *) fail "same signed body under a new GUID not a duplicate" ;; esac
case "$(send_webhook pull_request "$(PR_BODY synchronize)" "$OLD_DELIVERY")" in
  *'"status":"stale"'*) ;; *) fail "older delivery not stale" ;; esac
echo "    ok: same GUID and same body under a new GUID are duplicates; an older GUID is stale"

echo -e "\n\n[*] Agent is processing job in background. Waiting up to 60 seconds for the route..."
wait_for 60 "route document $ENV_ID.yml" test -f "$ROUTES_DIR/$ENV_ID.yml"

echo "==> 2b. Verifying secrets reach the container only through the read-only ramfs mount..."
inspect=$(docker inspect "$ENV_ID" 2>/dev/null) || fail "container $ENV_ID was not created"
case "$inspect" in *"$E2E_SECRET"*) fail "secret value visible in docker inspect" ;; esac
container_env=$(docker inspect "$ENV_ID" --format '{{range .Config.Env}}{{println .}}{{end}}')
case "$container_env" in *E2E_TOKEN=*) fail "secret key present in container env" ;; esac
mount_rw=$(docker inspect "$ENV_ID" --format '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.RW}}{{end}}{{end}}')
[ "$mount_rw" = "false" ] || fail "/run/secrets mount missing or writable (RW=$mount_rw)"
[ -f "$STAGING_DIR/$ENV_ID/E2E_TOKEN" ] || fail "secret not staged on ramfs"
[ "$(docker logs "$ENV_ID" 2>&1)" = "$E2E_SECRET" ] || fail "container could not read its mounted secret"
echo "    ok: no env, read-only bind mount, secret readable in the container"

echo "==> 2a. Verifying PR container hardening..."
[ "$(docker inspect "$ENV_ID" --format '{{json .HostConfig.CapDrop}}')" = '["ALL"]' ] || fail "capabilities not all dropped"
[ "$(docker inspect "$ENV_ID" --format '{{json .HostConfig.CapAdd}}')" = 'null' ] || fail "capabilities added"
[ "$(docker inspect "$ENV_ID" --format '{{json .HostConfig.SecurityOpt}}')" = '["no-new-privileges:true"]' ] || fail "no-new-privileges not set"
[ "$(docker inspect "$ENV_ID" --format '{{.HostConfig.ReadonlyRootfs}}')" = "true" ] || fail "root file system writable"
[ "$(docker inspect "$ENV_ID" --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.PidsLimit}}')" = "536870912 536870912 256" ] || fail "resource limits missing"
if docker exec "$ENV_ID" touch /probe 2>/dev/null; then fail "PR container wrote to its root file system"; fi
if docker exec "$ENV_ID" touch /tmp/probe 2>/dev/null; then fail "PR container wrote to /tmp"; fi
[ "$(docker exec "$ENV_ID" grep -E '^CapEff' /proc/1/status | awk '{print $2}')" = "0000000000000000" ] || fail "PID 1 holds capabilities"
[ "$(docker exec "$ENV_ID" grep -E '^NoNewPrivs' /proc/1/status | awk '{print $2}')" = "1" ] || fail "NoNewPrivs not set on PID 1"
echo "    ok: cap-drop ALL, no-new-privileges, read-only root, 512 MiB without swap, 256 tasks"

echo "==> 2c. Verifying routing through the route document and network isolation..."
grep -q "Host(\`$ENV_ID.$DOMAIN\`)" "$ROUTES_DIR/$ENV_ID.yml" || fail "route document has no rule for $ENV_ID.$DOMAIN"
labels=$(docker inspect "$ENV_ID" --format '{{json .Config.Labels}}')
case "$labels" in *traefik*) fail "container carries Traefik labels: $labels" ;; esac
page=""
for _ in $(seq 20); do
  page=$(curl -s -m 2 -H "Host: $ENV_ID.$DOMAIN" http://127.0.0.1/ || true)
  [ "$page" = "previewd-e2e-ok" ] && break
  sleep 1
done
[ "$page" = "previewd-e2e-ok" ] || fail "Traefik did not route $ENV_ID.$DOMAIN (got: $page)"
nets=$(docker inspect "$ENV_ID" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}')
[ "$nets" = "$ENV_ID-net " ] || fail "container networks are '$nets', want only $ENV_ID-net"
[ "$(docker network inspect "$ENV_ID-net" --format '{{.Internal}}')" = "true" ] || fail "$ENV_ID-net is not internal"
proxy_ip=$(docker inspect traefik-proxy --format "{{(index .NetworkSettings.Networks \"$ENV_ID-net\").IPAddress}}")
[ -n "$proxy_ip" ] || fail "Traefik is not attached to $ENV_ID-net"
# Positive control: wget works inside the container, so the refusals below are
# the network's doing. The probes ask for a routed host: a reachable Traefik
# would answer 200, which fails the test (a 404 for an unknown host would not).
[ "$(docker exec "$ENV_ID" wget -q -T 3 -O- http://127.0.0.1:8080/)" = "previewd-e2e-ok" ] || fail "wget control failed inside $ENV_ID"
if docker exec "$ENV_ID" wget -q -T 3 -O- --header "Host: $ENV_ID.$DOMAIN" "http://$proxy_ip/" >/dev/null 2>&1; then
  fail "PR container reached Traefik on its own network ($proxy_ip:80)"
fi
if docker exec "$ENV_ID" wget -q -T 3 -O- --header "Host: $ENV_ID.$DOMAIN" "http://172.30.255.2/" >/dev/null 2>&1; then  # airgap:allow local previewd-proxy address, isolation probe expected to fail
  fail "PR container reached Traefik's previewd-proxy address"
fi
echo "    ok: routed by file provider, internal network shared only with Traefik, Traefik not reachable from the PR"

echo "==> 2e. Crash: kill -9 the agent, plant orphan route files, restart..."
CONTAINER_ID=$(docker inspect "$ENV_ID" --format '{{.Id}}')
kill -9 "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
# A planted route document no job backs: the startup sweep must delete it.
printf '{"http":{"routers":{"evil":{"rule":"Host(`evil.%s`)","service":"evil"}},"services":{"evil":{"loadBalancer":{"servers":[{"url":"http://10.0.0.1"}]}}}}}' "$DOMAIN" >"$ROUTES_DIR/pr-1-0deadbeef0.yml" # airgap:allow planted orphan, deleted by the startup sweep, backend never contacted
echo 'http: {}' > "$ROUTES_DIR/injected.yaml"
echo partial > "$ROUTES_DIR/.pr-2-0deadbeef1.yml.tmp-1"
start_agent
for f in pr-1-0deadbeef0.yml injected.yaml .pr-2-0deadbeef1.yml.tmp-1; do
  [ ! -e "$ROUTES_DIR/$f" ] || fail "orphan $f survived the startup sweep"
done
[ -f "$ROUTES_DIR/$ENV_ID.yml" ] || fail "route of the kept environment removed"
[ "$(docker inspect "$ENV_ID" --format '{{.Id}}')" = "$CONTAINER_ID" ] || fail "kept environment was recreated"
[ "$(curl -s -m 2 -H "Host: $ENV_ID.$DOMAIN" http://127.0.0.1/)" = "previewd-e2e-ok" ] || fail "kept environment no longer routed"
[ "$(ls "$ROUTES_DIR")" = "$ENV_ID.yml" ] || fail "routes dir holds more than the kept route: $(ls -A "$ROUTES_DIR")"
echo "    ok: orphan, foreign and partial route files removed; the kept environment and its route survive the crash"

echo "==> 3. Testing Exhaustive Teardown (Action: closed)..."
case "$(send_webhook pull_request "$(PR_BODY closed)")" in
  *'"status":"queued"'*) ;; *) fail "closed not queued" ;; esac

echo -e "\n==> 3b. Verifying teardown removed the container and the staged secrets..."
wait_for 60 "teardown of $ENV_ID" sh -c "! docker inspect '$ENV_ID' && [ ! -e '$ROUTES_DIR/$ENV_ID.yml' ] && [ ! -e '$STAGING_DIR/$ENV_ID' ] && ! docker network inspect '$ENV_ID-net'"
if docker inspect "$ENV_ID" >/dev/null 2>&1; then fail "container $ENV_ID survived teardown"; fi
if [ -e "$STAGING_DIR/$ENV_ID" ]; then fail "staged secrets survived teardown"; fi
if [ -e "$ROUTES_DIR/$ENV_ID.yml" ]; then fail "route document survived teardown"; fi
if docker network inspect "$ENV_ID-net" >/dev/null 2>&1; then fail "network $ENV_ID-net survived teardown"; fi
code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 -H "Host: $ENV_ID.$DOMAIN" http://127.0.0.1/ || true)
for _ in $(seq 10); do
  [ "$code" = "404" ] && break
  sleep 1
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 -H "Host: $ENV_ID.$DOMAIN" http://127.0.0.1/ || true)
done
[ "$code" = "404" ] || fail "route still served after teardown (HTTP $code)"
echo "    ok: container, network, route and staged secrets removed"
