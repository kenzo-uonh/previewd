#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(pwd)
MOCK_DIR=""
STAGING_DIR=""
AGENT_PID=""
GIT_SERVER_PID=""
E2E_SECRET="e2e-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

fail() {
  echo "E2E FAILED: $*" >&2
  exit 1
}

cleanup() {
  echo -e "\n\n==> Shutting down and cleaning up..."
  if [ -n "$AGENT_PID" ]; then kill -SIGTERM "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "$GIT_SERVER_PID" ]; then kill -SIGTERM "$GIT_SERVER_PID" 2>/dev/null || true; fi

  cd "$PROJECT_ROOT"
  make docker-down >/dev/null 2>&1 || true

  if [ -n "$MOCK_DIR" ] && [ -d "$MOCK_DIR" ]; then rm -rf "$MOCK_DIR"; fi
  if [ -n "$STAGING_DIR" ] && mountpoint -q "$STAGING_DIR"; then
    sudo umount "$STAGING_DIR" || true
  fi
  if [ -n "$STAGING_DIR" ]; then rmdir "$STAGING_DIR" 2>/dev/null || true; fi
  echo "==> E2E Verification Complete."
}

trap cleanup EXIT

echo "==> Setting up local air-gapped Git repository..."
MOCK_DIR=$(mktemp -d)
git init -q --bare "$MOCK_DIR/mock.git"
git clone -q "$MOCK_DIR/mock.git" "$MOCK_DIR/src"

cd "$MOCK_DIR/src"
echo -e 'FROM alpine:latest\nCMD ["cat", "/run/secrets/E2E_TOKEN"]' > Dockerfile
git config user.name "E2E Test"
git config user.email "test@previewd.local"
git config commit.gpgsign false
git add Dockerfile
git commit -q -m "initial commit"
git push -q origin HEAD
MOCK_SHA=$(git rev-parse HEAD)

cd "$PROJECT_ROOT"

echo "==> Bootstrapping Traefik proxy and isolated networks..."
make docker-up

echo "==> Compiling CGO-free static binary..."
make build

echo "==> Mounting ramfs secret staging directory (sudo)..."
STAGING_DIR=$(mktemp -d)
sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs "$STAGING_DIR"
sudo chown "$(id -u):$(id -g)" "$STAGING_DIR"
printf 'E2E_TOKEN=%s\n' "$E2E_SECRET" > "$MOCK_DIR/secrets.env"
chmod 0600 "$MOCK_DIR/secrets.env"

echo "==> Starting previewd agent in background..."
PREVIEWD_WEBHOOK_SECRET="" \
  PREVIEWD_SECRETS_PATH="$MOCK_DIR/secrets.env" \
  PREVIEWD_SECRETS_STAGING_DIR="$STAGING_DIR" \
  ./bin/previewd &
AGENT_PID=$!

sleep 3

echo "==> 1. Testing Ping Handshake..."
curl -s -X POST http://localhost:8080/webhooks/github \
  -H "X-GitHub-Event: ping" \
  -H "Content-Type: application/json" \
  -d '{}'

echo -e "\n\n==> 2. Testing Environment Provisioning (Action: opened)..."
curl -s -X POST http://localhost:8080/webhooks/github \
  -H "X-GitHub-Event: pull_request" \
  -H "Content-Type: application/json" \
  -d "{
        \"action\": \"opened\",
        \"number\": 999,
        \"pull_request\": {
          \"head\": {\"sha\": \"$MOCK_SHA\"}
        },
        \"repository\": {
          \"clone_url\": \"file://$MOCK_DIR/mock.git\"
        }
      }"

echo -e "\n\n[*] Agent is processing job in background. Waiting 15 seconds for Docker build..."
sleep 15

echo "==> 2b. Verifying secrets reach the container only through the read-only ramfs mount..."
inspect=$(docker inspect pr-999 2>/dev/null) || fail "container pr-999 was not created"
case "$inspect" in *"$E2E_SECRET"*) fail "secret value visible in docker inspect" ;; esac
container_env=$(docker inspect pr-999 --format '{{range .Config.Env}}{{println .}}{{end}}')
case "$container_env" in *E2E_TOKEN=*) fail "secret key present in container env" ;; esac
mount_rw=$(docker inspect pr-999 --format '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.RW}}{{end}}{{end}}')
[ "$mount_rw" = "false" ] || fail "/run/secrets mount missing or writable (RW=$mount_rw)"
[ -f "$STAGING_DIR/pr-999/E2E_TOKEN" ] || fail "secret not staged on ramfs"
[ "$(docker logs pr-999 2>&1)" = "$E2E_SECRET" ] || fail "container could not read its mounted secret"
echo "    ok: no env, read-only bind mount, secret readable in the container"

echo "==> 3. Testing Exhaustive Teardown (Action: closed)..."
curl -s -X POST http://localhost:8080/webhooks/github \
  -H "X-GitHub-Event: pull_request" \
  -H "Content-Type: application/json" \
  -d '{
        "action": "closed",
        "number": 999
      }'

echo -e "\n==> 3b. Verifying teardown removed the container and the staged secrets..."
if docker inspect pr-999 >/dev/null 2>&1; then fail "container pr-999 survived teardown"; fi
if [ -e "$STAGING_DIR/pr-999" ]; then fail "staged secrets survived teardown"; fi
echo "    ok: container and staged secrets removed"
