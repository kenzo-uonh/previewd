#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(pwd)
MOCK_DIR=""
STAGING_DIR=""
AGENT_PID=""
GIT_SERVER_PID=""
E2E_SECRET="e2e-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
WEBHOOK_SECRET="hook-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

fail() {
  echo "E2E FAILED: $*" >&2
  exit 1
}

# send_webhook EVENT BODY: POST a webhook signed exactly as GitHub does.
send_webhook() {
  local sig
  sig=$(printf '%s' "$2" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.*= //')
  curl -s -X POST http://localhost:8080/webhooks/github \
    -H "X-GitHub-Event: $1" \
    -H "X-Hub-Signature-256: sha256=$sig" \
    -H "Content-Type: application/json" \
    --data-binary "$2"
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
# Unlocked memory is accepted here (logged as an error): mlockall needs
# LimitMEMLOCK=infinity, which the dev shell does not have.
PREVIEWD_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
  PREVIEWD_ALLOW_UNLOCKED_MEMORY=1 \
  PREVIEWD_SECRETS_PATH="$MOCK_DIR/secrets.env" \
  PREVIEWD_SECRETS_STAGING_DIR="$STAGING_DIR" \
  ./bin/previewd &
AGENT_PID=$!

sleep 3

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

echo -e "\n==> 2. Testing Environment Provisioning (Action: opened)..."
reply=$(send_webhook pull_request "$(PR_BODY opened)")
echo "$reply"
ENV_ID=$(printf '%s' "$reply" | sed -n 's/.*"environment_id":"\([a-z0-9-]*\)".*/\1/p')
[ -n "$ENV_ID" ] || fail "no environment_id in reply"

echo -e "\n\n[*] Agent is processing job in background. Waiting 15 seconds for Docker build..."
sleep 15

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

echo "==> 3. Testing Exhaustive Teardown (Action: closed)..."
send_webhook pull_request "$(PR_BODY closed)"

echo -e "\n==> 3b. Verifying teardown removed the container and the staged secrets..."
if docker inspect "$ENV_ID" >/dev/null 2>&1; then fail "container $ENV_ID survived teardown"; fi
if [ -e "$STAGING_DIR/$ENV_ID" ]; then fail "staged secrets survived teardown"; fi
echo "    ok: container and staged secrets removed"
