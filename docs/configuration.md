# Configuration

Operational parameters enforce hardware boundaries and are managed exclusively via environment variables. Secret values are never configuration: the webhook secret, the GitHub App key and the listener key are systemd credentials read by name (see [Credentials](#credentials)), and the per-repository application secrets live in the [secrets file](#previewd_secrets_path).

Every value is validated at start: a malformed value refuses to start. Each `PREVIEWD_ALLOW_*` opt-in that relaxes a fail-closed control is accepted only as the exact value `1` and is logged as an error at every start.

## Contents

- [Quick reference](#quick-reference)
- [Opt-ins that relax a control](#opt-ins-that-relax-a-control)
- [Webhook listener](#webhook-listener)
- [GitHub Enterprise Server](#github-enterprise-server)
- [Credentials](#credentials)
- [Approvals and trust](#approvals-and-trust)
- [Secrets and memory](#secrets-and-memory)
- [Builds](#builds)
- [Workers and containers](#workers-and-containers)
- [Routing](#routing)
- [Storage, retention and cleanup](#storage-retention-and-cleanup)

## Quick reference

| Variable | Default | Valid values |
|----------|---------|--------------|
| [`PREVIEWD_API_PORT`](#previewd_api_port) | `8080` | port |
| [`PREVIEWD_TLS_CERT_FILE`](#previewd_tls_cert_file-and-previewd_tls_key_credential) | — | **required** unless plaintext opt-in |
| [`PREVIEWD_TLS_KEY_CREDENTIAL`](#previewd_tls_cert_file-and-previewd_tls_key_credential) | — | **required** unless plaintext opt-in |
| [`PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS`](#previewd_allow_plaintext_webhooks) | unset | exactly `1` |
| [`PREVIEWD_WEBHOOK_ALLOWED_CIDRS`](#previewd_webhook_allowed_cidrs) | unset (any source) | comma-separated prefixes |
| [`PREVIEWD_WEBHOOK_SECRET_CREDENTIAL`](#previewd_webhook_secret_credential) | `webhook_secret` | credential name; **required credential** |
| [`PREVIEWD_DELIVERY_MAX_AGE`](#previewd_delivery_max_age) | `15m` | `1m`..`2h` |
| [`PREVIEWD_VCS_PROVIDER`](#previewd_vcs_provider) | `github` | `github` or `gitlab` |
| [`PREVIEWD_GHES_URL`](#previewd_ghes_url) | — | **required** with `github`, `https://host[:port]` |
| [`PREVIEWD_GHES_CA_FILE`](#previewd_ghes_ca_file) | unset (system roots) | PEM bundle path |
| [`PREVIEWD_GITHUB_APP_ID`](#previewd_github_app_id-and-previewd_github_app_key_credential) | — | **required** with `github` |
| [`PREVIEWD_GITHUB_APP_KEY_CREDENTIAL`](#previewd_github_app_id-and-previewd_github_app_key_credential) | `github-app-key` | credential name |
| [`PREVIEWD_GITLAB_URL`](#gitlab) | — | **required** with `gitlab`, `https://host[:port]` |
| [`PREVIEWD_GITLAB_CA_FILE`](#gitlab) | unset (system roots) | clean absolute PEM bundle path |
| [`PREVIEWD_GITLAB_TOKEN_CREDENTIAL`](#gitlab) | `gitlab-api-token` | credential name |
| [`PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL`](#gitlab) | `gitlab-webhook-secret` | credential name |
| [`PREVIEWD_APPROVERS`](#previewd_approvers) | unset (no approver) | `owner/repo:login#id`, comma-separated |
| [`PREVIEWD_LABEL_APPROVAL`](#previewd_label_approval) | unset | exactly `1` |
| [`PREVIEWD_APPROVAL_LABEL`](#previewd_approval_label) | `previewd-approved` | 1 to 50 bytes |
| [`PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS`](#previewd_approved_untrusted_full_secrets) | unset | `owner/repo`, comma-separated |
| [`PREVIEWD_APPROVAL_REVALIDATE_INTERVAL`](#previewd_approval_revalidate_interval-and-previewd_approval_revalidate_grace) | `10m` | `1m`..`1h` |
| [`PREVIEWD_APPROVAL_REVALIDATE_GRACE`](#previewd_approval_revalidate_interval-and-previewd_approval_revalidate_grace) | `1h` | interval..`24h` |
| [`PREVIEWD_SECRETS_PATH`](#previewd_secrets_path) | `secrets.env` | file, at most 1 MiB |
| [`PREVIEWD_SECRETS_STAGING_DIR`](#previewd_secrets_staging_dir) | `/run/previewd/secrets` | ramfs directory, `0700` |
| [`PREVIEWD_ALLOW_TMPFS_SECRETS`](#previewd_allow_tmpfs_secrets) | unset | exactly `1` |
| [`PREVIEWD_ALLOW_UNLOCKED_MEMORY`](#previewd_allow_unlocked_memory) | unset | exactly `1` |
| [`PREVIEWD_ALLOWED_BASE_IMAGES`](#previewd_allowed_base_images) | — | **required**, `name:tag@sha256:<64 hex>`, comma-separated |
| [`PREVIEWD_MAX_BUILD_CONTEXT_MIB`](#previewd_max_build_context_mib) | `512` | `1`..`16384` |
| [`PREVIEWD_BUILDKIT_CGROUP`](#previewd_buildkit_cgroup) | — | **required** unless unbounded opt-in |
| [`PREVIEWD_ALLOW_UNBOUNDED_BUILDS`](#previewd_allow_unbounded_builds) | unset | exactly `1` |
| [`PREVIEWD_MAX_CONCURRENT_BUILDS`](#previewd_max_concurrent_builds) | `1` | `1`..`16` |
| [`PREVIEWD_BUILD_TIMEOUT`](#previewd_build_timeout) | `20m` | `1m`..`2h` |
| [`PREVIEWD_BUILD_PROBE_ADDR`](#previewd_build_probe_addr) | default bridge gateway, port 9 | `IP:PORT` |
| [`PREVIEWD_MAX_BUILDS`](#previewd_max_builds) | `2` | `1`..`64` |
| [`PREVIEWD_CONTAINER_MEMORY_MIB`](#previewd_container_memory_mib) | `512` | `1`..`2^40` |
| [`PREVIEWD_CONTAINER_PIDS`](#previewd_container_pids) | `256` | `1`..`2^40` |
| [`PREVIEWD_TRAEFIK_DOMAIN`](#previewd_traefik_domain) | `local.previewd` | domain |
| [`PREVIEWD_ROUTES_DIR`](#previewd_routes_dir) | `/var/lib/previewd/routes` | existing absolute directory |
| [`PREVIEWD_TRAEFIK_CONTAINER`](#previewd_traefik_container) | `traefik-proxy` | container name |
| [`PREVIEWD_DB_PATH`](#previewd_db_path) | `previewd.sqlite` | path |
| [`PREVIEWD_RETENTION`](#previewd_retention) | `720h` | at least `24h` |
| [`PREVIEWD_ENV_TTL`](#previewd_env_ttl) | `168h` | at least `1h`, or exactly `0` |
| [`PREVIEWD_FEEDBACK`](#developer-feedback-previewd_feedback-and-previewd_preview_url_scheme) | on | `0` or `1` |
| [`PREVIEWD_PREVIEW_URL_SCHEME`](#developer-feedback-previewd_feedback-and-previewd_preview_url_scheme) | `http` | `http` or `https` |
| [`PREVIEWD_MIN_FREE_DISK_MIB`](#previewd_min_free_disk_mib) | `10240` | at least `1024` |
| [`PREVIEWD_DOCKER_DATA_ROOT`](#previewd_docker_data_root) | the daemon's `DockerRootDir` | clean absolute path |
| [`PREVIEWD_PRUNE_INTERVAL`](#previewd_prune_interval-and-previewd_prune_batch) | `1h` | `1m`..`24h` |
| [`PREVIEWD_PRUNE_BATCH`](#previewd_prune_interval-and-previewd_prune_batch) | `500` | `10`..`10000` |

## Opt-ins that relax a control

Each of these is logged as an error at every start. Use them only where the reason is understood.

| Setting | What it relaxes |
|---------|-----------------|
| `PREVIEWD_ALLOW_UNLOCKED_MEMORY=1` | Starts when `mlockall` cannot be applied |
| `PREVIEWD_ALLOW_TMPFS_SECRETS=1` | Accepts a tmpfs (swappable) secrets staging directory |
| `PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS=1` | Receives webhooks without TLS |
| `PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1` | Skips the cgroup checks of the startup build probe |
| `PREVIEWD_LABEL_APPROVAL=1` | Lets an approver approve by labeling the pull request |
| `PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS` | Gives approved untrusted deploys the trusted secret section (also logged at every such deploy and audited) |
| `PREVIEWD_ENV_TTL=0` | Disables the environment TTL |
| `PREVIEWD_FEEDBACK=0` | Posts no commit status and no comment on the pull or merge request |

## Webhook listener

### `PREVIEWD_API_PORT`

Agent HTTP listener port (default: 8080).

### `PREVIEWD_TLS_CERT_FILE` and `PREVIEWD_TLS_KEY_CREDENTIAL`

Required unless the plaintext opt-in. The webhook listener's certificate chain (a file) and the systemd credential holding its key.

- TLS 1.2 or later, AEAD suites only.
- `systemctl reload`/SIGHUP re-reads both; a pair that fails to load keeps the one in use.
- An expired, not yet valid or mismatched pair refuses to start.

### `PREVIEWD_ALLOW_PLAINTEXT_WEBHOOKS`

Set exactly `1` to receive webhooks in plaintext (delivery IDs and bodies readable on the network). Logged as an error at every start; contradicts the TLS keys.

### `PREVIEWD_WEBHOOK_ALLOWED_CIDRS`

Comma-separated prefixes (`10.0.0.0/8,fd00::/8`, no host bits) of the GHES addresses that may deliver webhooks. A peer outside them gets 403 before its body is read. Unset: any source (logged as a warning).

### `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL`

Default `webhook_secret`. Name of the systemd credential holding the HMAC secret of the GitHub webhook. **Required credential.**

- The secret is never read from the environment or from a configured path: the daemon refuses to start while `PREVIEWD_WEBHOOK_SECRET` is set (whatever its value, which is never read), and when the credential is missing, empty, or only line breaks.
- Trailing CR/LF bytes are dropped; every other byte is the key.
- Every webhook must carry the exact `X-Hub-Signature-256` for its body (at most 1 MiB).
- Changing the secret takes a restart.

### `PREVIEWD_DELIVERY_MAX_AGE`

How long after its signed time a delivery is still accepted (default: `15m`, a Go duration in 1m..2h; see V1-I7, step 5 of [Webhook Ingestion](architecture.md#webhook-ingestion)).

## Forge

### `PREVIEWD_VCS_PROVIDER`

`github` (the default: GHES and github.com) or `gitlab` (GitLab Self-Managed CE/EE and gitlab.com). Exactly those two spellings: anything else, case and padding included, refuses to start. One forge per daemon: only that forge's webhook route exists (`/webhooks/github` or `/webhooks/gitlab`).

The keys of the other forge are a contradiction, refused at start whatever their value: a stale `PREVIEWD_GHES_URL` in a GitLab deployment (or `PREVIEWD_GITLAB_URL` in a GitHub one) is never ignored. With `gitlab`, `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL` is refused too: the webhook secret is the credential of `PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL`. `PREVIEWD_APPROVERS` and `PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS` name projects as the forge spells them (see [Approvals and trust](#approvals-and-trust)); `PREVIEWD_LABEL_APPROVAL` is refused with `gitlab`.

## GitHub Enterprise Server

### `PREVIEWD_GHES_URL`

**Required.** The GitHub Enterprise Server, `https://host[:port]`, no path (the API is under `/api/v3`). previewd reads it as a GitHub App, through no proxy, following no redirect.

### `PREVIEWD_GHES_CA_FILE`

PEM bundle of the site CA that signs the GHES certificate. When set, it is the only trust (never added to the system roots); every block must be a certificate.

### `PREVIEWD_GITHUB_APP_ID` and `PREVIEWD_GITHUB_APP_KEY_CREDENTIAL`

`PREVIEWD_GITHUB_APP_ID` is **required**; `PREVIEWD_GITHUB_APP_KEY_CREDENTIAL` defaults to `github-app-key`. The GitHub App and the name of the systemd credential holding its private key (RSA, 2048 bits or more).

- The App needs **Pull requests: read**, **Contents: read** (source tarballs, H2) and the default **Metadata: read**, installed on the repositories previewd serves.
- Each read mints a token scoped to one repository, read only, with the one permission it needs, and revokes it before returning.
- [Developer feedback](#developer-feedback-previewd_feedback-and-previewd_preview_url_scheme) adds **Commit statuses: write** and **Pull requests: write**. Each write mints a token scoped to one repository and to that one permission at write level, and revokes it before returning. An App without them still deploys: the write is refused and logged at warn.

## GitLab

With `PREVIEWD_VCS_PROVIDER=gitlab` (V1.1 spec 3.1). The driver speaks REST API v4 over net/http only, through no proxy, following no redirect (the token cannot be carried to another host).

- `PREVIEWD_GITLAB_URL` is **required**: `https://host[:port]`, no path, user info, query or fragment.
- `PREVIEWD_GITLAB_CA_FILE` is the PEM bundle of the site CA that signs the GitLab certificate: a clean absolute path; when set it is the only trust; every block must be a certificate.
- `PREVIEWD_GITLAB_TOKEN_CREDENTIAL` (default `gitlab-api-token`) names the credential holding a **Project or Group Access Token** with `read_api` and `read_repository`, role Developer or more. The `api` scope instead of `read_api` also lets previewd write the commit status and the merge request note ([developer feedback](#developer-feedback-previewd_feedback-and-previewd_preview_url_scheme)); with `read_api` those writes are refused and logged at warn, and the deploy is not affected. previewd writes nothing else. It is sent in `PRIVATE-TOKEN` to the configured host only, kept in memory, never logged or quoted.
- `PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL` (default `gitlab-webhook-secret`) names the credential holding the secret token of the project or group hook. Every hook must carry exactly one `X-Gitlab-Token` equal to it (constant-time comparison); enable only **Merge request events**. GitLab does not sign the body, so keep the listener on TLS.
- `PREVIEWD_GITLAB_TOKEN` and `PREVIEWD_GITLAB_WEBHOOK_SECRET` (the secrets themselves) refuse to start whatever their value, as `PREVIEWD_WEBHOOK_SECRET` does.

Hooks: `open`, `reopen`, `update` (only when the head moved: a title or label edit builds nothing), `close` and `merge` (teardown). Ordering is by the instant the hook is received; the replay keys are `X-Gitlab-Event-UUID` and the body's digest. A trusted merge request is one whose head lives in the target project and whose author is an active member with Developer access or more.

The deploy gate (`orchestrator.GitLabAuthorizer`) reads GitLab again before anything is fetched or built, and again on every re-validation: the project is resolved from its path to its numeric ID (the reply must name exactly that path), then the merge request. It deploys only an **open** merge request that is **trusted**; a read that fails requeues the deploy (nothing runs), and a project, an author or a state that cannot be confirmed refuses it. The source is the project's archive at the exact commit (`GET /projects/:id/repository/archive.tar.gz?sha=`), extracted under the same bounds as a GHES tarball; git never runs for a merge request.

**Approvals.** A merge request that is not trusted (a fork, a deleted head project, an author who cannot push) deploys only on the approval of an account listed in `PREVIEWD_APPROVERS` for its project (`group[/subgroup]/project:username#id`, the login at most 39 bytes):

- An `approved` hook of that account is a grant of **the head the hook named**. GitLab binds an approval to no commit and keeps it across a push, so the commit is the store's: a new push revokes every other commit (`new_head`) and the merge request needs a new approval. An `unapproved` hook of that account revokes the commit (`dismissed`), however late it arrives. A hook of any other account is ignored (`202 ignored`).
- The author's own approval counts for nothing (GitLab can allow it, GitHub cannot): ignored at the hook, refused again by the gate.
- Before anything is fetched or built, and on every re-validation, the gate confirms on GitLab that the head is still that commit, that the approver still approves the merge request (`/merge_requests/:iid/approvals`), is still in `PREVIEWD_APPROVERS` (by account ID) and is still an active member with Developer access or more. A read that fails requeues the deploy; anything else refuses it and, on re-validation, tears the environment down.
- Recorded as `approval_granted` / `untrusted_deploy` with detail `approval` (schema 4). `PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS` applies as for GitHub. `PREVIEWD_LABEL_APPROVAL` is GitHub's and is refused at start with `gitlab`.

The merge request's opener is stored as `gitlab-user-<id>` (a hook names its author by ID only); the ID is the identity. A project path is at most 140 bytes (what the queue keeps); a longer one is refused at the hook.

## Credentials

Credentials are read by name from `$CREDENTIALS_DIRECTORY`, never from a configured path. Pass them in the unit with:

```ini
LoadCredentialEncrypted=github-app-key:/etc/credstore.encrypted/github-app-key
LoadCredentialEncrypted=webhook_secret:/etc/credstore.encrypted/webhook_secret
```

(or `LoadCredential=`). This command seals the secret from standard input:

```bash
systemd-creds encrypt --name=webhook_secret - /etc/credstore.encrypted/webhook_secret
```

In GHES, enable SSL verification on the webhook and make the listener certificate chain to a CA GHES trusts.

| Credential | Named by | Holds |
|------------|----------|-------|
| `webhook_secret` | `PREVIEWD_WEBHOOK_SECRET_CREDENTIAL` | HMAC secret of the GitHub webhook |
| `github-app-key` | `PREVIEWD_GITHUB_APP_KEY_CREDENTIAL` | GitHub App private key |
| `gitlab-api-token` | `PREVIEWD_GITLAB_TOKEN_CREDENTIAL` | GitLab Project or Group Access Token (`gitlab` provider) |
| `gitlab-webhook-secret` | `PREVIEWD_GITLAB_WEBHOOK_SECRET_CREDENTIAL` | Secret token of the GitLab hook (`gitlab` provider) |
| (no default name) | `PREVIEWD_TLS_KEY_CREDENTIAL` | Webhook listener's TLS key |

## Approvals and trust

### `PREVIEWD_APPROVERS`

Accounts whose review approves untrusted code, as comma-separated `owner/repo:login#id` entries (repository spelled as GitHub spells it; with `gitlab`, `group[/subgroup]/project:username#id`, the numeric user ID mandatory as well).

- The numeric account ID is mandatory and is the identity; the login is for logs and the audit trail.
- Any malformed entry, or an account listed twice for a repository, refuses to start.
- Unset: no approver.

### `PREVIEWD_LABEL_APPROVAL`

Set exactly `1` to let an approver approve by labeling the pull request. Logged as an error at every start.

### `PREVIEWD_APPROVAL_LABEL`

The approving label (default: `previewd-approved`), 1 to 50 bytes, no control character.

### `PREVIEWD_APPROVED_UNTRUSTED_FULL_SECRETS`

Comma-separated `owner/repo` list (D-V1-1 escape hatch): approved untrusted deploys of these repositories receive the trusted section. Logged as an error at every start and every such deploy, and audited (`full_secrets_opt_in`).

### `PREVIEWD_APPROVAL_REVALIDATE_INTERVAL` and `PREVIEWD_APPROVAL_REVALIDATE_GRACE`

`PREVIEWD_APPROVAL_REVALIDATE_INTERVAL` (default `10m`, 1m..1h) and `PREVIEWD_APPROVAL_REVALIDATE_GRACE` (default `1h`, at least the interval, at most 24h): every interval, each running environment is re-checked against GHES; see [Reconciliation](architecture.md#reconciliation).

## Secrets and memory

### `PREVIEWD_SECRETS_PATH`

Path to the local air-gapped secrets file (default: secrets.env), at most 1 MiB. Every key lives in a section:

```ini
[acme/app]
DB_PASSWORD=...        # trusted deploys: same-repository PRs opened by a writer
[acme/app:untrusted]
DB_PASSWORD=...        # approved fork or external PRs
```

- A key outside any section, a line without `=`, an invalid key, a header that is not `[owner/repo]` or `[owner/repo:untrusted]`, or a section or key declared twice refuses to start; errors name the line, never its content.
- An untrusted deploy receives its `:untrusted` section only, an empty set when there is none, never the trusted one.
- A missing file is an empty set.

### `PREVIEWD_SECRETS_STAGING_DIR`

Host directory where each environment's secrets are staged (default: `/run/previewd/secrets`). Must be on **ramfs**, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job. See [Mount the secrets staging root](deployment.md#4-mount-the-secrets-staging-root-ramfs).

### `PREVIEWD_ALLOW_TMPFS_SECRETS`

Set exactly `1` to accept a tmpfs staging directory. tmpfs pages can be swapped to disk, so use it only on hosts without swap. The opt-in is logged as an error at every start, and any other value is a configuration error.

### `PREVIEWD_ALLOW_UNLOCKED_MEMORY`

Set exactly `1` to start when `mlockall` cannot be applied. By default the daemon locks all current and future memory before reading any secret, and refuses to start unless `RLIMIT_MEMLOCK` is unlimited (systemd `LimitMEMLOCK=infinity`). The opt-in is logged as an error at every start.

## Builds

### `PREVIEWD_ALLOWED_BASE_IMAGES`

**Required.** Comma-separated base images a PR may build `FROM`, each `name:tag@sha256:<64 hex>` (tag **and** digest; `docker.io/library` defaults apply).

- Load each on the host under that `name:tag` (`docker load`): previewd never pulls, and refuses to start unless every entry's local `name:tag` is the pinned digest and carries no `ONBUILD` trigger.
- A `FROM` must spell the same image, tag included: the engine contacts the image's registry before every build whatever the pull flag, and falls back to the local image only by its `name:tag`, refusing it unless it is the pinned digest; a digest-only `FROM` cannot build offline (`scripts/verify-buildkit.sh`, cases `egress-filter`, `offline-base`, `digest-enforced`).
- The host egress filter is the control that keeps the engine off the registries (D-V1-2): install it (see [Bound the builds](deployment.md#5-bound-the-builds-and-filter-dockerds-egress)).
- Any malformed entry, or an image listed twice, refuses to start.

### `PREVIEWD_MAX_BUILD_CONTEXT_MIB`

Size cap of the build context tar, 1..16384 (default: 512). A larger checkout fails the deploy before any build request.

### `PREVIEWD_BUILDKIT_CGROUP`

Required unless the opt-in below. The cgroup v2 subtree, under `/sys/fs/cgroup`, where the engine runs BuildKit `RUN` steps, bounded by systemd (D-V1-4).

- At every start previewd requires its `memory.max`, `pids.max` and `cpu.max` quota finite and `memory.swap.max` 0, the subtree idle, a process of the probe build in it while the probe runs, and none left after. Any failure refuses to start.
- With the systemd cgroup driver, install the slice and the dockerd drop-in, then set `/sys/fs/cgroup/previewd.slice/previewd-builds.slice` (steps in [Bound the builds](deployment.md#5-bound-the-builds-and-filter-dockerds-egress)).
- Not yet verified on a cgroup v2 host (E0 `bound-*` cases pending).

### `PREVIEWD_ALLOW_UNBOUNDED_BUILDS`

Set exactly `1` to skip the cgroup checks of the startup probe (dev hosts, cgroup v1); the network check still runs. Contradicts `PREVIEWD_BUILDKIT_CGROUP`. Logged as an error at every start.

### `PREVIEWD_MAX_CONCURRENT_BUILDS`

Builds in flight at once across every worker, 1..16 (default: 1). Every build shares the BuildKit cgroup's limits (D-V1-4), so a value above 1 needs `previewd-builds.slice` scaled; it is logged at every start. A deploy takes a slot, without waiting, before it is authorized and holds it until it ends; with every slot taken it returns to the queue (retried after 5 s) and its worker takes the next job, so a teardown never waits behind a build. Each such return counts as an attempt of the deploy.

### `PREVIEWD_BUILD_TIMEOUT`

A build still running after this duration, 1m..2h, is cancelled (default: `20m`): previewd closes the build request, which stops the BuildKit solve and its `RUN` processes (`scripts/verify-buildkit.sh`, case `cancel`), and the deploy fails with `failure = 'build'`. A build the engine reports successful after its deadline fails too.

### `PREVIEWD_BUILD_PROBE_ADDR`

The startup probe's TCP target, `IP:PORT` (default: the default bridge's IPv4 gateway, port 9). Only "network unreachable" or "host unreachable" passes; a connection, a refusal or a timeout refuses to start. See [Startup build probe](architecture.md#startup-build-probe).

## Workers and containers

### `PREVIEWD_MAX_BUILDS`

Number of reconciler workers, i.e. jobs (deploys and teardowns) run at once, 1..64; one job per environment at a time regardless (default: 2). A value outside the range, or not an integer, refuses to start. How many of those jobs build at once is [`PREVIEWD_MAX_CONCURRENT_BUILDS`](#previewd_max_concurrent_builds).

### `PREVIEWD_CONTAINER_MEMORY_MIB`

Memory limit of each PR container, swap disabled (default: 512). Must be an integer in 1..2^40; anything else is a configuration error.

### `PREVIEWD_CONTAINER_PIDS`

Task limit of each PR container (default: 256). Same validation.

## Routing

### `PREVIEWD_TRAEFIK_DOMAIN`

Base routing domain for PR environments (default: local.previewd).

### `PREVIEWD_ROUTES_DIR`

Directory of the route documents, watched by Traefik's file provider (default: `/var/lib/previewd/routes`). Must exist (absolute path, not a symlink); the daemon refuses to start otherwise. Mounted read-only into Traefik.

### `PREVIEWD_TRAEFIK_CONTAINER`

Name of the Traefik container, joined to each environment network (default: `traefik-proxy`). Checked at startup.

## Storage, retention and cleanup

### `PREVIEWD_DB_PATH`

SQLite database path (default: previewd.sqlite).

### `PREVIEWD_RETENTION`

Age past which finished jobs, approval grants no longer live and deliveries are pruned, at least `24h` (default: `720h`). Deliveries are kept at least `PREVIEWD_DELIVERY_MAX_AGE` + 5 minutes, so a captured body outside V1-I7's window is refused by the handler, never accepted for want of its row.

### `PREVIEWD_ENV_TTL`

Age, at least `1h` (default: `168h`), after which an environment whose running version has not been replaced is torn down, and a deploy parked for an approval since its creation is dropped: each maintenance pass queues an internal teardown (`origin = 'ttl'`, audited `ttl_expired`) pinned to that job's commit, which supersedes a parked job. A later push, or an approval of the open head, deploys it again. `0`, exactly, disables the TTL and is logged as an error at every start.

### Developer feedback: `PREVIEWD_FEEDBACK` and `PREVIEWD_PREVIEW_URL_SCHEME`

On by default (V1.1 spec 3.3); `PREVIEWD_FEEDBACK=0`, exactly, turns it off, any other value than `0` or `1` refuses to start.

- **Commit status** `previewd`: `pending` when the deploy is authorized and starts, `success` with the preview URL when the environment runs, `failure` naming the step (`fetch`, `preflight`, `build`, `stage`, `start`, `route`, `commit`, or `setup`) once the rollback is done. GitLab spells it `failed`.
- **One sticky comment** per pull or merge request, found by its first line `<!-- previewd-status -->` and updated in place, never duplicated: 🟢 with the preview URL, the short commit, who authorized the deploy (the trusted author, or `login#id` of the approver) and the expiry from `PREVIEWD_ENV_TTL`; 🔴 with the failed step. Only a comment written by previewd's own credential (the GitHub App, the GitLab token's account) is ever taken for it or edited; a comment of anyone else carrying the marker is ignored. The search reads at most 10 pages of 100.
- **It fails open.** An error or a hang of the forge is logged at warn and dropped; each call is bounded to 10 s and runs after the state it reports is recorded. No deploy fails, waits or rolls back because of it.
- `PREVIEWD_PREVIEW_URL_SCHEME` is the scheme of the URL in the status and the comment (`http` by default: the shipped Traefik entrypoint `web` serves plain HTTP on port 80). Set `https` only where a TLS entrypoint fronts it.
- Titles, branch names and descriptions of the request are never copied into either: the text is previewd's own, built from validated identifiers, and a URL or a name that does not validate is not posted.

### `PREVIEWD_MIN_FREE_DISK_MIB`

Free space, at least `1024` (default: `10240`), that the file system of the Docker data root must have for a build to start.

- Below it, or when the free space cannot be read, the deploy is refused: FAILED with `failure = 'disk_floor'` and a `deploy_refused` audit row, nothing built.
- The daemon refuses to start only if the free space cannot be read; below the floor it starts and logs an error, so teardowns and the prune loop can free space.

### `PREVIEWD_DOCKER_DATA_ROOT`

The path whose file system is measured (default: the daemon's `DockerRootDir`, read at each check). Clean and absolute. With `userns-remap` the daemon's root is `/var/lib/docker/<uid>.<gid>`, which the daemon's user may not be allowed to reach: set `/var/lib/docker`, on the same file system.

### `PREVIEWD_PRUNE_INTERVAL` and `PREVIEWD_PRUNE_BATCH`

The maintenance loop runs a pass at start, then every interval, 1m..24h (default: `1h`), deleting at most a batch of rows per transaction, 10..10000 (default: 500), with a 150 ms pause between transactions so that webhooks waiting for the database lock get it, then returns up to 1,000 free pages to the file system (`PRAGMA incremental_vacuum`).

- A pass reads the host's environments first and never prunes the job that built one, nor any job newer than it; if the engine cannot be read the pass prunes nothing.
- Never pruned: a job not finished, the latest job of an environment, watermarks, revocations and new-head records, the newest 100 boot epochs, and the audit trail.
- Each pass first queues the TTL teardowns (`PREVIEWD_ENV_TTL`) and ends with an image prune (see [Disk](architecture.md#disk-v1-f5-v1-i9)).
