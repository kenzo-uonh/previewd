# Deployment

Host setup for running previewd on premises, without network access. Every step below is checked by the daemon at start: a missing or misconfigured control refuses to start rather than running degraded. Each `PREVIEWD_*` key mentioned here is described in [configuration.md](configuration.md); the reasons behind each control are in [architecture.md](architecture.md).

## Contents

1. [Host prerequisites](#1-host-prerequisites)
2. [Load images offline](#2-load-images-offline)
3. [Start Traefik](#3-start-traefik)
4. [Mount the secrets staging root (ramfs)](#4-mount-the-secrets-staging-root-ramfs)
5. [Bound the builds and filter dockerd's egress](#5-bound-the-builds-and-filter-dockerds-egress)
6. [Credentials and memory locking](#6-credentials-and-memory-locking)
7. [GitHub Enterprise Server](#7-github-enterprise-server)
8. [Start and verify](#8-start-and-verify)

## 1. Host prerequisites

- Linux with systemd, the systemd cgroup driver and cgroup v2 (bounded builds need it; on cgroup v1 previewd starts only with `PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1`, meant for dev hosts).
- Docker Engine. The build preflight uses BuildKit v0.33.1, the version Docker 29.8.2 embeds.
- The GitHub Enterprise Server and the previewd host on NTP: webhook ordering relies on the clock of the GHES that minted the delivery IDs ([Webhook Ingestion](architecture.md#webhook-ingestion), step 4).

## 2. Load images offline

previewd never pulls an image.

- **Traefik:** the image in `deployments/docker-compose.yml` is pinned by digest. On an air-gapped host, `docker load` it from a tar first; the digest pin makes `docker compose up` refuse any other image under the same tag.
- **Base images:** load each entry of [`PREVIEWD_ALLOWED_BASE_IMAGES`](configuration.md#previewd_allowed_base_images) under its `name:tag` (`docker load`). previewd refuses to start unless every entry's local `name:tag` is the pinned digest and carries no `ONBUILD` trigger.

## 3. Start Traefik

`PREVIEWD_ROUTES_DIR` must exist first (absolute path, not a symlink) and be the directory the daemon writes to (default `/var/lib/previewd/routes`). It is mounted read-only into Traefik.

```bash
make docker-up
```

This starts Traefik on port 80 and creates the `previewd-proxy` bridge network (`172.30.255.0/24`).

- If that subnet overlaps a site network, change it in both `deployments/docker-compose.yml` and `deployments/traefik.yml`.
- Traefik uses the file provider only (`deployments/traefik.yml`: no API, no telemetry). It runs digest-pinned and read-only, with no socket mounted and cgroup parent `system.slice`.
- previewd refuses to start if the Traefik container (`PREVIEWD_TRAEFIK_CONTAINER`) mounts a socket, enables the Docker provider, is privileged or is not running.

## 4. Mount the secrets staging root (ramfs)

The staging root lives in memory. Mount it before starting previewd:

```bash
sudo mkdir -p /run/previewd/secrets
sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs /run/previewd/secrets
sudo chown previewd:previewd /run/previewd/secrets
```

- ramfs is never swapped. A reboot discards it, together with every staged secret.
- The directory ([`PREVIEWD_SECRETS_STAGING_DIR`](configuration.md#previewd_secrets_staging_dir)) must be on ramfs, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job.
- A tmpfs directory is accepted only with [`PREVIEWD_ALLOW_TMPFS_SECRETS=1`](configuration.md#previewd_allow_tmpfs_secrets), on hosts without swap.

## 5. Bound the builds and filter dockerd's egress

A BuildKit `RUN` step is the PR author's code. Two files bound the engine that runs it (D-V1-4, D-V1-2):

| File | Install to | Effect |
|------|------------|--------|
| `deployments/previewd-builds.slice` | `/etc/systemd/system/` | Bounded subtree of every build: MemoryMax 4G, MemorySwapMax 0, CPUQuota 200%, TasksMax 2048 |
| `deployments/docker.service.d/previewd-builds.conf` | `/etc/systemd/system/docker.service.d/` | Makes the slice dockerd's default cgroup parent and filters dockerd's own egress (`IPAddressDeny`) |

With the systemd cgroup driver:

```bash
sudo cp deployments/previewd-builds.slice /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo cp deployments/docker.service.d/previewd-builds.conf /etc/systemd/system/docker.service.d/
sudo systemctl daemon-reload && sudo systemctl restart docker
```

Then set:

```bash
PREVIEWD_BUILDKIT_CGROUP=/sys/fs/cgroup/previewd.slice/previewd-builds.slice
```

- The drop-in makes that slice dockerd's default cgroup parent, where BuildKit runs every `RUN` (`docker-<id>.scope`), and filters dockerd's own egress (D-V1-2). The host egress filter is the control that keeps the engine off the registries: install it.
- Environment containers and Traefik name `system.slice` instead, and any other container on the host must too, or the subtree is busy and previewd refuses to start.
- The drop-in's `ExecStart` is docker-ce's packaged one plus `--cgroup-parent`; its header comment covers other packages and a site-managed `daemon.json`.
- The slice values hold one build at a time. Scale `previewd-builds.slice` before raising [`PREVIEWD_MAX_CONCURRENT_BUILDS`](configuration.md#previewd_max_concurrent_builds) above 1.
- At every start previewd checks the subtree's limits and runs the [startup build probe](architecture.md#startup-build-probe); see [`PREVIEWD_BUILDKIT_CGROUP`](configuration.md#previewd_buildkit_cgroup).
- Not yet verified on a cgroup v2 host (E0 `bound-*` cases pending).

## 6. Credentials and memory locking

- Seal the webhook secret, the GitHub App key and the listener's TLS key as systemd credentials and pass them to the unit by name: see [Credentials](configuration.md#credentials). None of them is ever read from the environment or a configured path.
- Set `LimitMEMLOCK=infinity` in the unit. The daemon locks all current and future memory before reading any secret and refuses to start unless `RLIMIT_MEMLOCK` is unlimited ([`PREVIEWD_ALLOW_UNLOCKED_MEMORY`](configuration.md#previewd_allow_unlocked_memory)).

## 7. GitHub Enterprise Server

- Create the GitHub App with **Pull requests: read**, **Contents: read** and **Metadata: read**, installed on the repositories previewd serves ([details](configuration.md#previewd_github_app_id-and-previewd_github_app_key_credential)).
- On the webhook, enable SSL verification and make the listener certificate chain to a CA GHES trusts.
- Restrict delivering sources with [`PREVIEWD_WEBHOOK_ALLOWED_CIDRS`](configuration.md#previewd_webhook_allowed_cidrs).
- List approvers for untrusted pull requests with [`PREVIEWD_APPROVERS`](configuration.md#previewd_approvers).

## 8. Start and verify

At every start, before the API listens, previewd runs the startup build probe and the [startup sweep](architecture.md#startup-sweep); any failure refuses the start.

- Probe the engine itself with `make verify-buildkit` (see the [README](../README.md#development--execution)); run with `PREVIEWD_BUILDKIT_CGROUP` set, it also checks the drop-in bounds.
- Verify the audit trail at any time with `previewd audit verify` ([Audit Trail](architecture.md#audit-trail)).
- Upgrades may migrate the database on first start, needing temporary disk space up to the database size ([Persistence](architecture.md#persistence)).
