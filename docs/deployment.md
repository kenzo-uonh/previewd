# Deployment

Host setup for running previewd on premises, without network access. Every step below is checked by the daemon at start: a missing or misconfigured control refuses to start rather than running degraded. Each `PREVIEWD_*` key mentioned here is described in [configuration.md](configuration.md); the reasons behind each control are in [architecture.md](architecture.md).

## Contents

1. [Host prerequisites](#1-host-prerequisites)
   - [Install the package](#install-the-package)
2. [Load images offline](#2-load-images-offline)
3. [Start Traefik](#3-start-traefik)
4. [Mount the secrets staging root (ramfs)](#4-mount-the-secrets-staging-root-ramfs)
5. [Bound the builds and filter dockerd's egress](#5-bound-the-builds-and-filter-dockerds-egress)
6. [Credentials and memory locking](#6-credentials-and-memory-locking)
7. [GitHub Enterprise Server](#7-github-enterprise-server)
8. [Start and verify](#8-start-and-verify)
9. [Day-2: doctor, backup and restore](#9-day-2-doctor-backup-and-restore)

## 1. Host prerequisites

- Linux with systemd, the systemd cgroup driver and cgroup v2 (bounded builds need it; on cgroup v1 previewd starts only with `PREVIEWD_ALLOW_UNBOUNDED_BUILDS=1`, meant for dev hosts). The package refuses to install without cgroup v2.
- Docker Engine (`dockerd` and the `docker` command). The package refuses to install without them. The build preflight uses BuildKit v0.33.1, the version Docker 29.8.2 embeds.
- The GitHub Enterprise Server and the previewd host on NTP: webhook ordering relies on the clock of the GHES that minted the delivery IDs ([Webhook Ingestion](architecture.md#webhook-ingestion), step 4).

### Install the package

`make release` builds `dist/previewd_<version>_amd64.deb` and `dist/previewd-<version>-1.x86_64.rpm` (`nfpm.yaml`). Copy one to the host and install it from the file, with no repository:

```bash
sudo apt-get install ./previewd_<version>_amd64.deb
sudo dnf install --disablerepo='*' ./previewd-<version>-1.x86_64.rpm
```

| Installed file | From |
|----------------|------|
| `/usr/bin/previewd` | `bin/previewd` |
| `/usr/lib/systemd/system/previewd.service` | `deployments/previewd.service` |
| `/usr/lib/systemd/system/previewd-builds.slice` | `deployments/previewd-builds.slice` |
| `/usr/lib/systemd/system/docker.service.d/previewd-builds.conf` | `deployments/docker.service.d/previewd-builds.conf` |
| `/usr/lib/systemd/system/run-previewd-secrets.mount` | `deployments/run-previewd-secrets.mount` |
| `/usr/lib/systemd/system/previewd-proxy.service` | `deployments/previewd-proxy.service` |
| `/etc/previewd/traefik.yml` (conffile) | `deployments/traefik.yml` |
| `/etc/sysctl.d/99-previewd.conf` (conffile) | `deployments/99-previewd.conf` |

- These are vendor files: every upgrade replaces them. Override in `/etc/systemd/system`, never in place: `systemctl edit previewd` or `systemctl edit previewd-builds.slice` for a drop-in; for the docker drop-in (another `ExecStart`, another allow-list), copy it to `/etc/systemd/system/docker.service.d/` under the same name and edit the copy, which then replaces the packaged one.

- The pre-install script runs before anything is unpacked and aborts the `apt`/`dnf` transaction, installing nothing, when `dockerd` or `docker` is missing from the host or `/sys/fs/cgroup` is not cgroup v2. It changes nothing; the finer controls are checked by [`previewd doctor`](#9-day-2-doctor-backup-and-restore).
- The post-install script creates the `docker` group if missing (Docker's packages keep an existing one) and the `previewd` system user (shell `/bin/false`, no home directory), adds it to `docker` and reloads systemd. It enables, starts and restarts nothing: finish the steps below, then `systemctl restart docker` (section 5) and `systemctl enable --now previewd` (section 8).
- The package declares no dependency: install Docker Engine separately.
- Membership of `docker` is root on the host (Engine API socket). Keep that group to previewd and the administrators.
- Site settings go in `/etc/previewd/previewd.conf` (`PREVIEWD_*` keys, [configuration.md](configuration.md)), read by the unit as `EnvironmentFile=`: paths and identifiers only, never a secret value. `sudo previewd init` writes a first one (mode 0600) from a few questions and runs the doctor against it; `sudo previewd setup-credentials NAME...` seals the credentials it lists ([Operator commands](configuration.md#operator-commands)).
- The unit keeps its state in `/var/lib/previewd` (`PREVIEWD_DB_PATH=/var/lib/previewd/previewd.sqlite`) and creates the default `PREVIEWD_ROUTES_DIR`, `/var/lib/previewd/routes`.
- The unit filters its sockets to loopback (`IPAddressDeny=any`, cgroup v2). Allow the GHES address, which delivers the webhooks and serves the API and git, in a drop-in (`systemctl edit previewd`): `[Service]` then `IPAddressAllow=<GHES IP>/32`.
- On removal (not on upgrade) the pre-remove script stops `previewd.service`, `previewd-proxy.service` and `run-previewd-secrets.mount`, unmounts the ramfs staging root and empties it (and `/run/credentials/previewd.service`) if it cannot, so no staged secret or transient credential outlives the package. It never touches `/var/lib/previewd` (the audit trail is never pruned: run `previewd backup` first), `/etc/previewd`, the sealed credentials in `/etc/credstore.encrypted`, the `docker` group or the `previewd` user.
- `/etc/sysctl.d/99-previewd.conf` enables unprivileged user namespaces (`kernel.unprivileged_userns_clone=1`, Debian and Ubuntu kernels; other kernels ignore the line and use `user.max_user_namespaces`, which must be above 0). Apply it with `sudo sysctl --system`. It widens what unprivileged users can do on the host: remove the file if the site forbids it and does not use the features that need it.
- `make test-packages` needs a cgroup v2 Docker host. In throwaway Ubuntu 24.04 and Fedora 42 containers without network it checks that the install is refused without Docker Engine and leaves nothing, then (with a stand-in `docker` and `dockerd`) installs and reinstalls both packages and checks the user, its groups, the installed files and the conffiles, then removes the package and checks that a staged secret is gone. It does not start the units (no systemd in those containers).

## 2. Load images offline

previewd never pulls an image.

- **Traefik:** the image in `deployments/docker-compose.yml` is pinned by digest. On an air-gapped host, `docker load` it from a tar first; the digest pin makes `docker compose up` refuse any other image under the same tag.
- **Base images:** load each entry of [`PREVIEWD_ALLOWED_BASE_IMAGES`](configuration.md#previewd_allowed_base_images) under its `name:tag` (`docker load`). previewd refuses to start unless every entry's local `name:tag` is the pinned digest and carries no `ONBUILD` trigger.

## 3. Start Traefik

`PREVIEWD_ROUTES_DIR` must exist first (absolute path, not a symlink) and be the directory the daemon writes to (default `/var/lib/previewd/routes`). It is mounted read-only into Traefik.

```bash
sudo systemctl enable --now previewd-proxy.service
```

`previewd-proxy.service` runs the Traefik container with `docker run` itself, as the `previewd` user: no `docker compose` on the host. It creates the `previewd-proxy` bridge network (`172.30.255.0/24`) if missing, runs the digest-pinned image with `--pull=never` (load it first, section 2), read-only, without capabilities but `NET_BIND_SERVICE`, with `/etc/previewd/traefik.yml` and the routes directory mounted read-only, and publishes port 80. It reads `PREVIEWD_ROUTES_DIR` and `PREVIEWD_TRAEFIK_CONTAINER` from `/etc/previewd/previewd.conf`, like the daemon. Traefik also serves its per-router request counters on `172.30.255.2:8082` (the `metrics` entry point of `traefik.yml`, not published), which the daemon reads for ingress activity ([configuration.md](configuration.md#ingress-activity-previewd_activity_sensing-and-previewd_traefik_metrics_addr)); `previewd.service` allows that one address.

- The unit is installed, never enabled. `previewd.service` is ordered after it but does not start it: a host that already runs Traefik with `make docker-up` (`deployments/docker-compose.yml`, the development path) keeps doing so, and must not enable both: they would fight for the container name, the address and port 80. The unit never removes a running container of its name.
- If the subnet overlaps a site network, change it in `previewd-proxy.service` (copy it to `/etc/systemd/system/`), `/etc/previewd/traefik.yml` and `docker.service.d/previewd-builds.conf` together.
- Traefik uses the file provider only (`traefik.yml`: no API, no telemetry), digest-pinned and read-only, with no socket mounted and cgroup parent `system.slice`.
- previewd refuses to start if the Traefik container (`PREVIEWD_TRAEFIK_CONTAINER`) mounts a socket, enables the Docker provider, is privileged or is not running.

## 4. Mount the secrets staging root (ramfs)

The staging root lives in memory. `run-previewd-secrets.mount` mounts a ramfs at `/run/previewd/secrets` (`mode=0700,nosuid,nodev,noexec`) at every boot:

```bash
sudo systemctl enable --now run-previewd-secrets.mount
```

`previewd.service` requires the mount (`RequiresMountsFor=`) and, because ramfs takes no `uid=` option, chowns the directory to `previewd` before each start. From a source checkout, without the unit, the equivalent by hand:

```bash
sudo mkdir -p /run/previewd/secrets
sudo mount -t ramfs -o mode=0700,nosuid,nodev,noexec ramfs /run/previewd/secrets
sudo chown previewd:previewd /run/previewd/secrets
```

- ramfs is never swapped. A reboot, or stopping the mount unit, discards it together with every staged secret. It has no size limit: only the daemon can write to it.
- The directory ([`PREVIEWD_SECRETS_STAGING_DIR`](configuration.md#previewd_secrets_staging_dir)) must be on ramfs, owned by the previewd user, mode `0700`. The daemon refuses to start otherwise and re-checks the filesystem type before every job. A site that moves it copies the mount unit under the escaped name of the new path and overrides `RequiresMountsFor=` and the `chown` in a `previewd.service` drop-in.
- A tmpfs directory is accepted only with [`PREVIEWD_ALLOW_TMPFS_SECRETS=1`](configuration.md#previewd_allow_tmpfs_secrets), on hosts without swap.

## 5. Bound the builds and filter dockerd's egress

A BuildKit `RUN` step is the PR author's code. Two files bound the engine that runs it (D-V1-4, D-V1-2):

| File | Install to | Effect |
|------|------------|--------|
| `deployments/previewd-builds.slice` | `/etc/systemd/system/` | Bounded subtree of every build: MemoryMax 4G, MemorySwapMax 0, CPUQuota 200%, TasksMax 2048 |
| `deployments/docker.service.d/previewd-builds.conf` | `/etc/systemd/system/docker.service.d/` | Makes the slice dockerd's default cgroup parent and filters dockerd's own egress (`IPAddressDeny`) |

The packages install both files under `/usr/lib/systemd/system/` (see [Install the package](#install-the-package) for overrides). From a source checkout, with the systemd cgroup driver:

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

- Seal the webhook secret, the GitHub App key and the listener's TLS key as systemd credentials and pass them to the unit by name: see [Credentials](configuration.md#credentials). None of them is ever read from the environment or a configured path. `deployments/previewd.service` loads `webhook_secret` and `github-app-key` from `/etc/credstore.encrypted/`, and systemd refuses to start it while either file is missing; add the TLS key credential in the drop-in, it has no default name.
- Set `LimitMEMLOCK=infinity` in the unit (`deployments/previewd.service` does). The daemon locks all current and future memory before reading any secret and refuses to start unless `RLIMIT_MEMLOCK` is unlimited ([`PREVIEWD_ALLOW_UNLOCKED_MEMORY`](configuration.md#previewd_allow_unlocked_memory)).

## 7. GitHub Enterprise Server

- Create the GitHub App with **Pull requests: read**, **Contents: read** and **Metadata: read**, installed on the repositories previewd serves ([details](configuration.md#previewd_github_app_id-and-previewd_github_app_key_credential)).
- On the webhook, enable SSL verification and make the listener certificate chain to a CA GHES trusts.
- Restrict delivering sources with [`PREVIEWD_WEBHOOK_ALLOWED_CIDRS`](configuration.md#previewd_webhook_allowed_cidrs).
- List approvers for untrusted pull requests with [`PREVIEWD_APPROVERS`](configuration.md#previewd_approvers).

## 8. Start and verify

At every start, before the API listens, previewd runs the startup build probe and the [startup sweep](architecture.md#startup-sweep); any failure refuses the start.

- Run `previewd doctor` first ([section 9](#9-day-2-doctor-backup-and-restore)): it reports every unmet host control at once, before the daemon refuses to start on the first.
- Probe the engine itself with `make verify-buildkit` (see the [README](../README.md#development--execution)); run with `PREVIEWD_BUILDKIT_CGROUP` set, it also checks the drop-in bounds.
- Verify the audit trail at any time with `previewd audit verify` ([Audit Trail](architecture.md#audit-trail)).
- Upgrades may migrate the database on first start, needing temporary disk space up to the database size ([Persistence](architecture.md#persistence)).

## 9. Day-2: doctor, backup and restore

### `previewd doctor`

Pre-flight diagnostic of the host. It runs every check, prints `[PASS]` or `[FAIL]` with the reason for each, and exits 0 when all passed, 1 when any failed, 2 on bad arguments. It changes nothing and needs no credential.

```bash
sudo previewd doctor [-conf /etc/previewd/previewd.conf] [-user previewd]
```

| Check | Passes when |
|-------|-------------|
| build cgroup | `PREVIEWD_BUILDKIT_CGROUP` (default `/sys/fs/cgroup/previewd.slice/previewd-builds.slice`) is on cgroup v2 with finite `memory.max`, `pids.max` and `cpu.max` quota and `memory.swap.max` 0 |
| dockerd egress | `systemctl show docker.service` reports `IPAddressDeny` covering IPv4 and IPv6 (`docker.service.d/previewd-builds.conf`, D-V1-2), no `IPAddressAllow` entry wider than a /8, and `NeedDaemonReload=no` |
| secrets staging | the staging directory is a ramfs mount point, mode `0700`, owned by the service user |
| memory lock | `previewd.service` has `LimitMEMLOCK=infinity` and the kernel lets the process `mlockall` |
| clock skew | the forge's `Date` header (GHES `/api/v3/`, GitLab `/api/v4/version`, over TLS against the site CA) is within 2 s of the host |
| traefik isolation | the proxy container is running, unprivileged, with no socket and no Docker provider (the daemon's own start check) |

- Settings come from the `PREVIEWD_*` lines of `-conf` (the unit's `EnvironmentFile=`), then the environment, then the daemon's defaults. Only the keys of the checks above are read.
- Run it as root, or as a user that can run `systemctl show` and reach the Docker socket. The memory-lock check reads the unit, not the caller's shell: a root shell is not bound by the limit the daemon will be.
- A control that cannot be read is a `[FAIL]`, never a warning. The forge is contacted with a `HEAD` request and no credential; the check needs the previewd host to reach it, so run it where the daemon runs.

### `previewd backup` and `previewd restore`

```bash
previewd backup [-db /var/lib/previewd/previewd.sqlite] -out /srv/backup/previewd-2026-10-20.sqlite
previewd restore -in /srv/backup/previewd-2026-10-20.sqlite [-db /var/lib/previewd/previewd.sqlite] [-force]
```

- `backup` runs beside the daemon. It reads a consistent snapshot through SQLite's online backup API (WAL frames included), takes no write lock (the daemon keeps committing; its WAL grows for the length of the copy) and writes one self-contained file, mode `0600`, that must not exist. Before exiting 0 it checks the copy: SQLite integrity, schema version and the whole audit hash chain. Exit 1 if the chain is broken, 2 on any other failure. Nothing is left behind on failure.
- The backup holds environment state, the job queue, replay protection and the audit trail: no secret, but the audit trail is evidence. Store it as such, and note its head hash (printed on success) elsewhere: `previewd audit verify -db BACKUP -head HASH` then proves it was not truncated.
- `restore` needs the daemon stopped. It verifies the backup again, copies it beside the target, verifies the copy, and renames it into place, mode `0600` (owned like the current database, or its directory, when run as root). It refuses a target with `-wal` or `-shm` beside it, and an existing target unless `-force`, which renames the old database to `<db>.replaced-<UTC time>`: nothing is deleted. Start the daemon afterwards; it migrates an older schema.
