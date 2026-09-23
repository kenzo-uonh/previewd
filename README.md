# previewd

`previewd` is a sovereign, single-node Environment-as-a-Service (EaaS) agent designed for regulated, air-gapped infrastructures. It orchestrates ephemeral environments for Pull Requests via the native Docker API, using dynamic Traefik routing and maintaining zero-secret disk persistence.

## Architecture & Tech Stack

*   **Core Daemon:** Statically compiled Go 1.27+ binary (`CGO_ENABLED=0`) requiring zero external OS dependencies.
*   **Orchestration:** Docker API (`github.com/docker/docker/client`) for isolated bridge networks and container lifecycles.
*   **Ingress & Routing:** Traefik reverse proxy bound to the local Docker socket, configured dynamically via runtime container labels.
*   **Persistence:** CGO-free SQLite (`modernc.org/sqlite`) storing minimal environment metadata to ensure crash recovery.
*   **Security Context:** Secrets are injected strictly into memory from a local vault file and never written to disk.

## Codebase Structure

```text
.
├── cmd/
│   └── previewd/
│       └── main.go                # Single binary entry point initializing config, store, and HTTP server.
├── deployments/
│   ├── docker-compose.yml         # Standalone installation for agent and Traefik reverse proxy.
│   └── traefik.yml                # Base Traefik static configuration.
├── internal/
│   ├── api/
│   │   ├── handlers.go            # Webhook receivers for GitHub PR events.
│   │   └── middleware.go          # Request authentication and payload signature verification.
│   ├── config/
│   │   └── config.go              # Air-gapped environment configuration loading.
│   ├── orchestrator/
│   │   ├── docker.go              # Docker Driver implementation for the MVP.
│   │   ├── engine.go              # Interface defining the Driver (Docker/Kubernetes).
│   │   ├── environment.go         # EaaS lifecycle logic (Clone, Start, Stop, Destroy).
│   │   └── queue.go               # Bounded worker pool for deployment concurrency.
│   ├── proxy/
│   │   └── labels.go              # Dynamic routing configuration and Docker label assignment.
│   ├── secrets/
│   │   └── injector.go            # In-memory secret mapping and container injection.
│   ├── store/
│   │   ├── db.go                  # modernc.org/sqlite connection pool (No CGO).
│   │   └── queries.go             # Agent persistence for active environment states.
│   └── vcs/
│       ├── clone.go               # Secure repository cloning execution.
│       └── github.go              # GitHub webhook payload schemas.
├── scripts/
│   ├── build.sh                   # Static binary compilation script.
│   └── verify-e2e.sh              # Local, air-gapped end-to-end integration validation.
├── Makefile                       # Build, test, and infrastructure automation targets.
├── go.mod                         # Go module dependencies.
└── go.sum                         # Go module checksums.

```

## Development & Execution

The project uses a strict `Makefile` for all build and verification pipelines to enforce simplicity and consistency.

### Core Commands

* **Initialize Infrastructure:** Start the local Traefik proxy on port 8081 and create the `previewd-proxy` bridge network.


```bash
make docker-up
```


* **Build the Agent:** Compile the static, CGO-free binary with version metadata injected via ldflags into the `bin/` directory.


```bash
make build
```


* **Run Locally:** Execute the `previewd` daemon.


```bash
make run
```


* **Execute End-to-End Tests:** Run the air-gapped validation suite using a locally generated bare Git repository to verify the complete environment lifecycle.


```bash
make e2e
```



## Configuration

Operational parameters enforce hardware boundaries and are managed exclusively via environment variables:

* `PREVIEWD_API_PORT`: Agent HTTP listener port (default: 8080).


* `PREVIEWD_TRAEFIK_DOMAIN`: Base routing domain for PR environments (default: local.previewd).


* `PREVIEWD_MAX_BUILDS`: Strict concurrency limit for active deployment workers to prevent host CPU/RAM exhaustion (default: 2).


* `PREVIEWD_SECRETS_PATH`: Path to the local air-gapped secrets file (default: secrets.env).


* `PREVIEWD_DB_PATH`: SQLite database path (default: previewd.sqlite).
