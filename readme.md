# Harbor Exempt

[![CI](https://github.com/listellm/harbor-exempt/actions/workflows/ci.yml/badge.svg)](https://github.com/listellm/harbor-exempt/actions/workflows/ci.yml)

Vulnerability management service for Harbor container registry — manage CVE risk acceptances with expiry, cascade logic, and automatic allowlist synchronisation.

## Overview

Harbor's built-in vulnerability scanning can block image pulls when CVEs exceed a severity threshold, but its allowlist mechanism is manual and project-scoped. Harbor Exempt sits alongside Harbor to provide structured risk acceptance workflows: operators accept CVEs with justification and expiry, and the service automatically syncs those decisions back to Harbor project allowlists. When acceptances expire or are revoked, the allowlist is updated accordingly.

## Features

- **Webhook-driven ingestion** — receives Harbor `SCANNING_COMPLETED` events and stores vulnerability data.
- **Risk acceptance with expiry** — accept individual CVEs or bulk-accept across projects, with configurable maximum expiry.
- **Cascade logic** — accepting a CVE in a project automatically covers all instances of that CVE across repositories within the project.
- **Automatic Harbor sync** — accepted CVEs are pushed to Harbor project-level allowlists; revocations and expiries remove them.
- **Fix availability checks** — queries OSV.dev to flag accepted CVEs that now have upstream fixes available.
- **Multi-arch support** — resolves manifest lists to find the correct architecture-specific vulnerability report.
- **Web UI** — operator dashboard built with Jinja2 and htmx for managing acceptances, viewing blocked images, and auditing decisions.
- **Prometheus metrics** — counters, gauges, and histograms for observability.
- **Liquibase migrations** — schema managed via Liquibase init container.

## Container Image

Published to GitHub Container Registry on every release:

```
ghcr.io/listellm/harbor-exempt
```

Available tags: `latest`, `v1`, `v1.0`, `v1.0.0` (semver).

```bash
docker pull ghcr.io/listellm/harbor-exempt:latest
```

## Quick Start

```bash
# Run locally (requires Python 3.13+)
cd image
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Build the image locally
docker build -t harbor-exempt:dev image/

# Lint the Helm chart
helm lint helm/ -f helm/linter_values.yaml
```

## Testing

Unit tests cover pure functions (no DB, no network). Dependencies are isolated in `requirements-dev.txt`.

```bash
cd image
pip install -r requirements-dev.txt
pytest
```

73 tests across five modules:

| Test file | Covers |
|-----------|--------|
| `tests/test_harbor.py` | Timestamp parsing, image reference parsing, URL encoding |
| `tests/test_main.py` | Template filter functions (datetime formatting, RAG colouring) |
| `tests/test_webhook.py` | Harbor vulnerability field mapping |
| `tests/test_osv.py` | OSV.dev response parsing |
| `tests/test_config.py` | Settings properties and validation |

## Docker Compose

Run the full stack locally without Kubernetes:

```bash
docker compose up
```

This builds the image from `image/`, starts PostgreSQL, runs Liquibase migrations, and launches the application on `http://localhost:8000`. No Harbor instance is required — the scheduler is disabled and the app runs without Harbor credentials.

To use the published image instead of building locally, replace the `build` directive in `docker-compose.yaml`:

```yaml
harbor-exempt:
  image: ghcr.io/listellm/harbor-exempt:latest
```

To tear down and remove the database volume:

```bash
docker compose down -v
```

## Configuration

All settings use the `HARBOR_EXEMPT_` environment variable prefix.

| Variable | Description | Default |
|----------|-------------|---------|
| `HARBOR_EXEMPT_DB_HOST` | PostgreSQL host | — |
| `HARBOR_EXEMPT_DB_PORT` | PostgreSQL port | `5432` |
| `HARBOR_EXEMPT_DB_NAME` | Database name | `harbor_exempt` |
| `HARBOR_EXEMPT_DB_USERNAME` | Database username | — |
| `HARBOR_EXEMPT_DB_PASSWORD` | Database password | — |
| `HARBOR_EXEMPT_DB_SSLMODE` | PostgreSQL SSL mode | — |
| `HARBOR_EXEMPT_HARBOR_URL` | Harbor API base URL | — |
| `HARBOR_EXEMPT_HARBOR_USERNAME` | Harbor username | — |
| `HARBOR_EXEMPT_HARBOR_PASSWORD` | Harbor password | — |
| `HARBOR_EXEMPT_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `HARBOR_EXEMPT_MAX_EXPIRY_DAYS` | Maximum acceptance expiry in days | `90` |
| `HARBOR_EXEMPT_SCHEDULER_ENABLED` | Enable background tasks (sync, expiry, fix checks) | `true` |
| `HARBOR_EXEMPT_SYNC_INTERVAL_SECONDS` | Harbor allowlist sync interval | `300` |
| `HARBOR_EXEMPT_EXPIRE_INTERVAL_SECONDS` | Acceptance expiry check interval | `3600` |
| `HARBOR_EXEMPT_EXCLUDED_PROJECTS` | Comma-separated project names to hide from all views | — |
| `HARBOR_EXEMPT_OSV_ENABLED` | Enable OSV.dev fix availability checks | `true` |
| `HARBOR_EXEMPT_FIX_CHECK_INTERVAL_SECONDS` | Fix availability check interval | `86400` |
| `HARBOR_EXEMPT_SLACK_WEBHOOK_URL` | Slack webhook URL for notifications | — |

## Helm Deployment

### Production

```bash
helm install harbor-exempt helm/ \
  --set image.registry=ghcr.io \
  --set image.repository=listellm/harbor-exempt \
  --set image.tag=v1.0.0 \
  --set database.host=db.example.com \
  --set database.sslmode=require \
  --set secrets.dbUsername=harbor_exempt \
  --set secrets.dbPassword=changeme \
  --set harbor.url=https://harbor.example.com \
  --set secrets.harborPassword=changeme
```

Sensitive values are stored in a Kubernetes Secret created by the chart. You can populate them via `--set`, a values file, or manage the Secret externally (e.g. Sealed Secrets, External Secrets Operator, or your preferred secrets tooling).

### Local Development

Enable the in-cluster PostgreSQL StatefulSet:

```bash
helm install harbor-exempt helm/ \
  --set image.registry=ghcr.io \
  --set image.repository=listellm/harbor-exempt \
  --set image.tag=latest \
  --set database.postgresql.enabled=true \
  --set secrets.dbUsername=harbor_exempt \
  --set secrets.dbPassword=harbor-exempt-local-password \
  --set secrets.harborPassword=Harbor12345
```

## Database

Harbor Exempt requires PostgreSQL. Schema migrations are managed by Liquibase, which runs as an init container before the application starts.

Migration changesets are located in `helm/files/liquibase/changesets/`.

Core tables: `projects` → `scans` → `vulnerabilities` → `acceptances`

## API Endpoints

### Core API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/scans` | Ingest a scan and upsert vulnerabilities |
| GET | `/api/v1/projects/{project}/vulnerabilities` | List vulnerabilities for a project |
| POST | `/api/v1/vulnerabilities/{vuln_id}/accept` | Accept risk for a vulnerability |
| POST | `/api/v1/acceptances/{acceptance_id}/revoke` | Revoke an acceptance |
| POST | `/api/v1/cves/{cve_id}/accept` | Bulk-accept a CVE across projects |
| GET | `/api/v1/projects/{project}/fixable` | List accepted vulnerabilities with a known fix |
| GET | `/api/v1/projects/{project}/accepted-cves` | Get accepted CVE IDs for Harbor allowlist sync |
| GET | `/api/v1/summary` | Dashboard summary data |

### Maintenance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/maintenance/expire` | Process expired acceptances |
| POST | `/api/v1/maintenance/sync` | Trigger Harbor allowlist sync |
| POST | `/api/v1/maintenance/check-fixes` | Check OSV.dev for fix availability |
| POST | `/api/v1/maintenance/backfill-cvss` | Backfill CVSS scores from Harbor |
| POST | `/api/v1/maintenance/backfill-tags` | Backfill image tags from Harbor |
| POST | `/api/v1/maintenance/cleanup-deleted-images` | Clean up orphaned vulnerabilities |

### Web UI

| Path | Description |
|------|-------------|
| `/` | Blocked images dashboard |
| `/accepted` | Accepted images |
| `/cves` | CVE list across all projects |
| `/cves/{cve_id}` | CVE detail |
| `/projects` | Project dashboard |
| `/projects/{name}` | Project detail |
| `/audit` | Acceptance/revocation audit log |
| `/fixes` | Accepted CVEs with known fixes |

### Health

| Path | Description |
|------|-------------|
| `/healthz` | Liveness probe |
| `/readyz` | Readiness probe |
| `/metrics` | Prometheus metrics |

## Tech Stack

- **Python 3.13** with FastAPI and uvicorn
- **asyncpg** — async PostgreSQL driver (no ORM)
- **httpx** — async HTTP client for Harbor API
- **Jinja2 + htmx** — server-rendered UI with dynamic updates
- **Pydantic** — configuration and request/response validation
- **Liquibase** — database migration management
- **Prometheus** — metrics via `prometheus_client`
- **Helm** — Kubernetes deployment
- **pytest + freezegun** — unit testing

## Security Scan

Trivy scan of `ghcr.io/listellm/harbor-exempt:latest` — 18 February 2026, base image `python:3.13.7-slim` (Debian 13.3).

**0 critical, 2 high, 0 Python dependency vulnerabilities.**

| Source | Library | CVE | Severity | Installed | Fixed | Status |
|--------|---------|-----|----------|-----------|-------|--------|
| OS (glibc) | libc-bin | CVE-2026-0861 | HIGH | 2.41-12+deb13u1 | — | No fix available |
| OS (glibc) | libc6 | CVE-2026-0861 | HIGH | 2.41-12+deb13u1 | — | No fix available |

The glibc finding (integer overflow in `memalign`) has no upstream Debian fix yet. All Python dependencies are clean.

```bash
# Reproduce
trivy image --severity HIGH,CRITICAL ghcr.io/listellm/harbor-exempt:latest
```

## Licence

MIT
