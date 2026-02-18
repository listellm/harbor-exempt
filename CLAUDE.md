# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Harbor Exempt** — a vulnerability management service for Harbor container registry. It ingests CVE scan results via Harbor webhooks, manages risk acceptances (with expiry and cascade logic), syncs accepted CVEs back to Harbor project-level allowlists, and provides a web UI for operators.

## Running Locally

```bash
# Build the image
docker build -t harbor-exempt:dev image/

# Run with a local PostgreSQL (uses in-cluster StatefulSet mode in Helm)
# Set all HARBOR_EXEMPT_* env vars — see image/app/config.py for full list

# Run the app directly (requires Python 3.13 + deps installed)
cd image
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Lint the Helm chart
helm lint helm/ -f helm/linter_values.yaml
```

## Architecture

### Python Application (`image/`)

**Entry point**: `app/main.py` — FastAPI app with lifespan manager that initialises the DB pool, Harbor client, optional seed migration, and background scheduler.

**Module responsibilities**:

| Module | Purpose |
|--------|---------|
| `app/config.py` | Pydantic-Settings config from `HARBOR_EXEMPT_` env vars; cached via `lru_cache` |
| `app/db.py` | All database queries via asyncpg; no ORM — raw parameterised SQL |
| `app/harbor.py` | `HarborClient` — async httpx wrapper for Harbor v2.0 API |
| `app/scheduler.py` | asyncio background tasks: Harbor sync, expiry, OSV checks, gauge refresh, reconcile, tag resolution, cleanup |
| `app/auth.py` | Unused stub — authentication has been removed |
| `app/models.py` | Pydantic request/response models |
| `app/metrics.py` | Prometheus metrics (counters, gauges, histograms) |
| `app/osv.py` | OSV.dev API client for fix availability checks |
| `app/webhook.py` | Harbor `SCANNING_COMPLETED` webhook handler |

**Routes** (`app/routes/`):

- `scans.py` — `POST /api/v1/scans` — direct scan ingestion
- `vulnerabilities.py` — accept/revoke/bulk-accept, fixable vulns
- `sync.py` — `GET /api/v1/projects/{project}/accepted-cves`
- `maintenance.py` — expiry trigger, CVSS backfill, tag backfill, Harbor sync, cleanup stubs
- `summary.py` — dashboard summary data
- `ui.py` — Jinja2-rendered UI pages

**Key design decisions**:

- **Cascade acceptance**: Harbor CVE allowlists are CVE-ID scoped. Accepting one instance auto-accepts all open siblings within the project (`cascade_accept_in_project`). Revoke mirrors this.
- **Event-driven sync**: On acceptance/revocation, the scheduler's `_sync_queue` is notified. Debounced batch sync avoids stampede.
- **Repository encoding**: Harbor API requires double URL-encoding of slash-containing paths (`%252F`). See `_encode_repository()` in `harbor.py`.
- **Multi-arch images**: Webhook fires for per-arch child digests; `fetch_vulnerability_report` resolves manifest list → amd64/linux child.
- **Auto-reconcile**: On webhook ingest, if new CVE instances appear whose CVE is already accepted, they are auto-accepted immediately. Scheduler runs a sweep periodically as a safety net.

### Database Schema

Managed by **Liquibase** (init container in Helm). Migrations in `helm/files/liquibase/changesets/`.

Core tables: `projects` → `scans` → `vulnerabilities` → `acceptances`

Vulnerability status lifecycle: `open` ↔ `accepted`, transitions to `fixed` when absent from a subsequent scan.

Unique constraint on vulnerabilities: `(project_id, cve_id, package, repository)`.

### Helm Chart (`helm/`)

The chart deploys Harbor Exempt plus an optional in-cluster PostgreSQL StatefulSet (dev only). Production uses an external PostgreSQL — secrets are managed via a plain Kubernetes Secret (populated however the operator chooses).

Notable resources:
- `deployment.yaml` — Harbor Exempt container + Liquibase init container
- `postgresql-statefulset.yaml` — optional local postgres (dev)
- `secret.yaml` — application secrets (DB credentials, Harbor password)
- `cilium_network_policies/` — egress/ingress CNP definitions
- `configmap-seed.yaml` — migration seed data (one-time first boot)

## Configuration

All settings are `HARBOR_EXEMPT_`-prefixed env vars. Key ones:

| Var | Purpose |
|-----|---------|
| `HARBOR_EXEMPT_DB_HOST/USERNAME/PASSWORD` | PostgreSQL connection |
| `HARBOR_EXEMPT_HARBOR_URL/USERNAME/PASSWORD` | Harbor API |
| `HARBOR_EXEMPT_EXCLUDED_PROJECTS` | Comma-separated projects to hide from all views |
| `HARBOR_EXEMPT_MAX_EXPIRY_DAYS` | Cap on acceptance expiry (default: 90) |
| `HARBOR_EXEMPT_SCHEDULER_ENABLED` | Disable background tasks (default: true) |

## Authentication

Harbor Exempt runs without authentication — all endpoints are unauthenticated. Deploy behind a network boundary or reverse proxy if access control is required.

## Testing

```bash
cd image
pip install -r requirements-dev.txt --break-system-packages  # system Python, no venv
pytest
```

- Tests are pure unit tests (no DB, no network) — run from `image/`
- `get_settings` uses `lru_cache` — `conftest.py` clears it via autouse fixture; don't construct `Settings` via `get_settings()` in tests, use `Settings(...)` directly

## Pre-commit Hooks

- **yapf** reformats Python automatically on first commit attempt — re-stage modified files and commit again
- **helmlint** runs `helm lint` on every commit — requires `helm` in PATH

## Pull Requests

This is a GitHub repo (`github.com/listellm/harbor-exempt`) — use `gh` CLI for PRs, not ADO MCP.
