"""Database access layer for Harbor Exempt using asyncpg.

Migrations are handled by Liquibase, not by this module.
This module provides the connection pool and query functions.
"""

import json
import logging
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import asyncpg

logger = logging.getLogger(__name__)


def _excluded_projects() -> set[str]:
    """Get excluded project names from config."""
    from app.config import get_settings
    return get_settings().excluded_projects_set


# Connection pool — initialised during app lifespan
_pool: asyncpg.Pool | None = None


async def init_pool(
    *,
    host: str,
    port: int = 5432,
    database: str = "harbor_exempt",
    user: str,
    password: str,
    ssl: str | None = None,
) -> asyncpg.Pool:
    """Create and return the asyncpg connection pool."""
    global _pool
    kwargs: dict = {
        "host": host,
        "port": port,
        "database": database,
        "user": user,
        "password": password,
        "min_size": 2,
        "max_size": 10,
    }
    if ssl:
        kwargs["ssl"] = ssl
    _pool = await asyncpg.create_pool(**kwargs)
    logger.info("Database connection pool initialised")
    return _pool


async def close_pool() -> None:
    """Close the connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("Database connection pool closed")


def get_pool() -> asyncpg.Pool:
    """Get the current connection pool."""
    if _pool is None:
        raise RuntimeError("Database pool not initialised")
    return _pool


@asynccontextmanager
async def acquire() -> AsyncGenerator[asyncpg.Connection, None]:
    """Acquire a connection from the pool for external transaction management."""
    pool = get_pool()
    async with pool.acquire() as conn:
        yield conn


@asynccontextmanager
async def _conn_or_acquire(conn: asyncpg.Connection | None = None) -> AsyncGenerator[asyncpg.Connection, None]:
    """Use provided connection or acquire one from the pool."""
    if conn is not None:
        yield conn
    else:
        pool = get_pool()
        async with pool.acquire() as c:
            yield c


async def check_connection() -> bool:
    """Check database connectivity for readiness probe."""
    pool = get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception:
        return False


# --- Project queries ---


async def upsert_project(name: str, *, conn: asyncpg.Connection | None = None) -> str:
    """Insert project or return existing. Returns project ID."""
    async with _conn_or_acquire(conn) as c:
        row = await c.fetchrow(
            """
            INSERT INTO projects (name)
            VALUES ($1)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            """,
            name,
        )
        return str(row["id"])


# --- Scan queries ---


async def create_scan(
    project_id: str,
    image: str,
    repository: str,
    digest: str | None,
    scanner: str | None,
    total: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    unknown: int,
    *,
    tag: str | None = None,
    push_time: datetime | None = None,
    pull_time: datetime | None = None,
    conn: asyncpg.Connection | None = None,
) -> str:
    """Create a scan record. Returns scan ID."""
    async with _conn_or_acquire(conn) as c:
        row = await c.fetchrow(
            """
            INSERT INTO scans (project_id, image, repository, digest, scanner,
                              total_vulnerabilities, critical, high, medium, low, unknown, tag,
                              push_time, pull_time)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            """,
            uuid.UUID(project_id),
            image,
            repository,
            digest,
            scanner,
            total,
            critical,
            high,
            medium,
            low,
            unknown,
            tag,
            push_time,
            pull_time,
        )
        return str(row["id"])


# --- Vulnerability queries ---


async def upsert_vulnerability(
    project_id: str,
    scan_id: str,
    cve_id: str,
    package: str,
    repository: str,
    installed_version: str | None,
    fixed_version: str | None,
    severity: str,
    description: str | None,
    references: list[str],
    cvss_score: float | None = None,
    *,
    conn: asyncpg.Connection | None = None,
) -> tuple[str, bool]:
    """Upsert a vulnerability. Returns (vuln_id, is_new).

    On conflict, updates last_seen_at, severity, versions, scan_id, cvss_score.
    If previously 'fixed', reopens to 'open'.
    """
    async with _conn_or_acquire(conn) as c:
        row = await c.fetchrow(
            """
            INSERT INTO vulnerabilities (
                project_id, cve_id, package, repository,
                installed_version, fixed_version, severity,
                description, "references", scan_id, cvss_score
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid, $11)
            ON CONFLICT (project_id, cve_id, package, repository)
            DO UPDATE SET
                last_seen_at = now(),
                severity = EXCLUDED.severity,
                installed_version = EXCLUDED.installed_version,
                fixed_version = EXCLUDED.fixed_version,
                description = EXCLUDED.description,
                "references" = EXCLUDED."references",
                scan_id = EXCLUDED.scan_id,
                cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
                status = CASE
                    WHEN vulnerabilities.status = 'fixed' THEN 'open'
                    ELSE vulnerabilities.status
                END
            RETURNING id, (xmax = 0) AS is_new
            """,
            uuid.UUID(project_id),
            cve_id,
            package,
            repository,
            installed_version,
            fixed_version,
            severity,
            description,
            references,
            uuid.UUID(scan_id),
            cvss_score,
        )
        return str(row["id"]), row["is_new"]


async def mark_fixed(
    project_id: str,
    repository: str,
    scan_id: str,
    reported_cve_ids: set[str],
    *,
    conn: asyncpg.Connection | None = None,
) -> int:
    """Mark vulnerabilities as fixed if not reported in this scan.

    Scoped to (project_id, repository) to prevent cross-image false fixes.
    Only marks 'open' vulnerabilities — accepted ones stay accepted.
    Returns count of newly fixed vulnerabilities.
    """
    if not reported_cve_ids:
        # If scan reported zero vulns, mark all open vulns for this repo as fixed
        async with _conn_or_acquire(conn) as c:
            result = await c.execute(
                """
                UPDATE vulnerabilities
                SET status = 'fixed', scan_id = $3::uuid
                WHERE project_id = $1::uuid
                  AND repository = $2
                  AND status = 'open'
                """,
                uuid.UUID(project_id),
                repository,
                uuid.UUID(scan_id),
            )
            count = int(result.split()[-1])
            return count

    # Build a list of (cve_id, package) tuples that were reported
    # We need to keep vulnerabilities that were NOT in the scan
    async with _conn_or_acquire(conn) as c:
        result = await c.execute(
            """
            UPDATE vulnerabilities
            SET status = 'fixed', scan_id = $3::uuid
            WHERE project_id = $1::uuid
              AND repository = $2
              AND status = 'open'
              AND cve_id != ALL($4)
            """,
            uuid.UUID(project_id),
            repository,
            uuid.UUID(scan_id),
            list(reported_cve_ids),
        )
        count = int(result.split()[-1])
        return count


# --- Vulnerability list/get queries ---


async def list_images_with_open_vulns(
    project_filter: str | None = None,
    search: str | None = None,
) -> list[dict]:
    """List all (project, repository) combos with open vulnerabilities.

    Returns severity breakdown and latest scan info for each.
    No pagination — result set is small (tens of repos). Threshold
    filtering and pagination happen in the caller.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        conditions = ["v.status = 'open'"]
        params: list = []
        param_idx = 1

        if project_filter:
            conditions.append(f"p.name = ${param_idx}")
            params.append(project_filter)
            param_idx += 1

        if search:
            conditions.append(f"v.repository ILIKE ${param_idx}")
            params.append(f"%{search}%")
            param_idx += 1

        excluded = _excluded_projects()
        if excluded:
            conditions.append(f"p.name != ALL(${param_idx})")
            params.append(list(excluded))
            param_idx += 1

        where_clause = " AND ".join(conditions)

        query = f"""
            SELECT p.name AS project_name, v.repository,
                   s.image AS latest_image, s.digest AS latest_digest,
                   s.tag AS latest_tag, s.imported_at AS last_scanned,
                   s.push_time, s.pull_time,
                   COUNT(*) FILTER (WHERE v.severity = 'CRITICAL') AS critical_count,
                   COUNT(*) FILTER (WHERE v.severity = 'HIGH') AS high_count,
                   COUNT(*) FILTER (WHERE v.severity = 'MEDIUM') AS medium_count,
                   COUNT(*) FILTER (WHERE v.severity = 'LOW') AS low_count,
                   COUNT(*) FILTER (WHERE v.severity = 'UNKNOWN') AS unknown_count,
                   COUNT(*) AS total_open
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            LEFT JOIN LATERAL (
                SELECT image, digest, tag, imported_at, push_time, pull_time FROM scans
                WHERE project_id = v.project_id AND repository = v.repository
                ORDER BY imported_at DESC LIMIT 1
            ) s ON true
            WHERE {where_clause}
            GROUP BY p.name, v.repository, s.image, s.digest, s.tag, s.imported_at,
                     s.push_time, s.pull_time
            ORDER BY
                COUNT(*) FILTER (WHERE v.severity = 'CRITICAL') DESC,
                COUNT(*) FILTER (WHERE v.severity = 'HIGH') DESC,
                COUNT(*) DESC
        """
        rows = await conn.fetch(query, *params)

        return [
            {
                "project_name": row["project_name"],
                "repository": row["repository"],
                "latest_image": row["latest_image"],
                "latest_digest": row["latest_digest"],
                "latest_tag": row["latest_tag"],
                "last_scanned": row["last_scanned"],
                "push_time": row["push_time"],
                "pull_time": row["pull_time"],
                "critical_count": row["critical_count"],
                "high_count": row["high_count"],
                "medium_count": row["medium_count"],
                "low_count": row["low_count"],
                "unknown_count": row["unknown_count"],
                "total_open": row["total_open"],
            } for row in rows
        ]


async def list_images_with_accepted_vulns(
    project_filter: str | None = None,
    search: str | None = None,
) -> list[dict]:
    """List all (project, repository) combos with accepted vulnerabilities.

    Returns accepted count, earliest expiry, and fix availability for each.
    Only includes images where at least one CVE has an active (non-expired,
    non-revoked) acceptance.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        conditions = [
            "v.status = 'accepted'",
            "a.revoked_at IS NULL",
            "a.expires_at > now()",
        ]
        params: list = []
        param_idx = 1

        if project_filter:
            conditions.append(f"p.name = ${param_idx}")
            params.append(project_filter)
            param_idx += 1

        if search:
            conditions.append(f"v.repository ILIKE ${param_idx}")
            params.append(f"%{search}%")
            param_idx += 1

        excluded = _excluded_projects()
        if excluded:
            conditions.append(f"p.name != ALL(${param_idx})")
            params.append(list(excluded))
            param_idx += 1

        where_clause = " AND ".join(conditions)

        query = f"""
            SELECT p.name AS project_name, v.repository,
                   s.image AS latest_image, s.digest AS latest_digest,
                   s.tag AS latest_tag, s.imported_at AS last_scanned,
                   s.push_time, s.pull_time,
                   COUNT(DISTINCT v.id) AS accepted_count,
                   COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'CRITICAL') AS critical_count,
                   COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'HIGH') AS high_count,
                   COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'MEDIUM') AS medium_count,
                   COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'LOW') AS low_count,
                   COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'UNKNOWN') AS unknown_count,
                   MIN(a.expires_at) AS earliest_expiry,
                   BOOL_OR(
                       (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                       OR cfc.fix_available = true
                   ) AS has_fix
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
              AND a.revoked_at IS NULL AND a.expires_at > now()
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            LEFT JOIN LATERAL (
                SELECT image, digest, tag, imported_at, push_time, pull_time FROM scans
                WHERE project_id = v.project_id AND repository = v.repository
                ORDER BY imported_at DESC LIMIT 1
            ) s ON true
            WHERE {where_clause}
            GROUP BY p.name, v.repository, s.image, s.digest, s.tag, s.imported_at,
                     s.push_time, s.pull_time
            ORDER BY MIN(a.expires_at) ASC, COUNT(DISTINCT v.id) DESC
        """
        rows = await conn.fetch(query, *params)

        return [
            {
                "project_name": row["project_name"],
                "repository": row["repository"],
                "latest_image": row["latest_image"],
                "latest_digest": row["latest_digest"],
                "latest_tag": row["latest_tag"],
                "last_scanned": row["last_scanned"],
                "push_time": row["push_time"],
                "pull_time": row["pull_time"],
                "critical_count": row["critical_count"],
                "high_count": row["high_count"],
                "medium_count": row["medium_count"],
                "low_count": row["low_count"],
                "unknown_count": row["unknown_count"],
                "accepted_count": row["accepted_count"],
                "earliest_expiry": row["earliest_expiry"],
                "has_fix": row["has_fix"] or False,
            } for row in rows
        ]


async def list_vulnerabilities(
    project_name: str,
    status: list[str] | None = None,
    severity: list[str] | None = None,
    page: int = 1,
    per_page: int = 100,
    repository: str | None = None,
) -> tuple[list[dict], int]:
    """List vulnerabilities for a project with optional filters.

    Returns (vulnerabilities, total_count).
    """
    pool = get_pool()
    offset = (page - 1) * per_page

    async with pool.acquire() as conn:
        # Build WHERE clause dynamically
        conditions = ["p.name = $1"]
        params: list = [project_name]
        param_idx = 2

        if status:
            conditions.append(f"v.status = ANY(${param_idx})")
            params.append(status)
            param_idx += 1

        if severity:
            conditions.append(f"v.severity = ANY(${param_idx})")
            params.append(severity)
            param_idx += 1

        if repository:
            conditions.append(f"v.repository = ${param_idx}")
            params.append(repository)
            param_idx += 1

        where_clause = " AND ".join(conditions)

        # Get total count
        count_query = f"""
            SELECT COUNT(*)
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            WHERE {where_clause}
        """
        total = await conn.fetchval(count_query, *params)

        # Get page of results with optional acceptance join
        params.extend([per_page, offset])
        data_query = f"""
            SELECT v.id, v.cve_id, v.package, v.repository,
                   v.installed_version, v.fixed_version, v.severity,
                   v.status, v.description, v.first_seen_at, v.last_seen_at,
                   a.id AS acceptance_id, a.accepted_by, a.justification,
                   a.expires_at AS acceptance_expires_at, a.created_at AS acceptance_created_at
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            LEFT JOIN LATERAL (
                SELECT id, accepted_by, justification, expires_at, created_at
                FROM acceptances
                WHERE vulnerability_id = v.id
                  AND revoked_at IS NULL
                  AND expires_at > now()
                ORDER BY created_at DESC
                LIMIT 1
            ) a ON true
            WHERE {where_clause}
            ORDER BY
                CASE v.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                v.cve_id,
                v.last_seen_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        rows = await conn.fetch(data_query, *params)

        vulnerabilities = []
        for row in rows:
            vuln = {
                "id": str(row["id"]),
                "cve_id": row["cve_id"],
                "package": row["package"],
                "repository": row["repository"],
                "installed_version": row["installed_version"],
                "fixed_version": row["fixed_version"],
                "severity": row["severity"],
                "status": row["status"],
                "description": row["description"],
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "acceptance": None,
            }
            if row["acceptance_id"]:
                vuln["acceptance"] = {
                    "id": str(row["acceptance_id"]),
                    "accepted_by": row["accepted_by"],
                    "justification": row["justification"],
                    "expires_at": row["acceptance_expires_at"],
                    "created_at": row["acceptance_created_at"],
                }
            vulnerabilities.append(vuln)

        return vulnerabilities, total


async def get_vulnerability(vuln_id: str) -> dict | None:
    """Get a single vulnerability by ID."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT v.*, p.name AS project_name
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            WHERE v.id = $1::uuid
            """,
            uuid.UUID(vuln_id),
        )
        if not row:
            return None
        return dict(row)


# --- Acceptance queries ---


async def create_acceptance(
    vuln_id: str,
    accepted_by: str,
    justification: str,
    expires_at: datetime,
) -> str:
    """Create a risk acceptance and update vulnerability status. Returns acceptance ID."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Check no active acceptance exists
            existing = await conn.fetchval(
                """
                SELECT id FROM acceptances
                WHERE vulnerability_id = $1::uuid
                  AND revoked_at IS NULL
                  AND expires_at > now()
                """,
                uuid.UUID(vuln_id),
            )
            if existing:
                raise ValueError("Vulnerability already has an active acceptance")

            # Create acceptance
            row = await conn.fetchrow(
                """
                INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                VALUES ($1::uuid, $2, $3, $4)
                RETURNING id
                """,
                uuid.UUID(vuln_id),
                accepted_by,
                justification,
                expires_at,
            )

            # Update vulnerability status
            await conn.execute(
                """
                UPDATE vulnerabilities SET status = 'accepted'
                WHERE id = $1::uuid
                """,
                uuid.UUID(vuln_id),
            )

            return str(row["id"])


async def revoke_acceptance(acceptance_id: str, revoked_by: str) -> tuple[str, str]:
    """Revoke an acceptance and reopen the vulnerability. Returns (vulnerability_id, project_name)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE acceptances
                SET revoked_at = now(), revoked_by = $2
                WHERE id = $1::uuid AND revoked_at IS NULL
                RETURNING vulnerability_id
                """,
                uuid.UUID(acceptance_id),
                revoked_by,
            )
            if not row:
                raise ValueError("Acceptance not found or already revoked")

            vuln_id = row["vulnerability_id"]

            # Reopen vulnerability
            await conn.execute(
                """
                UPDATE vulnerabilities SET status = 'open'
                WHERE id = $1::uuid
                """,
                vuln_id,
            )

            # Get project name
            project_row = await conn.fetchrow(
                """
                SELECT p.name
                FROM vulnerabilities v
                JOIN projects p ON p.id = v.project_id
                WHERE v.id = $1::uuid
                """,
                vuln_id,
            )
            project_name = project_row["name"] if project_row else "unknown"

            return str(vuln_id), project_name


async def bulk_accept(
    cve_id: str,
    projects: list[str] | None,
    accepted_by: str,
    justification: str,
    expires_at: datetime,
) -> list[dict]:
    """Accept a CVE across multiple projects. Returns list of created acceptances."""
    pool = get_pool()
    async with pool.acquire() as conn:
        # Find all open vulnerabilities matching CVE
        if projects:
            rows = await conn.fetch(
                """
                SELECT v.id, v.cve_id, p.name AS project_name
                FROM vulnerabilities v
                JOIN projects p ON p.id = v.project_id
                WHERE v.cve_id = $1
                  AND v.status = 'open'
                  AND p.name = ANY($2)
                """,
                cve_id,
                projects,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT v.id, v.cve_id, p.name AS project_name
                FROM vulnerabilities v
                JOIN projects p ON p.id = v.project_id
                WHERE v.cve_id = $1
                  AND v.status = 'open'
                """,
                cve_id,
            )

        acceptances = []
        async with conn.transaction():
            for row in rows:
                vuln_id = str(row["id"])
                # Check no active acceptance
                existing = await conn.fetchval(
                    """
                    SELECT id FROM acceptances
                    WHERE vulnerability_id = $1::uuid
                      AND revoked_at IS NULL
                      AND expires_at > now()
                    """,
                    row["id"],
                )
                if existing:
                    continue

                acc_row = await conn.fetchrow(
                    """
                    INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                    VALUES ($1::uuid, $2, $3, $4)
                    RETURNING id
                    """,
                    row["id"],
                    accepted_by,
                    justification,
                    expires_at,
                )

                await conn.execute(
                    "UPDATE vulnerabilities SET status = 'accepted' WHERE id = $1::uuid",
                    row["id"],
                )

                acceptances.append(
                    {
                        "acceptance_id": str(acc_row["id"]),
                        "vulnerability_id": vuln_id,
                        "cve_id": cve_id,
                        "project_name": row["project_name"],
                        "status": "accepted",
                    }
                )

        return acceptances


async def get_accepted_cves(project_name: str) -> list[str]:
    """Get list of CVE IDs with active acceptances for a project.

    Returns only CVE IDs where acceptance is non-expired and non-revoked.
    This is the exact list pushed to Harbor allowlists.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT v.cve_id
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
            WHERE p.name = $1
              AND a.revoked_at IS NULL
              AND a.expires_at > now()
            ORDER BY v.cve_id
            """,
            project_name,
        )
        return [row["cve_id"] for row in rows]


async def expire_acceptances() -> list[dict]:
    """Find and process expired acceptances.

    Sets vulnerability status back to 'open' for expired acceptances.
    Returns list of expired acceptance details for notification.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT a.id AS acceptance_id, a.accepted_by, a.expires_at,
                   v.id AS vulnerability_id, v.cve_id, v.package,
                   p.name AS project_name
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE a.expires_at < now()
              AND a.revoked_at IS NULL
              AND v.status = 'accepted'
            """,
        )

        expired = []
        async with conn.transaction():
            for row in rows:
                # Reopen vulnerability
                await conn.execute(
                    "UPDATE vulnerabilities SET status = 'open' WHERE id = $1::uuid",
                    row["vulnerability_id"],
                )
                expired.append(
                    {
                        "acceptance_id": str(row["acceptance_id"]),
                        "vulnerability_id": str(row["vulnerability_id"]),
                        "cve_id": row["cve_id"],
                        "package": row["package"],
                        "project": row["project_name"],
                        "accepted_by": row["accepted_by"],
                        "expired_at": row["expires_at"],
                    }
                )

        return expired


async def get_expiry_metrics() -> list[dict]:
    """Get acceptance expiry metrics per project for Prometheus alerting.

    Returns per-project: counts of acceptances expiring within 7d/14d/30d
    windows, plus the earliest expiry timestamp.  Used exclusively by the
    gauge refresh scheduler — UI/API summary is fed by get_summary().
    """
    pool = get_pool()
    excluded = _excluded_projects()
    extra_condition = ""
    params: list = []
    if excluded:
        extra_condition = "AND p.name != ALL($1)"
        params.append(list(excluded))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT p.name,
                   COUNT(*) FILTER (WHERE a.expires_at < now() + interval '7 days') AS expiring_7d,
                   COUNT(*) FILTER (WHERE a.expires_at < now() + interval '14 days') AS expiring_14d,
                   COUNT(*) FILTER (WHERE a.expires_at < now() + interval '30 days') AS expiring_30d,
                   MIN(a.expires_at) AS earliest_expiry
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE a.revoked_at IS NULL
              AND a.expires_at > now()
              {extra_condition}
            GROUP BY p.name
            """,
            *params,
        )
        return [dict(row) for row in rows]


async def get_summary() -> list[dict]:
    """Get dashboard summary — vulnerability counts per project by status and severity.

    Also includes count of acceptances expiring within 14 days.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                p.name,
                v.status,
                v.severity,
                COUNT(*) AS count
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            GROUP BY p.name, v.status, v.severity
            ORDER BY p.name
            """,
        )

        # Also get expiring-soon counts
        expiring_rows = await conn.fetch(
            """
            SELECT p.name, COUNT(*) AS count
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE a.revoked_at IS NULL
              AND a.expires_at > now()
              AND a.expires_at < now() + interval '14 days'
            GROUP BY p.name
            """,
        )
        expiring_map = {row["name"]: row["count"] for row in expiring_rows}

        # Get fixable counts (accepted vulns with a known fix via Trivy or OSV)
        fixable_rows = await conn.fetch(
            """
            SELECT p.name, COUNT(*) AS count
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            WHERE v.status = 'accepted'
              AND a.revoked_at IS NULL
              AND a.expires_at > now()
              AND (
                  (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                  OR cfc.fix_available = true
              )
            GROUP BY p.name
            """,
        )
        fixable_map = {row["name"]: row["count"] for row in fixable_rows}

        # Build summary
        projects: dict[str, dict] = {}
        for row in rows:
            name = row["name"]
            if name not in projects:
                projects[name] = {
                    "name": name,
                    "open": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "unknown": 0,
                    },
                    "accepted": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "unknown": 0,
                    },
                    "fixed": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "unknown": 0,
                    },
                    "expiring_soon": expiring_map.get(name, 0),
                    "fixable": fixable_map.get(name, 0),
                }

            status = row["status"]
            severity = row["severity"].lower()
            if status in projects[name] and severity in projects[name][status]:
                projects[name][status][severity] = row["count"]

        # Filter out excluded projects
        excluded = _excluded_projects()
        if excluded:
            projects = {k: v for k, v in projects.items() if k not in excluded}
            expiring_map = {k: v for k, v in expiring_map.items() if k not in excluded}

        return list(projects.values())


async def list_acceptances_for_vulnerability(vuln_id: str) -> list[dict]:
    """Return all acceptances for a vulnerability, including expired and revoked.

    Ordered by created_at DESC. Used on the vulnerability detail page.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT a.id, a.accepted_by, a.justification, a.expires_at,
                   a.created_at, a.revoked_at, a.revoked_by
            FROM acceptances a
            WHERE a.vulnerability_id = $1::uuid
            ORDER BY a.created_at DESC
            """,
            uuid.UUID(vuln_id),
        )
        return [dict(row) for row in rows]


async def list_audit_log(
    project: str | None = None,
    user: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Query acceptance/revocation events as an audit trail.

    Returns (events, total_count).
    Each event: timestamp, action, user, CVE, project, justification.
    """
    pool = get_pool()
    offset = (page - 1) * per_page

    async with pool.acquire() as conn:
        conditions: list[str] = []
        params: list = []
        param_idx = 1

        if project:
            conditions.append(f"p.name = ${param_idx}")
            params.append(project)
            param_idx += 1

        if user:
            conditions.append(f"(a.accepted_by = ${param_idx} OR a.revoked_by = ${param_idx})")
            params.append(user)
            param_idx += 1

        if from_date:
            conditions.append(f"a.created_at >= ${param_idx}")
            params.append(from_date)
            param_idx += 1

        if to_date:
            conditions.append(f"a.created_at <= ${param_idx}")
            params.append(to_date)
            param_idx += 1

        excluded = _excluded_projects()
        if excluded:
            conditions.append(f"p.name != ALL(${param_idx})")
            params.append(list(excluded))
            param_idx += 1

        where_clause = (" AND ".join(conditions)) if conditions else "true"

        count_query = f"""
            SELECT COUNT(*)
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE {where_clause}
        """
        total = await conn.fetchval(count_query, *params)

        params.extend([per_page, offset])
        data_query = f"""
            SELECT a.id AS acceptance_id,
                   a.accepted_by, a.justification,
                   a.expires_at, a.created_at,
                   a.revoked_at, a.revoked_by,
                   v.cve_id, v.package, v.severity,
                   p.name AS project_name
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE {where_clause}
            ORDER BY a.created_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        rows = await conn.fetch(data_query, *params)

        events = []
        for row in rows:
            action = "accepted"
            action_by = row["accepted_by"]
            action_at = row["created_at"]

            if row["revoked_at"]:
                action = "revoked"
                action_by = row["revoked_by"] or row["accepted_by"]
                action_at = row["revoked_at"]
            elif row["expires_at"] and row["expires_at"] < datetime.now(row["expires_at"].tzinfo):
                action = "expired"

            events.append(
                {
                    "acceptance_id": str(row["acceptance_id"]),
                    "action": action,
                    "action_by": action_by,
                    "action_at": action_at,
                    "accepted_by": row["accepted_by"],
                    "justification": row["justification"],
                    "expires_at": row["expires_at"],
                    "created_at": row["created_at"],
                    "revoked_at": row["revoked_at"],
                    "revoked_by": row["revoked_by"],
                    "cve_id": row["cve_id"],
                    "package": row["package"],
                    "severity": row["severity"],
                    "project_name": row["project_name"],
                }
            )

        return events, total


async def get_last_scan_timestamp() -> datetime | None:
    """Get the timestamp of the most recent scan.

    Returns:
        The imported_at timestamp of the latest scan, or None if no scans exist.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval("SELECT MAX(imported_at) FROM scans")


async def list_projects() -> list[str]:
    """Return all project names, sorted alphabetically."""
    pool = get_pool()
    excluded = _excluded_projects()
    async with pool.acquire() as conn:
        if excluded:
            rows = await conn.fetch(
                "SELECT name FROM projects WHERE name != ALL($1) ORDER BY name",
                list(excluded),
            )
        else:
            rows = await conn.fetch("SELECT name FROM projects ORDER BY name")
        return [row["name"] for row in rows]


async def list_scans_for_backfill() -> list[dict]:
    """List distinct (project, repository, digest) groups with NULL cvss_score vulns.

    Used by the CVSS backfill endpoint to know which Harbor reports to re-fetch.
    """
    pool = get_pool()
    excluded = _excluded_projects()
    extra_condition = ""
    params: list = []
    if excluded:
        extra_condition = "AND p.name != ALL($1)"
        params.append(list(excluded))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT DISTINCT p.name AS project_name, v.repository, s.digest
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN scans s ON s.id = v.scan_id
            WHERE v.cvss_score IS NULL
              AND s.digest IS NOT NULL
              {extra_condition}
            """,
            *params,
        )
        return [dict(row) for row in rows]


async def update_cvss_score(
    cve_id: str,
    package: str,
    repository: str,
    cvss_score: float,
) -> int:
    """Update CVSS score for vulnerabilities matching (cve_id, package, repository).

    Returns number of rows updated.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE vulnerabilities
            SET cvss_score = $4
            WHERE cve_id = $1
              AND package = $2
              AND repository = $3
              AND cvss_score IS NULL
            """,
            cve_id,
            package,
            repository,
            cvss_score,
        )
        return int(result.split()[-1])


async def list_scans_missing_tags() -> list[dict]:
    """List distinct (project, repository, digest) groups with NULL tag.

    Used by the tag backfill endpoint and background resolver to know
    which Harbor artifacts need tag resolution.
    """
    pool = get_pool()
    excluded = _excluded_projects()
    extra_condition = ""
    params: list = []
    if excluded:
        extra_condition = "AND p.name != ALL($1)"
        params.append(list(excluded))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT DISTINCT p.name AS project_name, s.repository, s.digest
            FROM scans s
            JOIN projects p ON p.id = s.project_id
            WHERE s.tag IS NULL
              AND s.digest IS NOT NULL
              {extra_condition}
            """,
            *params,
        )
        return [dict(row) for row in rows]


async def update_scan_tags(
    repository: str,
    digest: str,
    tag: str,
) -> int:
    """Update tag for all scans matching (repository, digest) where tag is NULL.

    Returns number of rows updated.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE scans
            SET tag = $3
            WHERE repository = $1
              AND digest = $2
              AND tag IS NULL
            """,
            repository,
            digest,
            tag,
        )
        return int(result.split()[-1])


SORT_COLUMNS = {
    "cve_id": "v.cve_id",
    "severity": "severity_rank",
    "score": "cvss_score",
    "projects": "project_count",
    "images": "image_count",
    "status": "open_count",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "fix": "has_fix",
}


async def list_cves(
    severity: list[str] | None = None,
    status_filter: list[str] | None = None,
    search: str | None = None,
    page: int = 1,
    per_page: int = 50,
    sort: str | None = None,
    sort_dir: str | None = None,
) -> tuple[list[dict], int]:
    """List unique CVEs aggregated across all projects.

    Args:
        severity: Filter by severity levels (e.g. ['CRITICAL', 'HIGH']).
        status_filter: Aggregate status filters — list of 'open', 'partial', 'accepted', 'fixed'.
                       Multiple values are OR'd. None (default) excludes fully-fixed CVEs.
        search: ILIKE search on cve_id.
        page: Page number (1-indexed).
        per_page: Results per page.
        sort: Column to sort by (must be key in SORT_COLUMNS).
        sort_dir: Sort direction — 'asc' or 'desc'.

    Returns (cves, total_count).
    """
    pool = get_pool()
    offset = (page - 1) * per_page

    async with pool.acquire() as conn:
        # Build WHERE conditions for the inner query
        conditions: list[str] = []
        params: list = []
        param_idx = 1

        if severity:
            conditions.append(f"v.severity = ANY(${param_idx})")
            params.append(severity)
            param_idx += 1

        if search:
            conditions.append(f"v.cve_id ILIKE ${param_idx}")
            params.append(f"%{search}%")
            param_idx += 1

        excluded = _excluded_projects()
        if excluded:
            conditions.append(f"p.name != ALL(${param_idx})")
            params.append(list(excluded))
            param_idx += 1

        where_clause = (" AND ".join(conditions)) if conditions else "true"

        # HAVING clause for aggregate status filter
        # Each selected status contributes conditions AND'd internally,
        # then all selected statuses are OR'd together.
        having_parts: list[str] = []
        if status_filter:
            status_conditions: list[str] = []
            for sf in status_filter:
                if sf == "open":
                    status_conditions.append("COUNT(*) FILTER (WHERE v.status = 'open') > 0")
                elif sf == "partial":
                    status_conditions.append(
                        "(COUNT(*) FILTER (WHERE v.status = 'open') > 0"
                        " AND COUNT(*) FILTER (WHERE v.status = 'accepted') > 0)"
                    )
                elif sf == "accepted":
                    status_conditions.append(
                        "(COUNT(*) FILTER (WHERE v.status = 'open') = 0"
                        " AND COUNT(*) FILTER (WHERE v.status = 'accepted') > 0)"
                    )
                elif sf == "fixed":
                    status_conditions.append("COUNT(*) FILTER (WHERE v.status IN ('open', 'accepted')) = 0")
            if status_conditions:
                having_parts.append("(" + " OR ".join(status_conditions) + ")")
        if not having_parts:
            # Default: exclude fully-fixed CVEs
            having_parts.append("COUNT(*) FILTER (WHERE v.status IN ('open', 'accepted')) > 0")

        having_clause = " AND ".join(having_parts)

        # Count total matching CVEs
        count_query = f"""
            SELECT COUNT(*) FROM (
                SELECT v.cve_id
                FROM vulnerabilities v
                JOIN projects p ON p.id = v.project_id
                WHERE {where_clause}
                GROUP BY v.cve_id
                HAVING {having_clause}
            ) sub
        """
        total = await conn.fetchval(count_query, *params)

        # Build ORDER BY clause
        sort_col = SORT_COLUMNS.get(sort) if sort else None
        direction = "ASC" if sort_dir == "asc" else "DESC"
        if sort_col:
            nulls = "NULLS LAST" if direction == "DESC" else "NULLS FIRST"
            order_clause = f"{sort_col} {direction} {nulls}, severity_rank DESC, last_seen DESC"
        else:
            order_clause = ("cvss_score DESC NULLS LAST, severity_rank DESC, open_count DESC, last_seen DESC")

        # Fetch page of CVEs
        params.extend([per_page, offset])
        data_query = f"""
            SELECT
                v.cve_id,
                MAX(CASE v.severity
                    WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                    WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1
                END) AS severity_rank,
                MAX(v.cvss_score) AS cvss_score,
                COUNT(DISTINCT p.name) AS project_count,
                COUNT(DISTINCT v.repository) AS image_count,
                COUNT(*) FILTER (WHERE v.status = 'open') AS open_count,
                COUNT(*) FILTER (WHERE v.status = 'accepted') AS accepted_count,
                COUNT(*) FILTER (WHERE v.status = 'fixed') AS fixed_count,
                BOOL_OR(
                    (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                    OR cfc.fix_available = true
                ) AS has_fix,
                STRING_AGG(DISTINCT CASE WHEN v.status = 'open' THEN p.name END, ', ') AS open_projects,
                STRING_AGG(DISTINCT CASE WHEN v.status = 'accepted' THEN p.name END, ', ') AS accepted_projects,
                MIN(v.first_seen_at) AS first_seen,
                MAX(v.last_seen_at) AS last_seen
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            WHERE {where_clause}
            GROUP BY v.cve_id
            HAVING {having_clause}
            ORDER BY {order_clause}
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        rows = await conn.fetch(data_query, *params)

        severity_map = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "UNKNOWN"}

        cves = []
        for row in rows:
            cves.append(
                {
                    "cve_id": row["cve_id"],
                    "severity": severity_map.get(row["severity_rank"], "UNKNOWN"),
                    "cvss_score": float(row["cvss_score"]) if row["cvss_score"] is not None else None,
                    "project_count": row["project_count"],
                    "image_count": row["image_count"],
                    "open_count": row["open_count"],
                    "accepted_count": row["accepted_count"],
                    "fixed_count": row["fixed_count"],
                    "has_fix": row["has_fix"] or False,
                    "open_projects": row["open_projects"],
                    "accepted_projects": row["accepted_projects"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
            )

        return cves, total


async def get_cve_instances(cve_id: str) -> list[dict]:
    """Get all instances of a CVE across projects with acceptance info.

    Returns list of vulnerability instances with project name and active acceptance details.
    """
    pool = get_pool()
    excluded = _excluded_projects()
    extra_condition = ""
    query_params: list = [cve_id]
    if excluded:
        extra_condition = "AND p.name != ALL($2)"
        query_params.append(list(excluded))

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT
                v.id, v.cve_id, v.package, v.repository,
                v.installed_version, v.fixed_version, v.severity,
                v.cvss_score,
                v.status, v.description, v."references",
                v.first_seen_at, v.last_seen_at,
                p.name AS project_name,
                a.id AS acceptance_id, a.accepted_by, a.justification,
                a.expires_at AS acceptance_expires_at,
                a.created_at AS acceptance_created_at
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            LEFT JOIN LATERAL (
                SELECT id, accepted_by, justification, expires_at, created_at
                FROM acceptances
                WHERE vulnerability_id = v.id
                  AND revoked_at IS NULL
                  AND expires_at > now()
                ORDER BY created_at DESC
                LIMIT 1
            ) a ON true
            WHERE v.cve_id = $1
              {extra_condition}
            ORDER BY
                p.name,
                CASE v.status
                    WHEN 'open' THEN 1 WHEN 'accepted' THEN 2 ELSE 3
                END,
                v.repository
            """,
            *query_params,
        )

        instances = []
        for row in rows:
            inst = {
                "id": str(row["id"]),
                "cve_id": row["cve_id"],
                "package": row["package"],
                "repository": row["repository"],
                "installed_version": row["installed_version"],
                "fixed_version": row["fixed_version"],
                "severity": row["severity"],
                "cvss_score": float(row["cvss_score"]) if row["cvss_score"] is not None else None,
                "status": row["status"],
                "description": row["description"],
                "references": row["references"],
                "first_seen_at": row["first_seen_at"],
                "last_seen_at": row["last_seen_at"],
                "project_name": row["project_name"],
                "acceptance": None,
            }
            if row["acceptance_id"]:
                inst["acceptance"] = {
                    "id": str(row["acceptance_id"]),
                    "accepted_by": row["accepted_by"],
                    "justification": row["justification"],
                    "expires_at": row["acceptance_expires_at"],
                    "created_at": row["acceptance_created_at"],
                }
            instances.append(inst)

        return instances


async def cascade_accept_in_project(
    vuln_id: str,
    accepted_by: str,
    justification: str,
    expires_at: datetime,
) -> list[dict]:
    """Accept a CVE across all open instances in the same project.

    Harbor CVE allowlists are CVE-ID scoped — accepting one instance effectively
    allows the CVE across the entire project. This function cascades the acceptance
    to all open siblings so the UI reflects reality.

    Returns list of created acceptances (same shape as bulk_accept).
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        # Look up trigger vulnerability
        trigger = await conn.fetchrow(
            """
            SELECT v.cve_id, v.project_id, p.name AS project_name
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            WHERE v.id = $1::uuid
            """,
            uuid.UUID(vuln_id),
        )
        if not trigger:
            raise ValueError("Vulnerability not found")

        cve_id = trigger["cve_id"]
        project_id = trigger["project_id"]
        project_name = trigger["project_name"]

        # Find all open instances of this CVE in the project
        rows = await conn.fetch(
            """
            SELECT v.id, v.cve_id
            FROM vulnerabilities v
            WHERE v.project_id = $1 AND v.cve_id = $2 AND v.status = 'open'
            """,
            project_id,
            cve_id,
        )

        acceptances = []
        async with conn.transaction():
            for row in rows:
                vid = row["id"]
                # Skip if already has an active acceptance
                existing = await conn.fetchval(
                    """
                    SELECT id FROM acceptances
                    WHERE vulnerability_id = $1
                      AND revoked_at IS NULL
                      AND expires_at > now()
                    """,
                    vid,
                )
                if existing:
                    continue

                acc_row = await conn.fetchrow(
                    """
                    INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                    """,
                    vid,
                    accepted_by,
                    justification,
                    expires_at,
                )

                await conn.execute(
                    "UPDATE vulnerabilities SET status = 'accepted' WHERE id = $1",
                    vid,
                )

                acceptances.append(
                    {
                        "acceptance_id": str(acc_row["id"]),
                        "vulnerability_id": str(vid),
                        "cve_id": cve_id,
                        "project_name": project_name,
                        "status": "accepted",
                    }
                )

        return acceptances


async def cascade_revoke_in_project(
    acceptance_id: str,
    revoked_by: str,
) -> list[dict]:
    """Revoke a CVE acceptance across all instances in the same project.

    Mirrors cascade_accept_in_project — when revoking, all active acceptances
    for the same CVE in the project are revoked together.

    Returns list of revoked acceptances.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        # Look up trigger acceptance
        trigger = await conn.fetchrow(
            """
            SELECT a.vulnerability_id, v.cve_id, v.project_id, p.name AS project_name
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            JOIN projects p ON p.id = v.project_id
            WHERE a.id = $1::uuid
            """,
            uuid.UUID(acceptance_id),
        )
        if not trigger:
            raise ValueError("Acceptance not found")

        cve_id = trigger["cve_id"]
        project_id = trigger["project_id"]
        project_name = trigger["project_name"]

        # Find all active acceptances for this CVE in the project
        rows = await conn.fetch(
            """
            SELECT a.id AS acceptance_id, a.vulnerability_id
            FROM acceptances a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE v.project_id = $1 AND v.cve_id = $2
              AND a.revoked_at IS NULL AND a.expires_at > now()
            """,
            project_id,
            cve_id,
        )

        revoked = []
        async with conn.transaction():
            for row in rows:
                await conn.execute(
                    """
                    UPDATE acceptances
                    SET revoked_at = now(), revoked_by = $2
                    WHERE id = $1 AND revoked_at IS NULL
                    """,
                    row["acceptance_id"],
                    revoked_by,
                )

                await conn.execute(
                    "UPDATE vulnerabilities SET status = 'open' WHERE id = $1",
                    row["vulnerability_id"],
                )

                revoked.append(
                    {
                        "acceptance_id": str(row["acceptance_id"]),
                        "vulnerability_id": str(row["vulnerability_id"]),
                        "cve_id": cve_id,
                        "project_name": project_name,
                    }
                )

        return revoked


async def get_open_siblings(vuln_id: str) -> list[dict]:
    """Get open instances of the same CVE in the same project.

    Returns list of dicts with keys: repository, package.
    Used to show cascade scope in the accept form.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT v.repository, v.package
            FROM vulnerabilities v
            WHERE v.project_id = (SELECT project_id FROM vulnerabilities WHERE id = $1::uuid)
              AND v.cve_id = (SELECT cve_id FROM vulnerabilities WHERE id = $1::uuid)
              AND v.status = 'open'
            ORDER BY v.repository, v.package
            """,
            uuid.UUID(vuln_id),
        )
        return [{"repository": r["repository"], "package": r["package"]} for r in rows]


async def import_seed_acceptances(seed_path: str) -> int:
    """Import acceptance seed data from JSON file into the database.

    Checks if the database already contains acceptances before importing.
    Creates stub scans and vulnerabilities for each CVE, then inserts acceptances.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        existing_count = await conn.fetchval("SELECT COUNT(*) FROM acceptances")
        if existing_count > 0:
            return 0

        try:
            with open(seed_path, encoding="utf-8") as f:
                seed_data = json.load(f)
        except Exception as e:
            logger.error("Failed to read seed file", extra={"path": seed_path, "error": str(e)})
            return 0

        acceptances_list = seed_data.get("acceptances", [])
        count = 0

        async with conn.transaction():
            for entry in acceptances_list:
                project_name = entry["project"]
                cve_id = entry["cve_id"]
                justification = entry["justification"]

                project_id = await upsert_project(project_name, conn=conn)

                scan_id = await create_scan(
                    project_id,
                    image="imported",
                    repository="imported",
                    digest=None,
                    scanner="migration",
                    total=0,
                    critical=0,
                    high=0,
                    medium=0,
                    low=0,
                    unknown=0,
                    conn=conn,
                )

                vuln_id_row = await conn.fetchrow(
                    """
                    INSERT INTO vulnerabilities (project_id, cve_id, package, repository, severity, status, scan_id)
                    VALUES ($1::uuid, $2, 'imported', 'imported', 'UNKNOWN', 'accepted', $3::uuid)
                    ON CONFLICT (project_id, cve_id, package, repository) DO NOTHING
                    RETURNING id
                    """,
                    uuid.UUID(project_id),
                    cve_id,
                    uuid.UUID(scan_id),
                )

                if vuln_id_row:
                    vuln_id = vuln_id_row["id"]
                else:
                    vuln_id = await conn.fetchval(
                        """
                        SELECT id FROM vulnerabilities
                        WHERE project_id = $1::uuid
                          AND cve_id = $2
                          AND package = 'imported'
                          AND repository = 'imported'
                        """,
                        uuid.UUID(project_id),
                        cve_id,
                    )

                expires_at = datetime.now(timezone.utc) + timedelta(days=90)

                await conn.execute(
                    """
                    INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                    VALUES ($1::uuid, 'migration', $2, $3)
                    """,
                    vuln_id,
                    justification,
                    expires_at,
                )

                count += 1

        logger.info("Migration seed imported", extra={"count": count})
        return count


async def cleanup_migration_stubs() -> dict:
    """Cascade active stub acceptances to real open vulnerabilities, then delete all stubs.

    Migration seed (M7) created stub records (package='imported', repository='imported')
    to preserve Harbor CVE allowlists during initial deployment. Now that real scan data
    has replaced them, stubs create confusion — e.g. a CVE shows 1 "accepted" instance
    (migration stub) alongside N open real instances.

    Single transaction:
    1. Find stubs with active acceptances → cascade to real open instances
    2. Delete all acceptances referencing stub vulnerability IDs
    3. Delete stub vulnerabilities
    4. Delete orphaned migration scans

    Returns counts: {acceptances_cascaded, stub_acceptances_deleted,
                     stub_vulnerabilities_deleted, stub_scans_deleted}
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # 1. Find all migration stubs with their active acceptance (if any)
            stubs = await conn.fetch(
                """
                SELECT v.id AS vuln_id, v.project_id, v.cve_id,
                       a.id AS acceptance_id, a.accepted_by, a.justification, a.expires_at
                FROM vulnerabilities v
                LEFT JOIN LATERAL (
                    SELECT id, accepted_by, justification, expires_at
                    FROM acceptances
                    WHERE vulnerability_id = v.id
                      AND revoked_at IS NULL
                      AND expires_at > now()
                    ORDER BY created_at DESC
                    LIMIT 1
                ) a ON true
                WHERE v.package = 'imported' AND v.repository = 'imported'
                """,
            )

            if not stubs:
                return {
                    "acceptances_cascaded": 0,
                    "stub_acceptances_deleted": 0,
                    "stub_vulnerabilities_deleted": 0,
                    "stub_scans_deleted": 0,
                }

            stub_vuln_ids = [row["vuln_id"] for row in stubs]
            acceptances_cascaded = 0

            # 2. For each stub with an active acceptance, cascade to real open instances
            for stub in stubs:
                if stub["acceptance_id"] is None:
                    continue

                # Find real open vulnerabilities for the same (project, CVE)
                real_open = await conn.fetch(
                    """
                    SELECT v.id
                    FROM vulnerabilities v
                    LEFT JOIN LATERAL (
                        SELECT id FROM acceptances
                        WHERE vulnerability_id = v.id
                          AND revoked_at IS NULL
                          AND expires_at > now()
                        LIMIT 1
                    ) a ON true
                    WHERE v.project_id = $1
                      AND v.cve_id = $2
                      AND v.status = 'open'
                      AND NOT (v.package = 'imported' AND v.repository = 'imported')
                      AND a.id IS NULL
                    """,
                    stub["project_id"],
                    stub["cve_id"],
                )

                for real in real_open:
                    await conn.execute(
                        """
                        INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                        VALUES ($1, $2, $3, $4)
                        """,
                        real["id"],
                        stub["accepted_by"],
                        stub["justification"],
                        stub["expires_at"],
                    )
                    await conn.execute(
                        "UPDATE vulnerabilities SET status = 'accepted' WHERE id = $1",
                        real["id"],
                    )
                    acceptances_cascaded += 1

            # 3. Delete all acceptances referencing stub vulnerability IDs (FK constraint)
            del_acc = await conn.execute(
                "DELETE FROM acceptances WHERE vulnerability_id = ANY($1::uuid[])",
                stub_vuln_ids,
            )
            stub_acceptances_deleted = int(del_acc.split()[-1])

            # 4. Delete stub vulnerabilities
            del_vuln = await conn.execute(
                "DELETE FROM vulnerabilities WHERE id = ANY($1::uuid[])",
                stub_vuln_ids,
            )
            stub_vulnerabilities_deleted = int(del_vuln.split()[-1])

            # 5. Delete orphaned migration scans (no remaining vulnerabilities)
            del_scans = await conn.execute(
                """
                DELETE FROM scans s
                WHERE s.scanner = 'migration'
                  AND NOT EXISTS (
                      SELECT 1 FROM vulnerabilities v WHERE v.scan_id = s.id
                  )
                """,
            )
            stub_scans_deleted = int(del_scans.split()[-1])

        results = {
            "acceptances_cascaded": acceptances_cascaded,
            "stub_acceptances_deleted": stub_acceptances_deleted,
            "stub_vulnerabilities_deleted": stub_vulnerabilities_deleted,
            "stub_scans_deleted": stub_scans_deleted,
        }
        logger.info("Migration stub cleanup completed", extra=results)
        return results


# --- OSV fix-check queries ---


async def get_accepted_without_fixed_version(cache_ttl_seconds: int = 86400,) -> list[dict]:
    """Return distinct CVE IDs for accepted vulns with no Trivy fixed_version.

    Excludes:
    - CVEs already checked within cache_ttl_seconds AND fix_available = true
      (fix doesn't un-exist — skip permanently once found)
    - CVEs checked within cache_ttl_seconds AND fix_available = false
      (honour TTL for negative results too)
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT v.cve_id
            FROM vulnerabilities v
            WHERE v.status = 'accepted'
              AND (v.fixed_version IS NULL OR v.fixed_version = '')
              AND NOT EXISTS (
                  SELECT 1 FROM cve_fix_checks cfc
                  WHERE cfc.cve_id = v.cve_id
                    AND (
                        cfc.fix_available = true
                        OR cfc.checked_at > now() - ($1 || ' seconds')::interval
                    )
              )
            """,
            str(cache_ttl_seconds),
        )
        return [{"cve_id": row["cve_id"]} for row in rows]


async def upsert_fix_check(
    cve_id: str,
    fix_available: bool,
    fixed_versions: list | None,
    raw_response: dict,
    *,
    conn: asyncpg.Connection | None = None,
) -> None:
    """Upsert a CVE fix check result into cve_fix_checks."""
    async with _conn_or_acquire(conn) as c:
        await c.execute(
            """
            INSERT INTO cve_fix_checks (cve_id, fix_available, fixed_versions, source, checked_at, raw_response)
            VALUES ($1, $2, $3::jsonb, 'osv', now(), $4::jsonb)
            ON CONFLICT (cve_id) DO UPDATE SET
                fix_available  = EXCLUDED.fix_available,
                fixed_versions = EXCLUDED.fixed_versions,
                checked_at     = EXCLUDED.checked_at,
                raw_response   = EXCLUDED.raw_response
            """,
            cve_id,
            fix_available,
            json.dumps(fixed_versions) if fixed_versions is not None else None,
            json.dumps(raw_response) if raw_response else None,
        )


def _parse_acceptance(raw: str | None) -> dict | None:
    """Parse a JSON-encoded acceptance dict, converting expires_at to datetime."""
    if not raw:
        return None
    acc = json.loads(raw)
    if acc.get("expires_at"):
        acc["expires_at"] = datetime.fromisoformat(acc["expires_at"])
    return acc


async def list_fixable_vulnerabilities(
    project_name: str,
    severity: list[str] | None = None,
    source: str | None = None,
    page: int = 1,
    per_page: int = 100,
    sort_by: str = "severity",
    sort_order: str = "asc",
) -> tuple[list[dict], int]:
    """Return accepted vulns where a fix is known (Trivy or OSV).

    fix_source values: 'trivy' | 'osv' | 'both'
    sort_by: 'severity' | 'cve' | 'package' | 'repository' | 'fix_source' | 'project' | 'accepted_by' | 'expires'
    sort_order: 'asc' | 'desc'
    """
    pool = get_pool()
    offset = (page - 1) * per_page

    # Map sort_by to SQL column
    sort_column_map = {
        "severity":
            "CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END",
        "cve":
            "v.cve_id",
        "package":
            "v.package",
        "repository":
            "v.repository",
        "fix_source":
            "CASE WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '') AND cfc.fix_available = true THEN 'both' WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '') THEN 'trivy' ELSE 'osv' END",
        "project":
            "p.name",
        "accepted_by":
            "a.accepted_by",
        "expires":
            "a.expires_at",
    }

    sort_column = sort_column_map.get(sort_by, sort_column_map["severity"])
    sort_direction = "DESC" if sort_order == "desc" else "ASC"

    # Secondary sort: if sorting by severity, add cve_id; otherwise add severity then cve_id
    if sort_by == "severity":
        order_clause = f"{sort_column} {sort_direction}, v.cve_id ASC"
    else:
        order_clause = f"{sort_column} {sort_direction}, CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END ASC, v.cve_id ASC"

    async with pool.acquire() as conn:
        conditions = [
            "p.name = $1",
            "v.status = 'accepted'",
            "a.revoked_at IS NULL",
            "a.expires_at > now()",
            "(  (v.fixed_version IS NOT NULL AND v.fixed_version != '')"
            "   OR cfc.fix_available = true  )",
        ]
        params: list = [project_name]
        param_idx = 2

        if severity:
            conditions.append(f"v.severity = ANY(${param_idx})")
            params.append(severity)
            param_idx += 1

        if source == "trivy":
            conditions.append("(v.fixed_version IS NOT NULL AND v.fixed_version != '')")
        elif source == "osv":
            conditions.append("(cfc.fix_available = true AND (v.fixed_version IS NULL OR v.fixed_version = ''))")

        where_clause = " AND ".join(conditions)

        total = await conn.fetchval(
            f"""
            SELECT COUNT(*)
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            WHERE {where_clause}
            """,
            *params,
        )

        params.extend([per_page, offset])
        rows = await conn.fetch(
            f"""
            SELECT
                v.id, v.cve_id, v.package, v.repository,
                v.severity, v.installed_version, v.fixed_version,
                cfc.fixed_versions AS osv_fixed_versions,
                CASE
                    WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                         AND cfc.fix_available = true THEN 'both'
                    WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '') THEN 'trivy'
                    ELSE 'osv'
                END AS fix_source,
                json_build_object(
                    'id', a.id::text,
                    'accepted_by', a.accepted_by,
                    'justification', a.justification,
                    'expires_at', a.expires_at
                ) AS acceptance,
                p.name as project_name
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            WHERE {where_clause}
            ORDER BY {order_clause}
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """,
            *params,
        )

        return [
            {
                "id": str(row["id"]),
                "cve_id": row["cve_id"],
                "package": row["package"],
                "repository": row["repository"],
                "severity": row["severity"],
                "installed_version": row["installed_version"],
                "fixed_version": row["fixed_version"],
                "osv_fixed_versions": json.loads(row["osv_fixed_versions"]) if row["osv_fixed_versions"] else None,
                "fix_source": row["fix_source"],
                "acceptance": _parse_acceptance(row["acceptance"]),
                "project": project_name,
            } for row in rows
        ], total


async def reconcile_accepted_cves_for_project(project_name: str) -> list[dict]:
    """Auto-accept open vulnerability instances whose CVE is already accepted in the project.

    Uses a single CTE to find open instances, create acceptances mirroring the
    existing one, and update vulnerability status. Idempotent — already-accepted
    instances are excluded.

    Returns list of reconciled instances: [{"vuln_id": str, "cve_id": str}, ...]
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            rows = await conn.fetch(
                """
                WITH active_acceptances AS (
                    -- For each CVE in the project, pick the acceptance with the latest expiry
                    SELECT DISTINCT ON (v.cve_id)
                           v.cve_id,
                           v.project_id,
                           a.accepted_by,
                           a.justification,
                           a.expires_at
                    FROM vulnerabilities v
                    JOIN projects p ON p.id = v.project_id
                    JOIN acceptances a ON a.vulnerability_id = v.id
                    WHERE p.name = $1
                      AND a.revoked_at IS NULL
                      AND a.expires_at > now()
                    ORDER BY v.cve_id, a.expires_at DESC
                ),
                open_targets AS (
                    -- Open instances of those CVEs that lack an active acceptance
                    SELECT v.id AS vuln_id,
                           v.cve_id,
                           aa.accepted_by,
                           aa.justification,
                           aa.expires_at
                    FROM vulnerabilities v
                    JOIN active_acceptances aa
                      ON aa.project_id = v.project_id AND aa.cve_id = v.cve_id
                    WHERE v.status = 'open'
                      AND NOT EXISTS (
                          SELECT 1 FROM acceptances ex
                          WHERE ex.vulnerability_id = v.id
                            AND ex.revoked_at IS NULL
                            AND ex.expires_at > now()
                      )
                ),
                inserted AS (
                    -- Create mirrored acceptances with audit-trail prefix
                    INSERT INTO acceptances (vulnerability_id, accepted_by, justification, expires_at)
                    SELECT ot.vuln_id,
                           'harbor-exempt:auto-reconcile/' || ot.accepted_by,
                           ot.justification,
                           ot.expires_at
                    FROM open_targets ot
                    RETURNING vulnerability_id
                )
                -- Flip matched vulnerabilities to accepted and return their details
                UPDATE vulnerabilities v
                SET status = 'accepted'
                FROM inserted i
                WHERE v.id = i.vulnerability_id
                RETURNING v.id, v.cve_id
                """,
                project_name,
            )

            return [{"vuln_id": str(row["id"]), "cve_id": row["cve_id"]} for row in rows]


async def get_fixable_counts() -> list[dict]:
    """Per-project / severity / source counts for VULNS_FIXABLE gauge refresh."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                p.name AS project,
                v.severity,
                CASE
                    WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                         AND cfc.fix_available = true THEN 'both'
                    WHEN (v.fixed_version IS NOT NULL AND v.fixed_version != '') THEN 'trivy'
                    ELSE 'osv'
                END AS source,
                COUNT(*) AS cnt
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            JOIN acceptances a ON a.vulnerability_id = v.id
            LEFT JOIN cve_fix_checks cfc ON cfc.cve_id = v.cve_id
            WHERE v.status = 'accepted'
              AND a.revoked_at IS NULL
              AND a.expires_at > now()
              AND (
                  (v.fixed_version IS NOT NULL AND v.fixed_version != '')
                  OR cfc.fix_available = true
              )
            GROUP BY p.name, v.severity, 3
            ORDER BY p.name, v.severity
            """
        )
        return [dict(row) for row in rows]


async def list_app_repositories(project_name: str) -> list[str]:
    """List all distinct repositories in Harbor Exempt for a given project.

    Returns:
        List of repository names (e.g., ["platform/app", "platform/worker"])
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT v.repository
            FROM vulnerabilities v
            JOIN projects p ON p.id = v.project_id
            WHERE p.name = $1
            ORDER BY v.repository
            """,
            project_name,
        )
        return [row["repository"] for row in rows]


async def delete_vulnerabilities_for_repository(repository: str) -> int:
    """Delete all vulnerabilities for a given repository.

    Cascades to acceptances via foreign key constraint.

    Returns:
        Number of vulnerabilities deleted
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM vulnerabilities
            WHERE repository = $1
            """,
            repository,
        )
        # Result is like "DELETE 42", extract the count
        return int(result.split()[-1]) if result else 0
