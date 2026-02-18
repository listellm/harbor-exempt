"""Scan ingest route for Harbor Exempt."""

import logging
import time

from fastapi import APIRouter

from app.db import acquire, create_scan, mark_fixed, upsert_project, upsert_vulnerability
from app.harbor import extract_repository
from app.metrics import SCAN_PROCESSING_DURATION, SCANS_TOTAL, VULNS_INGESTED_TOTAL
from app.models import ScanRequest, ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post("/scans", response_model=ScanResponse, status_code=201)
async def ingest_scan(request: ScanRequest,) -> ScanResponse:
    """Ingest a scan and upsert vulnerabilities.

    1. Upsert project by name
    2. Extract repository from image reference
    3. Create scan record
    4. Upsert each vulnerability
    5. Mark as fixed any vulns for this (project, repository) not in this scan
    """
    start_time = time.monotonic()

    # Pre-compute severity counts (no DB needed)
    repository = extract_repository(request.image)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in request.vulnerabilities:
        sev = vuln.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # All DB writes in a single transaction — if any step fails, everything rolls back
    async with acquire() as conn:
        async with conn.transaction():
            # 1. Upsert project
            project_id = await upsert_project(request.project, conn=conn)

            # 2. Create scan record
            scan_id = await create_scan(
                project_id=project_id,
                image=request.image,
                repository=repository,
                digest=request.digest,
                scanner=request.scanner,
                total=len(request.vulnerabilities),
                critical=severity_counts["CRITICAL"],
                high=severity_counts["HIGH"],
                medium=severity_counts["MEDIUM"],
                low=severity_counts["LOW"],
                unknown=severity_counts["UNKNOWN"],
                conn=conn,
            )

            # 3. Upsert vulnerabilities
            created = 0
            updated = 0
            reported_cve_ids: set[str] = set()

            for vuln in request.vulnerabilities:
                reported_cve_ids.add(vuln.cve_id)
                vuln_id, is_new = await upsert_vulnerability(
                    project_id=project_id,
                    scan_id=scan_id,
                    cve_id=vuln.cve_id,
                    package=vuln.package,
                    repository=repository,
                    installed_version=vuln.installed_version,
                    fixed_version=vuln.fixed_version,
                    severity=vuln.severity.upper(),
                    description=vuln.description,
                    references=vuln.references,
                    cvss_score=vuln.cvss_score,
                    conn=conn,
                )
                if is_new:
                    created += 1
                else:
                    updated += 1

            # 4. Mark fixed — scoped to (project_id, repository)
            fixed = await mark_fixed(project_id, repository, scan_id, reported_cve_ids, conn=conn)

    logger.info(
        "Scan ingested",
        extra={
            "project": request.project,
            "repository": repository,
            "scan_id": scan_id,
            "vulns_created": created,
            "vulns_updated": updated,
            "vulns_fixed": fixed,
            "vulns_total": len(request.vulnerabilities),
        },
    )

    # Update metrics
    SCANS_TOTAL.labels(project=request.project).inc()
    VULNS_INGESTED_TOTAL.labels(project=request.project, status="created").inc(created)
    VULNS_INGESTED_TOTAL.labels(project=request.project, status="updated").inc(updated)
    VULNS_INGESTED_TOTAL.labels(project=request.project, status="fixed").inc(fixed)
    SCAN_PROCESSING_DURATION.observe(time.monotonic() - start_time)

    return ScanResponse(
        scan_id=scan_id,
        project=request.project,
        created=created,
        updated=updated,
        fixed=fixed,
        total=len(request.vulnerabilities),
    )
