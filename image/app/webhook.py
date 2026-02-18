"""Harbor webhook handler for Harbor Exempt.

Receives Harbor scan-complete webhook events, fetches the full
vulnerability report from Harbor's API, maps Harbor fields to
Harbor Exempt format, and calls the scan ingest logic internally.
"""

import logging
import time

from fastapi import APIRouter, HTTPException

from app.db import (
    acquire,
    create_scan,
    mark_fixed,
    reconcile_accepted_cves_for_project,
    upsert_project,
    upsert_vulnerability,
)
from app.harbor import extract_repository, extract_tag
from app.metrics import (
    AUTO_RECONCILE_TOTAL,
    SCAN_PROCESSING_DURATION,
    SCANS_TOTAL,
    VULNS_INGESTED_TOTAL,
)
from app.models import HarborWebhookPayload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["webhooks"])


def _map_harbor_vulnerability(vuln: dict) -> dict:
    """Map Harbor vulnerability fields to Harbor Exempt format."""
    # Extract CVSS v3 score from Trivy's preferred_cvss structure
    cvss_score = None
    preferred_cvss = vuln.get("preferred_cvss")
    if preferred_cvss and isinstance(preferred_cvss, dict):
        cvss_score = preferred_cvss.get("score_v3")
    return {
        "cve_id": vuln.get("id", ""),
        "package": vuln.get("package", ""),
        "installed_version": vuln.get("version", ""),
        "fixed_version": vuln.get("fix_version") or None,
        "severity": (vuln.get("severity") or "UNKNOWN").upper(),
        "cvss_score": cvss_score,
        "description": vuln.get("description", ""),
        "references": vuln.get("links") or [],
    }


@router.post("/webhooks/harbor")
async def harbor_webhook(payload: HarborWebhookPayload,) -> dict:
    """Receive Harbor scan-complete webhook.

    1. Parse the webhook event to extract project, repository, digest
    2. Fetch full vulnerability report from Harbor API
    3. Map Harbor fields to Harbor Exempt format
    4. Call scan ingest logic internally
    """
    from app.main import get_harbor_client

    if payload.type != "SCANNING_COMPLETED":
        logger.debug("Ignoring non-scan webhook", extra={"type": payload.type})
        return {"status": "ignored", "reason": f"event type {payload.type} not handled"}

    start_time = time.monotonic()

    event_data = payload.event_data
    logger.debug("Raw Harbor webhook event_data", extra={"event_data": event_data})

    resources = event_data.get("resources", [])
    if not resources:
        raise HTTPException(status_code=400, detail="No resources in webhook payload")

    resource = resources[0]
    # resource_url may contain the hostname (e.g. localhost:8088/platform/library/debian:tag)
    # so we only use it as the display image reference for logging and scan records
    image_ref = resource.get("resource_url", "")
    digest = resource.get("digest", "")

    # Prefer structured repository data from event_data when available.
    # Harbor sends event_data.repository with:
    #   namespace      — project name (e.g. "platform")
    #   repo_full_name — full path (e.g. "platform/library/debian")
    #   name           — path within project (e.g. "library/debian")
    repo_data = event_data.get("repository", {})
    if repo_data and "namespace" in repo_data:
        project_name = repo_data["namespace"]
        repository = repo_data.get("repo_full_name", "")
    else:
        # Fallback: strip hostname from resource_url using extract_repository
        logger.warning(
            "No repository metadata in webhook payload, falling back to resource_url parsing",
            extra={"resource_url": image_ref},
        )
        repository = extract_repository(image_ref)
        project_name = repository.split("/")[0] if "/" in repository else repository

    # Skip excluded projects before any further processing
    from app.config import get_settings
    if project_name in get_settings().excluded_projects_set:
        logger.info("Ignoring webhook for excluded project", extra={"project": project_name})
        return {"status": "ignored", "reason": f"project {project_name} is excluded"}

    # Extract tag from image reference (free, no API call)
    tag = extract_tag(image_ref)

    harbor = get_harbor_client()
    if not harbor:
        raise HTTPException(status_code=503, detail="Harbor client not configured")

    # Resolve tag from Harbor if not present in the image reference
    if tag is None and digest:
        try:
            tag = await harbor.resolve_tag(
                project=project_name,
                repository=repository,
                digest=digest,
            )
        except Exception:
            logger.debug(
                "Tag resolution failed, background job will retry",
                extra={
                    "project": project_name,
                    "repository": repository,
                    "digest": digest
                },
            )

    # Fetch full vulnerability report
    try:
        report = await harbor.fetch_vulnerability_report(
            project=project_name,
            repository=repository,
            digest=digest,
        )
    except Exception as e:
        logger.error(
            "Failed to fetch vulnerability report from Harbor",
            extra={
                "project": project_name,
                "repository": repository,
                "error": str(e)
            },
        )
        raise HTTPException(status_code=502, detail=f"Failed to fetch report: {e}")

    harbor_vulns = report["vulnerabilities"]
    push_time = report.get("push_time")
    pull_time = report.get("pull_time")

    # Map to Harbor Exempt format and ingest
    vulnerabilities = [_map_harbor_vulnerability(v) for v in harbor_vulns]

    # Pre-compute severity counts (no DB needed)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulnerabilities:
        sev = v["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    # All DB writes in a single transaction
    async with acquire() as conn:
        async with conn.transaction():
            project_id = await upsert_project(project_name, conn=conn)

            scan_id = await create_scan(
                project_id=project_id,
                image=image_ref,
                repository=repository,
                digest=digest,
                scanner="Trivy",
                total=len(vulnerabilities),
                critical=severity_counts["CRITICAL"],
                high=severity_counts["HIGH"],
                medium=severity_counts["MEDIUM"],
                low=severity_counts["LOW"],
                unknown=severity_counts["UNKNOWN"],
                tag=tag,
                push_time=push_time,
                pull_time=pull_time,
                conn=conn,
            )

            created = 0
            updated = 0
            reported_cve_ids: set[str] = set()

            for v in vulnerabilities:
                reported_cve_ids.add(v["cve_id"])
                vuln_id, is_new = await upsert_vulnerability(
                    project_id=project_id,
                    scan_id=scan_id,
                    cve_id=v["cve_id"],
                    package=v["package"],
                    repository=repository,
                    installed_version=v["installed_version"],
                    fixed_version=v["fixed_version"],
                    severity=v["severity"],
                    description=v["description"],
                    references=v["references"],
                    cvss_score=v.get("cvss_score"),
                    conn=conn,
                )
                if is_new:
                    created += 1
                else:
                    updated += 1

            fixed = await mark_fixed(project_id, repository, scan_id, reported_cve_ids, conn=conn)

    # Auto-reconcile: apply existing project-level acceptances to new instances
    if created > 0:
        try:
            reconciled = await reconcile_accepted_cves_for_project(project_name)
            if reconciled:
                AUTO_RECONCILE_TOTAL.labels(project=project_name, trigger="webhook").inc(len(reconciled))
                logger.info(
                    "Auto-reconciled acceptances after webhook ingest",
                    extra={
                        "project": project_name,
                        "repository": repository,
                        "reconciled_count": len(reconciled),
                        "cves": [r["cve_id"] for r in reconciled],
                    },
                )
        except Exception:
            logger.warning(
                "Auto-reconcile failed after webhook ingest",
                extra={
                    "project": project_name,
                    "repository": repository
                },
                exc_info=True,
            )

    logger.info(
        "Harbor webhook processed",
        extra={
            "project": project_name,
            "repository": repository,
            "digest": digest,
            "vulns_created": created,
            "vulns_updated": updated,
            "vulns_fixed": fixed,
            "vulns_total": len(vulnerabilities),
        },
    )

    # Update metrics
    SCANS_TOTAL.labels(project=project_name).inc()
    VULNS_INGESTED_TOTAL.labels(project=project_name, status="created").inc(created)
    VULNS_INGESTED_TOTAL.labels(project=project_name, status="updated").inc(updated)
    VULNS_INGESTED_TOTAL.labels(project=project_name, status="fixed").inc(fixed)
    SCAN_PROCESSING_DURATION.observe(time.monotonic() - start_time)

    return {
        "status": "processed",
        "scan_id": scan_id,
        "project": project_name,
        "created": created,
        "updated": updated,
        "fixed": fixed,
        "total": len(vulnerabilities),
    }
