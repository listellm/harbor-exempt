"""Vulnerability management routes for Harbor Exempt."""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query

from app.config import get_settings
from app.db import (
    bulk_accept,
    cascade_accept_in_project,
    cascade_revoke_in_project,
    get_vulnerability,
    list_fixable_vulnerabilities,
    list_vulnerabilities,
)
from app.metrics import ACCEPTANCES_CREATED_TOTAL, ACCEPTANCES_REVOKED_TOTAL
from app.models import (
    AcceptRequest,
    AcceptResponse,
    BulkAcceptRequest,
    BulkAcceptResponse,
    FixableVulnerabilityResponse,
    RevokeRequest,
    VulnerabilityListResponse,
    VulnerabilityResponse,
)
from app.scheduler import request_sync

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])


@router.get(
    "/projects/{project}/fixable",
    response_model=list[FixableVulnerabilityResponse],
)
async def list_fixable(
    project: str,
    severity: str | None = Query(default=None, description="Comma-separated severities"),
    source: str | None = Query(default=None, description="Filter by fix source: trivy, osv"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=100, ge=1, le=500),
) -> list[FixableVulnerabilityResponse]:
    """List accepted vulnerabilities with a known fix available (Trivy or OSV)."""
    severity_list = None
    if severity:
        severity_list = [s.strip().upper() for s in severity.split(",")]

    vulns, _total = await list_fixable_vulnerabilities(
        project_name=project,
        severity=severity_list,
        source=source,
        page=page,
        per_page=per_page,
    )

    return [FixableVulnerabilityResponse(**v) for v in vulns]


@router.get("/projects/{project}/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_project_vulnerabilities(
    project: str,
    status: str | None = Query(default=None, description="Filter: open, accepted, fixed"),
    severity: str | None = Query(default=None, description="Comma-separated severities"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=100, ge=1, le=500),
) -> VulnerabilityListResponse:
    """List vulnerabilities for a project with optional filters."""
    severity_list = None
    if severity:
        severity_list = [s.strip().upper() for s in severity.split(",")]

    vulnerabilities, total = await list_vulnerabilities(
        project_name=project,
        status=[status] if status else None,
        severity=severity_list,
        page=page,
        per_page=per_page,
    )

    return VulnerabilityListResponse(
        project=project,
        total=total,
        page=page,
        per_page=per_page,
        vulnerabilities=[VulnerabilityResponse(**v) for v in vulnerabilities],
    )


@router.post("/vulnerabilities/{vuln_id}/accept", response_model=AcceptResponse, status_code=201)
async def accept_risk(
    vuln_id: str,
    request: AcceptRequest,
) -> AcceptResponse:
    """Accept risk for a vulnerability."""
    settings = get_settings()
    now = datetime.now(timezone.utc)

    # Validation
    if request.expires_at <= now:
        raise HTTPException(status_code=400, detail="expires_at must be in the future")

    max_expiry = now + timedelta(days=settings.max_expiry_days)
    if request.expires_at > max_expiry:
        raise HTTPException(
            status_code=400,
            detail=f"expires_at must be within {settings.max_expiry_days} days",
        )

    if not request.justification.strip():
        raise HTTPException(status_code=400, detail="justification must not be empty")

    # Check vulnerability exists
    vuln = await get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    try:
        acceptances = await cascade_accept_in_project(
            vuln_id=vuln_id,
            accepted_by=request.accepted_by,
            justification=request.justification,
            expires_at=request.expires_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    cascade_count = len(acceptances)
    project_name = vuln.get("project_name", "unknown")

    # Increment metrics for each cascaded acceptance
    for _ in acceptances:
        ACCEPTANCES_CREATED_TOTAL.labels(project=project_name).inc()

    # Trigger event-driven Harbor sync
    request_sync(project_name)

    # Find the trigger vulnerability's acceptance
    trigger_acceptance = next(
        (a for a in acceptances if a["vulnerability_id"] == vuln_id),
        acceptances[0] if acceptances else None,
    )
    acceptance_id = trigger_acceptance["acceptance_id"] if trigger_acceptance else ""

    logger.info(
        "Risk accepted",
        extra={
            "vulnerability_id": vuln_id,
            "cve_id": vuln["cve_id"],
            "accepted_by": request.accepted_by,
            "acceptance_id": acceptance_id,
            "cascade_count": cascade_count,
        },
    )

    return AcceptResponse(
        acceptance_id=acceptance_id,
        vulnerability_id=vuln_id,
        cve_id=vuln["cve_id"],
        status="accepted",
    )


@router.post("/acceptances/{acceptance_id}/revoke")
async def revoke_risk_acceptance(
    acceptance_id: str,
    request: RevokeRequest,
) -> dict:
    """Revoke an acceptance and reopen the vulnerability."""
    try:
        revoked_list = await cascade_revoke_in_project(acceptance_id, request.revoked_by)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    cascade_count = len(revoked_list)
    # Use the trigger acceptance's details for the response
    trigger = next(
        (r for r in revoked_list if r["acceptance_id"] == acceptance_id),
        revoked_list[0] if revoked_list else None,
    )
    vuln_id = trigger["vulnerability_id"] if trigger else ""
    project_name = trigger["project_name"] if trigger else "unknown"

    # Increment metrics for each cascaded revocation
    for _ in revoked_list:
        ACCEPTANCES_REVOKED_TOTAL.labels(project=project_name).inc()

    # Trigger event-driven Harbor sync
    request_sync(project_name)

    logger.info(
        "Acceptance revoked",
        extra={
            "acceptance_id": acceptance_id,
            "vulnerability_id": vuln_id,
            "revoked_by": request.revoked_by,
            "cascade_count": cascade_count,
        },
    )

    return {
        "acceptance_id": acceptance_id,
        "vulnerability_id": vuln_id,
        "status": "open",
        "cascade_count": cascade_count,
    }


@router.post("/cves/{cve_id}/accept", response_model=BulkAcceptResponse, status_code=201)
async def bulk_accept_cve(
    cve_id: str,
    request: BulkAcceptRequest,
) -> BulkAcceptResponse:
    """Accept a CVE across multiple projects."""
    settings = get_settings()
    now = datetime.now(timezone.utc)

    if request.expires_at <= now:
        raise HTTPException(status_code=400, detail="expires_at must be in the future")

    max_expiry = now + timedelta(days=settings.max_expiry_days)
    if request.expires_at > max_expiry:
        raise HTTPException(
            status_code=400,
            detail=f"expires_at must be within {settings.max_expiry_days} days",
        )

    if not request.justification.strip():
        raise HTTPException(status_code=400, detail="justification must not be empty")

    acceptances = await bulk_accept(
        cve_id=cve_id,
        projects=request.projects,
        accepted_by=request.accepted_by,
        justification=request.justification,
        expires_at=request.expires_at,
    )

    # Increment metrics per project and trigger sync
    for acceptance in acceptances:
        project_name = acceptance.get("project_name", "unknown")
        ACCEPTANCES_CREATED_TOTAL.labels(project=project_name).inc()
        request_sync(project_name)

    logger.info(
        "Bulk acceptance created",
        extra={
            "cve_id": cve_id,
            "acceptances_created": len(acceptances),
            "accepted_by": request.accepted_by,
        },
    )

    return BulkAcceptResponse(
        cve_id=cve_id,
        acceptances_created=len(acceptances),
        acceptances=[AcceptResponse(**a) for a in acceptances],
    )
