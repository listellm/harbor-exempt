"""Sync query route for Harbor Exempt."""

from fastapi import APIRouter

from app.db import get_accepted_cves
from app.models import AcceptedCvesResponse

router = APIRouter(prefix="/api/v1", tags=["sync"])


@router.get("/projects/{project}/accepted-cves", response_model=AcceptedCvesResponse)
async def get_project_accepted_cves(project: str,) -> AcceptedCvesResponse:
    """Get accepted CVE IDs for a project.

    Returns the exact list to push to the Harbor project CVE allowlist.
    Only includes CVEs with active (non-expired, non-revoked) acceptances.
    """
    cves = await get_accepted_cves(project)
    return AcceptedCvesResponse(project=project, cves=cves)
