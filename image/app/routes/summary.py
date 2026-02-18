"""Dashboard summary route for Harbor Exempt."""

from fastapi import APIRouter

from app.db import get_summary
from app.models import ProjectSummary, SeverityCounts, SummaryResponse

router = APIRouter(prefix="/api/v1", tags=["summary"])


@router.get("/summary", response_model=SummaryResponse)
async def dashboard_summary() -> SummaryResponse:
    """Get dashboard summary — vulnerability counts per project."""
    data = await get_summary()

    projects = []
    for item in data:
        projects.append(
            ProjectSummary(
                name=item["name"],
                open=SeverityCounts(**item["open"]),
                accepted=SeverityCounts(**item["accepted"]),
                fixed=SeverityCounts(**item["fixed"]),
                expiring_soon=item["expiring_soon"],
                fixable=item.get("fixable", 0),
            )
        )

    return SummaryResponse(projects=projects)
