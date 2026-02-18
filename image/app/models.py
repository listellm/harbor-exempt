"""Pydantic models for Harbor Exempt API requests and responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class VulnerabilityInput(BaseModel):
    """Single vulnerability in a scan submission."""

    cve_id: str
    package: str
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str
    cvss_score: float | None = None
    description: str | None = None
    references: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Scan ingest request."""

    project: str
    image: str
    digest: str | None = None
    scanner: str = "Trivy"
    vulnerabilities: list[VulnerabilityInput]


class ScanResponse(BaseModel):
    """Scan ingest response."""

    scan_id: str
    project: str
    created: int
    updated: int
    fixed: int
    total: int


class VulnerabilityResponse(BaseModel):
    """Single vulnerability in list response."""

    id: str
    cve_id: str
    package: str
    repository: str
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str
    status: str
    description: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    acceptance: dict | None = None


class VulnerabilityListResponse(BaseModel):
    """Paginated vulnerability list."""

    project: str
    total: int
    page: int
    per_page: int
    vulnerabilities: list[VulnerabilityResponse]


class AcceptRequest(BaseModel):
    """Risk acceptance request."""

    accepted_by: str
    justification: str
    expires_at: datetime


class AcceptResponse(BaseModel):
    """Risk acceptance response."""

    acceptance_id: str
    vulnerability_id: str
    cve_id: str
    status: str


class RevokeRequest(BaseModel):
    """Acceptance revocation request."""

    revoked_by: str


class BulkAcceptRequest(BaseModel):
    """Bulk risk acceptance request."""

    accepted_by: str
    justification: str
    expires_at: datetime
    projects: list[str] | None = None


class BulkAcceptResponse(BaseModel):
    """Bulk risk acceptance response."""

    cve_id: str
    acceptances_created: int
    acceptances: list[AcceptResponse]


class AcceptedCvesResponse(BaseModel):
    """Accepted CVEs for Harbor sync."""

    project: str
    cves: list[str]


class SeverityCounts(BaseModel):
    """Vulnerability counts by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class ProjectSummary(BaseModel):
    """Per-project vulnerability summary."""

    name: str
    open: SeverityCounts
    accepted: SeverityCounts
    fixed: SeverityCounts
    expiring_soon: int = 0
    fixable: int = 0


class FixableVulnerabilityResponse(BaseModel):
    """Accepted vulnerability with a known fix available."""

    id: UUID
    cve_id: str
    package: str
    repository: str
    severity: str
    installed_version: str | None
    fixed_version: str | None  # Trivy fix
    osv_fixed_versions: list | None  # OSV fix details
    fix_source: str  # trivy | osv | both
    acceptance: dict | None
    project: str


class SummaryResponse(BaseModel):
    """Dashboard summary."""

    projects: list[ProjectSummary]


class HarborWebhookPayload(BaseModel):
    """Harbor scan-complete webhook payload."""

    type: str
    occur_at: int | None = None
    operator: str | None = None
    event_data: dict
