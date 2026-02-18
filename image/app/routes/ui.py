"""Web UI routes for Harbor Exempt — server-rendered with Jinja2 + htmx."""

import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import get_settings
from app.db import (
    bulk_accept,
    cascade_accept_in_project,
    cascade_revoke_in_project,
    get_cve_instances,
    get_last_scan_timestamp,
    get_open_siblings,
    get_summary,
    get_vulnerability,
    list_acceptances_for_vulnerability,
    list_audit_log,
    list_cves,
    list_fixable_vulnerabilities,
    list_images_with_accepted_vulns,
    list_images_with_open_vulns,
    list_projects,
    list_vulnerabilities,
)
from app.main import templates
from app.metrics import (
    ACCEPTANCES_CREATED_TOTAL,
    ACCEPTANCES_REVOKED_TOTAL,
    HARBOR_DRIFT_CVES,
    HARBOR_SYNC_LAST_SUCCESS,
)
from app.scheduler import request_sync

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ui"])


async def _compute_platform_status(harbor_client, settings) -> list[dict]:
    """Compute RAG status for platform health indicators.

    Returns a list of status dicts with keys: name, status, label, detail.
    """
    statuses = []

    # 1. Harbor connectivity
    if harbor_client:
        harbor_status = await harbor_client.check_health()
        statuses.append({"name": "Harbor", **harbor_status})
    else:
        statuses.append(
            {
                "name": "Harbor",
                "status": "grey",
                "label": "Not configured",
                "detail": "Harbor client not initialised",
            }
        )

    # 2. Sync freshness — based on last successful sync timestamp
    if harbor_client:
        last_sync_ts = HARBOR_SYNC_LAST_SUCCESS._value.get()
        if last_sync_ts == 0:
            statuses.append(
                {
                    "name": "Sync",
                    "status": "red",
                    "label": "Never",
                    "detail": "No successful sync recorded",
                }
            )
        else:
            age = time.time() - last_sync_ts
            interval = settings.sync_interval_seconds
            mins = int(age // 60)
            if age < interval * 1.5:
                statuses.append(
                    {
                        "name": "Sync",
                        "status": "green",
                        "label": "Current",
                        "detail": f"Last sync {mins}m ago",
                    }
                )
            elif age < interval * 3:
                statuses.append(
                    {
                        "name": "Sync",
                        "status": "amber",
                        "label": "Stale",
                        "detail": f"Last sync {mins}m ago",
                    }
                )
            else:
                statuses.append(
                    {
                        "name": "Sync",
                        "status": "red",
                        "label": "Overdue",
                        "detail": f"Last sync {mins}m ago",
                    }
                )
    else:
        statuses.append(
            {
                "name": "Sync",
                "status": "grey",
                "label": "Disabled",
                "detail": "Harbor sync not configured",
            }
        )

    # 3. Scan freshness — based on most recent scan timestamp
    try:
        last_scan = await get_last_scan_timestamp()
        if last_scan is None:
            statuses.append(
                {
                    "name": "Scans",
                    "status": "red",
                    "label": "No scans",
                    "detail": "No scans have been received",
                }
            )
        else:
            now = datetime.now(timezone.utc)
            scan_age = now - last_scan
            hours = scan_age.total_seconds() / 3600
            if hours < 1:
                mins = int(scan_age.total_seconds() // 60)
                statuses.append(
                    {
                        "name": "Scans",
                        "status": "green",
                        "label": "Active",
                        "detail": f"Last scan {mins}m ago",
                    }
                )
            elif hours < 24:
                statuses.append(
                    {
                        "name": "Scans",
                        "status": "amber",
                        "label": "Stale",
                        "detail": f"Last scan {int(hours)}h ago",
                    }
                )
            else:
                days = int(hours // 24)
                statuses.append(
                    {
                        "name": "Scans",
                        "status": "red",
                        "label": "Inactive",
                        "detail": f"Last scan {days}d ago",
                    }
                )
    except Exception:
        statuses.append(
            {
                "name": "Scans",
                "status": "grey",
                "label": "Unknown",
                "detail": "Could not query scan status",
            }
        )

    # 4. Drift — check if any project has non-zero drift
    if harbor_client:
        total_drift = 0
        drift_projects = []
        for labels, metric in HARBOR_DRIFT_CVES._metrics.items():
            value = metric._value.get()
            if value > 0:
                total_drift += int(value)
                project_name = labels[0]  # (project, direction)
                if project_name not in drift_projects:
                    drift_projects.append(project_name)

        if total_drift == 0:
            statuses.append(
                {
                    "name": "Drift",
                    "status": "green",
                    "label": "In sync",
                    "detail": "No allowlist drift detected",
                }
            )
        else:
            statuses.append(
                {
                    "name": "Drift",
                    "status": "red",
                    "label": f"{total_drift} CVEs",
                    "detail": f"Drift in: {', '.join(drift_projects)}",
                }
            )
    else:
        statuses.append({
            "name": "Drift",
            "status": "grey",
            "label": "N/A",
            "detail": "Harbor sync not configured",
        })

    return statuses


def _base_context(request: Request, active_nav: str = "") -> dict:
    """Build base template context with nav state."""
    return {
        "request": request,
        "current_user": None,
        "is_admin": True,
        "active_nav": active_nav,
    }


def _strip_registry(image: str | None) -> str | None:
    """Strip registry hostname prefix from an image reference.

    'localhost:8088/platform/app:v1' -> 'platform/app:v1'
    'harbor.example.com/platform/app:v1' -> 'platform/app:v1'
    'platform/app:v1' -> 'platform/app:v1' (no change)
    """
    if not image:
        return image
    parts = image.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        return parts[1]
    return image


# --- Full pages ---


@router.get("/", response_class=HTMLResponse)
async def images_list(
    request: Request,
    project: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> HTMLResponse:
    """Blocked images homepage — images blocked from pull by Harbor threshold."""
    from app.main import get_harbor_client

    all_images = await list_images_with_open_vulns(
        project_filter=project,
        search=search,
    )

    # Fetch project thresholds from Harbor
    harbor = get_harbor_client()
    threshold_map: dict[str, dict] = {}
    if harbor:
        try:
            harbor_projects = await harbor.list_projects()
            threshold_map = {p["name"]: p for p in harbor_projects}
        except Exception:
            logger.warning("Failed to fetch Harbor project thresholds", exc_info=True)

    # Filter to only blocked images (prevent_vul enabled + open vulns >= threshold)
    blocked: list[dict] = []
    for img in all_images:
        hp = threshold_map.get(img["project_name"], {})
        if not hp.get("prevent_vul"):
            continue
        threshold = hp.get("severity_threshold")
        severities = THRESHOLD_SEVERITY_MAP.get(threshold, [])
        blocking = sum(img[f"{s.lower()}_count"] for s in severities)
        if blocking > 0:
            img["blocking_count"] = blocking
            img["threshold"] = threshold
            img["latest_image"] = _strip_registry(img.get("latest_image"))
            blocked.append(img)

    # Client-side pagination over the filtered result
    total = len(blocked)
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    start = (page - 1) * per_page
    page_images = blocked[start:start + per_page]

    ctx = _base_context(request, "images")
    ctx.update(
        {
            "images": page_images,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
            "project": project,
            "search": search or "",
            "all_projects": sorted(k for k in threshold_map if k not in get_settings().excluded_projects_set),
            "active_sub_tab": "blocked",
        }
    )
    return templates.TemplateResponse("images.html", ctx)


@router.get("/accepted", response_class=HTMLResponse)
async def accepted_images_list(
    request: Request,
    project: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> HTMLResponse:
    """Accepted images — images where all blocking CVEs are accepted through."""
    from app.main import get_harbor_client

    all_accepted = await list_images_with_accepted_vulns(
        project_filter=project,
        search=search,
    )

    # Fetch project thresholds from Harbor
    harbor = get_harbor_client()
    threshold_map: dict[str, dict] = {}
    if harbor:
        try:
            harbor_projects = await harbor.list_projects()
            threshold_map = {p["name"]: p for p in harbor_projects}
        except Exception:
            logger.warning("Failed to fetch Harbor project thresholds", exc_info=True)

    # Fetch open vulns for cross-reference
    open_images = await list_images_with_open_vulns(
        project_filter=project,
        search=search,
    )

    # Filter to fully-accepted images only
    accepted = _filter_accepted_images(all_accepted, threshold_map, open_images)

    # Strip registry prefix
    for img in accepted:
        img["latest_image"] = _strip_registry(img.get("latest_image"))

    # Client-side pagination
    total = len(accepted)
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    start = (page - 1) * per_page
    page_images = accepted[start:start + per_page]

    ctx = _base_context(request, "images")
    ctx.update(
        {
            "images": page_images,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
            "project": project,
            "search": search or "",
            "all_projects": sorted(k for k in threshold_map if k not in get_settings().excluded_projects_set),
            "active_sub_tab": "accepted",
        }
    )
    return templates.TemplateResponse("accepted_images.html", ctx)


@router.get("/images", response_class=HTMLResponse)
async def image_detail(
    request: Request,
    project: str = Query(...),
    repo: str = Query(...),
    status: list[str] | None = Query(default=None),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Image detail — vulnerabilities for a specific image/repo in a project."""
    from app.main import get_harbor_client

    # Default to open + accepted when no status filter is specified
    if status is None:
        status = ["open", "accepted"]

    severity_list = None
    if severity:
        severity_list = [s.strip().upper() for s in severity.split(",")]
    else:
        # Default to Harbor threshold severities
        harbor = get_harbor_client()
        if harbor:
            try:
                threshold = await harbor.get_project_threshold(project)
                if threshold:
                    severity_list = THRESHOLD_SEVERITY_MAP.get(threshold.lower())
            except Exception:
                logger.warning("Failed to fetch Harbor threshold for %s", project, exc_info=True)

    vulnerabilities, total = await list_vulnerabilities(
        project_name=project,
        status=status,
        severity=severity_list,
        page=page,
        per_page=per_page,
        repository=repo,
    )

    # Fetch latest scan info for the header
    images = await list_images_with_open_vulns(project_filter=project, search=repo)
    image_info = next((i for i in images if i["repository"] == repo), None)

    # Fetch threshold for display
    threshold = None
    harbor = get_harbor_client()
    if harbor:
        try:
            threshold = await harbor.get_project_threshold(project)
        except Exception:
            pass

    partial_url = f"/partials/images/vulnerabilities?project={project}&repo={repo}"

    ctx = _base_context(request, "images")
    ctx.update(
        {
            "project_name": project,
            "repository": repo,
            "latest_image": _strip_registry(image_info["latest_image"]) if image_info else None,
            "latest_digest": image_info["latest_digest"] if image_info else None,
            "latest_tag": image_info.get("latest_tag") if image_info else None,
            "last_scanned": image_info["last_scanned"] if image_info else None,
            "threshold": threshold,
            "vulnerabilities": vulnerabilities,
            "total": total,
            "page": page,
            "per_page": per_page,
            "status": status,
            "severity": severity_list or [],
            "partial_url": partial_url,
        }
    )
    return templates.TemplateResponse("image_detail.html", ctx)


@router.get("/cves", response_class=HTMLResponse)
async def cve_list(
    request: Request,
    severity: list[str] | None = Query(default=None),
    status: list[str] | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str | None = Query(default=None),
    sort_dir: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """CVE list — unique CVEs aggregated across all projects."""
    # Default severity filter: CRITICAL, HIGH, MEDIUM, LOW
    severity_list = severity or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    cves, total = await list_cves(
        severity=severity_list,
        status_filter=status or None,
        search=search,
        page=page,
        per_page=per_page,
        sort=sort,
        sort_dir=sort_dir,
    )

    ctx = _base_context(request, "cves")
    ctx.update(
        {
            "cves": cves,
            "total": total,
            "page": page,
            "per_page": per_page,
            "severity": severity_list,
            "status": status or [],
            "search": search or "",
            "sort": sort or "",
            "sort_dir": sort_dir or "",
        }
    )
    return templates.TemplateResponse("cve_list.html", ctx)


@router.get("/cves/{cve_id}", response_class=HTMLResponse)
async def cve_detail(request: Request, cve_id: str) -> HTMLResponse:
    """CVE detail — all affected projects, repos, acceptance status."""
    settings = get_settings()
    instances = await get_cve_instances(cve_id)
    if not instances:
        return HTMLResponse("<h1>CVE not found</h1>", status_code=404)

    # Extract description and references from first instance
    description = next((i["description"] for i in instances if i["description"]), None)
    references = next((i["references"] for i in instances if i.get("references")), [])

    # Highest severity across instances
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
    severity = max(
        (i["severity"] for i in instances),
        key=lambda s: severity_order.get(s, 0),
    )

    # Highest CVSS score across instances
    cvss_scores = [i["cvss_score"] for i in instances if i.get("cvss_score") is not None]
    cvss_score = max(cvss_scores) if cvss_scores else None

    # Aggregate counts
    open_count = sum(1 for i in instances if i["status"] == "open")
    accepted_count = sum(1 for i in instances if i["status"] == "accepted")
    fixed_count = sum(1 for i in instances if i["status"] == "fixed")
    project_names = sorted({i["project_name"] for i in instances})
    open_projects = sorted({i["project_name"] for i in instances if i["status"] == "open"})

    ctx = _base_context(request, "cves")
    ctx.update(
        {
            "cve_id": cve_id,
            "instances": instances,
            "description": description,
            "references": references or [],
            "severity": severity,
            "cvss_score": cvss_score,
            "open_count": open_count,
            "accepted_count": accepted_count,
            "fixed_count": fixed_count,
            "project_names": project_names,
            "open_projects": open_projects,
            "total_instances": len(instances),
            "max_expiry_days": settings.max_expiry_days,
        }
    )
    return templates.TemplateResponse("cve_detail.html", ctx)


@router.get("/projects", response_class=HTMLResponse)
async def projects_dashboard(request: Request) -> HTMLResponse:
    """Project dashboard — summary cards with Harbor threshold metadata."""
    from app.main import get_harbor_client

    projects = await get_summary()

    # Merge Harbor vulnerability prevention thresholds
    harbor = get_harbor_client()
    if harbor:
        try:
            harbor_projects = await harbor.list_projects()
            threshold_map = {p["name"]: p for p in harbor_projects}
            for project in projects:
                hp = threshold_map.get(project["name"], {})
                project["prevent_vul"] = hp.get("prevent_vul", False)
                project["severity_threshold"] = hp.get("severity_threshold")
        except Exception:
            logger.warning("Failed to fetch Harbor project thresholds", exc_info=True)

    ctx = _base_context(request, "projects")
    ctx["projects"] = projects
    return templates.TemplateResponse("dashboard.html", ctx)


THRESHOLD_SEVERITY_MAP = {
    "critical": ["CRITICAL"],
    "high": ["CRITICAL", "HIGH"],
    "medium": ["CRITICAL", "HIGH", "MEDIUM"],
    "low": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
}


def _filter_accepted_images(
    all_accepted: list[dict],
    threshold_map: dict[str, dict],
    open_images: list[dict],
) -> list[dict]:
    """Filter accepted images to those where all blocking CVEs are accepted.

    An image is "accepted through" when:
    - Its project has prevent_vul enabled
    - It has accepted CVEs at the threshold severity (was subject to blocking)
    - It has zero open CVEs at the threshold severity (all blocking CVEs accepted)

    This makes Blocked and Accepted mutually exclusive for a given threshold.
    """
    # Build lookup: (project, repo) -> open counts at each severity
    open_lookup: dict[tuple[str, str], dict] = {}
    for img in open_images:
        key = (img["project_name"], img["repository"])
        open_lookup[key] = img

    filtered: list[dict] = []
    for img in all_accepted:
        hp = threshold_map.get(img["project_name"], {})
        if not hp.get("prevent_vul"):
            continue

        threshold = hp.get("severity_threshold")
        severities = THRESHOLD_SEVERITY_MAP.get(threshold, [])
        if not severities:
            continue

        # Count accepted CVEs at threshold severity
        blocking_accepted = sum(img[f"{s.lower()}_count"] for s in severities)
        if blocking_accepted == 0:
            continue

        # Count open CVEs at threshold severity for the same image
        open_img = open_lookup.get((img["project_name"], img["repository"]), {})
        open_blocking = sum(open_img.get(f"{s.lower()}_count", 0) for s in severities)
        if open_blocking > 0:
            continue

        img["blocking_accepted"] = blocking_accepted
        img["threshold"] = threshold
        filtered.append(img)

    return filtered


def _group_vulnerabilities(vulnerabilities: list[dict]) -> list[dict]:
    """Group vulnerabilities by (cve_id, package) for display deduplication.

    When the same CVE+package appears across multiple repositories within a
    project, they are grouped into a single expandable parent row. The first
    occurrence becomes the representative parent; all occurrences (including
    the first) become children shown on expand.

    Single-repository vulns are returned unchanged (no children key).
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for vuln in vulnerabilities:
        key = (vuln["cve_id"], vuln["package"])
        groups.setdefault(key, []).append(vuln)

    result: list[dict] = []
    for children in groups.values():
        if len(children) == 1:
            result.append(children[0])
        else:
            parent = children[0].copy()
            parent["_children"] = children
            parent["_group_id"] = parent["id"]
            # Aggregate: earliest first_seen, latest last_seen
            first_seen = [c["first_seen_at"] for c in children if c["first_seen_at"]]
            last_seen = [c["last_seen_at"] for c in children if c["last_seen_at"]]
            if first_seen:
                parent["first_seen_at"] = min(first_seen)
            if last_seen:
                parent["last_seen_at"] = max(last_seen)
            result.append(parent)

    return result


@router.get("/projects/{name}", response_class=HTMLResponse)
async def project_detail(
    request: Request,
    name: str,
    status: list[str] | None = Query(default=None),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Project detail — vulnerability table with filters."""
    from app.main import get_harbor_client

    # Default to open + accepted when no status filter is specified
    if status is None:
        status = ["open", "accepted"]

    severity_list = None
    if severity:
        severity_list = [s.strip().upper() for s in severity.split(",")]
    else:
        # Default to Harbor threshold when no severity filter is specified
        harbor = get_harbor_client()
        if harbor:
            try:
                threshold = await harbor.get_project_threshold(name)
                if threshold:
                    severity_list = THRESHOLD_SEVERITY_MAP.get(threshold.lower())
            except Exception:
                logger.warning("Failed to fetch Harbor threshold for %s", name, exc_info=True)

    vulnerabilities, total = await list_vulnerabilities(
        project_name=name,
        status=status,
        severity=severity_list,
        page=page,
        per_page=per_page,
    )
    vulnerabilities = _group_vulnerabilities(vulnerabilities)

    ctx = _base_context(request, "")
    ctx.update(
        {
            "project_name": name,
            "vulnerabilities": vulnerabilities,
            "total": total,
            "page": page,
            "per_page": per_page,
            "status": status,
            "severity": severity_list or [],
        }
    )
    return templates.TemplateResponse("project.html", ctx)


@router.get("/projects/{name}/vulnerabilities/{vuln_id}", response_class=HTMLResponse)
async def vulnerability_detail(
    request: Request,
    name: str,
    vuln_id: str,
) -> HTMLResponse:
    """Vulnerability detail — CVE info, acceptance history."""
    settings = get_settings()
    vuln = await get_vulnerability(vuln_id)
    if not vuln:
        return HTMLResponse("<h1>Vulnerability not found</h1>", status_code=404)

    acceptances = await list_acceptances_for_vulnerability(vuln_id)

    # Find active acceptance
    now = datetime.now(timezone.utc)
    active_acceptance = None
    for acc in acceptances:
        if acc["revoked_at"] is None and acc["expires_at"] > now:
            active_acceptance = acc
            break

    ctx = _base_context(request, "")
    ctx.update(
        {
            "vuln": vuln,
            "project_name": name,
            "acceptances": acceptances,
            "active_acceptance": active_acceptance,
            "now": now,
            "max_expiry_days": settings.max_expiry_days,
        }
    )
    return templates.TemplateResponse("vulnerability.html", ctx)


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    project: str | None = Query(default=None),
    user: str | None = Query(default=None),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Audit log — acceptance/revocation history."""
    parsed_from = _parse_date(from_date)
    parsed_to = _parse_date(to_date, end_of_day=True)

    events, total = await list_audit_log(
        project=project,
        user=user,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )

    ctx = _base_context(request, "audit")
    ctx.update(
        {
            "events": events,
            "total": total,
            "page": page,
            "per_page": per_page,
            "project": project,
            "user_filter": user,
            "from_date": from_date,
            "to_date": to_date,
            "all_projects": await list_projects(),
        }
    )
    return templates.TemplateResponse("audit.html", ctx)


# --- htmx partials ---


@router.get("/partials/status", response_class=HTMLResponse)
async def partial_status(request: Request) -> HTMLResponse:
    """Partial — platform status bar for header (loaded via htmx)."""
    from app.main import get_harbor_client

    settings = get_settings()
    harbor = get_harbor_client()
    platform_status = await _compute_platform_status(harbor, settings)

    return templates.TemplateResponse(
        "partials/status_bar.html",
        {
            "request": request,
            "platform_status": platform_status
        },
    )


@router.get("/partials/projects/{name}/vulnerabilities", response_class=HTMLResponse)
async def partial_vuln_table(
    request: Request,
    name: str,
    status: list[str] | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Partial — vulnerability table body for htmx filter/paginate."""
    vulnerabilities, total = await list_vulnerabilities(
        project_name=name,
        status=status,
        severity=severity,
        page=page,
        per_page=per_page,
    )
    vulnerabilities = _group_vulnerabilities(vulnerabilities)

    ctx = _base_context(request)
    ctx.update(
        {
            "project_name": name,
            "vulnerabilities": vulnerabilities,
            "total": total,
            "page": page,
            "per_page": per_page,
            "status": status or [],
            "severity": severity or [],
        }
    )
    return templates.TemplateResponse("partials/vuln_table.html", ctx)


@router.get("/partials/images", response_class=HTMLResponse)
async def partial_image_table(
    request: Request,
    project: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> HTMLResponse:
    """Partial — image table body for htmx filter/paginate."""
    from app.main import get_harbor_client

    all_images = await list_images_with_open_vulns(
        project_filter=project,
        search=search,
    )

    harbor = get_harbor_client()
    threshold_map: dict[str, dict] = {}
    if harbor:
        try:
            harbor_projects = await harbor.list_projects()
            threshold_map = {p["name"]: p for p in harbor_projects}
        except Exception:
            logger.warning("Failed to fetch Harbor project thresholds", exc_info=True)

    blocked: list[dict] = []
    for img in all_images:
        hp = threshold_map.get(img["project_name"], {})
        if not hp.get("prevent_vul"):
            continue
        threshold = hp.get("severity_threshold")
        severities = THRESHOLD_SEVERITY_MAP.get(threshold, [])
        blocking = sum(img[f"{s.lower()}_count"] for s in severities)
        if blocking > 0:
            img["blocking_count"] = blocking
            img["threshold"] = threshold
            img["latest_image"] = _strip_registry(img.get("latest_image"))
            blocked.append(img)

    total = len(blocked)
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    start = (page - 1) * per_page
    page_images = blocked[start:start + per_page]

    ctx = _base_context(request)
    ctx.update(
        {
            "images": page_images,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
            "project": project,
            "search": search or "",
        }
    )
    return templates.TemplateResponse("partials/image_table.html", ctx)


@router.get("/partials/accepted-images", response_class=HTMLResponse)
async def partial_accepted_image_table(
    request: Request,
    project: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> HTMLResponse:
    """Partial — accepted image table body for htmx filter/paginate."""
    from app.main import get_harbor_client

    all_accepted = await list_images_with_accepted_vulns(
        project_filter=project,
        search=search,
    )

    # Fetch project thresholds from Harbor
    harbor = get_harbor_client()
    threshold_map: dict[str, dict] = {}
    if harbor:
        try:
            harbor_projects = await harbor.list_projects()
            threshold_map = {p["name"]: p for p in harbor_projects}
        except Exception:
            logger.warning("Failed to fetch Harbor project thresholds", exc_info=True)

    # Fetch open vulns for cross-reference
    open_images = await list_images_with_open_vulns(
        project_filter=project,
        search=search,
    )

    # Filter to fully-accepted images only
    accepted = _filter_accepted_images(all_accepted, threshold_map, open_images)

    for img in accepted:
        img["latest_image"] = _strip_registry(img.get("latest_image"))

    total = len(accepted)
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    start = (page - 1) * per_page
    page_images = accepted[start:start + per_page]

    ctx = _base_context(request)
    ctx.update(
        {
            "images": page_images,
            "total": total,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page,
            "project": project,
            "search": search or "",
        }
    )
    return templates.TemplateResponse("partials/accepted_image_table.html", ctx)


@router.get("/partials/images/vulnerabilities", response_class=HTMLResponse)
async def partial_image_vuln_table(
    request: Request,
    project: str = Query(...),
    repo: str = Query(...),
    status: list[str] | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Partial — vulnerability table for a specific image, htmx filter/paginate."""
    vulnerabilities, total = await list_vulnerabilities(
        project_name=project,
        status=status,
        severity=severity,
        page=page,
        per_page=per_page,
        repository=repo,
    )

    partial_url = f"/partials/images/vulnerabilities?project={project}&repo={repo}"

    ctx = _base_context(request)
    ctx.update(
        {
            "project_name": project,
            "vulnerabilities": vulnerabilities,
            "total": total,
            "page": page,
            "per_page": per_page,
            "status": status or [],
            "severity": severity or [],
            "partial_url": partial_url,
        }
    )
    return templates.TemplateResponse("partials/vuln_table.html", ctx)


@router.get("/partials/cves", response_class=HTMLResponse)
async def partial_cve_table(
    request: Request,
    severity: list[str] | None = Query(default=None),
    status: list[str] | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str | None = Query(default=None),
    sort_dir: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Partial — CVE table body for htmx filter/paginate."""
    severity_list = severity or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    cves, total = await list_cves(
        severity=severity_list,
        status_filter=status or None,
        search=search,
        page=page,
        per_page=per_page,
        sort=sort,
        sort_dir=sort_dir,
    )

    ctx = _base_context(request)
    ctx.update(
        {
            "cves": cves,
            "total": total,
            "page": page,
            "per_page": per_page,
            "severity": severity_list,
            "status": status or [],
            "search": search or "",
            "sort": sort or "",
            "sort_dir": sort_dir or "",
        }
    )
    return templates.TemplateResponse("partials/cve_table.html", ctx)


@router.get("/partials/cves/{cve_id}/instances", response_class=HTMLResponse)
async def partial_cve_instances(request: Request, cve_id: str) -> HTMLResponse:
    """Partial — CVE instance rows for htmx refresh."""
    settings = get_settings()
    instances = await get_cve_instances(cve_id)

    ctx = _base_context(request)
    ctx.update({
        "cve_id": cve_id,
        "instances": instances,
        "max_expiry_days": settings.max_expiry_days,
    })
    return templates.TemplateResponse("partials/cve_instance_table.html", ctx)


@router.get("/partials/cves/{cve_id}/detail-body", response_class=HTMLResponse)
async def partial_cve_detail_body(request: Request, cve_id: str) -> HTMLResponse:
    """Partial — full CVE detail body (summary + instances) for htmx refresh."""
    settings = get_settings()
    instances = await get_cve_instances(cve_id)

    open_count = sum(1 for i in instances if i["status"] == "open")
    accepted_count = sum(1 for i in instances if i["status"] == "accepted")
    fixed_count = sum(1 for i in instances if i["status"] == "fixed")
    project_names = sorted({i["project_name"] for i in instances})
    open_projects = sorted({i["project_name"] for i in instances if i["status"] == "open"})

    ctx = _base_context(request)
    ctx.update(
        {
            "cve_id": cve_id,
            "instances": instances,
            "open_count": open_count,
            "accepted_count": accepted_count,
            "fixed_count": fixed_count,
            "project_names": project_names,
            "open_projects": open_projects,
            "total_instances": len(instances),
            "max_expiry_days": settings.max_expiry_days,
        }
    )
    return templates.TemplateResponse("partials/cve_detail_body.html", ctx)


@router.post("/ui/bulk-accept-cve", response_class=HTMLResponse)
async def ui_bulk_accept_cve(
    request: Request,
    cve_id: str = Form(...),
    justification: str = Form(...),
    expires_at: str = Form(...),
    projects: list[str] | None = Form(default=None),
) -> HTMLResponse:
    """Bulk accept a CVE across selected open instances — returns updated detail body."""
    settings = get_settings()
    now = datetime.now(timezone.utc)

    try:
        expires = datetime.strptime(expires_at, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        ctx = _base_context(request)
        ctx.update({"error": "Invalid date format", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    if expires <= now:
        ctx = _base_context(request)
        ctx.update({"error": "Expiry must be in the future", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    max_expiry = now + timedelta(days=settings.max_expiry_days)
    if expires > max_expiry:
        ctx = _base_context(request)
        ctx.update({
            "error": f"Expiry must be within {settings.max_expiry_days} days",
            "cve_id": cve_id,
        })
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    if not justification.strip():
        ctx = _base_context(request)
        ctx.update({"error": "Justification is required", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    accepted_by = "anonymous"

    # Filter out empty strings from form multi-select
    project_list = [p for p in (projects or []) if p.strip()] or None

    acceptances = await bulk_accept(
        cve_id=cve_id,
        projects=project_list,
        accepted_by=accepted_by,
        justification=justification.strip(),
        expires_at=expires,
    )

    # Increment metrics per project and trigger sync
    for acceptance in acceptances:
        project_name = acceptance.get("project_name", "unknown")
        ACCEPTANCES_CREATED_TOTAL.labels(project=project_name).inc()
        request_sync(project_name)

    logger.info(
        "Bulk accept CVE via UI",
        extra={
            "cve_id": cve_id,
            "projects": project_list,
            "acceptances_created": len(acceptances),
            "accepted_by": accepted_by,
        }
    )

    # Return refreshed detail body
    instances = await get_cve_instances(cve_id)
    open_count = sum(1 for i in instances if i["status"] == "open")
    accepted_count = sum(1 for i in instances if i["status"] == "accepted")
    fixed_count = sum(1 for i in instances if i["status"] == "fixed")
    open_projects = sorted({i["project_name"] for i in instances if i["status"] == "open"})

    ctx = _base_context(request)
    ctx.update(
        {
            "cve_id": cve_id,
            "instances": instances,
            "acceptances_created": len(acceptances),
            "open_count": open_count,
            "accepted_count": accepted_count,
            "fixed_count": fixed_count,
            "open_projects": open_projects,
            "total_instances": len(instances),
            "max_expiry_days": settings.max_expiry_days,
        }
    )
    return templates.TemplateResponse("partials/cve_detail_body.html", ctx)


@router.get("/partials/accept-form/{vuln_id}", response_class=HTMLResponse)
async def partial_accept_form(
    request: Request,
    vuln_id: str,
    project_name: str = Query(default=""),
    context: str | None = Query(default=None),
) -> HTMLResponse:
    """Partial — inline accept risk form."""
    settings = get_settings()
    vuln = await get_vulnerability(vuln_id)
    p_name = project_name or (vuln["project_name"] if vuln else "")
    siblings = await get_open_siblings(vuln_id)

    ctx = _base_context(request)
    ctx.update(
        {
            "vuln_id": vuln_id,
            "project_name": p_name,
            "max_expiry_days": settings.max_expiry_days,
            "context": context or "",
            "siblings": siblings,
        }
    )
    return templates.TemplateResponse("partials/accept_form.html", ctx)


@router.post("/ui/accept", response_class=HTMLResponse)
async def ui_accept(
    request: Request,
    vulnerability_id: str = Form(...),
    project_name: str = Form(...),
    justification: str = Form(...),
    expires_at: str = Form(...),
    redirect: str | None = Form(default=None),
    context: str | None = Form(default=None),
) -> HTMLResponse:
    """Accept risk — returns updated row or redirect."""
    settings = get_settings()
    now = datetime.now(timezone.utc)

    try:
        expires = datetime.strptime(expires_at, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return _accept_error(request, vulnerability_id, project_name, "Invalid date format", context)

    if expires <= now:
        return _accept_error(request, vulnerability_id, project_name, "Expiry must be in the future", context)

    max_expiry = now + timedelta(days=settings.max_expiry_days)
    if expires > max_expiry:
        return _accept_error(
            request,
            vulnerability_id,
            project_name,
            f"Expiry must be within {settings.max_expiry_days} days",
            context,
        )

    if not justification.strip():
        return _accept_error(request, vulnerability_id, project_name, "Justification is required", context)

    accepted_by = "anonymous"

    try:
        acceptances = await cascade_accept_in_project(
            vuln_id=vulnerability_id,
            accepted_by=accepted_by,
            justification=justification.strip(),
            expires_at=expires,
        )
    except ValueError as e:
        return _accept_error(request, vulnerability_id, project_name, str(e), context)

    cascade_count = len(acceptances)

    # Increment metrics for each cascaded acceptance
    for _ in acceptances:
        ACCEPTANCES_CREATED_TOTAL.labels(project=project_name).inc()

    # Trigger event-driven Harbor sync
    request_sync(project_name)

    logger.info(
        "Risk accepted via UI",
        extra={
            "vulnerability_id": vulnerability_id,
            "accepted_by": accepted_by,
            "cascade_count": cascade_count,
        }
    )

    if redirect:
        return RedirectResponse(url=redirect, status_code=303)

    # Re-fetch vulnerability
    vuln = await get_vulnerability(vulnerability_id)

    # Build HX-Trigger header for table refresh when siblings were affected
    hx_triggers = []
    if cascade_count > 1:
        hx_triggers.append("refreshVulnTable")
    if context == "cve_instance" and cascade_count > 1:
        hx_triggers.append("refreshCveInstances")

    # Return correct row shape depending on calling context
    if context == "cve_instance":
        acceptances = await list_acceptances_for_vulnerability(vulnerability_id)
        active = None
        for acc in acceptances:
            if acc["revoked_at"] is None and acc["expires_at"] > now:
                active = {
                    "id": str(acc["id"]),
                    "accepted_by": acc["accepted_by"],
                    "justification": acc["justification"],
                    "expires_at": acc["expires_at"],
                    "created_at": acc["created_at"],
                }
                break

        inst = {
            "id": str(vuln["id"]),
            "cve_id": vuln["cve_id"],
            "package": vuln["package"],
            "repository": vuln["repository"],
            "installed_version": vuln["installed_version"],
            "fixed_version": vuln["fixed_version"],
            "severity": vuln["severity"],
            "cvss_score": float(vuln["cvss_score"]) if vuln.get("cvss_score") is not None else None,
            "status": vuln["status"],
            "project_name": project_name,
            "acceptance": active,
        }
        ctx = _base_context(request)
        ctx["inst"] = inst
        response = templates.TemplateResponse("partials/cve_instance_row.html", ctx)
        if hx_triggers:
            response.headers["HX-Trigger"] = ", ".join(hx_triggers)
        return response

    ctx = _base_context(request)
    ctx.update({"vuln": vuln, "project_name": project_name})
    response = templates.TemplateResponse("partials/accept_result.html", ctx)
    if hx_triggers:
        response.headers["HX-Trigger"] = ", ".join(hx_triggers)
    return response


@router.post("/ui/revoke", response_class=HTMLResponse)
async def ui_revoke(
    request: Request,
    acceptance_id: str = Form(...),
    vulnerability_id: str = Form(...),
    project_name: str = Form(...),
    context: str | None = Form(default=None),
) -> HTMLResponse:
    """Revoke acceptance — returns updated row."""
    revoked_by = "anonymous"

    try:
        revoked_list = await cascade_revoke_in_project(acceptance_id, revoked_by)
    except ValueError as e:
        ctx = _base_context(request)
        colspan = "10" if context == "cve_instance" else "9"
        ctx.update({"error": str(e), "vuln_id": vulnerability_id, "colspan": colspan})
        return templates.TemplateResponse("partials/revoke_result.html", ctx)

    cascade_count = len(revoked_list)
    project_name_from_db = revoked_list[0]["project_name"] if revoked_list else project_name

    # Increment metrics for each cascaded revocation
    for _ in revoked_list:
        ACCEPTANCES_REVOKED_TOTAL.labels(project=project_name_from_db).inc()

    # Trigger event-driven Harbor sync
    request_sync(project_name_from_db)

    logger.info(
        "Acceptance revoked via UI",
        extra={
            "acceptance_id": acceptance_id,
            "revoked_by": revoked_by,
            "cascade_count": cascade_count,
        }
    )

    # Build HX-Trigger header for table refresh when siblings were affected
    hx_triggers = []
    if cascade_count > 1:
        hx_triggers.append("refreshVulnTable")
    if context == "cve_instance" and cascade_count > 1:
        hx_triggers.append("refreshCveInstances")

    # Re-fetch vulnerability
    vuln = await get_vulnerability(vulnerability_id)
    if not vuln:
        ctx = _base_context(request)
        colspan = "10" if context == "cve_instance" else "9"
        ctx.update({"error": "Vulnerability not found", "vuln_id": vulnerability_id, "colspan": colspan})
        return templates.TemplateResponse("partials/revoke_result.html", ctx)

    # Rebuild acceptance info
    acceptances = await list_acceptances_for_vulnerability(vulnerability_id)
    now = datetime.now(timezone.utc)
    active = None
    for acc in acceptances:
        if acc["revoked_at"] is None and acc["expires_at"] > now:
            active = {
                "id": str(acc["id"]),
                "accepted_by": acc["accepted_by"],
                "justification": acc["justification"],
                "expires_at": acc["expires_at"],
                "created_at": acc["created_at"],
            }
            break

    # Return correct row shape depending on calling context
    if context == "cve_instance":
        inst = {
            "id": str(vuln["id"]),
            "cve_id": vuln["cve_id"],
            "package": vuln["package"],
            "repository": vuln["repository"],
            "installed_version": vuln["installed_version"],
            "fixed_version": vuln["fixed_version"],
            "severity": vuln["severity"],
            "cvss_score": float(vuln["cvss_score"]) if vuln.get("cvss_score") is not None else None,
            "status": vuln["status"],
            "project_name": project_name,
            "acceptance": active,
        }
        ctx = _base_context(request)
        ctx["inst"] = inst
        response = templates.TemplateResponse("partials/cve_instance_row.html", ctx)
        if hx_triggers:
            response.headers["HX-Trigger"] = ", ".join(hx_triggers)
        return response

    vuln_dict = {
        "id": str(vuln["id"]),
        "cve_id": vuln["cve_id"],
        "package": vuln["package"],
        "repository": vuln["repository"],
        "installed_version": vuln["installed_version"],
        "fixed_version": vuln["fixed_version"],
        "severity": vuln["severity"],
        "status": vuln["status"],
        "description": vuln["description"],
        "first_seen_at": vuln["first_seen_at"],
        "last_seen_at": vuln["last_seen_at"],
        "acceptance": active,
    }

    ctx = _base_context(request)
    ctx.update({"vuln": vuln_dict, "project_name": project_name})
    response = templates.TemplateResponse("partials/revoke_result.html", ctx)
    if hx_triggers:
        response.headers["HX-Trigger"] = ", ".join(hx_triggers)
    return response


@router.post("/ui/bulk-accept", response_class=HTMLResponse)
async def ui_bulk_accept(
    request: Request,
    cve_id: str = Form(...),
    justification: str = Form(...),
    expires_at: str = Form(...),
    projects: list[str] | None = Form(default=None),
) -> HTMLResponse:
    """Bulk accept — returns result summary."""
    settings = get_settings()
    now = datetime.now(timezone.utc)

    try:
        expires = datetime.strptime(expires_at, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        ctx = _base_context(request)
        ctx.update({"error": "Invalid date format", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    if expires <= now:
        ctx = _base_context(request)
        ctx.update({"error": "Expiry must be in the future", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    max_expiry = now + timedelta(days=settings.max_expiry_days)
    if expires > max_expiry:
        ctx = _base_context(request)
        ctx.update({
            "error": f"Expiry must be within {settings.max_expiry_days} days",
            "cve_id": cve_id,
        })
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    if not justification.strip():
        ctx = _base_context(request)
        ctx.update({"error": "Justification is required", "cve_id": cve_id})
        return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)

    accepted_by = "anonymous"

    # Filter out empty strings from form multi-select
    project_list = [p for p in (projects or []) if p.strip()] or None

    acceptances = await bulk_accept(
        cve_id=cve_id,
        projects=project_list,
        accepted_by=accepted_by,
        justification=justification.strip(),
        expires_at=expires,
    )

    # Increment metrics per project and trigger sync
    for acceptance in acceptances:
        project_name = acceptance.get("project_name", "unknown")
        ACCEPTANCES_CREATED_TOTAL.labels(project=project_name).inc()
        request_sync(project_name)

    logger.info(
        "Bulk accept via UI",
        extra={
            "cve_id": cve_id,
            "acceptances_created": len(acceptances),
            "accepted_by": accepted_by,
        }
    )

    ctx = _base_context(request)
    ctx.update(
        {
            "cve_id": cve_id,
            "acceptances_created": len(acceptances),
            "acceptances": acceptances,
            "projects": project_list,
        }
    )
    return templates.TemplateResponse("partials/bulk_accept_result.html", ctx)


@router.get("/partials/audit", response_class=HTMLResponse)
async def partial_audit(
    request: Request,
    project: str | None = Query(default=None),
    user: str | None = Query(default=None),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    """Partial — audit rows for htmx pagination/filter."""
    parsed_from = _parse_date(from_date)
    parsed_to = _parse_date(to_date, end_of_day=True)

    events, total = await list_audit_log(
        project=project,
        user=user,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )

    ctx = _base_context(request)
    ctx["events"] = events
    return templates.TemplateResponse("partials/audit_row.html", ctx)


# --- Helpers ---


def _parse_date(date_str: str | None, end_of_day: bool = False) -> datetime | None:
    """Parse a YYYY-MM-DD date string to timezone-aware datetime."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    except ValueError:
        return None


def _accept_error(
    request: Request,
    vuln_id: str,
    project_name: str,
    error: str,
    context: str | None = None,
) -> HTMLResponse:
    """Return accept error partial."""
    ctx = _base_context(request)
    colspan = "10" if context == "cve_instance" else "9"
    ctx.update({
        "error": error,
        "vuln": {
            "id": vuln_id
        },
        "project_name": project_name,
        "colspan": colspan,
    })
    return templates.TemplateResponse("partials/accept_result.html", ctx)


# --- Fixes routes ---


@router.get("/fixes", response_class=HTMLResponse)
async def fixes_page(
    request: Request,
    project: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=500),
    sort: str = Query(default="severity"),
    order: str = Query(default="asc"),
) -> HTMLResponse:
    """Fixes page — accepted CVEs with a known fix available."""
    severity_list = [s.strip().upper() for s in severity.split(",")] if severity else None

    all_projects = await list_projects()

    # Gather fixable vulnerabilities for the selected (or all) projects
    # list_projects() returns list[str]
    if project:
        project_names = [project]
    else:
        project_names = all_projects

    vulns: list[dict] = []
    total = 0
    for proj in project_names:
        page_vulns, proj_total = await list_fixable_vulnerabilities(
            project_name=proj,
            severity=severity_list,
            source=source,
            page=page,
            per_page=per_page,
            sort_by=sort,
            sort_order=order,
        )
        vulns.extend(page_vulns)
        total += proj_total

    ctx = _base_context(request, active_nav="fixes")
    ctx.update(
        {
            "vulns": vulns,
            "total": total,
            "page": page,
            "per_page": per_page,
            "project_filter": project,
            "severity_filter": severity,
            "source_filter": source,
            "all_projects": all_projects,
            "sort": sort,
            "order": order,
        }
    )
    return templates.TemplateResponse("fixes.html", ctx)


@router.get("/partials/fixes", response_class=HTMLResponse)
async def fixes_partial(
    request: Request,
    project: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=500),
    sort: str = Query(default="severity"),
    order: str = Query(default="asc"),
) -> HTMLResponse:
    """Partial — fixable CVE table for htmx filter/paginate."""
    severity_list = [s.strip().upper() for s in severity.split(",")] if severity else None

    all_projects = await list_projects()

    if project:
        project_names = [project]
    else:
        project_names = all_projects

    vulns: list[dict] = []
    total = 0
    for proj in project_names:
        page_vulns, proj_total = await list_fixable_vulnerabilities(
            project_name=proj,
            severity=severity_list,
            source=source,
            page=page,
            per_page=per_page,
            sort_by=sort,
            sort_order=order,
        )
        vulns.extend(page_vulns)
        total += proj_total

    ctx = _base_context(request)
    ctx.update(
        {
            "vulns": vulns,
            "total": total,
            "page": page,
            "per_page": per_page,
            "project_filter": project,
            "severity_filter": severity,
            "source_filter": source,
            "sort": sort,
            "order": order,
        }
    )
    return templates.TemplateResponse("partials/fixes_table.html", ctx)
