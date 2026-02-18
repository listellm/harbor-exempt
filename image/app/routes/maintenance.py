"""Maintenance routes for Harbor Exempt — expiry and Harbor sync."""

import logging

import httpx
from fastapi import APIRouter, Request

from app.config import get_settings
from app.db import (
    cleanup_migration_stubs,
    delete_vulnerabilities_for_repository,
    expire_acceptances,
    get_accepted_cves,
    get_accepted_without_fixed_version,
    get_summary,
    list_app_repositories,
    list_scans_for_backfill,
    list_scans_missing_tags,
    update_cvss_score,
    update_scan_tags,
    upsert_fix_check,
)
from app.metrics import (
    ACCEPTANCES_EXPIRED_TOTAL,
    HARBOR_SYNC_PROJECTS_TOTAL,
    OSV_CHECK_LAST_SUCCESS,
)
from app.webhook import _map_harbor_vulnerability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/maintenance", tags=["maintenance"])


async def _send_slack_notification(webhook_url: str, expired: dict) -> None:
    """Send Slack notification for expired acceptance."""
    payload = {
        "blocks":
            [
                {
                    "type": "section",
                    "text":
                        {
                            "type":
                                "mrkdwn",
                            "text":
                                (
                                    ":warning: *Risk acceptance expired*\n"
                                    f"*CVE:* {expired['cve_id']}\n"
                                    f"*Package:* {expired['package']}\n"
                                    f"*Project:* {expired['project']}\n"
                                    f"*Accepted by:* {expired['accepted_by']}\n"
                                    f"*Expired:* {expired['expired_at'].strftime('%Y-%m-%d')}"
                                ),
                        },
                },
            ],
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
    except Exception as e:
        logger.error(
            "Failed to send Slack notification",
            extra={
                "error": str(e),
                "cve_id": expired["cve_id"]
            },
        )


@router.post("/expire")
async def run_expiry() -> dict:
    """Check and process expired acceptances.

    Reopens vulnerabilities with expired acceptances and sends
    Slack notifications. Idempotent — safe to call repeatedly.
    """
    settings = get_settings()
    expired = await expire_acceptances()

    # Increment metrics per project
    for item in expired:
        ACCEPTANCES_EXPIRED_TOTAL.labels(project=item["project"]).inc()

    # Send Slack notifications
    if expired and settings.slack_webhook_url:
        for item in expired:
            await _send_slack_notification(settings.slack_webhook_url, item)

    logger.info(
        "Expiry check completed",
        extra={"expired_count": len(expired)},
    )

    return {"expired": len(expired), "details": expired}


@router.post("/sync")
async def sync_to_harbor(request: Request,) -> dict:
    """Sync accepted CVEs to Harbor project allowlists.

    For each project with vulnerabilities:
    1. Set project to project-level allowlist mode
    2. Push accepted CVE list to Harbor
    """
    from app.main import get_harbor_client

    harbor = get_harbor_client()
    if not harbor:
        return {"error": "Harbor client not configured", "synced": 0}

    # Get all projects from summary
    summary = await get_summary()
    synced = 0

    for project in summary:
        project_name = project["name"]
        cves = await get_accepted_cves(project_name)

        try:
            await harbor.set_project_allowlist_mode(project_name)
            await harbor.update_project_allowlist(project_name, cves)
            synced += 1
            HARBOR_SYNC_PROJECTS_TOTAL.labels(result="success").inc()

            logger.info(
                "Synced project allowlist to Harbor",
                extra={
                    "project": project_name,
                    "cve_count": len(cves),
                },
            )
        except Exception as e:
            HARBOR_SYNC_PROJECTS_TOTAL.labels(result="error").inc()
            logger.error(
                "Failed to sync project to Harbor",
                extra={
                    "project": project_name,
                    "error": str(e),
                },
            )

    return {"synced": synced, "total_projects": len(summary)}


@router.post("/backfill-cvss")
async def backfill_cvss() -> dict:
    """Backfill CVSS scores from Harbor vulnerability reports.

    Re-fetches reports for vulnerabilities with NULL cvss_score
    and updates scores from Harbor's preferred_cvss.score_v3 field.
    Idempotent — safe to call repeatedly.
    """
    from app.main import get_harbor_client

    harbor = get_harbor_client()
    if not harbor:
        return {"error": "Harbor client not configured", "updated": 0}

    groups = await list_scans_for_backfill()
    updated = 0
    errors = 0

    for group in groups:
        try:
            report = await harbor.fetch_vulnerability_report(
                project=group["project_name"],
                repository=group["repository"],
                digest=group["digest"],
            )
            harbor_vulns = report["vulnerabilities"]
            for hv in harbor_vulns:
                mapped = _map_harbor_vulnerability(hv)
                if mapped["cvss_score"] is not None:
                    count = await update_cvss_score(
                        cve_id=mapped["cve_id"],
                        package=mapped["package"],
                        repository=group["repository"],
                        cvss_score=mapped["cvss_score"],
                    )
                    updated += count
        except Exception as e:
            errors += 1
            logger.error(
                "Failed to backfill CVSS for group",
                extra={
                    "project": group["project_name"],
                    "repository": group["repository"],
                    "error": str(e),
                },
            )

    logger.info(
        "CVSS backfill completed",
        extra={
            "groups": len(groups),
            "updated": updated,
            "errors": errors
        },
    )

    return {"groups_processed": len(groups), "scores_updated": updated, "errors": errors}


@router.post("/backfill-tags")
async def backfill_tags() -> dict:
    """Backfill image tags from Harbor for scans with NULL tag.

    Queries Harbor to resolve human-readable tags for artifact digests
    and updates scan records. Idempotent — safe to call repeatedly.
    """
    from app.main import get_harbor_client

    harbor = get_harbor_client()
    if not harbor:
        return {"error": "Harbor client not configured", "resolved": 0}

    groups = await list_scans_missing_tags()
    resolved = 0
    errors = 0

    for group in groups:
        try:
            tag = await harbor.resolve_tag(
                project=group["project_name"],
                repository=group["repository"],
                digest=group["digest"],
            )
            if tag:
                count = await update_scan_tags(
                    repository=group["repository"],
                    digest=group["digest"],
                    tag=tag,
                )
                resolved += count
        except Exception as e:
            errors += 1
            logger.error(
                "Failed to resolve tag for group",
                extra={
                    "project": group["project_name"],
                    "repository": group["repository"],
                    "error": str(e),
                },
            )

    logger.info(
        "Tag backfill completed",
        extra={
            "groups": len(groups),
            "resolved": resolved,
            "errors": errors,
        },
    )

    return {"groups_processed": len(groups), "tags_resolved": resolved, "errors": errors}


@router.post("/check-fixes")
async def check_fixes() -> dict:
    """Check OSV.dev for fix availability on accepted CVEs without a Trivy fix.

    Respects the configured cache TTL — CVEs already checked within TTL are skipped.
    Idempotent — safe to call repeatedly.
    """
    import time

    from app.osv import check_cve

    settings = get_settings()

    if not settings.osv_enabled:
        return {"error": "OSV fix checks are disabled", "checked": 0}

    pending = await get_accepted_without_fixed_version(cache_ttl_seconds=settings.fix_check_cache_ttl_seconds,)

    new_fixes = 0
    errors = 0

    for item in pending:
        cve_id = item["cve_id"]
        try:
            fix_available, fixed_versions, raw = await check_cve(cve_id)
            await upsert_fix_check(
                cve_id=cve_id,
                fix_available=fix_available,
                fixed_versions=fixed_versions if fixed_versions else None,
                raw_response=raw,
            )
            if fix_available:
                new_fixes += 1
        except Exception as e:
            errors += 1
            logger.error(
                "OSV fix check failed",
                extra={
                    "cve_id": cve_id,
                    "error": str(e)
                },
            )

    OSV_CHECK_LAST_SUCCESS.set(time.time())

    logger.info(
        "Manual OSV fix check completed",
        extra={
            "checked": len(pending),
            "new_fixes_found": new_fixes,
            "errors": errors,
        },
    )

    return {
        "checked": len(pending),
        "new_fixes_found": new_fixes,
        "errors": errors,
    }


@router.post("/cleanup-migration-stubs")
async def cleanup_migration_stubs_endpoint() -> dict:
    """Clean up migration seed stubs by cascading acceptances to real instances.

    Cascades active stub acceptances to real open vulnerability instances,
    then deletes all stub records. Idempotent — safe to call repeatedly
    (second call returns all zeros). Harbor allowlists are not affected.
    """
    results = await cleanup_migration_stubs()

    logger.info(
        "Migration stub cleanup endpoint called",
        extra=results,
    )

    return results


@router.post("/cleanup-deleted-images")
async def cleanup_deleted_images() -> dict:
    """Clean up orphaned vulnerabilities for images deleted from Harbor.

    For each project:
    1. Lists all repositories in Harbor
    2. Lists all repositories in Harbor Exempt
    3. Deletes vulnerabilities for repositories not found in Harbor

    Idempotent — safe to call repeatedly.
    """
    from app.main import get_harbor_client

    harbor = get_harbor_client()
    if not harbor:
        return {"error": "Harbor client not configured", "deleted": 0}

    summary = await get_summary()
    total_deleted = 0
    projects_cleaned = 0
    errors = 0

    for project in summary:
        project_name = project["name"]

        try:
            # Get repositories from Harbor and Harbor Exempt
            harbor_repos = set(await harbor.list_repositories(project_name))
            app_repos = set(await list_app_repositories(project_name))

            # Find orphaned repositories (in Harbor Exempt but not in Harbor)
            orphaned_repos = app_repos - harbor_repos

            if orphaned_repos:
                logger.info(
                    "Found orphaned repositories",
                    extra={
                        "project": project_name,
                        "count": len(orphaned_repos),
                        "repositories": list(orphaned_repos),
                    },
                )

                # Delete vulnerabilities for each orphaned repository
                for repo in orphaned_repos:
                    deleted = await delete_vulnerabilities_for_repository(repo)
                    total_deleted += deleted
                    logger.info(
                        "Deleted vulnerabilities for orphaned repository",
                        extra={
                            "project": project_name,
                            "repository": repo,
                            "deleted_count": deleted,
                        },
                    )

                projects_cleaned += 1

        except Exception as e:
            errors += 1
            logger.error(
                "Failed to cleanup project",
                extra={
                    "project": project_name,
                    "error": str(e),
                },
            )

    logger.info(
        "Deleted images cleanup completed",
        extra={
            "projects_checked": len(summary),
            "projects_cleaned": projects_cleaned,
            "total_deleted": total_deleted,
            "errors": errors,
        },
    )

    return {
        "projects_checked": len(summary),
        "projects_cleaned": projects_cleaned,
        "vulnerabilities_deleted": total_deleted,
        "errors": errors,
    }
