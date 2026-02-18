"""Background scheduler for Harbor Exempt — replaces Kubernetes CronJobs.

Provides asyncio-based periodic tasks for Harbor sync and acceptance expiry.
Runs as background tasks during application lifespan, eliminating the need
for separate CronJob resources.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from app.db import (
    delete_vulnerabilities_for_repository,
    expire_acceptances,
    get_accepted_cves,
    get_expiry_metrics,
    get_fixable_counts,
    get_summary,
    get_accepted_without_fixed_version,
    list_projects,
    list_app_repositories,
    list_scans_missing_tags,
    reconcile_accepted_cves_for_project,
    update_scan_tags,
    upsert_fix_check,
)
from app.metrics import (
    ACCEPTANCE_EARLIEST_EXPIRY,
    ACCEPTANCES_ACTIVE,
    ACCEPTANCES_EXPIRED_TOTAL,
    ACCEPTANCES_EXPIRING,
    AUTO_RECONCILE_TOTAL,
    HARBOR_DRIFT_CVES,
    HARBOR_EVENT_SYNC_DURATION,
    HARBOR_EVENT_SYNC_TOTAL,
    HARBOR_SYNC_LAST_SUCCESS,
    HARBOR_SYNC_PROJECTS_TOTAL,
    OSV_CHECK_LAST_SUCCESS,
    OSV_LOOKUPS_TOTAL,
    SCHEDULER_TASK_DURATION,
    SYNC_EVENTS_QUEUED_TOTAL,
    VULNS_FIXABLE,
    VULNS_OPEN,
)

if TYPE_CHECKING:
    from app.config import Settings
    from app.harbor import HarborClient

logger = logging.getLogger(__name__)

_sync_queue: asyncio.Queue | None = None


def request_sync(project_name: str) -> None:
    """Request an event-driven sync for a specific project.

    Queues the project for synchronisation to Harbor. This is called by
    route handlers when vulnerabilities are accepted or revoked. If the
    scheduler is disabled (queue not initialised), this is a no-op.

    Args:
        project_name: Project to sync to Harbor
    """
    if _sync_queue is None:
        return

    try:
        _sync_queue.put_nowait(project_name)
        SYNC_EVENTS_QUEUED_TOTAL.labels(project=project_name).inc()
        logger.debug(
            "Queued project for sync",
            extra={"project": project_name},
        )
    except asyncio.QueueFull:
        logger.warning(
            "Sync queue full, dropping event",
            extra={"project": project_name},
        )


async def sync_single_project(project_name: str, harbor_client: HarborClient) -> None:
    """Sync a single project's accepted CVEs to Harbor allowlist.

    This is used by the event-driven sync consumer. Unlike the scheduled
    sync (run_sync), this does NOT perform drift detection — it just pushes
    the current accepted CVE list to Harbor immediately.

    Args:
        project_name: Project to sync
        harbor_client: Initialised Harbor API client

    Raises:
        Exception: Propagates errors to caller for logging/retry
    """
    try:
        cves = await get_accepted_cves(project_name)
        await harbor_client.set_project_allowlist_mode(project_name)
        await harbor_client.update_project_allowlist(project_name, cves)

        HARBOR_EVENT_SYNC_TOTAL.labels(project=project_name, result="success").inc()
        logger.info(
            "Event-driven sync completed",
            extra={
                "project": project_name,
                "cve_count": len(cves),
            },
        )
    except Exception as e:
        HARBOR_EVENT_SYNC_TOTAL.labels(project=project_name, result="error").inc()
        logger.error(
            "Event-driven sync failed",
            extra={
                "project": project_name,
                "error": str(e),
            },
        )
        raise


async def _event_sync_consumer(harbor_client: HarborClient, settings: Settings) -> None:
    """Background consumer for event-driven Harbor sync.

    Processes project sync requests from the queue with debouncing:
    1. Wait for first event (blocking)
    2. Collect additional events for debounce_seconds (non-blocking)
    3. Deduplicate project names
    4. Sync each unique project to Harbor
    5. Refresh Prometheus gauges
    6. Repeat

    Args:
        harbor_client: Initialised Harbor API client
        settings: Application settings
    """
    global _sync_queue

    logger.info(
        "Event sync consumer started",
        extra={"debounce_seconds": settings.sync_debounce_seconds},
    )

    while True:
        try:
            # Wait for first event (blocking)
            project = await _sync_queue.get()
            projects = {project}

            # Collect additional events for debounce window
            debounce_end = time.time() + settings.sync_debounce_seconds
            while time.time() < debounce_end:
                try:
                    timeout = max(0.1, debounce_end - time.time())
                    next_project = await asyncio.wait_for(
                        _sync_queue.get(),
                        timeout=timeout,
                    )
                    projects.add(next_project)
                except asyncio.TimeoutError:
                    break

            # Sync all unique projects in batch
            start_time = time.time()
            success_count = 0
            error_count = 0

            for project_name in projects:
                try:
                    await sync_single_project(project_name, harbor_client)
                    success_count += 1
                except Exception:
                    # Error already logged in sync_single_project
                    error_count += 1

            # Refresh gauges after batch sync
            await run_refresh_gauges()

            duration = time.time() - start_time
            HARBOR_EVENT_SYNC_DURATION.observe(duration)

            logger.info(
                "Event sync batch completed",
                extra={
                    "project_count": len(projects),
                    "success_count": success_count,
                    "error_count": error_count,
                    "duration_seconds": round(duration, 2),
                },
            )

        except asyncio.CancelledError:
            logger.info("Event sync consumer cancelled")
            raise
        except Exception as e:
            logger.error(
                "Event sync consumer error",
                extra={"error": str(e)},
            )
            # Continue processing events


async def _run_periodic(
    name: str,
    coro_fn,
    interval_seconds: int,
    logger: logging.Logger,
) -> None:
    """Generic periodic task runner.

    Sleeps first to allow application to fully initialise, then runs
    the coroutine function on a fixed interval. Logs execution duration
    and continues on errors (except CancelledError).

    Args:
        name: Task name for logging
        coro_fn: Coroutine function to execute periodically
        interval_seconds: Interval between executions
        logger: Logger instance
    """
    # Initial delay to let app fully start
    await asyncio.sleep(interval_seconds)

    while True:
        start_time = time.time()
        try:
            await coro_fn()
            duration = time.time() - start_time
            SCHEDULER_TASK_DURATION.labels(task=name).observe(duration)
            logger.info(
                f"{name} completed successfully",
                extra={
                    "task": name,
                    "duration_seconds": round(duration, 2),
                },
            )
        except asyncio.CancelledError:
            logger.info(f"{name} cancelled", extra={"task": name})
            raise
        except Exception as e:
            duration = time.time() - start_time
            SCHEDULER_TASK_DURATION.labels(task=name).observe(duration)
            logger.error(
                f"{name} failed",
                extra={
                    "task": name,
                    "error": str(e),
                    "duration_seconds": round(duration, 2),
                },
            )

        await asyncio.sleep(interval_seconds)


async def run_sync(harbor_client: HarborClient, settings: Settings) -> None:
    """Sync accepted CVEs to Harbor project allowlists.

    For each project with vulnerabilities:
    1. Get accepted CVEs from database
    2. Read current Harbor allowlist
    3. Compare and record drift
    4. Set project to project-level allowlist mode
    5. Push CVE list to Harbor allowlist

    Updates prometheus metric on successful sync.
    Continues to next project if one fails.

    Args:
        harbor_client: Initialised Harbor API client
        settings: Application settings
    """
    summary = await get_summary()

    for project in summary:
        project_name = project["name"]
        try:
            cves = await get_accepted_cves(project_name)

            # Drift detection: compare Harbor Exempt state with Harbor state
            try:
                harbor_cves = await harbor_client.get_project_allowlist(project_name)
                app_set = set(cves)
                harbor_set = set(harbor_cves)
                extra_in_harbor = harbor_set - app_set
                missing_in_harbor = app_set - harbor_set

                HARBOR_DRIFT_CVES.labels(
                    project=project_name,
                    direction="extra_in_harbor",
                ).set(len(extra_in_harbor))
                HARBOR_DRIFT_CVES.labels(
                    project=project_name,
                    direction="missing_in_harbor",
                ).set(len(missing_in_harbor))

                if extra_in_harbor or missing_in_harbor:
                    logger.warning(
                        "CVE allowlist drift detected",
                        extra={
                            "project": project_name,
                            "extra_in_harbor": sorted(extra_in_harbor),
                            "missing_in_harbor": sorted(missing_in_harbor),
                        },
                    )
            except Exception:
                logger.warning(
                    "Failed to check drift for project",
                    extra={"project": project_name},
                    exc_info=True,
                )

            await harbor_client.set_project_allowlist_mode(project_name)
            await harbor_client.update_project_allowlist(project_name, cves)
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
            continue

    # Update success timestamp metric
    HARBOR_SYNC_LAST_SUCCESS.set(time.time())


async def run_expire(settings: Settings) -> None:
    """Process expired acceptances.

    Finds acceptances that have passed their expiry date, reopens
    the vulnerabilities, and sends Slack notifications if configured.

    Args:
        settings: Application settings
    """
    from app.routes.maintenance import _send_slack_notification

    expired = await expire_acceptances()

    # Increment expiry counter per project
    for item in expired:
        ACCEPTANCES_EXPIRED_TOTAL.labels(project=item["project"]).inc()

    # Send Slack notifications for expired acceptances
    if expired and settings.slack_webhook_url:
        for item in expired:
            await _send_slack_notification(settings.slack_webhook_url, item)

    logger.info(
        "Expiry check completed",
        extra={"expired_count": len(expired)},
    )


async def run_refresh_gauges() -> None:
    """Refresh Prometheus gauges from current database state.

    Queries the summary endpoint data and updates gauges for open
    vulnerabilities, active acceptances, and expiring acceptances.
    Also queries expiry metrics for multi-window counts and earliest
    expiry timestamp per project.
    """
    summary = await get_summary()
    expiry_metrics = await get_expiry_metrics()

    # Clear stale label sets before re-populating
    VULNS_OPEN._metrics.clear()
    ACCEPTANCES_ACTIVE._metrics.clear()
    ACCEPTANCES_EXPIRING._metrics.clear()
    ACCEPTANCE_EARLIEST_EXPIRY._metrics.clear()
    VULNS_FIXABLE._metrics.clear()

    for project in summary:
        name = project["name"]

        # Open vulnerabilities by severity
        open_counts = project.get("open", {})
        for severity in ("critical", "high", "medium", "low", "unknown"):
            VULNS_OPEN.labels(
                project=name,
                severity=severity.upper(),
            ).set(open_counts.get(severity, 0))

        # Active acceptances (sum of all accepted vulns across severities)
        accepted_counts = project.get("accepted", {})
        total_accepted = sum(accepted_counts.values())
        ACCEPTANCES_ACTIVE.labels(project=name).set(total_accepted)

    # Expiry metrics: multi-window counts + earliest expiry timestamp
    for row in expiry_metrics:
        name = row["name"]

        for window, key in (("7d", "expiring_7d"), ("14d", "expiring_14d"), ("30d", "expiring_30d")):
            ACCEPTANCES_EXPIRING.labels(project=name, window=window).set(row[key])

        if row["earliest_expiry"] is not None:
            ACCEPTANCE_EARLIEST_EXPIRY.labels(project=name).set(row["earliest_expiry"].timestamp(),)

    # VULNS_FIXABLE gauge
    fixable_counts = await get_fixable_counts()
    for row in fixable_counts:
        VULNS_FIXABLE.labels(
            project=row["project"],
            severity=row["severity"],
            source=row["source"],
        ).set(row["cnt"])

    logger.info(
        "Gauge refresh completed",
        extra={"projects": len(summary)},
    )


async def run_check_external_fixes(settings: Settings) -> None:
    """Check OSV.dev for fix availability on accepted CVEs without a Trivy fix.

    Processes only CVEs not already checked within the cache TTL.
    Respects 1 rps rate limit via the OSV client.

    Args:
        settings: Application settings with OSV configuration.
    """
    from app.osv import check_cve

    pending = await get_accepted_without_fixed_version(cache_ttl_seconds=settings.fix_check_cache_ttl_seconds,)

    if not pending:
        logger.debug("No accepted CVEs pending OSV fix check")
        return

    new_fixes = 0

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
            logger.error(
                "OSV fix check failed for CVE",
                extra={
                    "cve_id": cve_id,
                    "error": str(e)
                },
            )

    # Refresh VULNS_FIXABLE gauge after run
    VULNS_FIXABLE._metrics.clear()
    fixable_counts = await get_fixable_counts()
    for row in fixable_counts:
        VULNS_FIXABLE.labels(
            project=row["project"],
            severity=row["severity"],
            source=row["source"],
        ).set(row["cnt"])

    OSV_CHECK_LAST_SUCCESS.set(time.time())

    logger.info(
        "OSV fix check completed",
        extra={
            "checked": len(pending),
            "new_fixes_found": new_fixes,
        },
    )


async def run_resolve_tags(harbor_client: HarborClient) -> None:
    """Resolve missing tags for scans by querying Harbor.

    Finds scans with NULL tag, attempts to resolve via the Harbor API,
    and updates the database with discovered tags.

    Args:
        harbor_client: Initialised Harbor API client.
    """
    groups = await list_scans_missing_tags()
    if not groups:
        logger.debug("No scans missing tags")
        return

    resolved = 0
    errors = 0

    for group in groups:
        try:
            tag = await harbor_client.resolve_tag(
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
        except Exception:
            errors += 1
            logger.debug(
                "Tag resolution failed for group",
                extra={
                    "project": group["project_name"],
                    "repository": group["repository"],
                },
            )

    logger.info(
        "Tag resolution completed",
        extra={
            "groups": len(groups),
            "resolved": resolved,
            "errors": errors,
        },
    )


async def run_reconcile_acceptances() -> None:
    """Reconcile accepted CVEs across all projects.

    Safety-net sweep: for each project, auto-accepts open vulnerability
    instances whose CVE already has an active acceptance. Catches any
    edge cases the webhook-path reconciliation might miss.
    """
    projects = await list_projects()

    total_reconciled = 0
    for project_name in projects:
        try:
            reconciled = await reconcile_accepted_cves_for_project(project_name)
            if reconciled:
                count = len(reconciled)
                total_reconciled += count
                AUTO_RECONCILE_TOTAL.labels(project=project_name, trigger="scheduler").inc(count)
                logger.info(
                    "Scheduler reconciled acceptances",
                    extra={
                        "project": project_name,
                        "reconciled_count": count,
                        "cves": [r["cve_id"] for r in reconciled],
                    },
                )
        except Exception:
            logger.warning(
                "Scheduler reconcile failed for project",
                extra={"project": project_name},
                exc_info=True,
            )

    if total_reconciled:
        logger.info(
            "Reconcile sweep completed",
            extra={
                "total_reconciled": total_reconciled,
                "projects_checked": len(projects)
            },
        )


async def run_cleanup_deleted_images(harbor_client: HarborClient) -> None:
    """Clean up orphaned vulnerabilities for images deleted from Harbor.

    For each project with vulnerabilities:
    1. Lists all repositories in Harbor
    2. Lists all repositories in Harbor Exempt
    3. Deletes vulnerabilities for repositories not found in Harbor

    Args:
        harbor_client: Initialised Harbor API client
    """
    summary = await get_summary()
    total_deleted = 0
    projects_cleaned = 0

    for project in summary:
        project_name = project["name"]

        try:
            # Get repositories from Harbor and Harbor Exempt
            harbor_repos = set(await harbor_client.list_repositories(project_name))
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

                projects_cleaned += 1

        except Exception:
            logger.warning(
                "Failed to cleanup project",
                extra={"project": project_name},
                exc_info=True,
            )

    if total_deleted or projects_cleaned:
        logger.info(
            "Deleted images cleanup completed",
            extra={
                "projects_checked": len(summary),
                "projects_cleaned": projects_cleaned,
                "total_deleted": total_deleted,
            },
        )


def start_scheduler(
    settings: Settings,
    harbor_client: HarborClient | None,
) -> list[asyncio.Task]:
    """Create and start background scheduler tasks.

    Args:
        settings: Application settings with interval configuration
        harbor_client: Initialised Harbor client (None to skip sync task)

    Returns:
        List of created asyncio tasks
    """
    global _sync_queue
    tasks = []

    # Only create sync task if Harbor client is configured
    if harbor_client is not None:
        sync_task = asyncio.create_task(
            _run_periodic(
                name="harbor_sync",
                coro_fn=lambda: run_sync(harbor_client, settings),
                interval_seconds=settings.sync_interval_seconds,
                logger=logger,
            ),
            name="harbor_sync",
        )
        tasks.append(sync_task)
        logger.info(
            "Started Harbor sync task",
            extra={"interval_seconds": settings.sync_interval_seconds},
        )

        # Tag resolution task (same interval as sync)
        tag_resolve_task = asyncio.create_task(
            _run_periodic(
                name="resolve_tags",
                coro_fn=lambda: run_resolve_tags(harbor_client),
                interval_seconds=settings.sync_interval_seconds,
                logger=logger,
            ),
            name="resolve_tags",
        )
        tasks.append(tag_resolve_task)
        logger.info(
            "Started tag resolution task",
            extra={"interval_seconds": settings.sync_interval_seconds},
        )

        # Initialise event sync queue and consumer
        _sync_queue = asyncio.Queue()
        event_sync_task = asyncio.create_task(
            _event_sync_consumer(harbor_client, settings),
            name="event_sync_consumer",
        )
        tasks.append(event_sync_task)
        logger.info(
            "Started event sync consumer",
            extra={"debounce_seconds": settings.sync_debounce_seconds},
        )

    # Always create expire task
    expire_task = asyncio.create_task(
        _run_periodic(
            name="expire_acceptances",
            coro_fn=lambda: run_expire(settings),
            interval_seconds=settings.expire_interval_seconds,
            logger=logger,
        ),
        name="expire_acceptances",
    )
    tasks.append(expire_task)
    logger.info(
        "Started expiry task",
        extra={"interval_seconds": settings.expire_interval_seconds},
    )

    # Reconcile accepted CVEs (purely DB work, no Harbor dependency)
    reconcile_task = asyncio.create_task(
        _run_periodic(
            name="reconcile_acceptances",
            coro_fn=run_reconcile_acceptances,
            interval_seconds=settings.sync_interval_seconds,
            logger=logger,
        ),
        name="reconcile_acceptances",
    )
    tasks.append(reconcile_task)
    logger.info(
        "Started reconcile acceptances task",
        extra={"interval_seconds": settings.sync_interval_seconds},
    )

    # Gauge refresh task (same interval as sync)
    gauge_task = asyncio.create_task(
        _run_periodic(
            name="refresh_gauges",
            coro_fn=run_refresh_gauges,
            interval_seconds=settings.sync_interval_seconds,
            logger=logger,
        ),
        name="refresh_gauges",
    )
    tasks.append(gauge_task)
    logger.info(
        "Started gauge refresh task",
        extra={"interval_seconds": settings.sync_interval_seconds},
    )

    # OSV fix check task (runs daily)
    if settings.osv_enabled:
        fix_check_task = asyncio.create_task(
            _run_periodic(
                name="check_external_fixes",
                coro_fn=lambda: run_check_external_fixes(settings),
                interval_seconds=settings.fix_check_interval_seconds,
                logger=logger,
            ),
            name="check_external_fixes",
        )
        tasks.append(fix_check_task)
        logger.info(
            "Started OSV fix check task",
            extra={"interval_seconds": settings.fix_check_interval_seconds},
        )

    # Cleanup deleted images task (runs daily, requires Harbor client)
    if harbor_client is not None:
        cleanup_task = asyncio.create_task(
            _run_periodic(
                name="cleanup_deleted_images",
                coro_fn=lambda: run_cleanup_deleted_images(harbor_client),
                interval_seconds=settings.cleanup_deleted_images_interval_seconds,
                logger=logger,
            ),
            name="cleanup_deleted_images",
        )
        tasks.append(cleanup_task)
        logger.info(
            "Started cleanup deleted images task",
            extra={"interval_seconds": settings.cleanup_deleted_images_interval_seconds},
        )

    return tasks


def stop_scheduler(tasks: list[asyncio.Task]) -> None:
    """Cancel all scheduler tasks.

    Args:
        tasks: List of asyncio tasks to cancel
    """
    global _sync_queue
    _sync_queue = None

    for task in tasks:
        task.cancel()
    logger.info("Scheduler tasks cancelled", extra={"task_count": len(tasks)})
