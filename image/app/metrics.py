"""Centralised Prometheus metric definitions for Harbor Exempt."""

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

SCANS_TOTAL = Counter(
    "harbor_exempt_scans_total",
    "Total scans ingested",
    ["project"],
)

VULNS_INGESTED_TOTAL = Counter(
    "harbor_exempt_vulnerabilities_ingested_total",
    "Vulnerabilities processed during scan ingest",
    ["project", "status"],
)

ACCEPTANCES_CREATED_TOTAL = Counter(
    "harbor_exempt_acceptances_created_total",
    "Risk acceptances created",
    ["project"],
)

ACCEPTANCES_REVOKED_TOTAL = Counter(
    "harbor_exempt_acceptances_revoked_total",
    "Risk acceptances revoked",
    ["project"],
)

ACCEPTANCES_EXPIRED_TOTAL = Counter(
    "harbor_exempt_acceptances_expired_total",
    "Risk acceptances expired",
    ["project"],
)

HARBOR_API_ERRORS_TOTAL = Counter(
    "harbor_exempt_harbor_api_errors_total",
    "Harbor API call errors",
    ["method"],
)

HARBOR_SYNC_PROJECTS_TOTAL = Counter(
    "harbor_exempt_harbor_sync_projects_total",
    "Projects synced to Harbor",
    ["result"],
)

HARBOR_EVENT_SYNC_TOTAL = Counter(
    "harbor_exempt_harbor_event_sync_total",
    "Event-driven syncs to Harbor",
    ["project", "result"],
)

SYNC_EVENTS_QUEUED_TOTAL = Counter(
    "harbor_exempt_sync_events_queued_total",
    "Sync events queued from accept/revoke operations",
    ["project"],
)

AUTO_RECONCILE_TOTAL = Counter(
    "harbor_exempt_auto_reconcile_total",
    "Vulnerability instances auto-accepted during reconciliation",
    ["project", "trigger"],
)

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------

VULNS_OPEN = Gauge(
    "harbor_exempt_vulnerabilities_open",
    "Open vulnerabilities",
    ["project", "severity"],
)

ACCEPTANCES_ACTIVE = Gauge(
    "harbor_exempt_acceptances_active",
    "Active (non-expired, non-revoked) acceptances",
    ["project"],
)

ACCEPTANCES_EXPIRING = Gauge(
    "harbor_exempt_acceptances_expiring_soon",
    "Acceptances expiring within window threshold",
    ["project", "window"],
)

ACCEPTANCE_EARLIEST_EXPIRY = Gauge(
    "harbor_exempt_acceptance_earliest_expiry_timestamp",
    "Unix timestamp of the soonest-expiring active acceptance per project",
    ["project"],
)

HARBOR_SYNC_LAST_SUCCESS = Gauge(
    "harbor_exempt_harbor_sync_last_success_timestamp",
    "Unix timestamp of last successful Harbor sync",
)

HARBOR_DRIFT_CVES = Gauge(
    "harbor_exempt_harbor_drift_cves",
    "CVE allowlist drift between Harbor Exempt and Harbor",
    ["project", "direction"],
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

HARBOR_API_DURATION = Histogram(
    "harbor_exempt_harbor_api_duration_seconds",
    "Harbor API call duration",
    ["method"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

SCAN_PROCESSING_DURATION = Histogram(
    "harbor_exempt_scan_processing_duration_seconds",
    "Scan ingest processing duration",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

SCHEDULER_TASK_DURATION = Histogram(
    "harbor_exempt_scheduler_task_duration_seconds",
    "Scheduler task execution duration",
    ["task"],
    buckets=(0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
)

HARBOR_EVENT_SYNC_DURATION = Histogram(
    "harbor_exempt_harbor_event_sync_duration_seconds",
    "Event-driven sync batch duration",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

OSV_API_DURATION = Histogram(
    "harbor_exempt_osv_api_duration_seconds",
    "OSV.dev API call duration",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# ---------------------------------------------------------------------------
# OSV / fix-check counters + gauges
# ---------------------------------------------------------------------------

OSV_LOOKUPS_TOTAL = Counter(
    "harbor_exempt_osv_lookups_total",
    "OSV.dev API lookups",
    ["result"],  # fix_found | no_fix | error | cached
)

VULNS_FIXABLE = Gauge(
    "harbor_exempt_vulnerabilities_fixable",
    "Accepted vulnerabilities with a known fix available",
    ["project", "severity", "source"],  # trivy | osv
)

OSV_CHECK_LAST_SUCCESS = Gauge(
    "harbor_exempt_osv_check_last_success_timestamp",
    "Unix timestamp of last successful OSV fix check run",
)
