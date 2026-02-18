"""OSV.dev API client for CVE fix availability checks.

Rate-limited to 1 request per second. Returns fix availability
and fixed version details from the OSV.dev vulnerability database.
"""

import asyncio
import logging
import time

import httpx

from app.metrics import OSV_API_DURATION, OSV_LOOKUPS_TOTAL

logger = logging.getLogger(__name__)

OSV_BASE_URL = "https://api.osv.dev/v1/vulns"
_RATE_LIMIT_SECONDS = 1.0

_last_request_time: float = 0.0


async def _rate_limit() -> None:
    """Enforce 1 rps rate limit via asyncio.sleep."""
    global _last_request_time
    now = time.monotonic()
    elapsed = now - _last_request_time
    if elapsed < _RATE_LIMIT_SECONDS:
        await asyncio.sleep(_RATE_LIMIT_SECONDS - elapsed)
    _last_request_time = time.monotonic()


def _extract_fixed_versions(data: dict) -> list[dict]:
    """Parse fixed versions from OSV affected[].ranges[].events."""
    fixed: list[dict] = []
    for affected in data.get("affected", []):
        ecosystem = affected.get("package", {}).get("ecosystem", "")
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append({
                        "ecosystem": ecosystem,
                        "fixed": event["fixed"],
                        "type": rng.get("type", ""),
                    })
    return fixed


async def check_cve(cve_id: str) -> tuple[bool, list[dict], dict]:
    """Query OSV.dev for fix availability for a single CVE.

    Args:
        cve_id: CVE identifier (e.g. CVE-2023-12345)

    Returns:
        Tuple of (fix_available, fixed_versions, raw_response).
        On 404, returns (False, [], {}) — not counted as error.
    """
    await _rate_limit()

    url = f"{OSV_BASE_URL}/{cve_id}"
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)

        duration = time.monotonic() - start
        OSV_API_DURATION.observe(duration)

        if response.status_code == 404:
            OSV_LOOKUPS_TOTAL.labels(result="no_fix").inc()
            return False, [], {}

        response.raise_for_status()
        data = response.json()

        fixed_versions = _extract_fixed_versions(data)
        fix_available = len(fixed_versions) > 0

        result_label = "fix_found" if fix_available else "no_fix"
        OSV_LOOKUPS_TOTAL.labels(result=result_label).inc()

        logger.debug(
            "OSV lookup completed",
            extra={
                "cve_id": cve_id,
                "fix_available": fix_available,
                "fixed_version_count": len(fixed_versions),
            },
        )

        return fix_available, fixed_versions, data

    except httpx.HTTPStatusError as e:
        duration = time.monotonic() - start
        OSV_API_DURATION.observe(duration)
        OSV_LOOKUPS_TOTAL.labels(result="error").inc()
        logger.warning(
            "OSV API HTTP error",
            extra={
                "cve_id": cve_id,
                "status_code": e.response.status_code
            },
        )
        raise

    except Exception as e:
        duration = time.monotonic() - start
        OSV_API_DURATION.observe(duration)
        OSV_LOOKUPS_TOTAL.labels(result="error").inc()
        logger.error(
            "OSV API request failed",
            extra={
                "cve_id": cve_id,
                "error": str(e)
            },
        )
        raise
