"""Harbor API client for Harbor Exempt.

Handles vulnerability report fetching, CVE allowlist management,
and manifest list resolution. Implements all learnings from prototyping around
URL encoding, multi-arch images, and report structure.
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime

import httpx

from app.metrics import HARBOR_API_DURATION, HARBOR_API_ERRORS_TOTAL

logger = logging.getLogger(__name__)

REPORT_MIME_TYPE = "application/vnd.security.vulnerability.report; version=1.1"
TARGET_PLATFORM = {"os": "linux", "architecture": "amd64"}


def _parse_harbor_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp from the Harbor API into a datetime.

    Harbor returns timestamps like '2024-01-15T10:30:00.000Z' or
    '0001-01-01T00:00:00.000Z' for never-pulled artifacts.
    Returns None for missing, empty, or zero-epoch values.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # Harbor uses 0001-01-01 as a sentinel for "never"
        if dt.year <= 1:
            return None
        return dt
    except (ValueError, TypeError):
        return None


def extract_repository(image_ref: str) -> str:
    """Extract repository path from image reference.

    Strips any hostname prefix, tag (after ':') and digest (after '@') to get
    the bare repository path. A leading segment is treated as a hostname if it
    contains a ':' (port) or a '.' (domain).

    Examples:
        platform/app:v1.2.3 -> platform/app
        platform/app@sha256:abc -> platform/app
        platform/app:v1.2.3@sha256:abc -> platform/app
        localhost:8088/platform/app:v1.2.3 -> platform/app
        harbor.example.com/platform/app -> platform/app
    """
    # Strip digest first (after @)
    repo = image_ref.split("@")[0]
    # Strip tag (after last :, but not port numbers)
    parts = repo.rsplit(":", 1)
    if len(parts) == 2 and "/" in parts[0]:
        # Only strip if the part before : contains a slash (it's a tag, not a port)
        repo = parts[0]

    # Strip hostname prefix if the first segment looks like a host
    # (contains a port ':' or a domain '.')
    if "/" in repo:
        first_segment = repo.split("/", 1)[0]
        if ":" in first_segment or "." in first_segment:
            repo = repo.split("/", 1)[1]

    return repo


def extract_tag(image_ref: str) -> str | None:
    """Extract tag from an image reference, if present.

    Returns the tag portion of the reference, or None if only a digest
    is present (no tag).

    Examples:
        platform/app:v1.2.3 -> v1.2.3
        platform/app@sha256:abc -> None
        platform/app:v1.2.3@sha256:abc -> v1.2.3
        localhost:8088/platform/app:v1.2.3 -> v1.2.3
    """
    # Strip digest suffix first
    ref = image_ref.split("@")[0]

    # Find the last colon — but only treat it as a tag separator
    # if there is a slash before it (otherwise it could be a port)
    parts = ref.rsplit(":", 1)
    if len(parts) == 2 and "/" in parts[0]:
        return parts[1]

    return None


def _encode_repository(repo_name: str) -> str:
    """Double URL-encode repository paths for Harbor API.

    Harbor API requires repository paths with slashes to be URL-encoded,
    but httpx normalises %2F back to /. Double-encoding (%252F) survives
    the normalisation — Harbor decodes it to %2F, then to /.
    """
    return repo_name.replace("/", "%252F")


class HarborClient:
    """Async client for Harbor v2.0 API."""

    def __init__(self, base_url: str, username: str, password: str) -> None:
        """Initialise the Harbor client.

        Args:
            base_url: Harbor base URL (e.g. https://harbor.example.com)
            username: Harbor robot account username
            password: Harbor robot account password
        """
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            auth=(username, password),
            timeout=30.0,
            follow_redirects=True,
        )

    @contextmanager
    def _timed(self, method: str):
        """Time a Harbor API call and record errors."""
        start = time.monotonic()
        try:
            yield
        except Exception:
            HARBOR_API_ERRORS_TOTAL.labels(method=method).inc()
            raise
        finally:
            HARBOR_API_DURATION.labels(method=method).observe(time.monotonic() - start)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def check_health(self) -> dict:
        """Check Harbor instance health via the health API.

        Returns:
            Dict with keys:
                - status: "green", "amber", or "red"
                - label: Short human-readable status
                - detail: Longer description
        """
        try:
            with self._timed("health_check"):
                response = await self._client.get("/api/v2.0/health")
                response.raise_for_status()
                data = response.json()

            overall = data.get("status", "unknown")
            components = data.get("components", [])
            unhealthy = [c["name"] for c in components if c.get("status") != "healthy"]

            if overall == "healthy":
                return {
                    "status": "green",
                    "label": "Connected",
                    "detail": f"All {len(components)} components healthy",
                }

            # Reachable but degraded
            return {
                "status": "amber",
                "label": "Degraded",
                "detail": f"Unhealthy: {', '.join(unhealthy)}",
            }
        except Exception as e:
            return {
                "status": "red",
                "label": "Unreachable",
                "detail": str(e),
            }

    async def fetch_vulnerability_report(
        self,
        project: str,
        repository: str,
        digest: str,
    ) -> dict:
        """Fetch vulnerability report for an artifact from Harbor.

        Handles manifest list resolution — if the artifact is a manifest list,
        resolves to the amd64/linux child and fetches its report.
        Returns push_time and pull_time from the parent artifact (manifest list
        or single-arch) since those represent the user-visible timestamps.

        Args:
            project: Harbor project name (e.g. 'platform')
            repository: Repository path within project (e.g. 'app' for platform/app)
            digest: Image digest (sha256:...)

        Returns:
            Dict with keys:
                - vulnerabilities: list of vulnerability dicts
                - push_time: datetime or None
                - pull_time: datetime or None
        """
        with self._timed("fetch_report"):
            # Strip project prefix from repository if present
            repo_path = repository
            if repo_path.startswith(f"{project}/"):
                repo_path = repo_path[len(project) + 1:]

            encoded_repo = _encode_repository(repo_path)

            # Fetch the artifact
            artifact_url = f"/api/v2.0/projects/{project}/repositories/{encoded_repo}/artifacts/{digest}"
            response = await self._client.get(
                artifact_url,
                params={"with_scan_overview": "true"},
            )
            response.raise_for_status()
            artifact = response.json()

            # Extract timestamps from the parent artifact
            push_time = _parse_harbor_timestamp(artifact.get("push_time"))
            pull_time = _parse_harbor_timestamp(artifact.get("pull_time"))

            # Check if manifest list (multi-arch)
            references = artifact.get("references")
            if references:
                logger.info(
                    "Artifact is manifest list, resolving child",
                    extra={
                        "project": project,
                        "repository": repository,
                        "children": len(references),
                    },
                )
                child_digest = self._find_platform_child(references)
                if child_digest:
                    vulns = await self._fetch_report_for_digest(
                        project,
                        encoded_repo,
                        child_digest,
                    )
                    return {
                        "vulnerabilities": vulns,
                        "push_time": push_time,
                        "pull_time": pull_time,
                    }
                logger.warning(
                    "No matching platform child found in manifest list",
                    extra={
                        "project": project,
                        "repository": repository
                    },
                )
                return {
                    "vulnerabilities": [],
                    "push_time": push_time,
                    "pull_time": pull_time,
                }

            # Single-arch — fetch report directly
            vulns = await self._fetch_report_for_digest(
                project,
                encoded_repo,
                digest,
            )
            return {
                "vulnerabilities": vulns,
                "push_time": push_time,
                "pull_time": pull_time,
            }

    def _find_platform_child(self, references: list[dict]) -> str | None:
        """Find child artifact matching target platform (amd64/linux)."""
        for ref in references:
            platform = ref.get("platform", {})
            if (
                platform.get("architecture") == TARGET_PLATFORM["architecture"] and
                platform.get("os") == TARGET_PLATFORM["os"]
            ):
                return ref.get("child_digest")
        return None

    async def _fetch_report_for_digest(
        self,
        project: str,
        encoded_repo: str,
        digest: str,
    ) -> list[dict]:
        """Fetch the vulnerability report for a specific digest.

        Unwraps the MIME-type key from Harbor's response structure.
        """
        url = (
            f"/api/v2.0/projects/{project}/repositories/{encoded_repo}"
            f"/artifacts/{digest}/additions/vulnerabilities"
        )
        response = await self._client.get(url)
        response.raise_for_status()
        data = response.json()

        # Unwrap MIME-type key
        report = data.get(REPORT_MIME_TYPE, {})
        return report.get("vulnerabilities", [])

    async def resolve_tag(
        self,
        project: str,
        repository: str,
        digest: str,
    ) -> str | None:
        """Resolve a human-readable tag for an artifact digest.

        Multi-arch images in Harbor store the tag on the parent manifest
        list, while scan webhooks fire for child (per-architecture)
        artifacts that only have a digest.  This method finds the parent
        and returns its first tag.

        Strategy:
        1. Check if the digest itself carries a tag.
        2. List repository artifacts and find a manifest list whose
           ``references`` contain this digest; return its first tag.

        Args:
            project: Harbor project name.
            repository: Full repository path (e.g. 'platform/app').
            digest: Child artifact digest (sha256:...).

        Returns:
            The tag string, or None if no tag could be resolved.
        """
        repo_path = repository
        if repo_path.startswith(f"{project}/"):
            repo_path = repo_path[len(project) + 1:]

        encoded_repo = _encode_repository(repo_path)

        with self._timed("resolve_tag"):
            # 1. Check the digest itself for tags
            try:
                url = f"/api/v2.0/projects/{project}/repositories/{encoded_repo}/artifacts/{digest}"
                response = await self._client.get(url, params={"with_tag": "true"})
                response.raise_for_status()
                artifact = response.json()
                tags = artifact.get("tags")
                if tags:
                    return tags[0].get("name")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.debug(
                        "Artifact not found during tag resolution",
                        extra={
                            "project": project,
                            "repository": repository,
                            "digest": digest
                        },
                    )
                    return None
                raise

            # 2. Search repository artifacts for a parent manifest list
            max_pages = 5
            page_size = 50
            for page in range(1, max_pages + 1):
                response = await self._client.get(
                    f"/api/v2.0/projects/{project}/repositories/{encoded_repo}/artifacts",
                    params={
                        "with_tag": "true",
                        "page": page,
                        "page_size": page_size
                    },
                )
                response.raise_for_status()
                artifacts = response.json()

                if not artifacts:
                    break

                for art in artifacts:
                    refs = art.get("references")
                    if not refs:
                        continue
                    for ref in refs:
                        if ref.get("child_digest") == digest:
                            art_tags = art.get("tags")
                            if art_tags:
                                return art_tags[0].get("name")

                if len(artifacts) < page_size:
                    break

        return None

    async def update_project_allowlist(
        self,
        project_name: str,
        cve_ids: list[str],
    ) -> None:
        """Update project CVE allowlist with full replacement.

        This is a PUT operation — the provided list completely replaces
        the existing allowlist.

        Args:
            project_name: Harbor project name
            cve_ids: List of CVE IDs to allow
        """
        with self._timed("update_allowlist"):
            items = [{"cve_id": cve_id} for cve_id in cve_ids]
            payload = {
                "cve_allowlist": {
                    "items": items,
                },
            }

            # Clear accumulated session cookies to prevent Harbor CSRF enforcement
            self._client.cookies.clear()
            response = await self._client.put(
                f"/api/v2.0/projects/{project_name}",
                json=payload,
            )
            response.raise_for_status()

            logger.info(
                "Updated Harbor project CVE allowlist",
                extra={
                    "project": project_name,
                    "cve_count": len(cve_ids),
                },
            )

    async def set_project_allowlist_mode(self, project_name: str) -> None:
        """Set project to use project-level CVE allowlist mode.

        Harbor defaults to 'System allowlist' mode. This sets it to
        'Project allowlist' mode so project-specific exceptions apply.
        Idempotent — safe to call on every sync run.
        """
        with self._timed("set_allowlist_mode"):
            payload = {
                "metadata": {
                    "reuse_sys_cve_allowlist": "false",
                },
            }

            # Clear accumulated session cookies to prevent Harbor CSRF enforcement
            self._client.cookies.clear()
            response = await self._client.put(
                f"/api/v2.0/projects/{project_name}",
                json=payload,
            )

            # 409 is acceptable (already set)
            if response.status_code == 409:
                logger.debug(
                    "Project allowlist mode already set",
                    extra={"project": project_name},
                )
                return

            response.raise_for_status()

            logger.info(
                "Set project to project-level allowlist mode",
                extra={"project": project_name},
            )

    async def get_project_allowlist(self, project_name: str) -> list[str]:
        """Fetch the current CVE allowlist from a Harbor project.

        Returns:
            Sorted list of CVE IDs currently in the project's allowlist.
        """
        with self._timed("get_allowlist"):
            response = await self._client.get(f"/api/v2.0/projects/{project_name}",)
            response.raise_for_status()
            data = response.json()

            items = data.get("cve_allowlist", {}).get("items", [])
            return sorted(item["cve_id"] for item in items)

    async def get_project_threshold(self, project_name: str) -> str | None:
        """Get the vulnerability severity threshold for a single project.

        Returns:
            Severity level ("critical", "high", "medium", "low") or None
            if the project doesn't exist or has no threshold configured.
        """
        with self._timed("get_threshold"):
            response = await self._client.get(
                "/api/v2.0/projects",
                params={
                    "name": project_name,
                    "page": 1,
                    "page_size": 1
                },
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            if not data:
                return None

            metadata = data[0].get("metadata", {})
            return metadata.get("severity") or None

    async def list_projects(self) -> list[dict]:
        """List all Harbor projects with vulnerability prevention metadata.

        Returns:
            List of dicts with keys:
                - name: project name
                - prevent_vul: whether vulnerable image deployment is blocked
                - severity_threshold: severity level at which images are blocked
                  ("critical", "high", "medium", "low") or None
        """
        with self._timed("list_projects"):
            projects: list[dict] = []
            page = 1
            page_size = 100

            while True:
                response = await self._client.get(
                    "/api/v2.0/projects",
                    params={
                        "page": page,
                        "page_size": page_size
                    },
                )
                response.raise_for_status()
                data = response.json()

                if not data:
                    break

                for p in data:
                    metadata = p.get("metadata", {})
                    projects.append(
                        {
                            "name": p["name"],
                            "prevent_vul": metadata.get("prevent_vul", "false").lower() == "true",
                            "severity_threshold": metadata.get("severity") or None,
                        }
                    )

                if len(data) < page_size:
                    break
                page += 1

            return projects

    async def list_repositories(self, project_name: str) -> list[str]:
        """List all repository names in a Harbor project.

        Args:
            project_name: The Harbor project name

        Returns:
            List of repository names (e.g., ["platform/app", "platform/worker"])
        """
        with self._timed("list_repositories"):
            repositories: list[str] = []
            page = 1
            page_size = 100

            while True:
                response = await self._client.get(
                    f"/api/v2.0/projects/{project_name}/repositories",
                    params={
                        "page": page,
                        "page_size": page_size
                    },
                )
                response.raise_for_status()
                data = response.json()

                if not data:
                    break

                for repo in data:
                    # Extract just the repository name without the project prefix
                    # Harbor returns "platform/app" format
                    repo_name = repo.get("name", "")
                    if repo_name:
                        repositories.append(repo_name)

                if len(data) < page_size:
                    break
                page += 1

            return repositories
