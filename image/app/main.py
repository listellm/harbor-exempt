"""FastAPI application for Harbor Exempt — Vulnerability Management Service."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import generate_latest
from starlette.responses import Response

from app.config import get_settings
from app.db import check_connection, close_pool, init_pool
from app.harbor import HarborClient

logger = logging.getLogger(__name__)

# Template engine
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def format_datetime(value: datetime | None, fmt: str = "%d/%m/%Y %H:%M") -> str:
    """Format a datetime for display in templates."""
    if value is None:
        return "—"
    return value.strftime(fmt)


def scan_age_class(value: datetime | None) -> str:
    """Return CSS class for RAG colouring based on scan age.

    Green: scanned today
    Amber: scanned 1-7 days ago
    Red:   scanned more than 7 days ago
    """
    if value is None:
        return "scan-age-red"
    now = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    days = (now - value).days
    if days < 1:
        return "scan-age-green"
    if days <= 7:
        return "scan-age-amber"
    return "scan-age-red"


def expiry_age_class(value: datetime | None) -> str:
    """Return CSS class for RAG colouring based on expiry proximity.

    Inverse of scan_age_class — sooner expiry is worse:
    Red:   expires within 7 days
    Amber: expires within 14 days
    Green: expires more than 14 days from now
    """
    if value is None:
        return "scan-age-red"
    now = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    days = (value - now).days
    if days <= 7:
        return "scan-age-red"
    if days <= 14:
        return "scan-age-amber"
    return "scan-age-green"


def parse_report_date(date_str: str | None, end_of_day: bool = False) -> datetime | None:
    """Parse a YYYY-MM-DD date string to a timezone-aware UTC datetime.

    Args:
        date_str:    Date in ``YYYY-MM-DD`` format, or ``None``/empty string.
        end_of_day:  When *True* the time component is set to 23:59:59 so the
                     date is treated as the inclusive upper bound of a range.

    Returns:
        A timezone-aware :class:`~datetime.datetime` in UTC, or ``None`` when
        *date_str* is absent or cannot be parsed.
    """
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    except ValueError:
        return None


templates.env.filters["format_datetime"] = format_datetime
templates.env.filters["scan_age_class"] = scan_age_class
templates.env.filters["expiry_age_class"] = expiry_age_class

# Global Harbor client
_harbor_client: HarborClient | None = None


def get_harbor_client() -> HarborClient | None:
    """Get the initialised Harbor client."""
    return _harbor_client


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application lifecycle."""
    global _harbor_client

    settings = get_settings()
    settings.configure_logging()

    logger.info("Initialising Harbor Exempt")

    # Initialise database pool
    if settings.database_configured:
        await init_pool(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_username,
            password=settings.db_password,
            ssl=settings.db_sslmode,
        )
        logger.info("Database pool initialised")
    else:
        logger.warning("Database connection not configured — running without database")

    # Initialise Harbor client
    if settings.harbor_url and settings.harbor_username and settings.harbor_password:
        _harbor_client = HarborClient(
            base_url=settings.harbor_url,
            username=settings.harbor_username,
            password=settings.harbor_password,
        )
        logger.info("Harbor client initialised", extra={"url": settings.harbor_url})
    else:
        logger.warning("Harbor credentials not configured — sync disabled")

    # Seed migration — import existing CVE acceptances on first boot
    if settings.migration_seed_path:
        from app.db import import_seed_acceptances

        seed_file = Path(settings.migration_seed_path)
        if seed_file.exists():
            imported = await import_seed_acceptances(str(seed_file))
            if imported:
                logger.info("Migration seed complete", extra={"imported": imported})
        else:
            logger.warning("Migration seed file not found", extra={"path": settings.migration_seed_path})

    # Start background scheduler
    scheduler_tasks: list[asyncio.Task] = []
    if settings.scheduler_enabled:
        from app.scheduler import start_scheduler
        scheduler_tasks = start_scheduler(settings, _harbor_client)
        logger.info(
            "Background scheduler started",
            extra={
                "sync_interval": settings.sync_interval_seconds,
                "expire_interval": settings.expire_interval_seconds,
            },
        )

    yield

    # Graceful shutdown
    logger.info("Shutting down Harbor Exempt...")

    # Stop scheduler before closing clients
    if scheduler_tasks:
        from app.scheduler import stop_scheduler
        stop_scheduler(scheduler_tasks)
        logger.info("Background scheduler stopped")

    if _harbor_client:
        await _harbor_client.close()
        _harbor_client = None

    await close_pool()

    logger.info("Harbor Exempt shutdown complete")


app = FastAPI(
    title="Harbor Exempt",
    description="Vulnerability Management Service for Harbor CVE Exceptions",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Mount route routers
from app.routes.maintenance import router as maintenance_router
from app.routes.scans import router as scans_router
from app.routes.summary import router as summary_router
from app.routes.sync import router as sync_router
from app.routes.ui import router as ui_router
from app.routes.vulnerabilities import router as vulns_router
from app.webhook import router as webhook_router

app.include_router(scans_router)
app.include_router(vulns_router)
app.include_router(sync_router)
app.include_router(maintenance_router)
app.include_router(summary_router)
app.include_router(webhook_router)
app.include_router(ui_router)


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe — app is running."""
    return {"status": "healthy"}


@app.get("/readyz")
async def readyz() -> dict:
    """Readiness probe — database is connected."""
    settings = get_settings()
    if not settings.database_configured:
        return {"status": "healthy", "database": "not configured"}

    db_ok = await check_connection()
    if not db_ok:
        return Response(
            content='{"status": "unhealthy", "database": "disconnected"}',
            status_code=503,
            media_type="application/json",
        )
    return {"status": "healthy", "database": "connected"}


@app.get("/metrics")
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
