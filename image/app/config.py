"""Configuration management for Harbor Exempt using Pydantic Settings."""

import json
import logging
import sys
from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter for production observability."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_obj = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        # Include extra fields from record
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in (
                    "name",
                    "msg",
                    "args",
                    "created",
                    "filename",
                    "funcName",
                    "levelname",
                    "levelno",
                    "lineno",
                    "module",
                    "msecs",
                    "pathname",
                    "process",
                    "processName",
                    "relativeCreated",
                    "stack_info",
                    "exc_info",
                    "exc_text",
                    "message",
                    "thread",
                    "threadName",
                    "taskName",
                ):
                    log_obj[key] = value
        return json.dumps(log_obj)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="HARBOR_EXEMPT_",
        case_sensitive=False,
    )

    # Logging
    log_level: str = "INFO"

    # Database — separate fields to avoid URL-encoding issues with special characters
    db_host: str | None = None
    db_port: int = 5432
    db_name: str = "harbor_exempt"
    db_username: str | None = None
    db_password: str | None = None
    db_sslmode: str | None = None

    # Harbor Integration
    harbor_url: str | None = None
    harbor_username: str | None = None
    harbor_password: str | None = None

    # Slack Notifications
    slack_webhook_url: str | None = None

    # Risk Acceptance Constraints
    max_expiry_days: int = 90

    # Scheduler
    scheduler_enabled: bool = True
    sync_interval_seconds: int = 300
    expire_interval_seconds: int = 3600
    sync_debounce_seconds: int = 2
    cleanup_deleted_images_interval_seconds: int = 86400  # 24h

    # Migration
    migration_seed_path: str = ""  # Path to JSON seed file (empty = disabled)

    # Project Exclusion
    excluded_projects: str = ""  # Comma-separated project names to hide from all views

    # OSV.dev fix availability checks
    osv_enabled: bool = True
    fix_check_interval_seconds: int = 86400  # 24h
    fix_check_cache_ttl_seconds: int = 86400  # skip re-check within TTL

    @model_validator(mode="after")
    def validate_configuration(self) -> Self:
        """Validate configuration on startup.

        Checks critical configuration and fails fast if required settings
        are missing or invalid.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Validate database configuration
        if not self.db_host:
            warnings.append("HARBOR_EXEMPT_DB_HOST not set - database operations will fail")

        # Validate log level
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_levels:
            errors.append(
                f"Invalid HARBOR_EXEMPT_LOG_LEVEL '{self.log_level}'. "
                f"Must be one of: {', '.join(sorted(valid_levels))}"
            )

        # Log warnings (don't fail)
        if warnings:
            # Use print since logging isn't configured yet
            for warning in warnings:
                print(f"[CONFIG WARNING] {warning}", file=sys.stderr)

        # Fail fast on errors
        if errors:
            for error in errors:
                print(f"[CONFIG ERROR] {error}", file=sys.stderr)
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

        return self

    @property
    def excluded_projects_set(self) -> set[str]:
        """Parse excluded_projects into a set for efficient lookup."""
        if not self.excluded_projects:
            return set()
        return {p.strip() for p in self.excluded_projects.split(",") if p.strip()}

    @property
    def database_configured(self) -> bool:
        """Check if database connection parameters are set."""
        return bool(self.db_host and self.db_username and self.db_password)

    def configure_logging(self) -> None:
        """Configure structured JSON logging."""
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logging.root.handlers = [handler]
        logging.root.setLevel(getattr(logging, self.log_level.upper(), logging.INFO))


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
