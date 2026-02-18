"""Unit tests for Settings properties and validator in app.config."""

import pytest

from app.config import Settings


class TestExcludedProjectsSet:
    """Tests for Settings.excluded_projects_set property."""

    def test_empty_string_returns_empty_set(self):
        s = Settings(excluded_projects="")
        assert s.excluded_projects_set == set()

    def test_single_project(self):
        s = Settings(excluded_projects="alpha")
        assert s.excluded_projects_set == {"alpha"}

    def test_csv_multiple_projects(self):
        s = Settings(excluded_projects="alpha,beta,gamma")
        assert s.excluded_projects_set == {"alpha", "beta", "gamma"}

    def test_whitespace_is_trimmed(self):
        s = Settings(excluded_projects=" alpha , beta ")
        assert s.excluded_projects_set == {"alpha", "beta"}

    def test_trailing_comma_is_ignored(self):
        s = Settings(excluded_projects="alpha,")
        assert s.excluded_projects_set == {"alpha"}


class TestDatabaseConfigured:
    """Tests for Settings.database_configured property."""

    def test_all_fields_set_returns_true(self):
        s = Settings(db_host="pg.example.com", db_username="user", db_password="pass")
        assert s.database_configured is True

    def test_missing_host_returns_false(self):
        s = Settings(db_host=None, db_username="user", db_password="pass")
        assert s.database_configured is False

    def test_missing_username_returns_false(self):
        s = Settings(db_host="pg.example.com", db_username=None, db_password="pass")
        assert s.database_configured is False

    def test_missing_password_returns_false(self):
        s = Settings(db_host="pg.example.com", db_username="user", db_password=None)
        assert s.database_configured is False


class TestValidateConfiguration:
    """Tests for Settings.validate_configuration model validator."""

    @pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    def test_valid_log_levels_pass(self, level):
        s = Settings(log_level=level)
        assert s.log_level == level

    def test_invalid_log_level_raises(self):
        with pytest.raises(ValueError, match="Invalid HARBOR_EXEMPT_LOG_LEVEL"):
            Settings(log_level="VERBOSE")
