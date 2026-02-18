"""Shared pytest fixtures for Harbor Exempt unit tests."""

import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear the lru_cache on get_settings before and after each test.

    Prevents cross-test contamination when Settings is constructed with
    different kwargs in test_config.py.
    """
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
