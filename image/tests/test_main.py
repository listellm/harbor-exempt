"""Unit tests for template filter functions in app.main."""

from datetime import datetime, timezone

from freezegun import freeze_time

from app.main import expiry_age_class, format_datetime, scan_age_class


class TestFormatDatetime:
    """Tests for format_datetime."""

    def test_none_returns_em_dash(self):
        assert format_datetime(None) == "—"

    def test_default_format(self):
        dt = datetime(2024, 6, 15, 9, 30)
        assert format_datetime(dt) == "15/06/2024 09:30"

    def test_custom_format(self):
        dt = datetime(2024, 6, 15, 9, 30)
        assert format_datetime(dt, "%Y-%m-%d") == "2024-06-15"

    def test_midnight(self):
        dt = datetime(2024, 6, 15, 0, 0)
        assert format_datetime(dt) == "15/06/2024 00:00"


class TestScanAgeClass:
    """Tests for scan_age_class."""

    def test_none_returns_red(self):
        assert scan_age_class(None) == "scan-age-red"

    @freeze_time("2024-06-15 12:00:00")
    def test_same_day_returns_green(self):
        dt = datetime(2024, 6, 15, 10, 0, tzinfo=timezone.utc)
        assert scan_age_class(dt) == "scan-age-green"

    @freeze_time("2024-06-15 12:00:00")
    def test_one_day_ago_returns_amber(self):
        dt = datetime(2024, 6, 14, 12, 0, tzinfo=timezone.utc)
        assert scan_age_class(dt) == "scan-age-amber"

    @freeze_time("2024-06-15 12:00:00")
    def test_seven_days_ago_returns_amber(self):
        dt = datetime(2024, 6, 8, 12, 0, tzinfo=timezone.utc)
        assert scan_age_class(dt) == "scan-age-amber"

    @freeze_time("2024-06-15 12:00:00")
    def test_eight_days_ago_returns_red(self):
        dt = datetime(2024, 6, 7, 12, 0, tzinfo=timezone.utc)
        assert scan_age_class(dt) == "scan-age-red"

    @freeze_time("2024-06-15 12:00:00")
    def test_naive_datetime_treated_as_utc(self):
        """Naive datetimes should be treated as UTC and not raise an error."""
        dt = datetime(2024, 6, 15, 10, 0)  # no tzinfo
        assert scan_age_class(dt) == "scan-age-green"


class TestExpiryAgeClass:
    """Tests for expiry_age_class."""

    def test_none_returns_red(self):
        assert expiry_age_class(None) == "scan-age-red"

    @freeze_time("2024-06-15 12:00:00")
    def test_expires_now_returns_red(self):
        dt = datetime(2024, 6, 15, 12, 0, tzinfo=timezone.utc)
        assert expiry_age_class(dt) == "scan-age-red"

    @freeze_time("2024-06-15 12:00:00")
    def test_seven_days_returns_red(self):
        dt = datetime(2024, 6, 22, 12, 0, tzinfo=timezone.utc)
        assert expiry_age_class(dt) == "scan-age-red"

    @freeze_time("2024-06-15 12:00:00")
    def test_eight_days_returns_amber(self):
        dt = datetime(2024, 6, 23, 12, 0, tzinfo=timezone.utc)
        assert expiry_age_class(dt) == "scan-age-amber"

    @freeze_time("2024-06-15 12:00:00")
    def test_fourteen_days_returns_amber(self):
        dt = datetime(2024, 6, 29, 12, 0, tzinfo=timezone.utc)
        assert expiry_age_class(dt) == "scan-age-amber"

    @freeze_time("2024-06-15 12:00:00")
    def test_fifteen_days_returns_green(self):
        dt = datetime(2024, 6, 30, 12, 0, tzinfo=timezone.utc)
        assert expiry_age_class(dt) == "scan-age-green"

    @freeze_time("2024-06-15 12:00:00")
    def test_naive_datetime_treated_as_utc(self):
        """Naive datetimes should be treated as UTC and not raise an error."""
        dt = datetime(2024, 6, 22, 12, 0)  # no tzinfo, 7 days from frozen now
        assert expiry_age_class(dt) == "scan-age-red"
