"""Unit tests for the CVE acceptance report feature."""

from datetime import timezone

from app.main import parse_report_date


class TestParseReportDate:
    """Tests for parse_report_date used by the report routes."""

    def test_none_returns_none(self):
        assert parse_report_date(None) is None

    def test_empty_string_returns_none(self):
        assert parse_report_date("") is None

    def test_valid_date_returns_midnight_utc(self):
        result = parse_report_date("2025-01-15")
        assert result is not None
        assert result.year == 2025
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 0
        assert result.minute == 0
        assert result.tzinfo == timezone.utc

    def test_end_of_day_sets_time_to_235959(self):
        result = parse_report_date("2025-01-15", end_of_day=True)
        assert result is not None
        assert result.hour == 23
        assert result.minute == 59
        assert result.second == 59

    def test_invalid_format_returns_none(self):
        assert parse_report_date("15/01/2025") is None

    def test_invalid_date_returns_none(self):
        assert parse_report_date("not-a-date") is None

    def test_result_is_timezone_aware(self):
        result = parse_report_date("2025-06-01")
        assert result is not None
        assert result.tzinfo is not None

    def test_from_before_to_is_valid_range(self):
        from_dt = parse_report_date("2025-01-01")
        to_dt = parse_report_date("2025-12-31", end_of_day=True)
        assert from_dt is not None
        assert to_dt is not None
        assert from_dt < to_dt

    def test_same_day_range_is_non_empty(self):
        from_dt = parse_report_date("2025-06-15")
        to_dt = parse_report_date("2025-06-15", end_of_day=True)
        assert from_dt is not None
        assert to_dt is not None
        assert from_dt < to_dt
