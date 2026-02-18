"""Unit tests for pure functions in app.harbor."""

from datetime import datetime, timezone

from app.harbor import (
    _encode_repository,
    _parse_harbor_timestamp,
    extract_repository,
    extract_tag,
)


class TestParseHarborTimestamp:
    """Tests for _parse_harbor_timestamp."""

    def test_none_returns_none(self):
        assert _parse_harbor_timestamp(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_harbor_timestamp("") is None

    def test_harbor_sentinel_returns_none(self):
        """Harbor uses 0001-01-01 to indicate 'never'."""
        assert _parse_harbor_timestamp("0001-01-01T00:00:00.000Z") is None

    def test_valid_iso_timestamp(self):
        result = _parse_harbor_timestamp("2024-01-15T10:30:00.000Z")
        assert result == datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

    def test_valid_timestamp_is_utc_aware(self):
        result = _parse_harbor_timestamp("2024-06-01T00:00:00.000Z")
        assert result is not None
        assert result.tzinfo is not None

    def test_malformed_string_returns_none(self):
        assert _parse_harbor_timestamp("not-a-date") is None


class TestExtractRepository:
    """Tests for extract_repository."""

    def test_strips_tag(self):
        assert extract_repository("platform/app:v1.2.3") == "platform/app"

    def test_strips_digest(self):
        assert extract_repository("platform/app@sha256:abc123") == "platform/app"

    def test_strips_tag_and_digest(self):
        assert extract_repository("platform/app:v1.2.3@sha256:abc") == "platform/app"

    def test_strips_hostname_with_port(self):
        assert extract_repository("localhost:8088/platform/app:v1.2.3") == "platform/app"

    def test_strips_fqdn_hostname(self):
        assert extract_repository("harbor.example.com/platform/app") == "platform/app"

    def test_nested_path(self):
        assert extract_repository("platform/nested/app:latest") == "platform/nested/app"


class TestExtractTag:
    """Tests for extract_tag."""

    def test_extracts_tag(self):
        assert extract_tag("platform/app:v1.2.3") == "v1.2.3"

    def test_digest_only_returns_none(self):
        assert extract_tag("platform/app@sha256:abc123") is None

    def test_tag_and_digest_returns_tag(self):
        assert extract_tag("platform/app:v1.2.3@sha256:abc") == "v1.2.3"

    def test_hostname_with_port_and_tag(self):
        assert extract_tag("localhost:8088/platform/app:v1.2.3") == "v1.2.3"

    def test_no_tag_returns_none(self):
        assert extract_tag("platform/app") is None

    def test_port_only_no_slash_returns_none(self):
        """A bare 'host:port' has no slash before the colon — not a tag."""
        assert extract_tag("localhost:8088") is None


class TestEncodeRepository:
    """Tests for _encode_repository."""

    def test_single_slash(self):
        assert _encode_repository("platform/app") == "platform%252Fapp"

    def test_multiple_slashes(self):
        assert _encode_repository("platform/nested/app") == "platform%252Fnested%252Fapp"

    def test_no_slash(self):
        assert _encode_repository("app") == "app"

    def test_empty_string(self):
        assert _encode_repository("") == ""
