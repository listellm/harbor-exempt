"""Unit tests for _extract_fixed_versions in app.osv."""

from app.osv import _extract_fixed_versions


class TestExtractFixedVersions:
    """Tests for _extract_fixed_versions."""

    def test_empty_dict_returns_empty(self):
        assert _extract_fixed_versions({}) == []

    def test_empty_affected_list_returns_empty(self):
        assert _extract_fixed_versions({"affected": []}) == []

    def test_single_fix(self):
        data = {
            "affected":
                [
                    {
                        "package": {
                            "ecosystem": "PyPI"
                        },
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {
                                    "introduced": "0"
                                },
                                {
                                    "fixed": "1.2.3"
                                },
                            ],
                        }],
                    }
                ]
        }
        result = _extract_fixed_versions(data)
        assert result == [{"ecosystem": "PyPI", "fixed": "1.2.3", "type": "SEMVER"}]

    def test_multiple_ecosystems(self):
        data = {
            "affected":
                [
                    {
                        "package": {
                            "ecosystem": "PyPI"
                        },
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [{
                                "fixed": "1.0.0"
                            }]
                        }],
                    },
                    {
                        "package": {
                            "ecosystem": "npm"
                        },
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [{
                                "fixed": "2.0.0"
                            }]
                        }],
                    },
                ]
        }
        result = _extract_fixed_versions(data)
        assert len(result) == 2
        ecosystems = {r["ecosystem"] for r in result}
        assert ecosystems == {"PyPI", "npm"}

    def test_events_without_fixed_key_are_skipped(self):
        data = {
            "affected":
                [
                    {
                        "package": {
                            "ecosystem": "Go"
                        },
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [{
                                "introduced": "0"
                            }, {
                                "last_affected": "1.0.0"
                            }],
                        }],
                    }
                ]
        }
        assert _extract_fixed_versions(data) == []

    def test_missing_package_ecosystem_defaults_to_empty_string(self):
        data = {
            "affected": [{
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{
                        "fixed": "1.0.0"
                    }]
                }],
            }]
        }
        result = _extract_fixed_versions(data)
        assert result == [{"ecosystem": "", "fixed": "1.0.0", "type": "SEMVER"}]

    def test_missing_range_type_defaults_to_empty_string(self):
        data = {
            "affected": [{
                "package": {
                    "ecosystem": "Debian"
                },
                "ranges": [{
                    "events": [{
                        "fixed": "1.0.0"
                    }]
                }],
            }]
        }
        result = _extract_fixed_versions(data)
        assert result == [{"ecosystem": "Debian", "fixed": "1.0.0", "type": ""}]

    def test_empty_ranges_returns_empty(self):
        data = {
            "affected": [{
                "package": {
                    "ecosystem": "PyPI"
                },
                "ranges": [],
            }]
        }
        assert _extract_fixed_versions(data) == []
