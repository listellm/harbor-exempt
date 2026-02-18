"""Unit tests for _map_harbor_vulnerability in app.webhook."""

import pytest

from app.webhook import _map_harbor_vulnerability

FULL_VULN = {
    "id": "CVE-2023-12345",
    "package": "openssl",
    "version": "1.1.1",
    "fix_version": "1.1.1t",
    "severity": "HIGH",
    "preferred_cvss": {
        "score_v3": 7.5
    },
    "description": "A buffer overflow vulnerability.",
    "links": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
}


class TestMapHarborVulnerability:
    """Tests for _map_harbor_vulnerability."""

    def test_full_payload_maps_correctly(self):
        result = _map_harbor_vulnerability(FULL_VULN)
        assert result["cve_id"] == "CVE-2023-12345"
        assert result["package"] == "openssl"
        assert result["installed_version"] == "1.1.1"
        assert result["fixed_version"] == "1.1.1t"
        assert result["severity"] == "HIGH"
        assert result["cvss_score"] == 7.5
        assert result["description"] == "A buffer overflow vulnerability."
        assert result["references"] == ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]

    def test_severity_is_uppercased(self):
        vuln = {**FULL_VULN, "severity": "critical"}
        assert _map_harbor_vulnerability(vuln)["severity"] == "CRITICAL"

    def test_missing_severity_defaults_to_unknown(self):
        vuln = {k: v for k, v in FULL_VULN.items() if k != "severity"}
        assert _map_harbor_vulnerability(vuln)["severity"] == "UNKNOWN"

    def test_none_severity_defaults_to_unknown(self):
        vuln = {**FULL_VULN, "severity": None}
        assert _map_harbor_vulnerability(vuln)["severity"] == "UNKNOWN"

    def test_empty_fix_version_becomes_none(self):
        vuln = {**FULL_VULN, "fix_version": ""}
        assert _map_harbor_vulnerability(vuln)["fixed_version"] is None

    def test_cvss_score_extracted(self):
        vuln = {**FULL_VULN, "preferred_cvss": {"score_v3": 9.8}}
        assert _map_harbor_vulnerability(vuln)["cvss_score"] == 9.8

    def test_missing_preferred_cvss_gives_none_score(self):
        vuln = {k: v for k, v in FULL_VULN.items() if k != "preferred_cvss"}
        assert _map_harbor_vulnerability(vuln)["cvss_score"] is None

    def test_preferred_cvss_without_score_v3_gives_none(self):
        vuln = {**FULL_VULN, "preferred_cvss": {"score_v2": 6.0}}
        assert _map_harbor_vulnerability(vuln)["cvss_score"] is None

    def test_empty_links_returns_empty_list(self):
        vuln = {**FULL_VULN, "links": []}
        assert _map_harbor_vulnerability(vuln)["references"] == []

    def test_none_links_returns_empty_list(self):
        vuln = {**FULL_VULN, "links": None}
        assert _map_harbor_vulnerability(vuln)["references"] == []

    def test_missing_links_returns_empty_list(self):
        vuln = {k: v for k, v in FULL_VULN.items() if k != "links"}
        assert _map_harbor_vulnerability(vuln)["references"] == []
