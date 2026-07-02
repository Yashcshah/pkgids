"""Tests for pkgids.advisory — OSV enrichment."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from pkgids.advisory import query_osv


# ── helpers ───────────────────────────────────────────────────────────────────

def _osv_response(vulns: list[dict]) -> MagicMock:
    """Build a mock requests.Response for an OSV query."""
    mock = MagicMock()
    mock.raise_for_status.return_value = None
    mock.json.return_value = {"vulns": vulns} if vulns else {}
    return mock


_SAMPLE_VULN = {
    "id": "PYSEC-2022-999",
    "aliases": ["CVE-2022-34501", "GHSA-xxxx-yyyy-zzzz"],
    "summary": "Remote code execution via malicious setup.py",
    "details": "Full details here...",
}


# ── normalized result structure ───────────────────────────────────────────────

class TestQueryOsvStructure:
    def test_returns_all_required_fields_on_hit(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")

        assert "advisory_hit"       in result
        assert "advisory_source"    in result
        assert "advisory_count"     in result
        assert "advisory_ids"       in result
        assert "advisory_summaries" in result
        assert "advisory_error"     in result

    def test_returns_all_required_fields_on_miss(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([])):
            result = query_osv("pypi", "six", "1.16.0")

        assert "advisory_hit"       in result
        assert "advisory_source"    in result
        assert "advisory_count"     in result
        assert "advisory_ids"       in result
        assert "advisory_summaries" in result
        assert "advisory_error"     in result

    def test_no_raw_osv_blob_in_result(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        # The full raw OSV response must not be embedded
        assert "vulns"    not in result
        assert "affected" not in result
        assert "details"  not in result


# ── hit parsing ───────────────────────────────────────────────────────────────

class TestQueryOsvHit:
    def test_advisory_hit_true_when_vulns(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert result["advisory_hit"] is True

    def test_advisory_source_is_osv(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert result["advisory_source"] == "osv"

    def test_advisory_count(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert result["advisory_count"] == 1

    def test_advisory_ids_includes_osv_id_and_aliases(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert "PYSEC-2022-999"       in result["advisory_ids"]
        assert "CVE-2022-34501"       in result["advisory_ids"]
        assert "GHSA-xxxx-yyyy-zzzz"  in result["advisory_ids"]

    def test_advisory_summaries_populated(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert len(result["advisory_summaries"]) == 1
        assert "Remote code execution" in result["advisory_summaries"][0]

    def test_advisory_error_none_on_success(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([_SAMPLE_VULN])):
            result = query_osv("pypi", "bin-collection", "0.1")
        assert result["advisory_error"] is None

    def test_summary_truncated_to_200_chars(self):
        long_summary = "x" * 300
        vuln = {**_SAMPLE_VULN, "summary": long_summary}
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([vuln])):
            result = query_osv("pypi", "pkg", "1.0")
        assert len(result["advisory_summaries"][0]) <= 200


# ── miss / empty ──────────────────────────────────────────────────────────────

class TestQueryOsvMiss:
    def test_advisory_hit_false_when_no_vulns(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([])):
            result = query_osv("pypi", "six", "1.16.0")
        assert result["advisory_hit"] is False

    def test_advisory_count_zero(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([])):
            result = query_osv("pypi", "six", "1.16.0")
        assert result["advisory_count"] == 0

    def test_advisory_ids_empty(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([])):
            result = query_osv("pypi", "six", "1.16.0")
        assert result["advisory_ids"] == []

    def test_advisory_source_osv_even_on_miss(self):
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response([])):
            result = query_osv("pypi", "six", "1.16.0")
        assert result["advisory_source"] == "osv"


# ── error handling — never raises ─────────────────────────────────────────────

class TestQueryOsvFailureSafety:
    def test_timeout_returns_error_field_not_exception(self):
        with patch("pkgids.advisory.requests.post",
                   side_effect=requests.Timeout("timed out")):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_hit"]   is False
        assert result["advisory_error"] is not None
        assert "timed" in result["advisory_error"].lower()

    def test_connection_error_returns_error_field(self):
        with patch("pkgids.advisory.requests.post",
                   side_effect=requests.ConnectionError("no route")):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_hit"]   is False
        assert result["advisory_error"] is not None

    def test_http_error_returns_error_field(self):
        mock = MagicMock()
        mock.raise_for_status.side_effect = requests.HTTPError("503")
        with patch("pkgids.advisory.requests.post", return_value=mock):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_hit"]   is False
        assert result["advisory_error"] is not None

    def test_bad_json_returns_error_field(self):
        mock = MagicMock()
        mock.raise_for_status.return_value = None
        mock.json.side_effect = json.JSONDecodeError("bad", "", 0)
        with patch("pkgids.advisory.requests.post", return_value=mock):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_hit"]   is False
        assert result["advisory_error"] is not None

    def test_unsupported_ecosystem_returns_error_field(self):
        result = query_osv("maven", "com.example:pkg", "1.0")
        assert result["advisory_hit"]   is False
        assert result["advisory_error"] is not None
        assert result["advisory_source"] is None

    def test_advisory_source_none_on_error(self):
        with patch("pkgids.advisory.requests.post",
                   side_effect=requests.Timeout()):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_source"] is None


# ── multiple vulns ────────────────────────────────────────────────────────────

class TestQueryOsvMultipleVulns:
    def test_count_reflects_multiple_vulns(self):
        vulns = [
            {"id": "PYSEC-2022-1", "summary": "first"},
            {"id": "PYSEC-2022-2", "aliases": ["CVE-2022-9999"], "summary": "second"},
        ]
        with patch("pkgids.advisory.requests.post",
                   return_value=_osv_response(vulns)):
            result = query_osv("pypi", "pkg", "1.0")
        assert result["advisory_count"] == 2
        assert result["advisory_hit"] is True
        assert "PYSEC-2022-1"  in result["advisory_ids"]
        assert "PYSEC-2022-2"  in result["advisory_ids"]
        assert "CVE-2022-9999" in result["advisory_ids"]
        assert len(result["advisory_summaries"]) == 2
