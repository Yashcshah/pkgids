"""Tests for dataset.py — reading OSV metadata, no package execution."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkgids.dataset import _cache_path, _extract_record, fetch


# ── _extract_record unit tests ────────────────────────────────────────────────

class TestExtractRecord:
    def _osv(self, **overrides) -> dict:
        base = {
            "id": "GHSA-test-1234-abcd",
            "summary": "Exfiltrates credentials on install.",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "evil-pkg"},
                "versions": ["1.0.0", "1.0.1"],
            }],
        }
        base.update(overrides)
        return base

    def test_basic_fields_present(self):
        r = _extract_record("pypi", "evil-pkg", self._osv())
        for key in ("ecosystem", "name", "version", "osv_id", "summary"):
            assert key in r, f"missing field: {key}"

    def test_ecosystem_set_correctly(self):
        r = _extract_record("npm", "evil-pkg", self._osv())
        assert r["ecosystem"] == "npm"

    def test_name_taken_from_osv_package(self):
        r = _extract_record("pypi", "dir-name", self._osv())
        assert r["name"] == "evil-pkg"   # from affected[0].package.name

    def test_name_falls_back_to_dir_name(self):
        osv = self._osv()
        osv["affected"][0]["package"].pop("name")
        r = _extract_record("pypi", "fallback-name", osv)
        assert r["name"] == "fallback-name"

    def test_first_version_selected(self):
        r = _extract_record("pypi", "x", self._osv())
        assert r["version"] == "1.0.0"

    def test_no_versions_gives_none(self):
        osv = self._osv()
        osv["affected"][0]["versions"] = []
        r = _extract_record("pypi", "x", osv)
        assert r["version"] is None

    def test_osv_id_extracted(self):
        r = _extract_record("pypi", "x", self._osv())
        assert r["osv_id"] == "GHSA-test-1234-abcd"

    def test_summary_from_summary_field(self):
        r = _extract_record("pypi", "x", self._osv())
        assert "credentials" in r["summary"]

    def test_summary_falls_back_to_details(self):
        osv = self._osv()
        osv["summary"] = ""
        osv["details"] = "This package is very malicious because..."
        r = _extract_record("pypi", "x", osv)
        assert "malicious" in r["summary"]

    def test_summary_truncated_at_140_chars(self):
        osv = self._osv()
        osv["summary"] = ""
        osv["details"] = "x" * 200
        r = _extract_record("pypi", "x", osv)
        assert len(r["summary"]) <= 140

    def test_no_affected_gives_none_version(self):
        osv = {"id": "X", "summary": "s", "affected": []}
        r = _extract_record("pypi", "x", osv)
        assert r["version"] is None
        assert r["name"] == "x"


# ── cache helpers ─────────────────────────────────────────────────────────────

class TestCacheHelpers:
    def test_cache_path_is_in_data_dir(self):
        p = _cache_path("pypi")
        assert p.name == "malicious_pypi.json"
        assert p.parent.name == "data"

    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        sample = [{"ecosystem": "pypi", "name": "x", "version": "1.0",
                   "osv_id": "GHSA-x", "summary": "bad"}]
        cache = tmp_path / "malicious_pypi.json"
        cache.write_text(json.dumps(sample))
        loaded = json.loads(cache.read_text())
        assert loaded == sample


# ── fetch() with mocked HTTP ──────────────────────────────────────────────────

def _make_dir_listing(pkg_names: list[str]) -> list[dict]:
    return [
        {"type": "dir", "name": n, "url": f"https://api.github.com/fake/{n}"}
        for n in pkg_names
    ]


def _make_file_listing(pkg_name: str, osv_id: str) -> list[dict]:
    return [{"name": f"{osv_id}.json",
             "download_url": f"https://raw.github.com/fake/{pkg_name}/{osv_id}.json"}]


def _make_osv(pkg_name: str, osv_id: str, version: str = "1.0.0") -> dict:
    return {
        "id": osv_id,
        "summary": f"{pkg_name} steals data",
        "affected": [{"package": {"ecosystem": "PyPI", "name": pkg_name},
                      "versions": [version]}],
    }


class TestFetch:
    def _mock_get(self, pkg_names: list[str]):
        """Return a requests.get side_effect that serves fake API responses."""
        responses: dict[str, object] = {}
        # Ecosystem directory listing
        responses["ecosystem"] = _make_dir_listing(pkg_names)
        # Per-package directory listing + OSV file
        for i, name in enumerate(pkg_names):
            osv_id = f"GHSA-{i:04d}"
            responses[f"pkg_{name}"] = _make_file_listing(name, osv_id)
            responses[f"osv_{name}"] = _make_osv(name, osv_id)

        call_order: list[str] = []
        call_order.append("ecosystem")
        for name in pkg_names:
            call_order.append(f"pkg_{name}")
            call_order.append(f"osv_{name}")

        idx = [0]

        def side_effect(url, **kwargs):
            key = call_order[idx[0]] if idx[0] < len(call_order) else "ecosystem"
            idx[0] += 1
            data = responses.get(key, [])
            m = MagicMock()
            m.raise_for_status.return_value = None
            m.json.return_value = data
            m.headers = {"X-RateLimit-Remaining": "59", "X-RateLimit-Reset": "0"}
            return m

        return side_effect

    def test_fetch_returns_records(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        pkg_names = ["evil-a", "evil-b", "evil-c"]
        with patch("pkgids.dataset.requests.get",
                   side_effect=self._mock_get(pkg_names)):
            records = fetch("pypi", limit=3, token="fake")
        assert len(records) == 3

    def test_fetch_respects_limit(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        pkg_names = [f"evil-{i}" for i in range(10)]
        with patch("pkgids.dataset.requests.get",
                   side_effect=self._mock_get(pkg_names)):
            records = fetch("pypi", limit=2, token="fake")
        assert len(records) == 2

    def test_fetch_writes_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        with patch("pkgids.dataset.requests.get",
                   side_effect=self._mock_get(["pkg-a"])):
            fetch("pypi", limit=1, token="fake")
        cache = tmp_path / "malicious_pypi.json"
        assert cache.exists()
        assert json.loads(cache.read_text()) != []

    def test_fetch_uses_cache_when_sufficient(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        cached = [{"ecosystem": "pypi", "name": f"pkg-{i}", "version": "1.0",
                   "osv_id": f"GHSA-{i}", "summary": "bad"}
                  for i in range(10)]
        (tmp_path / "malicious_pypi.json").write_text(json.dumps(cached))

        with patch("pkgids.dataset.requests.get") as mock_get:
            records = fetch("pypi", limit=5)
        mock_get.assert_not_called()
        assert len(records) == 5

    def test_fetch_refresh_bypasses_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pkgids.dataset._CACHE_DIR", tmp_path)
        cached = [{"ecosystem": "pypi", "name": "stale", "version": "0.0",
                   "osv_id": "OLD", "summary": "old"}] * 5
        (tmp_path / "malicious_pypi.json").write_text(json.dumps(cached))

        with patch("pkgids.dataset.requests.get",
                   side_effect=self._mock_get(["fresh-pkg"])):
            records = fetch("pypi", limit=1, refresh=True, token="fake")
        assert records[0]["name"] == "fresh-pkg"
