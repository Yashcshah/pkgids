"""Unit tests for pkgids/baseline.py — profile extraction (pure, no DB)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkgids.baseline import extract_profile


# ── helpers ───────────────────────────────────────────────────────────────────

def _summary(
    ecosystem="pypi", name="six", version="1.16.0",
    install_status="ok", install_exit=0, install_dur=2.1,
    import_status="ok",  import_exit=0,  import_dur=0.3,
    network_activity=None,
    install_pa=None, import_pa=None,
) -> dict:
    return {
        "ecosystem": ecosystem,
        "name":      name,
        "version":   version,
        "run_dir":   "/tmp/run",
        "phases": {
            "install": {
                "status":           install_status,
                "exit_code":        install_exit,
                "duration_secs":    install_dur,
                "process_activity": install_pa or {},
            },
            "import": {
                "status":           import_status,
                "exit_code":        import_exit,
                "duration_secs":    import_dur,
                "process_activity": import_pa or {},
            },
        },
        "network_activity": network_activity or {},
    }


def _pa(
    process_count=0,
    suspicious_execs=None,
    sensitive_file_accesses=None,
    any_suspicious=False,
) -> dict:
    return {
        "process_count":           process_count,
        "any_suspicious":          any_suspicious,
        "suspicious_execs":        suspicious_execs or [],
        "sensitive_file_accesses": sensitive_file_accesses or [],
        "socket_connections":      [],
        "control_events":          [],
        "telemetry_limited_process": False,
    }


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


# ── basic field extraction ────────────────────────────────────────────────────

class TestExtractProfileBasic:
    def test_ecosystem_name_version_copied(self):
        p = extract_profile(_summary())
        assert p["ecosystem"] == "pypi"
        assert p["name"]      == "six"
        assert p["version"]   == "1.16.0"

    def test_install_fields_extracted(self):
        p = extract_profile(_summary(install_status="ok", install_exit=0, install_dur=3.5))
        assert p["install_status"]        == "ok"
        assert p["install_exit_code"]     == 0
        assert p["install_duration_secs"] == 3.5

    def test_import_fields_extracted(self):
        p = extract_profile(_summary(import_status="failed", import_exit=1, import_dur=0.1))
        assert p["import_status"]        == "failed"
        assert p["import_exit_code"]     == 1
        assert p["import_duration_secs"] == 0.1

    def test_prediction_is_none_by_default(self):
        assert extract_profile(_summary())["prediction"] is None

    def test_no_run_dir_network_features_empty(self):
        p = extract_profile(_summary())
        assert p["network_domains"] == []
        assert p["network_hosts"]   == []
        assert p["network_ports"]   == []

    def test_no_activity_all_counts_zero(self):
        p = extract_profile(_summary())
        assert p["subprocess_count"]      == 0
        assert p["suspicious_exec_count"] == 0
        assert p["sensitive_file_count"]  == 0
        assert p["shell_cmd_count"]       == 0
        assert p["new_file_count"]        == 0
        assert p["any_suspicious"]        is False


# ── network features from network.jsonl ──────────────────────────────────────

class TestExtractProfileNetwork:
    def test_dns_query_captured_as_domain(self, tmp_path):
        _write_jsonl(tmp_path / "network.jsonl", [
            {"ts": 1.0, "type": "dns", "query": "evil.com"},
        ])
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert "evil.com" in p["network_domains"]

    def test_http_host_in_domains_and_hosts(self, tmp_path):
        _write_jsonl(tmp_path / "network.jsonl", [
            {"ts": 1.0, "type": "http", "host": "cdn.lib.io", "port": 80},
        ])
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert "cdn.lib.io" in p["network_domains"]
        assert "cdn.lib.io" in p["network_hosts"]

    def test_port_extracted(self, tmp_path):
        _write_jsonl(tmp_path / "network.jsonl", [
            {"ts": 1.0, "type": "http", "host": "x.com", "port": 443},
        ])
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert 443 in p["network_ports"]

    def test_duplicate_domains_deduplicated(self, tmp_path):
        _write_jsonl(tmp_path / "network.jsonl", [
            {"ts": 1.0, "query": "evil.com"},
            {"ts": 1.1, "query": "evil.com"},
        ])
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert p["network_domains"].count("evil.com") == 1

    def test_missing_network_jsonl_ok(self, tmp_path):
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert p["network_domains"] == []

    def test_network_activity_flag_sets_any_suspicious(self):
        s = _summary(network_activity={"install": True})
        assert extract_profile(s)["any_suspicious"] is True


# ── process activity features ─────────────────────────────────────────────────

class TestExtractProfileProcessActivity:
    def test_subprocess_count_summed_across_phases(self):
        s = _summary(
            install_pa=_pa(process_count=3),
            import_pa=_pa(process_count=2),
        )
        assert extract_profile(s)["subprocess_count"] == 5

    def test_suspicious_exec_count_summed(self):
        s = _summary(
            install_pa=_pa(suspicious_execs=[
                {"executable": "/usr/bin/curl", "argv": ["curl"], "pid": 1},
            ]),
            import_pa=_pa(suspicious_execs=[
                {"executable": "/usr/bin/wget", "argv": ["wget"], "pid": 2},
            ]),
        )
        assert extract_profile(s)["suspicious_exec_count"] == 2

    def test_sensitive_file_count_summed(self):
        s = _summary(
            install_pa=_pa(sensitive_file_accesses=[
                {"path": "/etc/passwd", "access_type": "read"},
            ]),
        )
        assert extract_profile(s)["sensitive_file_count"] == 1

    def test_shell_cmd_count(self):
        s = _summary(
            install_pa=_pa(suspicious_execs=[
                {"executable": "/bin/bash", "argv": ["bash", "-c", "id"], "pid": 1},
                {"executable": "/usr/bin/curl", "argv": ["curl"], "pid": 2},
            ]),
        )
        # Only bash counts as a shell command
        assert extract_profile(s)["shell_cmd_count"] == 1

    def test_any_suspicious_from_install_pa(self):
        s = _summary(install_pa=_pa(any_suspicious=True))
        assert extract_profile(s)["any_suspicious"] is True

    def test_any_suspicious_false_when_clean(self):
        s = _summary(
            install_pa=_pa(any_suspicious=False),
            import_pa=_pa(any_suspicious=False),
        )
        assert extract_profile(s)["any_suspicious"] is False


# ── new file count from telemetry.jsonl ───────────────────────────────────────

class TestExtractProfileTelemetry:
    def test_create_events_counted(self, tmp_path):
        _write_jsonl(tmp_path / "telemetry.jsonl", [
            {"event_type": "file", "mode": "create", "path": "/tmp/a"},
            {"event_type": "file", "mode": "create", "path": "/tmp/b"},
            {"event_type": "file", "mode": "write",  "path": "/tmp/c"},  # write, not create
        ])
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert p["new_file_count"] == 2

    def test_missing_telemetry_jsonl_ok(self, tmp_path):
        p = extract_profile(_summary(), run_dir=tmp_path)
        assert p["new_file_count"] == 0

    def test_blobs_included_when_non_empty(self):
        s = _summary(install_pa=_pa(process_count=2))
        p = extract_profile(s)
        assert p["install_process_activity"] is not None


# ── baseline auto-resolution (Supabase mocked) ────────────────────────────────

def _make_profile_row(version: str, prediction: str = "benign", any_suspicious: bool = False,
                      package_id: int = 1) -> dict:
    return {
        "id":                    10,
        "package_id":            package_id,
        "run_ts":                "2024-01-01T00:00:00Z",
        "version":               version,
        "prediction":            prediction,
        "any_suspicious":        any_suspicious,
        "network_domains":       [],
        "network_hosts":         [],
        "network_ports":         [],
        "subprocess_count":      2,
        "suspicious_exec_count": 0,
        "sensitive_file_count":  0,
        "shell_cmd_count":       0,
        "new_file_count":        0,
        "install_status":        "ok",
        "import_status":         "ok",
        "install_process_activity": None,
        "import_process_activity":  None,
    }


def _mock_client(pkg_rows: list[dict], prof_rows: list[dict]) -> MagicMock:
    """Build a minimal Supabase client mock."""
    client = MagicMock()

    def _make_chain(data):
        chain = MagicMock()
        chain.select.return_value = chain
        chain.eq.return_value     = chain
        chain.in_.return_value    = chain
        chain.order.return_value  = chain
        chain.limit.return_value  = chain
        chain.execute.return_value = MagicMock(data=data)
        return chain

    # table() dispatches on name
    def _table(name):
        if name == "packages":
            return _make_chain(pkg_rows)
        return _make_chain(prof_rows)

    client.table.side_effect = _table
    return client


class TestGetPreviousVersion:
    def test_returns_profile_for_predecessor(self):
        from pkgids.baseline import get_previous_version

        pkg_rows  = [{"id": 1, "version": "1.0.0"}, {"id": 2, "version": "2.0.0"}]
        # list_versions returns newest first: 2.0.0, 1.0.0
        prof_rows = [
            {**_make_profile_row("2.0.0", package_id=2), "run_ts": "2024-02-01T00:00:00Z"},
            {**_make_profile_row("1.0.0", package_id=1), "run_ts": "2024-01-01T00:00:00Z"},
        ]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_previous_version("pypi", "mypkg", "2.0.0")

        # Should return profile for 1.0.0 (the entry after 2.0.0 in run_ts order)
        assert result is not None
        assert result.get("version") == "1.0.0"

    def test_returns_none_when_no_predecessor(self):
        from pkgids.baseline import get_previous_version

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows = [_make_profile_row("1.0.0", package_id=1)]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_previous_version("pypi", "mypkg", "1.0.0")

        assert result is None

    def test_returns_none_when_version_not_found(self):
        from pkgids.baseline import get_previous_version

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows = [_make_profile_row("1.0.0", package_id=1)]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_previous_version("pypi", "mypkg", "9.9.9")

        assert result is None


class TestGetKnownGood:
    def test_returns_benign_not_suspicious_profile(self):
        from pkgids.baseline import get_known_good

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows = [_make_profile_row("1.0.0", prediction="benign", any_suspicious=False)]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_known_good("pypi", "mypkg")

        assert result is not None
        assert result["prediction"] == "benign"
        assert result["any_suspicious"] is False

    def test_returns_none_when_no_benign_profiles(self):
        from pkgids.baseline import get_known_good

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows: list = []   # empty

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_known_good("pypi", "mypkg")

        assert result is None

    def test_returns_none_when_no_packages(self):
        from pkgids.baseline import get_known_good

        with patch("pkgids.baseline._get_client", return_value=_mock_client([], [])):
            result = get_known_good("pypi", "mypkg")

        assert result is None


class TestGetRollingBaseline:
    def test_merges_domains_across_profiles(self):
        from pkgids.baseline import get_rolling_baseline

        pkg_rows = [{"id": 1, "version": "1.0.0"}, {"id": 2, "version": "1.1.0"}]
        prof_rows = [
            {**_make_profile_row("1.0.0", package_id=1), "network_domains": ["a.com"],
             "network_hosts": [], "network_ports": []},
            {**_make_profile_row("1.1.0", package_id=2), "network_domains": ["b.com"],
             "network_hosts": [], "network_ports": []},
        ]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_rolling_baseline("pypi", "mypkg", n=5)

        assert result is not None
        assert "a.com" in result["network_domains"]
        assert "b.com" in result["network_domains"]

    def test_takes_max_of_numeric_counts(self):
        from pkgids.baseline import get_rolling_baseline

        pkg_rows = [{"id": 1, "version": "1.0.0"}, {"id": 2, "version": "1.1.0"}]
        prof_rows = [
            {**_make_profile_row("1.0.0", package_id=1), "subprocess_count": 3,
             "network_domains": [], "network_hosts": [], "network_ports": []},
            {**_make_profile_row("1.1.0", package_id=2), "subprocess_count": 7,
             "network_domains": [], "network_hosts": [], "network_ports": []},
        ]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_rolling_baseline("pypi", "mypkg")

        assert result["subprocess_count"] == 7  # max

    def test_version_string_encodes_n(self):
        from pkgids.baseline import get_rolling_baseline

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows = [
            {**_make_profile_row("1.0.0", package_id=1),
             "network_domains": [], "network_hosts": [], "network_ports": []},
        ]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_rolling_baseline("pypi", "mypkg", n=3)

        assert "rolling_baseline" in result["version"]
        assert "1" in result["version"]  # n=1 actual rows found

    def test_returns_none_when_no_benign_profiles(self):
        from pkgids.baseline import get_rolling_baseline

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows: list = []

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_rolling_baseline("pypi", "mypkg")

        assert result is None

    def test_any_suspicious_is_false_in_envelope(self):
        from pkgids.baseline import get_rolling_baseline

        pkg_rows  = [{"id": 1, "version": "1.0.0"}]
        prof_rows = [
            {**_make_profile_row("1.0.0", package_id=1),
             "network_domains": [], "network_hosts": [], "network_ports": []},
        ]

        with patch("pkgids.baseline._get_client", return_value=_mock_client(pkg_rows, prof_rows)):
            result = get_rolling_baseline("pypi", "mypkg")

        assert result["any_suspicious"] is False
        assert result["prediction"] == "benign"
