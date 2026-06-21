"""Tests for the detonation orchestrator (capture.py)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkgids.capture import (
    _has_network,
    _import_command,
    _install_command,
    _read_phase_entries,
    _read_window,
    _top_module_name,
    run,
)
from tests.conftest import requires_sandbox


# ── command-builder unit tests ────────────────────────────────────────────────

class TestInstallCommand:
    def test_pypi_uses_pip3(self):
        assert _install_command("pypi", "six-1.16.0.tar.gz")[0] == "pip3"

    def test_pypi_break_system_packages(self):
        assert "--break-system-packages" in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_pypi_no_user_flag(self):
        assert "--user" not in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_pypi_no_build_isolation(self):
        assert "--no-build-isolation" in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_pypi_no_deps(self):
        assert "--no-deps" in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_pypi_artifact_path(self):
        assert "/work/six-1.16.0.tar.gz" in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_npm_uses_npm(self):
        assert _install_command("npm", "left-pad-1.3.0.tgz")[0] == "npm"

    def test_npm_scripts_enabled(self):
        assert "--ignore-scripts=false" in _install_command("npm", "left-pad-1.3.0.tgz")

    def test_npm_artifact_path(self):
        assert "/work/left-pad-1.3.0.tgz" in _install_command("npm", "left-pad-1.3.0.tgz")

    def test_unknown_ecosystem_raises(self):
        with pytest.raises(ValueError, match="Unsupported ecosystem"):
            _install_command("cargo", "serde-1.0.tgz")


class TestTopModuleName:
    def test_pypi_dash_to_underscore(self):
        assert _top_module_name("pypi", "my-package") == "my_package"

    def test_pypi_dot_to_underscore(self):
        assert _top_module_name("pypi", "my.package") == "my_package"

    def test_pypi_plain(self):
        assert _top_module_name("pypi", "six") == "six"

    def test_npm_plain(self):
        assert _top_module_name("npm", "left-pad") == "left-pad"

    def test_npm_scoped_strips_scope(self):
        assert _top_module_name("npm", "@types/node") == "node"

    def test_npm_scoped_no_at_sign(self):
        assert not _top_module_name("npm", "@scope/pkg").startswith("@")


class TestImportCommand:
    def test_pypi_uses_python3(self):
        cmd = _import_command("pypi", "requests")
        assert cmd[0] == "python3"
        assert "import requests" in " ".join(cmd)

    def test_pypi_dash_normalised(self):
        assert "import my_lib" in " ".join(_import_command("pypi", "my-lib"))

    def test_npm_uses_node(self):
        cmd = _import_command("npm", "left-pad")
        assert cmd[0] == "node"
        assert "require('left-pad')" in " ".join(cmd)

    def test_npm_scoped(self):
        assert "require('@scope/pkg')" in " ".join(_import_command("npm", "@scope/pkg"))

    def test_unknown_ecosystem_raises(self):
        with pytest.raises(ValueError):
            _import_command("cargo", "serde")


# ── timestamp-window filtering unit tests ────────────────────────────────────

class TestReadWindow:
    def test_entry_in_window_included(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"ts": 100.0, "type": "dns"}) + "\n")
        assert len(_read_window(f, 99.0, 101.0)) == 1

    def test_stale_entry_excluded(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"ts": 50.0, "type": "dns"}) + "\n")
        assert _read_window(f, 99.0, 101.0) == []

    def test_future_entry_excluded(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"ts": 200.0, "type": "tcp"}) + "\n")
        assert _read_window(f, 99.0, 101.0) == []

    def test_boundary_start_included(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"ts": 99.0, "type": "dns"}) + "\n")
        assert len(_read_window(f, 99.0, 101.0)) == 1

    def test_boundary_end_included(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"ts": 101.0, "type": "dns"}) + "\n")
        assert len(_read_window(f, 99.0, 101.0)) == 1

    def test_missing_ts_excluded(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text(json.dumps({"type": "dns"}) + "\n")  # no ts field
        assert _read_window(f, 0.0, 9999.0) == []

    def test_malformed_line_skipped(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text("not json\n" + json.dumps({"ts": 100.0, "type": "dns"}) + "\n")
        assert len(_read_window(f, 99.0, 101.0)) == 1

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "log.jsonl"
        f.write_text("")
        assert _read_window(f, 0.0, 9999.0) == []

    def test_missing_file_returns_empty(self, tmp_path):
        assert _read_window(tmp_path / "nope.jsonl", 0.0, 9999.0) == []

    def test_none_path_returns_empty(self):
        assert _read_window(None, 0.0, 9999.0) == []

    def test_multiple_entries_filtered_correctly(self, tmp_path):
        f = tmp_path / "log.jsonl"
        lines = [
            json.dumps({"ts": 50.0,  "type": "dns"}),   # before window
            json.dumps({"ts": 100.0, "type": "dns"}),   # in window
            json.dumps({"ts": 100.5, "type": "tcp"}),   # in window
            json.dumps({"ts": 150.0, "type": "dns"}),   # after window
        ]
        f.write_text("\n".join(lines) + "\n")
        result = _read_window(f, 99.0, 101.0)
        assert len(result) == 2
        assert {r["ts"] for r in result} == {100.0, 100.5}

    def test_stale_ip_reuse_scenario(self, tmp_path):
        """Simulates a recycled detonet IP: old entries prepended, new ones after."""
        f = tmp_path / "10.200.200.3.jsonl"
        old_run_ts = 1_000_000.0
        new_run_ts = 2_000_000.0
        lines = [
            json.dumps({"ts": old_run_ts, "type": "dns", "query": "evil.example.com"}),
            json.dumps({"ts": new_run_ts, "type": "dns", "query": "cdn.lib.com"}),
        ]
        f.write_text("\n".join(lines) + "\n")

        # Old run should see only its entry
        old_entries = _read_window(f, old_run_ts - 1, old_run_ts + 1)
        assert len(old_entries) == 1
        assert old_entries[0]["query"] == "evil.example.com"

        # New run should see only its entry (benign package, no evil.example.com)
        new_entries = _read_window(f, new_run_ts - 1, new_run_ts + 1)
        assert len(new_entries) == 1
        assert new_entries[0]["query"] == "cdn.lib.com"


class TestReadPhaseEntries:
    def test_reads_from_capture_log_in_window(self, tmp_path):
        log = tmp_path / "ip.jsonl"
        log.write_text(json.dumps({"ts": 100.0, "type": "dns"}) + "\n")
        entries = _read_phase_entries(str(log), 99.0, 101.0, tmp_path)
        assert len(entries) == 1

    def test_capture_log_stale_entries_excluded(self, tmp_path):
        log = tmp_path / "ip.jsonl"
        log.write_text(json.dumps({"ts": 50.0, "type": "dns"}) + "\n")
        entries = _read_phase_entries(str(log), 99.0, 101.0, tmp_path)
        assert entries == []

    def test_fallback_when_capture_log_none(self, tmp_path):
        (tmp_path / "10.200.200.3.jsonl").write_text(
            json.dumps({"ts": 100.0, "type": "dns"}) + "\n"
        )
        entries = _read_phase_entries(None, 99.0, 101.0, tmp_path)
        assert len(entries) == 1

    def test_fallback_still_timestamp_filtered(self, tmp_path):
        (tmp_path / "10.200.200.3.jsonl").write_text(
            json.dumps({"ts": 50.0, "type": "dns"}) + "\n"  # stale
        )
        entries = _read_phase_entries(None, 99.0, 101.0, tmp_path)
        assert entries == []

    def test_fallback_empty_dir(self, tmp_path):
        empty = tmp_path / "logs"
        empty.mkdir()
        assert _read_phase_entries(None, 0.0, 9999.0, empty) == []

    def test_fallback_nonexistent_dir(self, tmp_path):
        assert _read_phase_entries(None, 0.0, 9999.0, tmp_path / "no_such_dir") == []


class TestHasNetwork:
    def test_empty_list_is_false(self):
        assert _has_network([]) is False

    def test_non_empty_list_is_true(self):
        assert _has_network([{"ts": 1.0, "type": "dns"}]) is True

    def test_multiple_entries_is_true(self):
        assert _has_network([{"ts": 1.0}, {"ts": 2.0}]) is True


# ── run() orchestrator tests (Docker calls mocked) ───────────────────────────

def _fake_sandbox_result(capture_log: str | None = None) -> dict:
    return {
        "stdout":           "ok\n",
        "stderr":           "",
        "exit_code":        0,
        "timed_out":        False,
        "duration_seconds": 0.5,
        "container_name":   "pkgids-mock",
        "capture_log":      capture_log,
    }


@pytest.fixture
def fake_artifact(tmp_path) -> Path:
    d = tmp_path / "artifacts" / "pypi" / "six-1.16.0"
    d.mkdir(parents=True)
    f = d / "six-1.16.0.tar.gz"
    f.write_bytes(b"fake")
    return f


def _patch_all(fake_artifact: Path, run_dir: Path,
               phase_entries: list[dict] | None = None):
    """Patch all heavy calls in capture.run() for unit testing.

    phase_entries: what _read_phase_entries returns for every phase call.
                   Pass [] for 'no network activity' (default),
                   or a non-empty list for 'network activity detected'.
    """
    if phase_entries is None:
        phase_entries = []
    return [
        patch("pkgids.capture.fetch",              return_value=fake_artifact),
        patch("pkgids.capture.run_in_sandbox",     return_value=_fake_sandbox_result()),
        patch("pkgids.capture._detonet_bridge_iface", return_value="br-abc123456789"),
        patch("pkgids.capture._start_tcpdump",     return_value=MagicMock()),
        patch("pkgids.capture._stop_tcpdump"),
        patch("pkgids.capture._read_phase_entries", return_value=phase_entries),
    ]


def _run_mocked(fake_artifact, tmp_path, phase_entries=None, **kwargs):
    run_dir = tmp_path / "run"
    patches = _patch_all(fake_artifact, run_dir, phase_entries)
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
        return run("pypi", "six", "1.16.0", run_dir=run_dir, **kwargs)


class TestRunOrchestrator:
    def test_creates_run_dir(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert run_dir.is_dir()

    def test_install_json_written(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        install_json = Path(result["outputs"]["install_json"])
        assert install_json.exists()
        data = json.loads(install_json.read_text())
        assert data["exit_code"] == 0
        assert "command" in data
        assert "window" in data

    def test_import_json_written_by_default(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["outputs"]["import_json"] is not None
        assert Path(result["outputs"]["import_json"]).exists()

    def test_run_json_written(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        run_json = Path(result["run_dir"]) / "run.json"
        assert run_json.exists()
        data = json.loads(run_json.read_text())
        assert data["ecosystem"] == "pypi"
        assert data["name"] == "six"
        assert data["version"] == "1.16.0"

    def test_run_json_has_required_keys(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        for key in ("ecosystem", "name", "version", "run_dir", "artifact",
                    "phases", "network_activity", "outputs"):
            assert key in result, f"missing key: {key}"

    def test_phases_have_required_keys(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        for phase in ("install", "import"):
            p = result["phases"][phase]
            for key in ("exit_code", "duration_seconds", "timed_out", "network_activity"):
                assert key in p, f"phases.{phase} missing {key}"

    # ── network_activity is driven by filtered entries, not file existence ────

    def test_network_activity_true_when_entries_present(self, fake_artifact, tmp_path):
        result = _run_mocked(
            fake_artifact, tmp_path,
            phase_entries=[{"ts": time.time(), "type": "dns", "query": "evil.com"}],
        )
        assert result["network_activity"]["install"] is True

    def test_network_activity_false_when_no_entries(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, phase_entries=[])
        assert result["network_activity"]["install"] is False

    def test_stale_file_does_not_cause_false_positive(self, fake_artifact, tmp_path):
        """Core false-positive regression: capture_log exists but entries are filtered
        out by the timestamp window, so network_activity must be False."""
        result = _run_mocked(fake_artifact, tmp_path, phase_entries=[])
        # Even if the log file has content from a previous run, filtered entries=[]
        assert result["network_activity"]["install"] is False
        assert result["network_activity"]["import"] is False

    def test_network_jsonl_written_when_entries_exist(self, fake_artifact, tmp_path):
        result = _run_mocked(
            fake_artifact, tmp_path,
            phase_entries=[{"ts": time.time(), "type": "dns"}],
        )
        assert result["outputs"]["network_jsonl"] is not None
        assert Path(result["outputs"]["network_jsonl"]).exists()

    def test_network_jsonl_absent_when_no_entries(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, phase_entries=[])
        assert result["outputs"]["network_jsonl"] is None

    def test_network_jsonl_contains_only_filtered_entries(self, fake_artifact, tmp_path):
        entry = {"ts": time.time(), "type": "dns", "query": "cdn.lib.com"}
        result = _run_mocked(fake_artifact, tmp_path, phase_entries=[entry])
        nj = Path(result["outputs"]["network_jsonl"])
        lines = [json.loads(l) for l in nj.read_text().splitlines() if l.strip()]
        assert len(lines) == 2  # install + import each return the same mocked entry
        assert all(l["query"] == "cdn.lib.com" for l in lines)

    # ── skip_import ───────────────────────────────────────────────────────────

    def test_skip_import_flag(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, skip_import=True)
        assert result["phases"]["import"] == {"skipped": True}
        assert result["outputs"]["import_json"] is None
        assert result["network_activity"]["import"] is None

    def test_skip_import_calls_sandbox_once(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1] as mock_sb, patches[2], patches[3], patches[4], patches[5]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=True)
        assert mock_sb.call_count == 1

    def test_full_run_calls_sandbox_twice(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1] as mock_sb, patches[2], patches[3], patches[4], patches[5]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False)
        assert mock_sb.call_count == 2

    # ── tcpdump ───────────────────────────────────────────────────────────────

    def test_tcpdump_started_and_stopped(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1], patches[2], patches[3] as ms, patches[4] as mp, patches[5]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        ms.assert_called_once()
        mp.assert_called_once()

    def test_tcpdump_unavailable_does_not_abort(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",              return_value=fake_artifact),
            patch("pkgids.capture.run_in_sandbox",     return_value=_fake_sandbox_result()),
            patch("pkgids.capture._detonet_bridge_iface",
                  side_effect=RuntimeError("docker not available")),
            patch("pkgids.capture._read_phase_entries", return_value=[]),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert result["outputs"]["capture_pcap"] is None
        assert (run_dir / "install.json").exists()


# ── CLI integration tests ─────────────────────────────────────────────────────

class TestCLIDetonate:
    def _cli(self, argv, fake_artifact, tmp_path, phase_entries=None):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir, phase_entries)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            from pkgids.cli import main
            return main(argv + ["--run-dir", str(run_dir)])

    def test_detonate_returns_zero(self, fake_artifact, tmp_path):
        assert self._cli(["detonate", "pypi", "six", "1.16.0"], fake_artifact, tmp_path) == 0

    def test_detonate_invalid_ecosystem(self):
        from pkgids.cli import main
        assert main(["detonate", "cargo", "serde", "1.0.0"]) == 1

    def test_detonate_skip_import_flag(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1] as mock_sb, patches[2], patches[3], patches[4], patches[5]:
            from pkgids.cli import main
            main(["detonate", "pypi", "six", "1.16.0", "--skip-import", "--run-dir", str(run_dir)])
        assert mock_sb.call_count == 1


# ── real end-to-end test (requires Docker + sandbox + fakeinternet) ───────────

@requires_sandbox
def test_detonate_pypi_six_e2e(tmp_path):
    """Full pipeline against six==1.16.0.  Expects install success, network_activity=False."""
    from pkgids.capture import run as capture_run
    run_dir = tmp_path / "run"
    result = capture_run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False)

    assert result["ecosystem"] == "pypi"
    install = json.loads((run_dir / "install.json").read_text())
    assert install["exit_code"] == 0
    # six makes no network calls — this must be False after the timestamp fix
    assert result["network_activity"]["install"] is False
    assert result["network_activity"]["import"] is False
