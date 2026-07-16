"""Tests for the detonation orchestrator (capture.py)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkgids.capture import (
    _discover_submodule,
    _has_network,
    _import_command,
    _install_command,
    _phase_status,
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

    def test_pypi_no_deps_by_default(self):
        assert "--no-deps" in _install_command("pypi", "six-1.16.0.tar.gz")

    def test_pypi_with_deps_removes_no_deps(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz", with_deps=True)
        assert "--no-deps" not in cmd

    def test_pypi_with_deps_false_keeps_no_deps(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz", with_deps=False)
        assert "--no-deps" in cmd

    def test_pypi_with_deps_still_uses_target(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz", with_deps=True)
        assert "--target" in cmd
        assert "/scratch/site-packages" in cmd

    def test_pypi_target_scratch(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "--target" in cmd
        assert "/scratch/site-packages" in cmd

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

    def test_pypi_sys_path_insert(self):
        cmd = _import_command("pypi", "requests")
        assert "/scratch/site-packages" in " ".join(cmd)

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


class TestPhaseStatus:
    """Unit tests for the _phase_status() classifier."""

    def _raw(self, exit_code=0, timed_out=False, stdout="", stderr="") -> dict:
        return {"exit_code": exit_code, "timed_out": timed_out,
                "stdout": stdout, "stderr": stderr, "duration_seconds": 0.1}

    def test_ok_on_zero_exit(self):
        assert _phase_status(self._raw(exit_code=0), "install") == "ok"

    def test_failed_on_nonzero_exit(self):
        assert _phase_status(self._raw(exit_code=1, stderr="error"), "install") == "failed"

    def test_timed_out_takes_priority(self):
        assert _phase_status(self._raw(exit_code=0, timed_out=True), "install") == "timed_out"

    def test_timed_out_with_nonzero(self):
        assert _phase_status(self._raw(exit_code=1, timed_out=True), "install") == "timed_out"

    def test_crashed_on_not_running_in_stderr(self):
        raw = self._raw(exit_code=1,
                        stderr="Error response from daemon: container pkgids-abc is not running")
        assert _phase_status(raw, "install") == "crashed"

    def test_module_not_found_on_import(self):
        raw = self._raw(exit_code=1,
                        stderr="ModuleNotFoundError: No module named 'evil_pkg'")
        assert _phase_status(raw, "import") == "module_not_found"

    def test_no_module_named_also_detected(self):
        raw = self._raw(exit_code=1, stderr="No module named 'six'")
        assert _phase_status(raw, "import") == "module_not_found"

    def test_module_not_found_in_stdout(self):
        raw = self._raw(exit_code=1, stdout="ModuleNotFoundError: No module named 'x'")
        assert _phase_status(raw, "import") == "module_not_found"

    def test_module_not_found_only_for_import_phase(self):
        # The same stderr in an install phase must remain "failed", not "module_not_found".
        raw = self._raw(exit_code=1, stderr="ModuleNotFoundError: No module named 'x'")
        assert _phase_status(raw, "install") == "failed"

    def test_crashed_beats_module_not_found(self):
        raw = self._raw(exit_code=1,
                        stderr="container foo is not running\nModuleNotFoundError: ...")
        assert _phase_status(raw, "import") == "crashed"


# ── run() orchestrator tests (Docker calls mocked) ───────────────────────────

def _fake_sandbox_start(capture_log: str | None = None) -> dict:
    return {
        "container_name":    "pkgids-mock",
        "container_id":      "mockcontainerid0000000000000000000000000000000000000000000000000",
        "sandbox_ip":        None,
        "image":             "pkgids-sandbox:latest",
        "runtime":           "runsc",
        "capture_log":       capture_log,
        "_resolv_conf_path": None,
    }


def _fake_exec_result() -> dict:
    return {
        "stdout":           "ok\n",
        "stderr":           "",
        "exit_code":        0,
        "timed_out":        False,
        "duration_seconds": 0.5,
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

    Patch order (9 total):
        [0] fetch
        [1] start_sandbox_container
        [2] exec_in_sandbox
        [3] stop_sandbox_container
        [4] _detonet_bridge_iface
        [5] _start_tcpdump
        [6] _stop_tcpdump
        [7] _read_phase_entries
        [8] read_container_file   ← strace trace log (None = no telemetry/log empty)

    phase_entries: what _read_phase_entries returns for every phase call.
                   Pass [] for 'no network activity' (default),
                   or a non-empty list for 'network activity detected'.
    """
    if phase_entries is None:
        phase_entries = []
    return [
        patch("pkgids.capture.fetch",                   return_value=fake_artifact),
        patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
        patch("pkgids.capture.exec_in_sandbox",         return_value=_fake_exec_result()),
        patch("pkgids.capture.stop_sandbox_container"),
        patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc123456789"),
        patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
        patch("pkgids.capture._stop_tcpdump"),
        patch("pkgids.capture._read_phase_entries",     return_value=phase_entries),
        patch("pkgids.capture.read_container_file",     return_value=None),
    ]


def _run_mocked(fake_artifact, tmp_path, phase_entries=None, **kwargs):
    """Run the orchestrator with all Docker/tcpdump calls mocked.

    Idle phases are disabled by default (secs=0) so that exec_in_sandbox call
    counts in existing tests remain predictable.  Pass post_install_idle_secs or
    post_import_idle_secs explicitly to test idle-phase behaviour.
    """
    run_dir = tmp_path / "run"
    p = _patch_all(fake_artifact, run_dir, phase_entries)
    kwargs.setdefault("post_install_idle_secs", 0)
    kwargs.setdefault("post_import_idle_secs",  0)
    with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
        return run("pypi", "six", "1.16.0", run_dir=run_dir, **kwargs)


class TestRunOrchestrator:
    def test_creates_run_dir(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert run_dir.is_dir()

    def test_install_json_written(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        install_json = Path(result["outputs"]["install_json"])
        assert install_json.exists()
        data = json.loads(install_json.read_text())
        assert data["exit_code"] == 0
        assert data["phase"] == "install"
        assert "command" in data
        assert "t_start" in data
        assert "t_end" in data
        assert "duration_secs" in data

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
        # All phases must carry timing, status, and network_activity.
        for phase in ("startup", "install", "import", "shutdown"):
            p = result["phases"][phase]
            for key in ("phase", "status", "t_start", "t_end",
                        "duration_secs", "network_activity"):
                assert key in p, f"phases.{phase} missing {key}"
        # Exec phases additionally carry command-result fields.
        for phase in ("install", "import"):
            p = result["phases"][phase]
            for key in ("exit_code", "timed_out"):
                assert key in p, f"phases.{phase} missing {key}"

    def test_phase_names_match_keys(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        for phase_name in ("startup", "install", "import", "shutdown"):
            assert result["phases"][phase_name]["phase"] == phase_name

    def test_phase_window_is_ordered(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        for phase in ("startup", "install", "import", "shutdown"):
            p = result["phases"][phase]
            assert p["t_start"] <= p["t_end"], f"{phase}: t_start > t_end"

    def test_install_window_before_import_window(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        install_end   = result["phases"]["install"]["t_end"]
        import_start  = result["phases"]["import"]["t_start"]
        assert install_end <= import_start, "install and import windows overlap"

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
        # startup + install + import + shutdown each return the mocked entry (idle=0)
        assert len(lines) == 4
        assert all(l["query"] == "cdn.lib.com" for l in lines)

    # ── skip_import ───────────────────────────────────────────────────────────

    def test_skip_import_flag(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, skip_import=True)
        imp = result["phases"]["import"]
        assert imp["status"] == "skipped"
        assert imp["reason"] == "skip_import"
        assert result["outputs"]["import_json"] is None
        assert result["network_activity"]["import"] is None

    def test_skip_import_calls_exec_once(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2] as mock_exec, p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=True,
                post_install_idle_secs=0, post_import_idle_secs=0)
        assert mock_exec.call_count == 1

    def test_full_run_calls_exec_twice(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2] as mock_exec, p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False,
                post_install_idle_secs=0, post_import_idle_secs=0)
        assert mock_exec.call_count == 2

    def test_idle_phases_increase_exec_count(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2] as mock_exec, p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False,
                post_install_idle_secs=2, post_import_idle_secs=2)
        # install + post_install_idle + import + post_import_idle
        assert mock_exec.call_count == 4

    def test_skip_import_with_idle_calls_exec_twice(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2] as mock_exec, p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=True,
                post_install_idle_secs=2, post_import_idle_secs=0)
        # install + post_install_idle only
        assert mock_exec.call_count == 2

    # ── status field tests ────────────────────────────────────────────────────

    def test_status_ok_in_install_json(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        install = json.loads(Path(result["outputs"]["install_json"]).read_text())
        assert install["status"] == "ok"

    def test_status_ok_in_import_json(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        imp = json.loads(Path(result["outputs"]["import_json"]).read_text())
        assert imp["status"] == "ok"

    def test_status_in_phase_summary(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["phases"]["install"]["status"] == "ok"
        assert result["phases"]["import"]["status"]  == "ok"
        assert result["phases"]["startup"]["status"]  == "ok"
        assert result["phases"]["shutdown"]["status"] == "ok"

    def test_status_failed_when_exit_nonzero(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        failed = {**_fake_exec_result(), "exit_code": 1, "stderr": "install error"}
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=failed),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["install"]["status"] == "failed"

    def test_status_timed_out(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        hung = {**_fake_exec_result(), "timed_out": True, "exit_code": -1}
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=hung),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["install"]["status"] == "timed_out"

    def test_status_module_not_found_on_import(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        call_n = {"n": 0}
        def side_effect(*args, **kwargs):
            call_n["n"] += 1
            if call_n["n"] == 2:  # second exec = import
                return {**_fake_exec_result(), "exit_code": 1,
                        "stderr": "ModuleNotFoundError: No module named 'six'"}
            return _fake_exec_result()
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         side_effect=side_effect),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["import"]["status"] == "module_not_found"

    def test_telemetry_limited_false_with_capture_log(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        # _fake_sandbox_start returns capture_log=None, so telemetry_limited=True
        assert result["phases"]["install"]["telemetry_limited"] is True

    def test_telemetry_limited_false_when_log_known(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        # Use a known capture_log so telemetry_limited should be False
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container",
                  return_value=_fake_sandbox_start(capture_log="/tmp/fake.jsonl")),
            patch("pkgids.capture.exec_in_sandbox",         return_value=_fake_exec_result()),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["install"]["telemetry_limited"] is False

    # ── sandbox_meta tests ────────────────────────────────────────────────────

    def test_sandbox_meta_in_run_json(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert "sandbox_meta" in result
        for key in ("container_name", "container_id", "sandbox_ip", "image",
                    "runtime", "env_vars", "install_cmd", "import_cmd", "module_name"):
            assert key in result["sandbox_meta"], f"sandbox_meta missing {key}"

    def test_sandbox_meta_container_name(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["container_name"] == "pkgids-mock"

    def test_sandbox_meta_container_id(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["container_id"] is not None

    def test_sandbox_meta_module_name(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["module_name"] == "six"

    def test_sandbox_meta_env_vars_is_dict(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert isinstance(result["sandbox_meta"]["env_vars"], dict)

    def test_sandbox_meta_install_cmd_set(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["install_cmd"] is not None
        assert "pip3" in result["sandbox_meta"]["install_cmd"]

    def test_sandbox_meta_import_cmd_none_when_skip(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, skip_import=True)
        assert result["sandbox_meta"]["import_cmd"] is None

    def test_sandbox_meta_image_from_config(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["image"] == "pkgids-sandbox:latest"

    def test_sandbox_meta_runtime_from_config(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["sandbox_meta"]["runtime"] == "runsc"

    # ── failure handling tests ────────────────────────────────────────────────

    def test_skip_import_when_install_fails(self, fake_artifact, tmp_path):
        """skip_import_on_install_failure=True must block import on non-ok install."""
        run_dir = tmp_path / "run"
        call_n  = {"n": 0}
        def fail_install(*args, **kwargs):
            call_n["n"] += 1
            if call_n["n"] == 1:
                return {**_fake_exec_result(), "exit_code": 1, "stderr": "install failed"}
            return _fake_exec_result()
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         side_effect=fail_install),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         skip_import_on_install_failure=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["install"]["status"] == "failed"
        assert result["phases"]["import"]["status"]  == "skipped"
        assert result["phases"]["import"]["reason"]  == "install_failed"
        assert result["outputs"]["import_json"] is None

    def test_import_not_skipped_on_failure_by_default(self, fake_artifact, tmp_path):
        """Default behaviour: import still runs even when install exits non-zero."""
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",
                  return_value={**_fake_exec_result(), "exit_code": 1}),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         skip_import_on_install_failure=False,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        # import ran (and also got the failed result), but it ran
        assert "import" in result["phases"]
        assert result["phases"]["import"].get("status") != "skipped"

    def test_startup_failure_recorded_in_run_json(self, fake_artifact, tmp_path):
        """Appliance down must produce a run.json with startup.status=failed."""
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container",
                  side_effect=RuntimeError(
                      "fake network requested but 'pkgids-fakeinternet' is not running"
                  )),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert result["phases"]["startup"]["status"] == "failed"
        assert "error" in result["phases"]["startup"]
        assert result["outputs"]["install_json"] is None
        assert (run_dir / "run.json").exists()

    def test_startup_failure_no_sandbox_meta_container_id(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container",
                  side_effect=RuntimeError("appliance not running")),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert result["sandbox_meta"]["container_name"] is None
        assert result["sandbox_meta"]["container_id"]   is None
        # image and runtime come from config even when startup failed
        assert result["sandbox_meta"]["image"]   == "pkgids-sandbox:latest"
        assert result["sandbox_meta"]["runtime"] == "runsc"

    # ── process_activity / telemetry tests ───────────────────────────────────

    def test_process_activity_key_in_install_json(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        install = json.loads(Path(result["outputs"]["install_json"]).read_text())
        assert "process_activity" in install

    def test_process_activity_key_in_import_json(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        imp = json.loads(Path(result["outputs"]["import_json"]).read_text())
        assert "process_activity" in imp

    def test_process_activity_in_phase_summary(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert "process_activity" in result["phases"]["install"]
        assert "process_activity" in result["phases"]["import"]

    def test_process_activity_none_for_startup_shutdown(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert result["phases"]["startup"]["process_activity"]  is None
        assert result["phases"]["shutdown"]["process_activity"] is None

    def test_process_activity_limited_when_no_trace_log(self, fake_artifact, tmp_path):
        # read_container_file returns None (default mock) → telemetry_limited_process=True
        result = _run_mocked(fake_artifact, tmp_path)
        pa = result["phases"]["install"]["process_activity"]
        assert pa["telemetry_limited_process"] is True
        assert pa["any_suspicious"] is False

    def test_process_activity_any_suspicious_true_when_trace_has_curl(
        self, fake_artifact, tmp_path
    ):
        strace_log = (
            '12345 execve("/usr/bin/pip3", ["pip3", "install", "pkg"], 0x1) = 0\n'
            '12346 execve("/usr/bin/curl", ["curl", "http://evil.com"], 0x1) = 0\n'
        )
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=_fake_exec_result()),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=strace_log),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        pa = result["phases"]["install"]["process_activity"]
        assert pa["any_suspicious"] is True
        assert any(e["executable"] == "/usr/bin/curl"
                   for e in pa["suspicious_execs"])

    def test_process_activity_exec_cmd_is_bare_in_sandbox_meta(
        self, fake_artifact, tmp_path
    ):
        # sandbox_meta.install_cmd should record the original pip3 command,
        # not the strace-wrapped version.
        result = _run_mocked(fake_artifact, tmp_path)
        install_cmd = result["sandbox_meta"]["install_cmd"]
        assert install_cmd[0] == "pip3"
        assert "strace" not in install_cmd

    def test_telemetry_jsonl_key_in_outputs(self, fake_artifact, tmp_path):
        # With no trace data (read_container_file=None), no events are emitted
        # so telemetry.jsonl won't be written and the key should be None.
        result = _run_mocked(fake_artifact, tmp_path)
        assert "telemetry_jsonl" in result["outputs"]
        assert result["outputs"]["telemetry_jsonl"] is None

    def test_telemetry_jsonl_written_when_trace_data_present(
        self, fake_artifact, tmp_path
    ):
        strace_log = (
            '12345 1700000000.0 execve("/usr/bin/pip3", ["pip3"], 0x1) = 0\n'
        )
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=_fake_exec_result()),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=strace_log),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["outputs"]["telemetry_jsonl"] is not None
        path = Path(result["outputs"]["telemetry_jsonl"])
        assert path.exists()
        recs = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        assert any(r["event_type"] == "exec" for r in recs)

    # ── existing tests below ──────────────────────────────────────────────────

    def test_startup_and_shutdown_in_phases(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert "startup"  in result["phases"]
        assert "shutdown" in result["phases"]
        assert result["phases"]["startup"]["phase"]  == "startup"
        assert result["phases"]["shutdown"]["phase"] == "shutdown"

    def test_idle_phases_appear_when_nonzero(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         post_install_idle_secs=2, post_import_idle_secs=2)
        assert "post_install_idle" in result["phases"]
        assert "post_import_idle"  in result["phases"]
        assert result["phases"]["post_install_idle"]["phase"] == "post_install_idle"
        assert result["phases"]["post_import_idle"]["phase"]  == "post_import_idle"

    def test_idle_phases_absent_when_zero(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)  # defaults idle=0
        assert "post_install_idle" not in result["phases"]
        assert "post_import_idle"  not in result["phases"]

    def test_container_started_and_stopped(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1] as mock_start, p[2], p[3] as mock_stop, p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        mock_start.assert_called_once()
        mock_stop.assert_called_once()

    # ── tcpdump ───────────────────────────────────────────────────────────────

    def test_tcpdump_started_and_stopped(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5] as ms, p[6] as mp, p[7], p[8]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        ms.assert_called_once()
        mp.assert_called_once()

    def test_tcpdump_unavailable_does_not_abort(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=_fake_exec_result()),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",
                  side_effect=RuntimeError("docker not available")),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert result["outputs"]["capture_pcap"] is None
        assert (run_dir / "install.json").exists()


# ── Feature 2: multi-trigger matrix ─────────────────────────────────────────

class TestRunWithTriggers:
    """Tests for the trigger_plans parameter and the triggers list in run.json."""

    def test_triggers_list_present_in_output(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert "triggers" in result
        assert isinstance(result["triggers"], list)

    def test_default_triggers_are_install_and_import_root(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert tids == ["install", "import_root"]

    def test_triggers_list_has_required_fields(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        for trig in result["triggers"]:
            for key in ("trigger_id", "phase_label", "status", "t_start", "t_end",
                        "exit_code", "timed_out", "network_activity", "process_activity"):
                assert key in trig, f"trigger {trig['trigger_id']} missing {key}"

    def test_phases_shim_populated_from_default_triggers(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path)
        assert "install" in result["phases"]
        assert "import"  in result["phases"]
        assert result["phases"]["install"]["status"] == "ok"
        assert result["phases"]["import"]["status"]  == "ok"

    def test_install_with_deps_trigger_id_in_output(self, fake_artifact, tmp_path):
        result = _run_mocked(fake_artifact, tmp_path, with_deps=True)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert "install_with_deps" in tids
        assert "install" not in tids
        assert result["sandbox_meta"]["install_deps_enabled"] is True

    def test_custom_trigger_plans_replace_defaults(self, fake_artifact, tmp_path):
        from pkgids.triggers import TriggerPlan
        from pkgids.capture import _install_command

        run_dir = tmp_path / "run"
        plans = [
            TriggerPlan(
                trigger_id="install",
                phase_label="Install",
                command=tuple(_install_command("pypi", "six-1.16.0.tar.gz")),
                timeout=120,
            ),
        ]
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         trigger_plans=plans,
                         post_install_idle_secs=0,
                         post_import_idle_secs=0)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert tids == ["install"]
        # phases["import"] is missing from plans → fallback skipped entry
        assert result["phases"]["import"]["status"] == "skipped"
        assert result["phases"]["import"]["reason"] == "skip_import"

    def test_dependency_skipping_with_install_failed(self, fake_artifact, tmp_path):
        from pkgids.triggers import TriggerPlan

        run_dir = tmp_path / "run"
        plans = [
            TriggerPlan(
                trigger_id="install",
                phase_label="Install",
                command=("echo", "install"),
                timeout=30,
            ),
            TriggerPlan(
                trigger_id="import_root",
                phase_label="Import (root)",
                command=("echo", "import"),
                timeout=30,
                requires=("install",),
                dependency_skip_reason="install_failed",
            ),
        ]
        failed = {**_fake_exec_result(), "exit_code": 1, "stderr": "boom"}
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=failed),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         trigger_plans=plans,
                         post_install_idle_secs=0,
                         post_import_idle_secs=0)

        install_trig = next(t for t in result["triggers"] if t["trigger_id"] == "install")
        import_trig  = next(t for t in result["triggers"] if t["trigger_id"] == "import_root")
        assert install_trig["status"] == "failed"
        assert import_trig["status"]  == "skipped"
        assert result["phases"]["import"]["status"] == "skipped"
        assert result["phases"]["import"]["reason"] == "install_failed"
        assert result["outputs"]["import_json"] is None

    def test_skip_import_on_install_failure_uses_builtin_reason(self, fake_artifact, tmp_path):
        """Built-in skip_import_on_install_failure preserves the legacy 'install_failed' reason."""
        run_dir = tmp_path / "run"
        failed = {**_fake_exec_result(), "exit_code": 1, "stderr": "fail"}
        with (
            patch("pkgids.capture.fetch",                   return_value=fake_artifact),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         return_value=failed),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir,
                         skip_import_on_install_failure=True,
                         post_install_idle_secs=0,
                         post_import_idle_secs=0)
        assert result["phases"]["install"]["status"] == "failed"
        assert result["phases"]["import"]["status"]  == "skipped"
        assert result["phases"]["import"]["reason"]  == "install_failed"

    def test_trigger_network_activity_reflects_entries(self, fake_artifact, tmp_path):
        entry = {"ts": 1000.0, "type": "dns", "query": "evil.com"}
        result = _run_mocked(fake_artifact, tmp_path, phase_entries=[entry])
        install_trig = next(t for t in result["triggers"] if t["trigger_id"] == "install")
        assert install_trig["network_activity"] is True


# ── CLI integration tests ─────────────────────────────────────────────────────

class TestCLIDetonate:
    def _cli(self, argv, fake_artifact, tmp_path, phase_entries=None):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir, phase_entries)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            from pkgids.cli import main
            return main(argv + ["--run-dir", str(run_dir)])

    def test_detonate_returns_zero(self, fake_artifact, tmp_path):
        assert self._cli(["detonate", "pypi", "six", "1.16.0"], fake_artifact, tmp_path) == 0

    def test_detonate_invalid_ecosystem(self):
        from pkgids.cli import main
        assert main(["detonate", "cargo", "serde", "1.0.0"]) == 1

    def test_detonate_skip_import_flag(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        p = _patch_all(fake_artifact, run_dir)
        with p[0], p[1], p[2] as mock_exec, p[3], p[4], p[5], p[6], p[7], p[8]:
            from pkgids.cli import main
            main(["detonate", "pypi", "six", "1.16.0", "--skip-import", "--run-dir", str(run_dir)])
        # install + post_install_idle (config default = 2s); post_import_idle skipped
        assert mock_exec.call_count == 2


# ── with_deps mode ───────────────────────────────────────────────────────────

class TestWithDepsFlag:
    def test_install_deps_enabled_false_in_sandbox_meta(self, fake_artifact, tmp_path):
        """Default run records install_deps_enabled=False in sandbox_meta."""
        run_dir = tmp_path / "run1"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8]:
            summary = run("pypi", "six", "1.16.0",
                          run_dir=run_dir,
                          post_install_idle_secs=0,
                          post_import_idle_secs=0)
        assert summary["sandbox_meta"]["install_deps_enabled"] is False

    def test_install_deps_enabled_true_in_sandbox_meta(self, fake_artifact, tmp_path):
        """with_deps=True records install_deps_enabled=True."""
        run_dir = tmp_path / "run2"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8]:
            summary = run("pypi", "six", "1.16.0",
                          run_dir=run_dir,
                          with_deps=True,
                          post_install_idle_secs=0,
                          post_import_idle_secs=0)
        assert summary["sandbox_meta"]["install_deps_enabled"] is True
        assert "--no-deps" not in summary["sandbox_meta"]["install_cmd"]

    def test_default_install_cmd_has_no_deps(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run3"
        patches = _patch_all(fake_artifact, run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5], patches[6], patches[7], patches[8]:
            summary = run("pypi", "six", "1.16.0",
                          run_dir=run_dir,
                          post_install_idle_secs=0,
                          post_import_idle_secs=0)
        assert "--no-deps" in summary["sandbox_meta"]["install_cmd"]


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
    assert install["status"] == "ok"
    # six makes no network calls — this must be False after the timestamp fix
    assert result["network_activity"]["install"] is False
    assert result["network_activity"]["import"]  is False
    # sandbox_meta must be populated
    assert result["sandbox_meta"]["container_name"] is not None
    assert result["sandbox_meta"]["module_name"] == "six"


# ── Feature 2 v1.6: import_submodule trigger ─────────────────────────────────

class TestDiscoverSubmodule:
    """Unit tests for _discover_submodule() — pure static analysis, no sandbox."""

    def _make_artifact(self, tmp_path: Path, files: list[str]) -> Path:
        """Write a fake artifact + metadata.json so _discover_submodule can read the files list."""
        d = tmp_path / "pkg-1.0"
        d.mkdir(parents=True)
        art = d / "pkg-1.0.tar.gz"
        art.write_bytes(b"fake")
        (d / "metadata.json").write_text(json.dumps({"files": files}))
        return art

    def test_finds_first_public_submodule_alphabetically(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "requests-2.0/requests/__init__.py",
            "requests-2.0/requests/adapters.py",
            "requests-2.0/requests/auth.py",
            "requests-2.0/requests/utils.py",
        ])
        assert _discover_submodule(art, "requests", "pypi") == "requests.adapters"

    def test_returns_none_for_single_file_package(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "six-1.16.0/six.py",
        ])
        assert _discover_submodule(art, "six", "pypi") is None

    def test_skips_private_modules(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "mypkg-1.0/mypkg/__init__.py",
            "mypkg-1.0/mypkg/_internal.py",
            "mypkg-1.0/mypkg/_compat.py",
        ])
        assert _discover_submodule(art, "mypkg", "pypi") is None

    def test_skips_dunder_modules(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "mypkg-1.0/mypkg/__init__.py",
            "mypkg-1.0/mypkg/__main__.py",
            "mypkg-1.0/mypkg/__version__.py",
        ])
        assert _discover_submodule(art, "mypkg", "pypi") is None

    def test_src_layout_flat_py(self, tmp_path):
        """src-layout packages: members under src/ must still be discovered."""
        art = self._make_artifact(tmp_path, [
            "mypkg-1.0/src/mypkg/__init__.py",
            "mypkg-1.0/src/mypkg/utils.py",
        ])
        assert _discover_submodule(art, "mypkg", "pypi") == "mypkg.utils"

    def test_src_layout_multiple_submodules_returns_first_alphabetically(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "mypkg-1.0/src/mypkg/__init__.py",
            "mypkg-1.0/src/mypkg/zoo.py",
            "mypkg-1.0/src/mypkg/alpha.py",
        ])
        assert _discover_submodule(art, "mypkg", "pypi") == "mypkg.alpha"

    def test_returns_none_for_npm(self, tmp_path):
        art = self._make_artifact(tmp_path, [
            "package/lib/index.js",
            "package/lib/utils.js",
        ])
        assert _discover_submodule(art, "mypackage", "npm") is None

    def test_returns_none_when_metadata_absent_and_not_a_real_archive(self, tmp_path):
        """Falls back to _archive_members; returns None gracefully when tarball is fake."""
        d = tmp_path / "pkg-1.0"
        d.mkdir()
        art = d / "pkg-1.0.tar.gz"
        art.write_bytes(b"not a real tarball")
        # metadata.json absent, tarball unreadable → must return None, not raise
        assert _discover_submodule(art, "pkg", "pypi") is None

    def test_returns_none_for_namespace_package_style_no_public_top_level(self, tmp_path):
        """Namespace packages with deep hierarchy but no direct submodule under top_module."""
        art = self._make_artifact(tmp_path, [
            "mypkg-1.0/mypkg/__init__.py",
            # subpackage directory — no .py files at depth 1 below mypkg
            "mypkg-1.0/mypkg/sub/__init__.py",
        ])
        assert _discover_submodule(art, "mypkg", "pypi") is None


class TestImportSubmoduleTrigger:
    """Tests for the include_submodule=True flow in run()."""

    def _make_requests_artifact(self, tmp_path: Path) -> Path:
        d = tmp_path / "artifacts" / "pypi" / "requests-2.0"
        d.mkdir(parents=True)
        art = d / "requests-2.0.tar.gz"
        art.write_bytes(b"fake")
        (d / "metadata.json").write_text(json.dumps({"files": [
            "requests-2.0/requests/__init__.py",
            "requests-2.0/requests/adapters.py",
            "requests-2.0/requests/auth.py",
        ]}))
        return art

    def test_import_submodule_trigger_added_when_submodule_found(self, tmp_path):
        art = self._make_requests_artifact(tmp_path)
        run_dir = tmp_path / "run"
        p = _patch_all(art, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "requests", "2.0", run_dir=run_dir,
                         include_submodule=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert "import_submodule" in tids
        assert tids == ["install", "import_root", "import_submodule"]

    def test_import_submodule_omitted_when_no_submodule_found(self, fake_artifact, tmp_path):
        """single-file package (six.py) → no submodule discovered → triggers unchanged."""
        (fake_artifact.parent / "metadata.json").write_text(json.dumps({"files": [
            "six-1.16.0/six.py",
        ]}))
        result = _run_mocked(fake_artifact, tmp_path, include_submodule=True)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert "import_submodule" not in tids
        assert tids == ["install", "import_root"]

    def test_phases_import_key_still_present_alongside_import_submodule(self, tmp_path):
        """import_root owns phases["import"]; import_submodule gets phases["import_submodule"]."""
        art = self._make_requests_artifact(tmp_path)
        run_dir = tmp_path / "run"
        p = _patch_all(art, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "requests", "2.0", run_dir=run_dir,
                         include_submodule=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert "import"            in result["phases"]
        assert "import_submodule"  in result["phases"]
        assert result["phases"]["import"]["status"]           == "ok"
        assert result["phases"]["import_submodule"]["status"] == "ok"

    def test_phases_import_and_import_submodule_are_separate_entries(self, tmp_path):
        """The two phases entries must be distinct dicts with different phase labels."""
        art = self._make_requests_artifact(tmp_path)
        run_dir = tmp_path / "run"
        p = _patch_all(art, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "requests", "2.0", run_dir=run_dir,
                         include_submodule=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        assert result["phases"]["import"] is not result["phases"]["import_submodule"]
        assert result["phases"]["import"]["phase"]           == "import"
        assert result["phases"]["import_submodule"]["phase"] == "import_submodule"

    def test_import_submodule_json_written_separately_from_import_json(self, tmp_path):
        """import.json belongs to import_root; import_submodule.json is a distinct file."""
        art = self._make_requests_artifact(tmp_path)
        run_dir = tmp_path / "run"
        p = _patch_all(art, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            run("pypi", "requests", "2.0", run_dir=run_dir,
                include_submodule=True,
                post_install_idle_secs=0, post_import_idle_secs=0)
        assert (run_dir / "import.json").exists(),           "import.json missing"
        assert (run_dir / "import_submodule.json").exists(), "import_submodule.json missing"

    def test_import_submodule_skipped_when_import_root_fails(self, tmp_path):
        """import_root failure must trigger dependency_skip on import_submodule."""
        art = self._make_requests_artifact(tmp_path)
        run_dir = tmp_path / "run"
        call_n  = {"n": 0}
        def side_effect(*args, **kwargs):
            call_n["n"] += 1
            if call_n["n"] == 2:  # import_root is 2nd exec
                return {**_fake_exec_result(), "exit_code": 1,
                        "stderr": "ModuleNotFoundError: No module named 'requests'"}
            return _fake_exec_result()
        with (
            patch("pkgids.capture.fetch",                   return_value=art),
            patch("pkgids.capture.start_sandbox_container", return_value=_fake_sandbox_start()),
            patch("pkgids.capture.exec_in_sandbox",         side_effect=side_effect),
            patch("pkgids.capture.stop_sandbox_container"),
            patch("pkgids.capture._detonet_bridge_iface",   return_value="br-abc"),
            patch("pkgids.capture._start_tcpdump",          return_value=MagicMock()),
            patch("pkgids.capture._stop_tcpdump"),
            patch("pkgids.capture._read_phase_entries",     return_value=[]),
            patch("pkgids.capture.read_container_file",     return_value=None),
        ):
            result = run("pypi", "requests", "2.0", run_dir=run_dir,
                         include_submodule=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        import_root_t = next(t for t in result["triggers"] if t["trigger_id"] == "import_root")
        submodule_t   = next(t for t in result["triggers"] if t["trigger_id"] == "import_submodule")
        assert import_root_t["status"] in ("failed", "module_not_found")
        assert submodule_t["status"]   == "skipped"
        assert submodule_t["skip_reason"] == "import_root_failed"

    def test_src_layout_submodule_is_discovered_and_run(self, tmp_path):
        """src-layout artifacts must yield an import_submodule trigger."""
        d = tmp_path / "artifacts" / "pypi" / "mypkg-1.0"
        d.mkdir(parents=True)
        art = d / "mypkg-1.0.tar.gz"
        art.write_bytes(b"fake")
        (d / "metadata.json").write_text(json.dumps({"files": [
            "mypkg-1.0/src/mypkg/__init__.py",
            "mypkg-1.0/src/mypkg/utils.py",
        ]}))
        run_dir = tmp_path / "run"
        p = _patch_all(art, run_dir)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]:
            result = run("pypi", "mypkg", "1.0", run_dir=run_dir,
                         include_submodule=True,
                         post_install_idle_secs=0, post_import_idle_secs=0)
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert "import_submodule" in tids
        # confirm the discovered submodule is mypkg.utils
        submod_plan_cmd = next(
            t for t in result["triggers"] if t["trigger_id"] == "import_submodule"
        )
        # import_submodule.json captures the command used
        sub_json = json.loads((run_dir / "import_submodule.json").read_text())
        assert "mypkg.utils" in " ".join(sub_json["command"])

    def test_default_run_unaffected_when_include_submodule_false(self, fake_artifact, tmp_path):
        """include_submodule=False (default) must leave trigger list unchanged."""
        result = _run_mocked(fake_artifact, tmp_path)  # include_submodule defaults to False
        tids = [t["trigger_id"] for t in result["triggers"]]
        assert "import_submodule" not in tids
        assert tids == ["install", "import_root"]
