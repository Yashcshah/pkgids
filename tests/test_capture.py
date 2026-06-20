"""Tests for the detonation orchestrator (capture.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pkgids.capture import (
    _has_network,
    _import_command,
    _install_command,
    _top_module_name,
    run,
)
from tests.conftest import requires_sandbox


# ── command-builder unit tests (no Docker) ────────────────────────────────────

class TestInstallCommand:
    def test_pypi_uses_pip3(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert cmd[0] == "pip3"

    def test_pypi_no_build_isolation(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "--no-build-isolation" in cmd

    def test_pypi_no_deps(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "--no-deps" in cmd

    def test_pypi_break_system_packages(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "--break-system-packages" in cmd

    def test_pypi_no_user_flag(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "--user" not in cmd

    def test_pypi_artifact_path(self):
        cmd = _install_command("pypi", "six-1.16.0.tar.gz")
        assert "/work/six-1.16.0.tar.gz" in cmd

    def test_npm_uses_npm(self):
        cmd = _install_command("npm", "left-pad-1.3.0.tgz")
        assert cmd[0] == "npm"

    def test_npm_scripts_enabled(self):
        cmd = _install_command("npm", "left-pad-1.3.0.tgz")
        assert "--ignore-scripts=false" in cmd

    def test_npm_artifact_path(self):
        cmd = _install_command("npm", "left-pad-1.3.0.tgz")
        assert "/work/left-pad-1.3.0.tgz" in cmd

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
        name = _top_module_name("npm", "@scope/pkg")
        assert not name.startswith("@")


class TestImportCommand:
    def test_pypi_uses_python3(self):
        cmd = _import_command("pypi", "requests")
        assert cmd[0] == "python3"
        assert "import requests" in " ".join(cmd)

    def test_pypi_dash_normalised(self):
        cmd = _import_command("pypi", "my-lib")
        assert "import my_lib" in " ".join(cmd)

    def test_npm_uses_node(self):
        cmd = _import_command("npm", "left-pad")
        assert cmd[0] == "node"
        assert "require('left-pad')" in " ".join(cmd)

    def test_npm_scoped(self):
        cmd = _import_command("npm", "@scope/pkg")
        assert "require('@scope/pkg')" in " ".join(cmd)

    def test_unknown_ecosystem_raises(self):
        with pytest.raises(ValueError):
            _import_command("cargo", "serde")


class TestHasNetwork:
    def test_none_capture_log(self):
        assert _has_network({}) is False
        assert _has_network({"capture_log": None}) is False

    def test_missing_file(self, tmp_path):
        assert _has_network({"capture_log": str(tmp_path / "nope.jsonl")}) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        assert _has_network({"capture_log": str(f)}) is False

    def test_non_empty_file(self, tmp_path):
        f = tmp_path / "cap.jsonl"
        f.write_text('{"type":"dns"}\n')
        assert _has_network({"capture_log": str(f)}) is True


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
def capture_log_file(tmp_path) -> Path:
    """A fake fakeinternet log with one DNS entry."""
    f = tmp_path / "10.200.200.3.jsonl"
    f.write_text(json.dumps({"type": "dns", "query": "evil.com"}) + "\n")
    return f


@pytest.fixture
def fake_artifact(tmp_path) -> Path:
    """A minimal fake artifact file."""
    artifact_dir = tmp_path / "artifacts" / "pypi" / "six-1.16.0"
    artifact_dir.mkdir(parents=True)
    artifact = artifact_dir / "six-1.16.0.tar.gz"
    artifact.write_bytes(b"fake")
    return artifact


def _patch_all(fake_artifact: Path, capture_log: str | None, run_dir: Path):
    """Return a context-manager stack that mocks all heavy calls in capture.py."""
    sandbox_result = _fake_sandbox_result(capture_log)
    patches = [
        patch("pkgids.capture.fetch", return_value=fake_artifact),
        patch("pkgids.capture.run_in_sandbox", return_value=sandbox_result),
        patch("pkgids.capture._detonet_bridge_iface", return_value="br-abc123456789"),
        patch("pkgids.capture._start_tcpdump", return_value=MagicMock()),
        patch("pkgids.capture._stop_tcpdump"),
    ]
    return patches


class TestRunOrchestrator:
    def _run_mocked(self, fake_artifact, capture_log_file, tmp_path, **kwargs):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            return run("pypi", "six", "1.16.0", run_dir=run_dir, **kwargs)

    def test_creates_run_dir(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert run_dir.is_dir()

    def test_install_json_written(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        install_json = Path(result["outputs"]["install_json"])
        assert install_json.exists()
        data = json.loads(install_json.read_text())
        assert data["exit_code"] == 0
        assert "command" in data

    def test_import_json_written_by_default(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        import_json = result["outputs"]["import_json"]
        assert import_json is not None
        assert Path(import_json).exists()

    def test_run_json_written(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        run_json = Path(result["run_dir"]) / "run.json"
        assert run_json.exists()
        data = json.loads(run_json.read_text())
        assert data["ecosystem"] == "pypi"
        assert data["name"] == "six"
        assert data["version"] == "1.16.0"

    def test_run_json_has_required_keys(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        for key in ("ecosystem", "name", "version", "run_dir", "artifact",
                    "phases", "network_activity", "outputs"):
            assert key in result, f"missing key: {key}"

    def test_phases_have_required_keys(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        for phase in ("install", "import"):
            p = result["phases"][phase]
            for key in ("exit_code", "duration_seconds", "timed_out", "network_activity"):
                assert key in p, f"phases.{phase} missing {key}"

    def test_network_activity_detected(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        assert result["network_activity"]["install"] is True

    def test_network_jsonl_written(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path)
        assert result["outputs"]["network_jsonl"] is not None
        assert Path(result["outputs"]["network_jsonl"]).exists()

    def test_skip_import_flag(self, fake_artifact, capture_log_file, tmp_path):
        result = self._run_mocked(fake_artifact, capture_log_file, tmp_path, skip_import=True)
        assert result["phases"]["import"] == {"skipped": True}
        assert result["outputs"]["import_json"] is None
        assert result["network_activity"]["import"] is None

    def test_skip_import_calls_sandbox_once(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1] as mock_sandbox, patches[2], patches[3], patches[4]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=True)
        assert mock_sandbox.call_count == 1   # only install, no import

    def test_full_run_calls_sandbox_twice(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1] as mock_sandbox, patches[2], patches[3], patches[4]:
            run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False)
        assert mock_sandbox.call_count == 2   # install + import

    def test_tcpdump_started_and_stopped(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1], patches[2], patches[3] as mock_start, patches[4] as mock_stop:
            run("pypi", "six", "1.16.0", run_dir=run_dir)
        mock_start.assert_called_once()
        mock_stop.assert_called_once()

    def test_tcpdump_unavailable_does_not_abort(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        with (
            patch("pkgids.capture.fetch", return_value=fake_artifact),
            patch("pkgids.capture.run_in_sandbox",
                  return_value=_fake_sandbox_result(str(capture_log_file))),
            patch("pkgids.capture._detonet_bridge_iface",
                  side_effect=RuntimeError("docker not available")),
        ):
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        # run still completes; no pcap
        assert result["outputs"]["capture_pcap"] is None
        assert (run_dir / "install.json").exists()

    def test_no_network_activity_when_no_log(self, fake_artifact, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, None, run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = run("pypi", "six", "1.16.0", run_dir=run_dir)
        assert result["network_activity"]["install"] is False


# ── CLI integration tests (no Docker) ────────────────────────────────────────

class TestCLIDetonate:
    def _run_cli(self, argv, fake_artifact, capture_log_file, tmp_path):
        import subprocess, sys
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            from pkgids.cli import main
            return main(argv + ["--run-dir", str(run_dir)])

    def test_detonate_returns_zero(self, fake_artifact, capture_log_file, tmp_path):
        code = self._run_cli(
            ["detonate", "pypi", "six", "1.16.0"],
            fake_artifact, capture_log_file, tmp_path,
        )
        assert code == 0

    def test_detonate_invalid_ecosystem(self):
        from pkgids.cli import main
        assert main(["detonate", "cargo", "serde", "1.0.0"]) == 1

    def test_detonate_skip_import_flag(self, fake_artifact, capture_log_file, tmp_path):
        run_dir = tmp_path / "run"
        patches = _patch_all(fake_artifact, str(capture_log_file), run_dir)
        with patches[0], patches[1] as mock_sandbox, patches[2], patches[3], patches[4]:
            from pkgids.cli import main
            main(["detonate", "pypi", "six", "1.16.0",
                  "--skip-import", "--run-dir", str(run_dir)])
        assert mock_sandbox.call_count == 1


# ── real end-to-end test (requires Docker + sandbox image + fakeinternet) ─────

@requires_sandbox
def test_detonate_pypi_six_e2e(tmp_path):
    """Full pipeline against real six==1.16.0 — run on the Linux box only."""
    from pkgids.capture import run as capture_run
    run_dir = tmp_path / "run"
    result = capture_run("pypi", "six", "1.16.0", run_dir=run_dir, skip_import=False)

    assert result["ecosystem"] == "pypi"
    assert result["name"] == "six"
    assert (run_dir / "install.json").exists()
    assert (run_dir / "run.json").exists()

    install = json.loads((run_dir / "install.json").read_text())
    # six is a pure-Python package with no build deps; install should succeed
    assert install["exit_code"] == 0
