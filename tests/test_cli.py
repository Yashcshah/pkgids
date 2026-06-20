"""Tests for the pkgids CLI."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pkgids.cli", *args],
        capture_output=True,
        text=True,
    )


def _fake_run_result(tmp_path: Path) -> dict:
    """Minimal run summary that capture.run() would return."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return {
        "ecosystem": "pypi",
        "name": "requests",
        "version": "2.31.0",
        "run_dir": str(run_dir),
        "artifact": str(run_dir / "requests-2.31.0.tar.gz"),
        "phases": {
            "install": {"exit_code": 0, "duration_seconds": 1.0,
                        "timed_out": False, "network_activity": False},
            "import":  {"exit_code": 0, "duration_seconds": 0.5,
                        "timed_out": False, "network_activity": False},
        },
        "network_activity": {"install": False, "import": False},
        "outputs": {
            "install_json":  str(run_dir / "install.json"),
            "import_json":   str(run_dir / "import.json"),
            "network_jsonl": None,
            "capture_pcap":  None,
        },
    }


class TestDetonate:
    def test_valid_pypi_exits_zero(self, tmp_path):
        """detonate with a valid ecosystem calls capture.run and exits 0."""
        from pkgids.cli import main
        with patch("pkgids.capture.run", return_value=_fake_run_result(tmp_path)):
            code = main(["detonate", "pypi", "requests", "2.31.0",
                         "--run-dir", str(tmp_path / "run")])
        assert code == 0

    def test_valid_npm_exits_zero(self, tmp_path):
        from pkgids.cli import main
        result = _fake_run_result(tmp_path)
        result["ecosystem"] = "npm"
        result["name"] = "lodash"
        with patch("pkgids.capture.run", return_value=result):
            code = main(["detonate", "npm", "lodash", "4.17.21",
                         "--run-dir", str(tmp_path / "run")])
        assert code == 0

    def test_invalid_ecosystem_exits_nonzero(self):
        result = _run("detonate", "rubygems", "rails", "7.0.0")
        assert result.returncode != 0
        assert "rubygems" in result.stderr
        assert "pypi" in result.stderr or "npm" in result.stderr

    def test_invalid_ecosystem_no_stdout(self):
        result = _run("detonate", "cargo", "serde", "1.0.0")
        assert result.returncode != 0
        assert result.stdout.strip() == ""

    def test_no_subcommand_exits_nonzero(self):
        result = _run()
        assert result.returncode != 0
