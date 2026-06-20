"""Tests for the pkgids CLI."""

import json
import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pkgids.cli", *args],
        capture_output=True,
        text=True,
    )


class TestDetonate:
    def test_valid_pypi(self):
        result = _run("detonate", "pypi", "requests", "2.31.0")
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["ecosystem"] == "pypi"
        assert payload["name"] == "requests"
        assert payload["version"] == "2.31.0"
        assert payload["command"] == "detonate"

    def test_valid_npm(self):
        result = _run("detonate", "npm", "lodash", "4.17.21")
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["ecosystem"] == "npm"

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
