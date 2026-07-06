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


class TestScan:
    def _make_req(self, tmp_path: Path, content: str = "requests==2.28.0\n") -> Path:
        p = tmp_path / "requirements.txt"
        p.write_text(content, encoding="utf-8")
        return p

    def _fake_batch_result(self, verdict: str = "no_malicious_behavior_observed") -> dict:
        return {
            "batch_id":      "20240101T000000Z",
            "input_file":    "requirements.txt",
            "input_format":  "requirements_txt",
            "started_at":    "2024-01-01T00:00:00Z",
            "completed_at":  "2024-01-01T00:01:00Z",
            "parse_warnings": [],
            "summary": {
                "parsed_targets": 1, "parse_skipped": 0,
                "scheduled": 1, "resume_skipped": 0,
                "completed": 1, "errors": 0,
                "malicious": 0, "likely_malicious": 0,
                "suspicious": 0, "known_vulnerable": 0,
                "low_risk": 0, "no_malicious_behavior_observed": 1,
            },
            "results": [{
                "key":                "pypi:requests:2.28.0",
                "ecosystem":          "pypi",
                "name":               "requests",
                "version":            "2.28.0",
                "outcome":            "completed",
                "behavioral_verdict": verdict,
                "advisory_status":    "none",
                "final_verdict":      verdict,
                "score":              0,
                "confidence":         0.0,
                "run_dir":            None,
                "bundle_dir":         None,
                "error":              None,
            }],
        }

    def test_missing_file_exits_nonzero(self, tmp_path):
        from pkgids.cli import main
        code = main(["scan", str(tmp_path / "nonexistent.txt"),
                     "--output-dir", str(tmp_path / "out")])
        assert code != 0

    def test_workers_gt_1_exits_nonzero_with_v1_message(self, tmp_path, capsys):
        from pkgids.cli import main
        req = self._make_req(tmp_path)
        code = main(["scan", str(req), "--workers", "2",
                     "--output-dir", str(tmp_path / "out")])
        assert code == 1
        captured = capsys.readouterr()
        assert "v1" in captured.err

    def test_scan_calls_run_batch(self, tmp_path):
        from pkgids.cli import main
        req = self._make_req(tmp_path)
        with patch("pkgids.batch.run_batch",
                   return_value=self._fake_batch_result()) as mock_rb:
            code = main(["scan", str(req),
                         "--output-dir", str(tmp_path / "out"),
                         "--no-export"])
        assert mock_rb.call_count == 1

    def test_scan_exit_code_clean(self, tmp_path):
        from pkgids.cli import main
        req = self._make_req(tmp_path)
        with patch("pkgids.batch.run_batch",
                   return_value=self._fake_batch_result("no_malicious_behavior_observed")):
            code = main(["scan", str(req),
                         "--output-dir", str(tmp_path / "out"),
                         "--no-export"])
        assert code == 0

    def test_scan_exit_code_malicious(self, tmp_path):
        from pkgids.cli import main
        req = self._make_req(tmp_path)
        rv = self._fake_batch_result("malicious")
        rv["results"][0]["final_verdict"] = "malicious"
        with patch("pkgids.batch.run_batch", return_value=rv):
            code = main(["scan", str(req),
                         "--output-dir", str(tmp_path / "out"),
                         "--no-export"])
        assert code == 2

    def test_scan_exit_code_suspicious(self, tmp_path):
        from pkgids.cli import main
        req = self._make_req(tmp_path)
        rv = self._fake_batch_result("suspicious")
        rv["results"][0]["final_verdict"] = "suspicious"
        with patch("pkgids.batch.run_batch", return_value=rv):
            code = main(["scan", str(req),
                         "--output-dir", str(tmp_path / "out"),
                         "--no-export"])
        assert code == 1

    def test_scan_no_packages_after_parse_exits_0(self, tmp_path):
        from pkgids.cli import main
        p = tmp_path / "requirements.txt"
        p.write_text("# only comments\n# nothing useful\n", encoding="utf-8")
        code = main(["scan", str(p), "--output-dir", str(tmp_path / "out")])
        assert code == 0
