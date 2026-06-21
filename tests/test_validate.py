"""Tests for validate.py — label-comparison logic and report math."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pkgids.validate import compute_report, predict, run_validation
from tests.conftest import requires_sandbox


# ── predict() unit tests ──────────────────────────────────────────────────────

def _summary(install_net=False, import_net=False, import_skipped=False,
             install_timeout=False) -> dict:
    """Build a minimal capture.run() summary for predict() testing."""
    na: dict = {"install": install_net}
    phases: dict = {
        "install": {"exit_code": 0, "duration_seconds": 1.0,
                    "timed_out": install_timeout, "network_activity": install_net},
    }
    if import_skipped:
        na["import"] = None
        phases["import"] = {"skipped": True}
    else:
        na["import"] = import_net
        phases["import"] = {"exit_code": 0, "duration_seconds": 0.5,
                            "timed_out": False, "network_activity": import_net}
    return {"network_activity": na, "phases": phases}


class TestPredict:
    def test_no_network_is_benign(self):
        assert predict(_summary()) == "benign"

    def test_install_network_is_malicious(self):
        assert predict(_summary(install_net=True)) == "malicious"

    def test_import_network_is_malicious(self):
        assert predict(_summary(import_net=True)) == "malicious"

    def test_both_phases_network_is_malicious(self):
        assert predict(_summary(install_net=True, import_net=True)) == "malicious"

    def test_install_timeout_is_malicious(self):
        assert predict(_summary(install_timeout=True)) == "malicious"

    def test_skip_import_no_network_is_benign(self):
        assert predict(_summary(import_skipped=True)) == "benign"

    def test_skip_import_with_install_network_is_malicious(self):
        assert predict(_summary(install_net=True, import_skipped=True)) == "malicious"

    def test_none_network_activity_not_counted(self):
        # import=None means skipped, should not trigger malicious
        s = _summary(import_skipped=True)
        s["network_activity"]["import"] = None
        assert predict(s) == "benign"

    def test_false_network_activity_is_benign(self):
        s = _summary()
        s["network_activity"] = {"install": False, "import": False}
        assert predict(s) == "benign"


# ── compute_report() unit tests ───────────────────────────────────────────────

def _result(expected: str, predicted: str, name: str = "pkg",
            outcome: str = "completed") -> dict:
    return {
        "key":       f"pypi:{name}:1.0",
        "ecosystem": "pypi",
        "name":      name,
        "version":   "1.0",
        "expected":  expected,
        "predicted": predicted,
        "outcome":   outcome,
        "run_dir":   None,
    }


class TestComputeReport:
    def test_empty_results(self):
        r = compute_report([])
        assert r["total"] == 0
        assert r["available"] == 0
        assert r["tp"] == r["fp"] == r["tn"] == r["fn"] == 0
        assert r["detection_rate"] is None
        assert r["fp_rate"] is None

    def test_all_true_positives(self):
        results = [_result("malicious", "malicious", f"m{i}") for i in range(3)]
        r = compute_report(results)
        assert r["tp"] == 3
        assert r["fp"] == r["tn"] == r["fn"] == 0
        assert r["detection_rate"] == 1.0
        assert r["fp_rate"] is None   # no negatives

    def test_all_true_negatives(self):
        results = [_result("benign", "benign", f"b{i}") for i in range(4)]
        r = compute_report(results)
        assert r["tn"] == 4
        assert r["tp"] == r["fp"] == r["fn"] == 0
        assert r["fp_rate"] == 0.0
        assert r["detection_rate"] is None   # no positives

    def test_false_positive(self):
        results = [_result("benign", "malicious", "fp-pkg")]
        r = compute_report(results)
        assert r["fp"] == 1
        assert r["tn"] == 0
        assert r["fp_rate"] == 1.0
        assert "fp-pkg" in r["false_positives"]

    def test_false_negative(self):
        results = [_result("malicious", "benign", "fn-pkg")]
        r = compute_report(results)
        assert r["fn"] == 1
        assert r["detection_rate"] == 0.0
        assert "fn-pkg" in r["false_negatives"]

    def test_unavailable_excluded_from_matrix(self):
        results = [
            _result("malicious", "malicious", "tp"),
            _result("benign", "benign", outcome="unavailable"),
            _result("malicious", None, "u2", outcome="unavailable"),
        ]
        r = compute_report(results)
        assert r["available"] == 1
        assert r["unavailable"] == 2
        assert r["tp"] == 1
        assert r["fp"] == r["fn"] == 0

    def test_errors_excluded_from_matrix(self):
        results = [
            _result("benign", "benign", "ok"),
            _result("malicious", None, "err", outcome="error"),
        ]
        r = compute_report(results)
        assert r["available"] == 1
        assert r["errors"] == 1
        assert r["tn"] == 1

    def test_detection_rate_math(self):
        # 2 TP, 1 FN → detection_rate = 2/3
        results = [
            _result("malicious", "malicious", "tp1"),
            _result("malicious", "malicious", "tp2"),
            _result("malicious", "benign",    "fn1"),
        ]
        r = compute_report(results)
        assert abs(r["detection_rate"] - 2/3) < 1e-9

    def test_fp_rate_math(self):
        # 1 FP, 3 TN → fp_rate = 1/4
        results = [
            _result("benign", "malicious", "fp1"),
            _result("benign", "benign",    "tn1"),
            _result("benign", "benign",    "tn2"),
            _result("benign", "benign",    "tn3"),
        ]
        r = compute_report(results)
        assert abs(r["fp_rate"] - 0.25) < 1e-9

    def test_mixed_report(self):
        results = [
            _result("malicious", "malicious", "tp"),
            _result("malicious", "benign",    "fn"),
            _result("benign",    "benign",    "tn"),
            _result("benign",    "malicious", "fp"),
        ]
        r = compute_report(results)
        assert r["tp"] == 1
        assert r["fp"] == 1
        assert r["tn"] == 1
        assert r["fn"] == 1
        assert r["detection_rate"] == 0.5
        assert r["fp_rate"] == 0.5
        assert r["false_positives"] == ["fp"]
        assert r["false_negatives"] == ["fn"]

    def test_totals_add_up(self):
        results = [
            _result("malicious", "malicious", "tp"),
            _result("benign",    "benign",    "tn"),
            _result("benign",    "benign",    outcome="unavailable"),
            _result("malicious", None,        "e", outcome="error"),
        ]
        r = compute_report(results)
        assert r["total"] == 4
        assert r["available"] + r["unavailable"] + r["errors"] == 4

    def test_false_positives_list_names(self):
        results = [
            _result("benign", "malicious", "alpha"),
            _result("benign", "malicious", "beta"),
            _result("benign", "benign",    "gamma"),
        ]
        r = compute_report(results)
        assert set(r["false_positives"]) == {"alpha", "beta"}

    def test_false_negatives_list_names(self):
        results = [
            _result("malicious", "benign",    "miss-1"),
            _result("malicious", "malicious", "hit-1"),
        ]
        r = compute_report(results)
        assert r["false_negatives"] == ["miss-1"]


# ── run_validation() unit tests (mocked, no Docker) ──────────────────────────

def _fake_run_summary(install_net=False, import_net=False) -> dict:
    return {
        "ecosystem": "pypi", "name": "x", "version": "1.0",
        "run_dir": "/tmp/fake",
        "phases": {
            "install": {"exit_code": 0, "timed_out": False,
                        "network_activity": install_net, "duration_seconds": 1.0},
            "import":  {"exit_code": 0, "timed_out": False,
                        "network_activity": import_net, "duration_seconds": 0.5},
        },
        "network_activity": {"install": install_net, "import": import_net},
    }


def _write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ecosystem", "name", "version", "expected_label"])
        writer.writeheader()
        writer.writerows(rows)


class TestRunValidation:
    def test_benign_package_no_network_gives_tn(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "six",
                                "version": "1.16.0", "expected_label": "benign"}])
        with (
            patch("pkgids.validate._artifact_fetch"),
            patch("pkgids.validate._detonate", return_value=_fake_run_summary()),
        ):
            report = run_validation(csv_path, results_path)

        assert report["tn"] == 1
        assert report["fp"] == 0

    def test_malicious_package_with_network_gives_tp(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "evil",
                                "version": "1.0", "expected_label": "malicious"}])
        with (
            patch("pkgids.validate._artifact_fetch"),
            patch("pkgids.validate._detonate",
                  return_value=_fake_run_summary(install_net=True)),
        ):
            report = run_validation(csv_path, results_path)

        assert report["tp"] == 1
        assert report["fn"] == 0

    def test_unavailable_package_not_counted(self, tmp_path):
        import requests
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "removed",
                                "version": "0.1", "expected_label": "malicious"}])
        err = requests.HTTPError(response=type("R", (), {"status_code": 404})())
        with patch("pkgids.validate._artifact_fetch", side_effect=err):
            report = run_validation(csv_path, results_path)

        assert report["unavailable"] == 1
        assert report["available"] == 0

    def test_resumable_skips_completed(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "six",
                                "version": "1.16.0", "expected_label": "benign"}])

        # Pre-populate the results file
        key = "pypi:six:1.16.0"
        existing = [{"key": key, "ecosystem": "pypi", "name": "six",
                     "version": "1.16.0", "expected": "benign",
                     "predicted": "benign", "outcome": "completed", "run_dir": None}]
        results_path.write_text(json.dumps(existing))

        with patch("pkgids.validate._artifact_fetch") as mock_fetch:
            run_validation(csv_path, results_path)
        mock_fetch.assert_not_called()

    def test_results_written_to_file(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "six",
                                "version": "1.16.0", "expected_label": "benign"}])
        with (
            patch("pkgids.validate._artifact_fetch"),
            patch("pkgids.validate._detonate", return_value=_fake_run_summary()),
        ):
            run_validation(csv_path, results_path)

        assert results_path.exists()
        data = json.loads(results_path.read_text())
        assert len(data) == 1
        assert data[0]["outcome"] == "completed"

    def test_malformed_rows_skipped(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        with open(csv_path, "w") as f:
            f.write("ecosystem,name,version,expected_label\n")
            f.write(",,,\n")   # empty row
        with patch("pkgids.validate._detonate") as mock_det:
            run_validation(csv_path, results_path)
        mock_det.assert_not_called()

    def test_detonation_error_recorded(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        _write_csv(csv_path, [{"ecosystem": "pypi", "name": "six",
                                "version": "1.16.0", "expected_label": "benign"}])
        with (
            patch("pkgids.validate._artifact_fetch"),
            patch("pkgids.validate._detonate",
                  side_effect=RuntimeError("sandbox exploded")),
        ):
            report = run_validation(csv_path, results_path)

        assert report["errors"] == 1
        data = json.loads(results_path.read_text())
        assert data[0]["outcome"] == "error"


# ── CLI dataset + validate (smoke tests, no Docker) ───────────────────────────

class TestCLIDataset:
    def test_dataset_no_subcommand_exits_nonzero(self):
        from pkgids.cli import main
        assert main(["dataset"]) == 1

    def test_dataset_fetch_invalid_ecosystem(self):
        from pkgids.cli import main
        # argparse 'choices' should reject this
        with pytest.raises(SystemExit) as exc:
            main(["dataset", "fetch", "cargo"])
        assert exc.value.code != 0


class TestCLIValidate:
    def test_validate_missing_samples_exits_nonzero(self, tmp_path):
        from pkgids.cli import main
        code = main(["validate", "--samples", str(tmp_path / "nope.csv")])
        assert code == 1

    def test_validate_runs_and_prints_report(self, tmp_path):
        csv_path     = tmp_path / "samples.csv"
        results_path = tmp_path / "results.json"
        with open(csv_path, "w") as f:
            f.write("ecosystem,name,version,expected_label\n")
            f.write("pypi,six,1.16.0,benign\n")
        from pkgids.cli import main
        with (
            patch("pkgids.validate._artifact_fetch"),
            patch("pkgids.validate._detonate",
                  return_value=_fake_run_summary()),
        ):
            code = main([
                "validate",
                "--samples", str(csv_path),
                "--results", str(results_path),
            ])
        assert code == 0


# ── real end-to-end test (requires Docker + sandbox image + fakeinternet) ─────

@requires_sandbox
def test_validate_benign_samples_no_false_positives(tmp_path):
    """Run the 5 PyPI benign samples through the full pipeline.

    Expects: zero false positives (network_activity=False for all).
    """
    csv_path     = Path(__file__).parent.parent / "data" / "benign_samples.csv"
    results_path = tmp_path / "val_results.json"

    # Run only the PyPI subset to keep the test shorter
    pypi_csv = tmp_path / "pypi_benign.csv"
    with open(csv_path) as f_in, open(pypi_csv, "w") as f_out:
        for line in f_in:
            if line.startswith("ecosystem") or line.startswith("pypi"):
                f_out.write(line)

    report = run_validation(pypi_csv, results_path)

    assert report["fp"] == 0, (
        f"False positives detected on benign packages: {report['false_positives']}"
    )
    # All available samples should be true negatives
    assert report["tn"] == report["available"]
