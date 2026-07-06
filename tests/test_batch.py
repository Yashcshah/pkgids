"""Tests for pkgids.batch — batch detonation runner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from pkgids.batch import RESULT_KEYS, exit_code_for_results, run_batch


# ── fixtures & helpers ────────────────────────────────────────────────────────

def _pkg(name: str = "requests", version: str = "2.28.0",
         ecosystem: str = "pypi") -> dict:
    return {"ecosystem": ecosystem, "name": name, "version": version}


def _fake_run_summary(tmp_path: Path, name: str = "requests",
                      version: str = "2.28.0") -> dict:
    run_dir = tmp_path / "runs" / f"pypi-{name}-{version}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return {"run_dir": str(run_dir)}


def _fake_report(verdict: str = "no_malicious_behavior_observed") -> dict:
    return {
        "behavioral_verdict": verdict,
        "advisory_status":    "none",
        "verdict":            verdict,
        "score":              0 if "no_mal" in verdict else 80,
        "confidence":         0.0,
    }


def _fake_bundle(tmp_path: Path, name: str = "requests") -> Path:
    bundle = tmp_path / "exports" / f"pypi-{name}-2.28.0"
    bundle.mkdir(parents=True, exist_ok=True)
    return bundle


def _run(packages, tmp_path, *, resume=True, no_export=True,
         detonate_rv=None, report_rv=None, bundle_rv=None,
         detonate_effect=None, **kwargs):
    """Helper: run run_batch with three mocked inner functions."""
    out = tmp_path / "out"
    rv_sum = detonate_rv or _fake_run_summary(tmp_path)
    rv_rep = report_rv or _fake_report()
    rv_bun = bundle_rv or _fake_bundle(tmp_path)

    with (
        patch("pkgids.capture.run",
              side_effect=detonate_effect,
              return_value=None if detonate_effect else rv_sum) as mock_det,
        patch("pkgids.report.report", return_value=rv_rep) as mock_rep,
        patch("pkgids.report.export_bundle", return_value=rv_bun) as mock_exp,
    ):
        result = run_batch(
            packages,
            output_dir=out,
            resume=resume,
            no_export=no_export,
            **kwargs,
        )
    return result, mock_det, mock_rep, mock_exp


# ── exit_code_for_results ─────────────────────────────────────────────────────

class TestExitCodeForResults:
    def test_malicious_returns_2(self):
        r = [{"outcome": "completed", "final_verdict": "malicious"}]
        assert exit_code_for_results(r) == 2

    def test_likely_malicious_returns_2(self):
        r = [{"outcome": "completed", "final_verdict": "likely_malicious"}]
        assert exit_code_for_results(r) == 2

    def test_suspicious_returns_1(self):
        r = [{"outcome": "completed", "final_verdict": "suspicious"}]
        assert exit_code_for_results(r) == 1

    def test_known_vulnerable_returns_1(self):
        r = [{"outcome": "completed", "final_verdict": "known_vulnerable"}]
        assert exit_code_for_results(r) == 1

    def test_clean_returns_0(self):
        r = [{"outcome": "completed",
               "final_verdict": "no_malicious_behavior_observed"}]
        assert exit_code_for_results(r) == 0

    def test_all_errors_returns_0(self):
        r = [{"outcome": "error", "final_verdict": None}]
        assert exit_code_for_results(r) == 0

    def test_empty_returns_0(self):
        assert exit_code_for_results([]) == 0

    def test_mixed_malicious_and_clean_returns_2(self):
        r = [
            {"outcome": "completed", "final_verdict": "no_malicious_behavior_observed"},
            {"outcome": "completed", "final_verdict": "malicious"},
        ]
        assert exit_code_for_results(r) == 2

    def test_malicious_takes_priority_over_suspicious(self):
        r = [
            {"outcome": "completed", "final_verdict": "suspicious"},
            {"outcome": "completed", "final_verdict": "malicious"},
        ]
        assert exit_code_for_results(r) == 2

    def test_error_outcome_ignored_in_exit_code(self):
        r = [
            {"outcome": "error",     "final_verdict": "malicious"},
            {"outcome": "completed", "final_verdict": "no_malicious_behavior_observed"},
        ]
        assert exit_code_for_results(r) == 0


# ── run_batch ─────────────────────────────────────────────────────────────────

class TestRunBatchEmpty:
    def test_empty_packages_returns_zero_counts(self, tmp_path):
        result, *_ = _run([], tmp_path)
        assert result["results"] == []
        assert result["summary"]["completed"] == 0

    def test_empty_writes_batch_results_json(self, tmp_path):
        _run([], tmp_path)
        assert (tmp_path / "out" / "batch_results.json").exists()

    def test_empty_writes_batch_report_html(self, tmp_path):
        _run([], tmp_path)
        html = tmp_path / "out" / "batch_report.html"
        assert html.exists()
        assert "<!DOCTYPE html>" in html.read_text()


class TestRunBatchSinglePackage:
    def test_completed_outcome(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path)
        assert result["results"][0]["outcome"] == "completed"

    def test_all_verdict_fields_populated(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path)
        r = result["results"][0]
        assert r["behavioral_verdict"] is not None
        assert r["advisory_status"] is not None
        assert r["final_verdict"] is not None
        assert r["score"] is not None
        assert r["confidence"] is not None

    def test_result_has_exact_key_set(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path)
        assert set(result["results"][0].keys()) == RESULT_KEYS

    def test_detonate_called_once(self, tmp_path):
        _, mock_det, *_ = _run([_pkg()], tmp_path)
        assert mock_det.call_count == 1

    def test_report_called_once(self, tmp_path):
        _, _, mock_rep, _ = _run([_pkg()], tmp_path)
        assert mock_rep.call_count == 1

    def test_no_export_skips_export_bundle(self, tmp_path):
        _, _, _, mock_exp = _run([_pkg()], tmp_path, no_export=True)
        assert mock_exp.call_count == 0

    def test_export_called_when_no_export_false(self, tmp_path):
        _, _, _, mock_exp = _run([_pkg()], tmp_path, no_export=False)
        assert mock_exp.call_count == 1

    def test_bundle_dir_set_when_exported(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path, no_export=False)
        assert result["results"][0]["bundle_dir"] is not None


class TestRunBatchError:
    def test_exception_recorded_as_error(self, tmp_path):
        result, *_ = _run(
            [_pkg()], tmp_path,
            detonate_effect=RuntimeError("Docker not running"),
        )
        r = result["results"][0]
        assert r["outcome"] == "error"
        assert "Docker not running" in r["error"]

    def test_error_nulls_verdict_fields(self, tmp_path):
        result, *_ = _run(
            [_pkg()], tmp_path,
            detonate_effect=RuntimeError("boom"),
        )
        r = result["results"][0]
        assert r["final_verdict"] is None
        assert r["score"] is None

    def test_error_result_has_exact_key_set(self, tmp_path):
        result, *_ = _run(
            [_pkg()], tmp_path,
            detonate_effect=RuntimeError("boom"),
        )
        assert set(result["results"][0].keys()) == RESULT_KEYS

    def test_remaining_packages_run_after_error(self, tmp_path):
        calls = [RuntimeError("first fails"), _fake_run_summary(tmp_path)]
        result, mock_det, mock_rep, _ = _run(
            [_pkg("bad", "1.0.0"), _pkg("good", "2.0.0")],
            tmp_path,
            detonate_effect=calls,
        )
        assert mock_det.call_count == 2
        assert result["results"][0]["outcome"] == "error"
        assert result["results"][1]["outcome"] == "completed"


class TestRunBatchMultiplePackages:
    def test_all_packages_detonated(self, tmp_path):
        pkgs = [_pkg("a", "1.0.0"), _pkg("b", "2.0.0"), _pkg("c", "3.0.0")]
        result, mock_det, *_ = _run(pkgs, tmp_path)
        assert mock_det.call_count == 3
        assert len(result["results"]) == 3

    def test_summary_counts_match_results(self, tmp_path):
        pkgs = [_pkg("a", "1.0.0"), _pkg("b", "2.0.0")]
        result, *_ = _run(pkgs, tmp_path)
        s = result["summary"]
        assert s["completed"] == len([r for r in result["results"]
                                      if r["outcome"] == "completed"])
        assert s["errors"] == len([r for r in result["results"]
                                   if r["outcome"] == "error"])


class TestRunBatchResume:
    def _write_prior(self, out: Path, key: str,
                     verdict: str = "no_malicious_behavior_observed") -> None:
        out.mkdir(parents=True, exist_ok=True)
        prior = {
            "batch_id": "prior", "input_file": "", "input_format": "",
            "started_at": "T", "completed_at": "T",
            "parse_warnings": [], "summary": {},
            "results": [{
                "key": key, "ecosystem": key.split(":")[0],
                "name": key.split(":")[1], "version": key.split(":")[2],
                "outcome": "completed",
                "behavioral_verdict": verdict,
                "advisory_status": "none",
                "final_verdict": verdict,
                "score": 0, "confidence": 0.0,
                "run_dir": None, "bundle_dir": None, "error": None,
            }],
        }
        (out / "batch_results.json").write_text(json.dumps(prior))

    def test_resume_skips_completed_key(self, tmp_path):
        out = tmp_path / "out"
        self._write_prior(out, "pypi:requests:2.28.0")
        with (
            patch("pkgids.capture.run") as mock_det,
            patch("pkgids.report.report") as mock_rep,
            patch("pkgids.report.export_bundle") as mock_exp,
        ):
            run_batch([_pkg()], output_dir=out, resume=True, no_export=True)
        assert mock_det.call_count == 0

    def test_resume_result_count_includes_prior(self, tmp_path):
        out = tmp_path / "out"
        self._write_prior(out, "pypi:requests:2.28.0")
        with (
            patch("pkgids.capture.run",
                  return_value=_fake_run_summary(tmp_path, "flask", "3.0.0")),
            patch("pkgids.report.report", return_value=_fake_report()),
            patch("pkgids.report.export_bundle", return_value=_fake_bundle(tmp_path)),
        ):
            result = run_batch(
                [_pkg(), _pkg("flask", "3.0.0")],
                output_dir=out, resume=True, no_export=True,
            )
        assert len(result["results"]) == 2
        assert result["summary"]["resume_skipped"] == 1

    def test_no_resume_reruns_all(self, tmp_path):
        out = tmp_path / "out"
        self._write_prior(out, "pypi:requests:2.28.0")
        with (
            patch("pkgids.capture.run",
                  return_value=_fake_run_summary(tmp_path)) as mock_det,
            patch("pkgids.report.report", return_value=_fake_report()),
            patch("pkgids.report.export_bundle", return_value=_fake_bundle(tmp_path)),
        ):
            run_batch([_pkg()], output_dir=out, resume=False, no_export=True)
        assert mock_det.call_count == 1


class TestRunBatchOutputFiles:
    def test_batch_results_json_written(self, tmp_path):
        _run([_pkg()], tmp_path)
        assert (tmp_path / "out" / "batch_results.json").exists()

    def test_batch_results_json_top_level_schema(self, tmp_path):
        _run([_pkg()], tmp_path, parse_warnings=["line 1: skipped x"],
             input_file="req.txt", input_format="requirements_txt")
        data = json.loads((tmp_path / "out" / "batch_results.json").read_text())
        required_top = {
            "batch_id", "input_file", "input_format",
            "started_at", "completed_at", "parse_warnings", "summary", "results",
        }
        assert required_top <= set(data.keys())
        assert data["input_file"] == "req.txt"
        assert data["parse_warnings"] == ["line 1: skipped x"]

    def test_batch_results_json_summary_fields(self, tmp_path):
        _run([_pkg()], tmp_path)
        data = json.loads((tmp_path / "out" / "batch_results.json").read_text())
        required_summary = {
            "parsed_targets", "parse_skipped", "scheduled", "resume_skipped",
            "completed", "errors",
        }
        assert required_summary <= set(data["summary"].keys())

    def test_batch_report_html_written(self, tmp_path):
        _run([_pkg()], tmp_path)
        html = tmp_path / "out" / "batch_report.html"
        assert html.exists()
        assert "<!DOCTYPE html>" in html.read_text()

    def test_batch_results_json_written_incrementally(self, tmp_path):
        """JSON file exists after the first package even if second is pending."""
        out = tmp_path / "out"
        written_after_first: list[bool] = []

        real_run = __import__("pkgids.capture", fromlist=["run"]).run
        real_rep = __import__("pkgids.report", fromlist=["report"]).report
        real_exp = __import__("pkgids.report", fromlist=["export_bundle"]).export_bundle

        call_count = [0]

        def side_det(*a, **kw):
            call_count[0] += 1
            written_after_first.append((out / "batch_results.json").exists())
            return _fake_run_summary(tmp_path)

        with (
            patch("pkgids.capture.run", side_effect=side_det),
            patch("pkgids.report.report", return_value=_fake_report()),
            patch("pkgids.report.export_bundle", return_value=_fake_bundle(tmp_path)),
        ):
            run_batch([_pkg("a", "1.0.0"), _pkg("b", "2.0.0")],
                      output_dir=out, no_export=True)

        # By the time the second package runs, the file should already exist
        assert len(written_after_first) == 2
        assert written_after_first[1] is True

    def test_parse_warnings_stored_in_json(self, tmp_path):
        warns = ["line 3: skipping 'flask' — no version pin"]
        _run([_pkg()], tmp_path, parse_warnings=warns)
        data = json.loads((tmp_path / "out" / "batch_results.json").read_text())
        assert data["parse_warnings"] == warns


class TestRunBatchReturnSchema:
    def test_return_dict_top_level_keys(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path)
        required = {
            "batch_id", "input_file", "input_format",
            "started_at", "completed_at", "parse_warnings", "summary", "results",
        }
        assert required <= set(result.keys())

    def test_completed_at_not_none_after_run(self, tmp_path):
        result, *_ = _run([_pkg()], tmp_path)
        assert result["completed_at"] is not None
