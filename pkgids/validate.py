"""Validation harness: run detonation against labeled samples and score results."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Literal

import requests

from .fetch import fetch as _artifact_fetch
from .capture import run as _detonate

_DEFAULT_RESULTS = Path(__file__).parent.parent / "data" / "validation_results.json"


# ── prediction & scoring ──────────────────────────────────────────────────────

def predict(run_summary: dict) -> Literal["malicious", "benign"]:
    """Predict a label from a ``capture.run()`` summary dict.

    Rules (applied in order):
    1. Any phase with ``network_activity=True`` → malicious.
    2. Install phase timed out (likely hung on a C2 call) → malicious.
    3. Otherwise → benign.
    """
    na = run_summary.get("network_activity", {})
    if any(v is True for v in na.values()):
        return "malicious"

    phases  = run_summary.get("phases", {})
    install = phases.get("install", {})
    if isinstance(install, dict) and install.get("timed_out"):
        return "malicious"

    return "benign"


def compute_report(results: list[dict]) -> dict:
    """Compute a precision/recall report from a list of result records.

    Only samples with ``outcome == 'completed'`` contribute to the confusion
    matrix.  Unavailable and errored samples are counted separately.
    """
    available = [r for r in results if r.get("outcome") == "completed"]

    tp = sum(1 for r in available
             if r.get("expected") == "malicious" and r.get("predicted") == "malicious")
    fp = sum(1 for r in available
             if r.get("expected") == "benign"    and r.get("predicted") == "malicious")
    tn = sum(1 for r in available
             if r.get("expected") == "benign"    and r.get("predicted") == "benign")
    fn = sum(1 for r in available
             if r.get("expected") == "malicious" and r.get("predicted") == "benign")

    return {
        "total":          len(results),
        "available":      len(available),
        "unavailable":    sum(1 for r in results if r.get("outcome") == "unavailable"),
        "errors":         sum(1 for r in results if r.get("outcome") == "error"),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "detection_rate": tp / (tp + fn) if (tp + fn) > 0 else None,
        "fp_rate":        fp / (fp + tn) if (fp + tn) > 0 else None,
        "false_positives": [
            r["name"] for r in available
            if r.get("expected") == "benign" and r.get("predicted") == "malicious"
        ],
        "false_negatives": [
            r["name"] for r in available
            if r.get("expected") == "malicious" and r.get("predicted") == "benign"
        ],
    }


# ── persistence helpers ───────────────────────────────────────────────────────

def _load_results(path: Path) -> dict[str, dict]:
    """Return existing results keyed by 'ecosystem:name:version'."""
    if not path.exists():
        return {}
    return {r["key"]: r for r in json.loads(path.read_text())}


def _save_results(path: Path, results: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(list(results.values()), indent=2))


# ── main runner ───────────────────────────────────────────────────────────────

def run_validation(
    samples_csv: Path,
    results_path: Path = _DEFAULT_RESULTS,
    runs_base_dir: Path | None = None,
) -> dict:
    """Run the validation pipeline against all rows in *samples_csv*.

    Resumable: rows whose key (ecosystem:name:version) is already in
    *results_path* are skipped without re-running.

    Parameters
    ----------
    samples_csv:
        CSV with columns: ecosystem, name, version, expected_label.
    results_path:
        JSONL results file; created (or appended to) as each sample completes.
    runs_base_dir:
        Override for the detonation run directory.  None → auto-generated.

    Returns
    -------
    A report dict produced by :func:`compute_report`.
    """
    results = _load_results(results_path)

    with open(samples_csv, newline="", encoding="utf-8") as fh:
        samples = list(csv.DictReader(fh))

    for sample in samples:
        ecosystem = sample.get("ecosystem", "").strip()
        name      = sample.get("name", "").strip()
        version   = sample.get("version", "").strip() or None
        expected  = sample.get("expected_label", "").strip()

        if not (ecosystem and name and expected):
            print(f"[validate] skipping malformed row: {sample}", flush=True)
            continue

        key = f"{ecosystem}:{name}:{version}"
        if key in results:
            print(f"[validate] {name} already completed — skipping", flush=True)
            continue

        print(
            f"[validate] {ecosystem}:{name}@{version or '?'}  expected={expected}",
            flush=True,
        )

        record: dict = {
            "key":       key,
            "ecosystem": ecosystem,
            "name":      name,
            "version":   version,
            "expected":  expected,
            "predicted": None,
            "outcome":   None,
            "run_dir":   None,
        }

        # ── 1. Availability check ─────────────────────────────────────────────
        # HTTPError (4xx) or ValueError (npm version not found) → removed from registry
        try:
            _artifact_fetch(ecosystem, name, version or "")
        except (requests.HTTPError, ValueError):
            print(f"[validate]   unavailable — skipping", flush=True)
            record["outcome"] = "unavailable"
            results[key] = record
            _save_results(results_path, results)
            continue
        except Exception as exc:
            print(f"[validate]   fetch error: {exc}", flush=True)
            record["outcome"] = "error"
            record["error"]   = str(exc)
            results[key] = record
            _save_results(results_path, results)
            continue

        # ── 2. Detonation ─────────────────────────────────────────────────────
        # capture.run() re-fetches internally (artifact is already local)
        try:
            summary = _detonate(
                ecosystem, name, version or "",
                run_dir=runs_base_dir,
                skip_import=False,
            )
            record["predicted"] = predict(summary)
            record["outcome"]   = "completed"
            record["run_dir"]   = summary.get("run_dir")
        except Exception as exc:
            print(f"[validate]   detonation error: {exc}", flush=True)
            record["outcome"] = "error"
            record["error"]   = str(exc)

        results[key] = record
        _save_results(results_path, results)
        print(
            f"[validate]   outcome={record['outcome']}  "
            f"predicted={record.get('predicted')}",
            flush=True,
        )

    report = compute_report(list(results.values()))
    return report
