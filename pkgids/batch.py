"""Batch detonation runner: scan a list of packages sequentially.

Public API
----------
run_batch(packages, *, output_dir, ...)  -> dict
    Run detonation + report for each package; write batch_results.json and
    batch_report.html to output_dir.  Returns the full batch summary dict.

exit_code_for_results(results)           -> int
    Pure function: derive CLI exit code from a results list.
    2 — any malicious/likely_malicious, 1 — any suspicious/known_vulnerable, 0 otherwise.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

# ── constants ─────────────────────────────────────────────────────────────────

_VERDICT_FIELDS: tuple[str, ...] = (
    "malicious",
    "likely_malicious",
    "suspicious",
    "known_vulnerable",
    "low_risk",
    "no_malicious_behavior_observed",
)

_MALICIOUS_VERDICTS = frozenset({"malicious", "likely_malicious"})
_ELEVATED_VERDICTS  = frozenset({"suspicious", "known_vulnerable"})

_VERDICT_COLORS: dict[str, str] = {
    "malicious":                      "#ff4d4d",
    "likely_malicious":               "#ff8c00",
    "suspicious":                     "#ffd700",
    "known_vulnerable":               "#ff8c00",
    "low_risk":                       "#90ee90",
    "no_malicious_behavior_observed": "#4caf50",
}

# Exact key set every result record carries.  Checked by tests via RESULT_KEYS.
RESULT_KEYS: frozenset[str] = frozenset({
    "key",
    "ecosystem",
    "name",
    "version",
    "outcome",
    "behavioral_verdict",
    "advisory_status",
    "final_verdict",
    "score",
    "confidence",
    "run_dir",
    "bundle_dir",
    "error",
})


# ── internal helpers ──────────────────────────────────────────────────────────

def _utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_batch_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _empty_result(pkg: dict) -> dict:
    """Return a result record with all keys present and set to None / derived."""
    return {
        "key":                f"{pkg['ecosystem']}:{pkg['name']}:{pkg['version']}",
        "ecosystem":          pkg["ecosystem"],
        "name":               pkg["name"],
        "version":            pkg["version"],
        "outcome":            None,
        "behavioral_verdict": None,
        "advisory_status":    None,
        "final_verdict":      None,
        "score":              None,
        "confidence":         None,
        "run_dir":            None,
        "bundle_dir":         None,
        "error":              None,
    }


def _load_existing(results_path: Path) -> dict[str, dict]:
    """Return completed results from a prior run keyed by package key."""
    if not results_path.exists():
        return {}
    try:
        data = json.loads(results_path.read_text(encoding="utf-8"))
        return {r["key"]: r for r in data.get("results", [])}
    except (json.JSONDecodeError, KeyError, TypeError):
        return {}


def _compute_summary(
    results: list[dict],
    *,
    parsed_targets: int,
    parse_skipped: int,
    resume_skipped: int,
) -> dict:
    completed = [r for r in results if r.get("outcome") == "completed"]
    errors    = [r for r in results if r.get("outcome") == "error"]

    verdict_counts: dict[str, int] = {v: 0 for v in _VERDICT_FIELDS}
    for r in completed:
        fv = r.get("final_verdict") or ""
        if fv in verdict_counts:
            verdict_counts[fv] += 1

    return {
        "parsed_targets": parsed_targets,
        "parse_skipped":  parse_skipped,
        "scheduled":      parsed_targets - resume_skipped,
        "resume_skipped": resume_skipped,
        "completed":      len(completed),
        "errors":         len(errors),
        **verdict_counts,
    }


def _write_batch_json(
    path: Path,
    *,
    batch_id: str,
    input_file: str,
    input_format: str,
    started_at: str,
    completed_at: str | None,
    parse_warnings: Sequence[str],
    summary: dict,
    results: list[dict],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "batch_id":      batch_id,
        "input_file":    input_file,
        "input_format":  input_format,
        "started_at":    started_at,
        "completed_at":  completed_at,
        "parse_warnings": list(parse_warnings),
        "summary":       summary,
        "results":       results,
    }
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ── HTML report ───────────────────────────────────────────────────────────────

def _verdict_color(verdict: str | None) -> str:
    return _VERDICT_COLORS.get(verdict or "", "#aaaaaa")


def _build_batch_html(
    results: list[dict],
    *,
    batch_id: str,
    input_file: str,
    summary: dict,
    completed_at: str | None,
) -> str:
    # Errors at bottom; within non-errors, highest score first
    rows_sorted = sorted(
        results,
        key=lambda r: (
            1 if r.get("outcome") == "error" else 0,
            -(r.get("score") or -1),
        ),
    )

    rows_html = ""
    for i, r in enumerate(rows_sorted, 1):
        fv        = r.get("final_verdict") or "—"
        bv        = r.get("behavioral_verdict") or "—"
        adv       = r.get("advisory_status") or "—"
        score     = r.get("score")
        conf      = r.get("confidence")
        score_str = str(score) if score is not None else "—"
        conf_str  = f"{conf:.2f}" if conf is not None else "—"
        color     = _verdict_color(r.get("final_verdict"))

        bd = r.get("bundle_dir")
        if bd:
            report_link = f'<a href="../{Path(bd).name}/report.html">open</a>'
        else:
            report_link = '<span style="color:#666">—</span>'

        dim = ' style="opacity:0.65"' if r.get("outcome") == "error" else ""
        rows_html += (
            f"\n        <tr{dim}>"
            f"<td>{i}</td>"
            f"<td>{r.get('ecosystem', '')}</td>"
            f"<td>{r.get('name', '')}</td>"
            f"<td>{r.get('version', '')}</td>"
            f"<td>{bv}</td>"
            f"<td>{adv}</td>"
            f'<td style="color:{color};font-weight:600">{fv}</td>'
            f'<td style="text-align:right">{score_str}</td>'
            f'<td style="text-align:right">{conf_str}</td>'
            f"<td>{report_link}</td>"
            f"</tr>"
        )

    ts     = completed_at or "in progress"
    total  = summary.get("completed", 0) + summary.get("errors", 0)
    mal    = summary.get("malicious", 0) + summary.get("likely_malicious", 0)
    sus    = summary.get("suspicious", 0) + summary.get("known_vulnerable", 0)
    nerr   = summary.get("errors", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pkgids batch scan — {batch_id}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&display=swap">
<style>
:root{{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;
      --text:#e2e8f0;--muted:#64748b;--accent:#6366f1}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);
      font-family:'IBM Plex Mono',monospace;font-size:13px;padding:2rem}}
h1{{font-size:1.2rem;margin-bottom:0.25rem}}
.meta{{color:var(--muted);margin-bottom:1.5rem;font-size:11px}}
.chips{{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.chip{{background:var(--surface);border:1px solid var(--border);
       border-radius:6px;padding:0.5rem 1rem}}
.chip-label{{color:var(--muted);font-size:10px;text-transform:uppercase;
             letter-spacing:0.05em}}
.chip-val{{font-size:1.1rem;font-weight:700}}
table{{border-collapse:collapse;width:100%}}
th{{background:var(--surface);border:1px solid var(--border);
    padding:0.5rem 0.75rem;text-align:left;font-weight:600;
    color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:0.05em;position:sticky;top:0}}
td{{border:1px solid var(--border);padding:0.4rem 0.75rem;
    background:var(--surface)}}
tr:hover td{{background:#1f2333}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
footer{{margin-top:2rem;color:var(--muted);font-size:11px}}
</style>
</head>
<body>
<h1>pkgids batch scan</h1>
<p class="meta">batch&nbsp;ID:&nbsp;{batch_id}&nbsp;&middot;&nbsp;\
input:&nbsp;{input_file}&nbsp;&middot;&nbsp;{ts}&nbsp;UTC</p>
<div class="chips">
  <div class="chip">
    <div class="chip-label">scanned</div>
    <div class="chip-val">{total}</div>
  </div>
  <div class="chip">
    <div class="chip-label">malicious&nbsp;/&nbsp;likely</div>
    <div class="chip-val" style="color:#ff4d4d">{mal}</div>
  </div>
  <div class="chip">
    <div class="chip-label">suspicious&nbsp;/&nbsp;vuln</div>
    <div class="chip-val" style="color:#ffd700">{sus}</div>
  </div>
  <div class="chip">
    <div class="chip-label">errors</div>
    <div class="chip-val">{nerr}</div>
  </div>
</div>
<table>
<thead><tr>
  <th>#</th><th>Ecosystem</th><th>Package</th><th>Version</th>
  <th>Behavioral&nbsp;Verdict</th><th>Advisory&nbsp;Status</th>
  <th>Final&nbsp;Verdict</th><th>Score</th><th>Confidence</th><th>Report</th>
</tr></thead>
<tbody>{rows_html}
</tbody>
</table>
<footer>generated&nbsp;{ts}&nbsp;UTC&nbsp;&middot;&nbsp;pkgids</footer>
</body>
</html>"""


# ── public API ────────────────────────────────────────────────────────────────

def exit_code_for_results(results: list[dict]) -> int:
    """Derive a CLI exit code from a batch results list.

    Returns
    -------
    2  any completed package has final_verdict in {malicious, likely_malicious}
    1  any completed package has final_verdict in {suspicious, known_vulnerable}
    0  all clean, or no completed packages
    """
    completed_verdicts = {
        r.get("final_verdict")
        for r in results
        if r.get("outcome") == "completed"
    }
    if completed_verdicts & _MALICIOUS_VERDICTS:
        return 2
    if completed_verdicts & _ELEVATED_VERDICTS:
        return 1
    return 0


def run_batch(
    packages: list[dict],
    *,
    output_dir: Path,
    export_root: Path | None = None,
    resume: bool = True,
    with_deps: bool = False,
    skip_import: bool = False,
    no_export: bool = False,
    parse_warnings: Sequence[str] = (),
    parse_skipped: int = 0,
    input_file: str = "",
    input_format: str = "",
) -> dict:
    """Run the detonation + report pipeline for each package sequentially.

    Parameters
    ----------
    packages:
        Normalized package dicts from ``sbom.parse()``.
    output_dir:
        Directory where ``batch_results.json`` and ``batch_report.html`` go.
    export_root:
        Root for per-package export bundles; ``None`` → default (``exports/``).
    resume:
        Skip packages whose key is already present in a prior run's
        ``batch_results.json``.
    with_deps / skip_import:
        Forwarded to each ``capture.run()`` call.
    no_export:
        When ``True``, skip the per-package ``export_bundle()`` call.
    parse_warnings:
        Warnings from ``sbom.parse()``, stored verbatim in ``batch_results.json``.
    parse_skipped:
        Entry count dropped during parsing, stored in ``summary.parse_skipped``.
    input_file / input_format:
        Metadata stored in ``batch_results.json``.

    Returns
    -------
    dict
        Full batch summary matching the ``batch_results.json`` top-level schema.
    """
    from .capture import run as _detonate
    from .report import report as _report, export_bundle as _export_bundle

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "batch_results.json"

    batch_id   = _make_batch_id()
    started_at = _utcnow_str()
    total      = len(packages)

    existing: dict[str, dict] = _load_existing(results_path) if resume else {}

    results:        list[dict] = []
    resume_skipped: int        = 0

    for idx, pkg in enumerate(packages, 1):
        key = f"{pkg['ecosystem']}:{pkg['name']}:{pkg['version']}"

        if resume and key in existing:
            print(f"[scan] {idx}/{total}  {key} — already completed, skipping",
                  flush=True)
            results.append(existing[key])
            resume_skipped += 1
            continue

        print(f"[scan] {idx}/{total}  {key}", flush=True)
        rec = _empty_result(pkg)

        try:
            run_summary = _detonate(
                pkg["ecosystem"],
                pkg["name"],
                pkg["version"],
                skip_import=True if skip_import else None,
                with_deps=with_deps,
            )
            run_dir      = Path(run_summary.get("run_dir", ""))
            rec["run_dir"] = str(run_dir)

            rep = _report(run_dir)
            rec["behavioral_verdict"] = rep.get("behavioral_verdict")
            rec["advisory_status"]    = rep.get("advisory_status")
            rec["final_verdict"]      = rep.get("verdict")
            rec["score"]              = rep.get("score")
            rec["confidence"]         = rep.get("confidence")
            rec["outcome"]            = "completed"

            if not no_export:
                try:
                    bundle          = _export_bundle(
                        run_dir, rep, export_root=export_root
                    )
                    rec["bundle_dir"] = str(bundle)
                except Exception as exc_exp:
                    print(f"[scan]   warning: export bundle failed: {exc_exp}",
                          flush=True)

            print(
                f"[scan]   verdict={rec['final_verdict']}  "
                f"score={rec['score']}",
                flush=True,
            )

        except Exception as exc:
            print(f"[scan]   ERROR: {exc}", flush=True)
            rec["outcome"] = "error"
            rec["error"]   = str(exc)

        results.append(rec)

        # Write after every package so the batch is resumable mid-run
        summary = _compute_summary(
            results,
            parsed_targets=total,
            parse_skipped=parse_skipped,
            resume_skipped=resume_skipped,
        )
        _write_batch_json(
            results_path,
            batch_id=batch_id,
            input_file=input_file,
            input_format=input_format,
            started_at=started_at,
            completed_at=None,
            parse_warnings=parse_warnings,
            summary=summary,
            results=results,
        )

    completed_at = _utcnow_str()
    summary = _compute_summary(
        results,
        parsed_targets=total,
        parse_skipped=parse_skipped,
        resume_skipped=resume_skipped,
    )

    _write_batch_json(
        results_path,
        batch_id=batch_id,
        input_file=input_file,
        input_format=input_format,
        started_at=started_at,
        completed_at=completed_at,
        parse_warnings=list(parse_warnings),
        summary=summary,
        results=results,
    )

    (output_dir / "batch_report.html").write_text(
        _build_batch_html(
            results,
            batch_id=batch_id,
            input_file=input_file,
            summary=summary,
            completed_at=completed_at,
        ),
        encoding="utf-8",
    )

    return {
        "batch_id":      batch_id,
        "input_file":    input_file,
        "input_format":  input_format,
        "started_at":    started_at,
        "completed_at":  completed_at,
        "parse_warnings": list(parse_warnings),
        "summary":       summary,
        "results":       results,
    }
