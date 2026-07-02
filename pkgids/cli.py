"""Command-line interface for pkgids."""

from __future__ import annotations

import argparse
import json
import sys

SUPPORTED_ECOSYSTEMS = {"pypi", "npm"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgids",
        description="Safely analyze software packages for malicious behavior.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── detonate ──────────────────────────────────────────────────────────────
    detonate = subparsers.add_parser(
        "detonate",
        help="Fetch, install, and observe a package in an isolated sandbox.",
    )
    detonate.add_argument(
        "ecosystem",
        help=f"Package ecosystem ({', '.join(sorted(SUPPORTED_ECOSYSTEMS))})",
    )
    detonate.add_argument("name", help="Package name")
    detonate.add_argument("version", help="Package version")
    detonate.add_argument(
        "--skip-import",
        action="store_true",
        default=False,
        help="Skip the import phase (overrides config detonation.skip_import)",
    )
    detonate.add_argument(
        "--run-dir",
        metavar="DIR",
        default=None,
        help="Write run artifacts to DIR instead of the auto-generated runs/<id>/ path",
    )

    # ── fetch ─────────────────────────────────────────────────────────────────
    fetch_cmd = subparsers.add_parser(
        "fetch",
        help="Download a package artifact without installing or executing it.",
    )
    fetch_cmd.add_argument(
        "ecosystem",
        help=f"Package ecosystem ({', '.join(sorted(SUPPORTED_ECOSYSTEMS))})",
    )
    fetch_cmd.add_argument("name", help="Package name")
    fetch_cmd.add_argument("version", help="Package version")

    # ── dataset ───────────────────────────────────────────────────────────────
    dataset_cmd = subparsers.add_parser(
        "dataset",
        help="Manage training/evaluation datasets.",
    )
    dataset_sub = dataset_cmd.add_subparsers(
        dest="dataset_command", metavar="DATASET_COMMAND"
    )

    ds_fetch = dataset_sub.add_parser(
        "fetch",
        help="Fetch malicious-package records from the OpenSSF malicious-packages repo.",
    )
    ds_fetch.add_argument(
        "ecosystem",
        choices=sorted(SUPPORTED_ECOSYSTEMS),
        help="Package ecosystem",
    )
    ds_fetch.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of records to fetch (default: 50)",
    )
    ds_fetch.add_argument(
        "--refresh",
        action="store_true",
        default=False,
        help="Ignore the local cache and re-fetch from GitHub",
    )
    ds_fetch.add_argument(
        "--token",
        default=None,
        metavar="TOKEN",
        help="GitHub personal access token (also read from GITHUB_TOKEN env var)",
    )

    # ── baseline ──────────────────────────────────────────────────────────────
    baseline_cmd = subparsers.add_parser(
        "baseline",
        help="Manage behavioral baselines stored in Supabase.",
    )
    baseline_sub = baseline_cmd.add_subparsers(
        dest="baseline_command", metavar="BASELINE_COMMAND"
    )

    bl_push = baseline_sub.add_parser(
        "push",
        help="Push a detonation result to the Supabase baseline store.",
    )
    bl_push.add_argument("ecosystem", choices=sorted(SUPPORTED_ECOSYSTEMS))
    bl_push.add_argument("name",    help="Package name")
    bl_push.add_argument("version", help="Package version")
    bl_push.add_argument(
        "--run-dir", metavar="DIR", required=True,
        help="Run directory produced by 'pkgids detonate'",
    )

    bl_list = baseline_sub.add_parser(
        "list",
        help="List all stored versions for a package.",
    )
    bl_list.add_argument("ecosystem", choices=sorted(SUPPORTED_ECOSYSTEMS))
    bl_list.add_argument("name", help="Package name")

    bl_show = baseline_sub.add_parser(
        "show",
        help="Show the stored behavior profile for a specific version.",
    )
    bl_show.add_argument("ecosystem", choices=sorted(SUPPORTED_ECOSYSTEMS))
    bl_show.add_argument("name",    help="Package name")
    bl_show.add_argument("version", help="Package version")

    # ── diff ──────────────────────────────────────────────────────────────────
    diff_cmd = subparsers.add_parser(
        "diff",
        help="Compare behavior profiles between two versions of a package.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Compare two behavior profiles.\n\n"
            "Provide both versions explicitly:\n"
            "  pkgids diff pypi requests 2.28.0 2.29.0\n\n"
            "Or provide only the candidate and auto-resolve the baseline:\n"
            "  pkgids diff pypi requests 2.29.0 --baseline-mode previous_known_good"
        ),
    )
    diff_cmd.add_argument("ecosystem", choices=sorted(SUPPORTED_ECOSYSTEMS))
    diff_cmd.add_argument("name", help="Package name")
    diff_cmd.add_argument(
        "versions", nargs="+", metavar="VERSION",
        help="[from_version] to_version  — one or two version strings",
    )
    diff_cmd.add_argument(
        "--baseline-mode",
        choices=["previous_version", "previous_known_good", "rolling_benign_baseline"],
        default="previous_known_good",
        help=(
            "How to resolve the baseline when from_version is omitted "
            "(default: previous_known_good)"
        ),
    )
    diff_cmd.add_argument(
        "--push", action="store_true", default=False,
        help="Persist the diff result to Supabase after computing it",
    )

    # ── report ────────────────────────────────────────────────────────────────
    report_cmd = subparsers.add_parser(
        "report",
        help="Generate a structured security report from a detonation run directory.",
    )
    report_cmd.add_argument(
        "run_dir", metavar="RUN_DIR",
        help="Run directory produced by 'pkgids detonate'",
    )
    report_cmd.add_argument(
        "--output-json", metavar="FILE", default=None,
        help="Write JSON report to FILE",
    )
    report_cmd.add_argument(
        "--output-html", metavar="FILE", default=None,
        help="Write HTML report to FILE",
    )
    report_cmd.add_argument(
        "--baseline-mode",
        choices=["previous_version", "previous_known_good", "rolling_benign_baseline"],
        default="previous_known_good",
        help="Baseline mode used when auto-computing a diff (default: previous_known_good)",
    )
    report_cmd.add_argument(
        "--no-diff", action="store_true", default=False,
        help="Skip the baseline diff step even if Supabase is configured",
    )

    # ── validate ──────────────────────────────────────────────────────────────
    validate_cmd = subparsers.add_parser(
        "validate",
        help="Run the validation harness against a labeled samples CSV.",
    )
    validate_cmd.add_argument(
        "--samples",
        required=True,
        metavar="CSV",
        help="Path to samples CSV (columns: ecosystem,name,version,expected_label)",
    )
    validate_cmd.add_argument(
        "--results",
        default=None,
        metavar="JSON",
        help="Path to results file (default: data/validation_results.json)",
    )
    validate_cmd.add_argument(
        "--run-dir",
        default=None,
        metavar="DIR",
        help="Base directory for detonation run artifacts",
    )
    validate_cmd.add_argument(
        "--local-artifacts",
        action="store_true",
        default=False,
        help=(
            "Read artifact_path from the CSV and use the local file directly "
            "instead of fetching from a package registry. "
            "Required for corpus validation (data/corpus_samples.csv)."
        ),
    )

    return parser


def _validate_ecosystem(ecosystem: str) -> int | None:
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        supported = ", ".join(sorted(SUPPORTED_ECOSYSTEMS))
        print(
            f"error: unsupported ecosystem '{ecosystem}'. "
            f"Supported ecosystems: {supported}",
            file=sys.stderr,
        )
        return 1
    return None


# ── command handlers ──────────────────────────────────────────────────────────

def cmd_detonate(args: argparse.Namespace) -> int:
    code = _validate_ecosystem(args.ecosystem)
    if code is not None:
        return code

    from .capture import run as _run

    skip_import = True if args.skip_import else None
    try:
        summary = _run(
            args.ecosystem, args.name, args.version,
            run_dir=args.run_dir,
            skip_import=skip_import,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    code = _validate_ecosystem(args.ecosystem)
    if code is not None:
        return code

    from .fetch import fetch

    try:
        artifact = fetch(args.ecosystem, args.name, args.version)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    metadata_path = artifact.parent / "metadata.json"
    metadata: dict = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())

    print(json.dumps({
        "artifact":      str(artifact),
        "upload_time":   metadata.get("upload_time"),
        "file_count":    metadata.get("file_count"),
        "install_hooks": metadata.get("install_hooks"),
    }, indent=2))
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    if not getattr(args, "baseline_command", None):
        print("error: 'pkgids baseline' requires a subcommand: push | list | show",
              file=sys.stderr)
        return 1
    if args.baseline_command == "push":
        return cmd_baseline_push(args)
    if args.baseline_command == "list":
        return cmd_baseline_list(args)
    if args.baseline_command == "show":
        return cmd_baseline_show(args)
    print(f"error: unknown baseline command '{args.baseline_command}'", file=sys.stderr)
    return 1


def cmd_baseline_push(args: argparse.Namespace) -> int:
    from pathlib import Path
    from .baseline import push_profile
    from .validate import predict

    run_dir  = Path(args.run_dir)
    run_json = run_dir / "run.json"
    if not run_json.exists():
        print(f"error: run.json not found in {run_dir}", file=sys.stderr)
        return 1

    try:
        summary    = json.loads(run_json.read_text())
        prediction = predict(summary)
        profile_id = push_profile(summary, run_dir=run_dir, prediction=prediction)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"profile_id": profile_id, "prediction": prediction}, indent=2))
    return 0


def cmd_baseline_list(args: argparse.Namespace) -> int:
    from .baseline import list_versions

    try:
        versions = list_versions(args.ecosystem, args.name)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not versions:
        print(f"No baselines found for {args.ecosystem}:{args.name}")
        return 0

    print(f"{'version':<20}  {'run_ts':<26}  {'prediction':<12}  suspicious  install    import")
    print("-" * 100)
    for v in versions:
        print(
            f"{str(v.get('version') or ''):<20}  "
            f"{str(v.get('run_ts') or ''):<26}  "
            f"{str(v.get('prediction') or 'unknown'):<12}  "
            f"{'yes' if v.get('any_suspicious') else 'no':<10}  "
            f"{str(v.get('install_status') or ''):<10} "
            f"{str(v.get('import_status') or '')}"
        )
    return 0


def cmd_baseline_show(args: argparse.Namespace) -> int:
    from .baseline import get_profile

    try:
        profile = get_profile(args.ecosystem, args.name, args.version)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if profile is None:
        print(f"No baseline for {args.ecosystem}:{args.name}@{args.version}")
        return 1

    print(json.dumps(profile, indent=2, default=str))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from .baseline import (
        get_profile, get_previous_version, get_known_good, get_rolling_baseline,
    )
    from .diff import diff_profiles, push_diff

    # ── resolve from_version / to_version ────────────────────────────────────
    versions = args.versions
    if len(versions) == 2:
        from_version, to_version = versions
    elif len(versions) == 1:
        to_version   = versions[0]
        from_version = None
    else:
        print("error: 'diff' accepts 1 or 2 version arguments", file=sys.stderr)
        return 1

    eco, name = args.ecosystem, args.name

    # ── fetch candidate profile ───────────────────────────────────────────────
    try:
        new = get_profile(eco, name, to_version)
    except Exception as exc:
        print(f"error fetching candidate profile: {exc}", file=sys.stderr)
        return 1
    if new is None:
        print(f"error: no baseline for {eco}:{name}@{to_version}", file=sys.stderr)
        return 1

    # ── fetch or auto-resolve baseline profile ────────────────────────────────
    old: dict | None = None
    if from_version:
        try:
            old = get_profile(eco, name, from_version)
        except Exception as exc:
            print(f"error fetching baseline profile: {exc}", file=sys.stderr)
            return 1
        if old is None:
            print(f"error: no baseline for {eco}:{name}@{from_version}", file=sys.stderr)
            return 1
    else:
        mode = args.baseline_mode
        try:
            if mode == "previous_version":
                old = get_previous_version(eco, name, to_version)
            elif mode == "rolling_benign_baseline":
                old = get_rolling_baseline(eco, name)
            else:  # previous_known_good (default)
                old = get_known_good(eco, name)
        except Exception as exc:
            print(f"error auto-resolving baseline ({mode}): {exc}", file=sys.stderr)
            return 1
        if old is None:
            print(
                f"error: no {mode} baseline found for {eco}:{name}. "
                "Push some profiles with 'pkgids baseline push' first.",
                file=sys.stderr,
            )
            return 1

    # ── compute diff ──────────────────────────────────────────────────────────
    try:
        result = diff_profiles(old, new)
    except Exception as exc:
        print(f"error computing diff: {exc}", file=sys.stderr)
        return 1

    if args.push:
        try:
            diff_id = push_diff(
                result, eco, name,
                from_profile_id=old.get("id"),
                to_profile_id=new.get("id"),
            )
            result["diff_id"] = diff_id
        except Exception as exc:
            print(f"warning: could not push diff to Supabase: {exc}", file=sys.stderr)

    print(json.dumps(result, indent=2))

    # Exit non-zero when suspicious so CI pipelines can gate on it.
    return 2 if result["is_suspicious"] else 0


def cmd_report(args: argparse.Namespace) -> int:
    from pathlib import Path as _Path
    from .report import report as _report

    run_dir = _Path(args.run_dir)
    if not run_dir.exists():
        print(f"error: run directory not found: {run_dir}", file=sys.stderr)
        return 1

    # ── optionally auto-compute a diff ────────────────────────────────────────
    diff: dict | None = None
    if not args.no_diff:
        try:
            run_json = run_dir / "run.json"
            if run_json.exists():
                run_data = json.loads(run_json.read_text())
                eco  = run_data.get("ecosystem")
                name = run_data.get("name")
                ver  = run_data.get("version")
                if eco and name and ver:
                    from .baseline import get_profile, get_previous_version, get_known_good
                    from .diff import diff_profiles
                    candidate = get_profile(eco, name, ver)
                    if candidate is not None:
                        mode = args.baseline_mode
                        if mode == "previous_version":
                            baseline = get_previous_version(eco, name, ver)
                        else:
                            baseline = get_known_good(eco, name)
                        if baseline is not None:
                            diff = diff_profiles(baseline, candidate)
        except Exception as exc:
            print(f"warning: could not compute diff: {exc}", file=sys.stderr)

    # ── build report ──────────────────────────────────────────────────────────
    try:
        result = _report(
            run_dir,
            diff=diff,
            output_json=args.output_json,
            output_html=args.output_html,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Print terse summary
    run     = result.get("run", {})
    verdict = result.get("verdict", "unknown")
    score   = result.get("score", 0.0)
    n_ind   = result.get("summary", {}).get("indicator_count", 0)
    tactics = ", ".join(result.get("tactics", [])) or "none"
    print(f"{'verdict':<12} {verdict}")
    print(f"{'score':<12} {score:.3f}")
    print(f"{'confidence':<12} {result.get('confidence', 'none')}")
    print(f"{'indicators':<12} {n_ind}")
    print(f"{'tactics':<12} {tactics}")
    if args.output_json:
        print(f"{'json':<12} {args.output_json}")
    if args.output_html:
        print(f"{'html':<12} {args.output_html}")

    return 2 if verdict == "malicious" else (1 if verdict == "suspicious" else 0)


def cmd_dataset(args: argparse.Namespace) -> int:
    if not getattr(args, "dataset_command", None):
        # No sub-subcommand given
        print("error: 'pkgids dataset' requires a subcommand: fetch", file=sys.stderr)
        return 1

    if args.dataset_command == "fetch":
        return cmd_dataset_fetch(args)

    print(f"error: unknown dataset command '{args.dataset_command}'", file=sys.stderr)
    return 1


def cmd_dataset_fetch(args: argparse.Namespace) -> int:
    from .dataset import fetch as ds_fetch

    try:
        records = ds_fetch(
            args.ecosystem,
            limit=args.limit,
            refresh=args.refresh,
            token=args.token,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Print a human-readable summary table
    print(f"{'#':<4}  {'ecosystem':<8}  {'name':<35}  {'version':<15}  osv_id")
    print("-" * 90)
    for i, r in enumerate(records, 1):
        name_col    = (r["name"] or "")[:35]
        version_col = (r["version"] or "n/a")[:15]
        print(f"{i:<4}  {r['ecosystem']:<8}  {name_col:<35}  {version_col:<15}  {r['osv_id']}")

    print(f"\n{len(records)} records  (cached to data/malicious_{args.ecosystem}.json)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from pathlib import Path
    from .validate import run_validation, _DEFAULT_RESULTS

    samples_csv  = Path(args.samples)
    results_path = Path(args.results) if args.results else _DEFAULT_RESULTS
    runs_dir     = Path(args.run_dir) if args.run_dir else None

    if not samples_csv.exists():
        print(f"error: samples file not found: {samples_csv}", file=sys.stderr)
        return 1

    try:
        report = run_validation(
            samples_csv, results_path, runs_dir,
            local_artifacts=args.local_artifacts,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Print report
    print()
    print("=" * 60)
    print("  Validation Report")
    print("=" * 60)
    print(f"  Total samples   : {report['total']}")
    print(f"  Available       : {report['available']}")
    print(f"  Unavailable     : {report['unavailable']}")
    print(f"  Errors          : {report['errors']}")
    print()
    print("  Confusion matrix (available samples only):")
    print(f"    TP={report['tp']}  FP={report['fp']}  TN={report['tn']}  FN={report['fn']}")
    dr = report["detection_rate"]
    fpr = report["fp_rate"]
    print(f"  Detection rate  : {dr:.1%}" if dr is not None else "  Detection rate  : n/a")
    print(f"  FP rate         : {fpr:.1%}" if fpr is not None else "  FP rate         : n/a")
    if report["false_positives"]:
        print(f"\n  False positives : {', '.join(report['false_positives'])}")
    if report["false_negatives"]:
        print(f"  False negatives : {', '.join(report['false_negatives'])}")
    print("=" * 60)
    print(f"\n  Results written to: {results_path}")
    return 0


# ── main ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 1

    if args.command == "detonate":  return cmd_detonate(args)
    if args.command == "fetch":     return cmd_fetch(args)
    if args.command == "dataset":   return cmd_dataset(args)
    if args.command == "validate":  return cmd_validate(args)
    if args.command == "baseline":  return cmd_baseline(args)
    if args.command == "diff":      return cmd_diff(args)
    if args.command == "report":    return cmd_report(args)

    print(f"error: unknown command '{args.command}'", file=sys.stderr)
    return 1


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
