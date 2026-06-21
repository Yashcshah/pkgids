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
        report = run_validation(samples_csv, results_path, runs_dir)
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

    print(f"error: unknown command '{args.command}'", file=sys.stderr)
    return 1


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
