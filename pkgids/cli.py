"""Command-line interface for pkgids."""

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
        help="Fetch and detonate a package in an isolated sandbox.",
    )
    detonate.add_argument(
        "ecosystem",
        help=f"Package ecosystem ({', '.join(sorted(SUPPORTED_ECOSYSTEMS))})",
    )
    detonate.add_argument("name", help="Package name")
    detonate.add_argument("version", help="Package version")

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

    return parser


def _validate_ecosystem(ecosystem: str) -> int | None:
    """Print an error and return exit code if ecosystem is unsupported."""
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        supported = ", ".join(sorted(SUPPORTED_ECOSYSTEMS))
        print(
            f"error: unsupported ecosystem '{ecosystem}'. "
            f"Supported ecosystems: {supported}",
            file=sys.stderr,
        )
        return 1
    return None


def cmd_detonate(args: argparse.Namespace) -> int:
    code = _validate_ecosystem(args.ecosystem)
    if code is not None:
        return code
    job = {
        "command": "detonate",
        "ecosystem": args.ecosystem,
        "name": args.name,
        "version": args.version,
    }
    print(json.dumps(job, indent=2))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    code = _validate_ecosystem(args.ecosystem)
    if code is not None:
        return code

    from .fetch import fetch  # local import keeps startup fast

    try:
        artifact = fetch(args.ecosystem, args.name, args.version)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    metadata_path = artifact.parent / "metadata.json"
    metadata: dict = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())

    summary = {
        "artifact": str(artifact),
        "upload_time": metadata.get("upload_time"),
        "file_count": metadata.get("file_count"),
        "install_hooks": metadata.get("install_hooks"),
    }
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 1

    if args.command == "detonate":
        return cmd_detonate(args)
    if args.command == "fetch":
        return cmd_fetch(args)

    print(f"error: unknown command '{args.command}'", file=sys.stderr)
    return 1


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
