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

    detonate = subparsers.add_parser(
        "detonate",
        help="Fetch and detonate a package in an isolated sandbox.",
    )
    detonate.add_argument("ecosystem", help=f"Package ecosystem ({', '.join(sorted(SUPPORTED_ECOSYSTEMS))})")
    detonate.add_argument("name", help="Package name")
    detonate.add_argument("version", help="Package version")

    return parser


def cmd_detonate(args: argparse.Namespace) -> int:
    if args.ecosystem not in SUPPORTED_ECOSYSTEMS:
        supported = ", ".join(sorted(SUPPORTED_ECOSYSTEMS))
        print(
            f"error: unsupported ecosystem '{args.ecosystem}'. "
            f"Supported ecosystems: {supported}",
            file=sys.stderr,
        )
        return 1

    job = {
        "command": "detonate",
        "ecosystem": args.ecosystem,
        "name": args.name,
        "version": args.version,
    }
    print(json.dumps(job, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 1

    if args.command == "detonate":
        return cmd_detonate(args)

    print(f"error: unknown command '{args.command}'", file=sys.stderr)
    return 1


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry_point()
