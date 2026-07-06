"""Parse package manifests into normalized package lists for batch scanning.

Supported formats (v1):
    requirements.txt  — pip requirements; == pins only
    CycloneDX JSON    — CycloneDX 1.4/1.5 SBOM; pypi and npm PURLs only
    CSV               — columns: ecosystem, name, version
"""

from __future__ import annotations

import csv as _csv
import json
import re
from pathlib import Path

_SUPPORTED_ECOSYSTEMS: frozenset[str] = frozenset({"pypi", "npm"})

# Matches a versioned requirements.txt line including optional extras.
_REQ_LINE_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)  # package name
    (?:\[(?P<extras>[^\]]*)\])?                              # optional [extras]
    \s*
    (?P<op>==|>=|<=|!=|~=|>|<)                              # version operator
    \s*
    (?P<version>[^\s;,]+)                                    # version string
    """,
    re.VERBOSE,
)

# Matches a name-only line with no version operator at all.
_REQ_NAME_ONLY_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    (?:\[[^\]]*\])?
    \s*$
    """,
    re.VERBOSE,
)


# ── internal warning helpers ──────────────────────────────────────────────────

def _warn(source: str, detail: str, line: int | None = None) -> dict:
    return {"source": source, "line": line, "detail": detail}


def _fmt(w: dict) -> str:
    prefix = f"line {w['line']}: " if w["line"] is not None else ""
    return prefix + w["detail"]


# ── requirements.txt ─────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> tuple[list[dict], list[dict]]:
    packages: list[dict] = []
    raw_warnings: list[dict] = []
    seen: set[str] = set()

    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#")[0].strip()   # strip inline comments
        line = line.split(";")[0].strip()  # strip env markers
        if not line:
            continue

        # pip directives: -r, -c, -i, -f, --index-url, etc.
        if line.startswith("-"):
            raw_warnings.append(_warn(
                "requirements_txt",
                f"skipping directive '{line[:60]}'",
                lineno,
            ))
            continue

        # VCS URLs
        for pfx in ("git+", "hg+", "svn+", "bzr+"):
            if line.startswith(pfx):
                raw_warnings.append(_warn(
                    "requirements_txt",
                    f"skipping VCS URL '{line[:60]}'",
                    lineno,
                ))
                break
        else:
            # Local paths
            for pfx in ("./", "../", "/", "file://"):
                if line.startswith(pfx):
                    raw_warnings.append(_warn(
                        "requirements_txt",
                        f"skipping local path '{line[:60]}'",
                        lineno,
                    ))
                    break
            else:
                # Versioned line?
                m = _REQ_LINE_RE.match(line)
                if m:
                    name    = m.group("name").lower()  # PEP 503 normalisation
                    op      = m.group("op")
                    version = m.group("version")
                    if op != "==":
                        raw_warnings.append(_warn(
                            "requirements_txt",
                            f"skipping '{name}' — only == pins supported in v1, "
                            f"got '{op}{version}'",
                            lineno,
                        ))
                    else:
                        key = f"pypi:{name}:{version}"
                        if key in seen:
                            raw_warnings.append(_warn(
                                "requirements_txt",
                                f"skipping duplicate 'pypi:{name}:{version}' "
                                f"(first occurrence kept)",
                                lineno,
                            ))
                        else:
                            seen.add(key)
                            packages.append({
                                "ecosystem": "pypi",
                                "name":      name,
                                "version":   version,
                            })
                    continue

                # Name-only line (no operator)?
                m2 = _REQ_NAME_ONLY_RE.match(line)
                if m2:
                    name = m2.group("name").lower()
                    raw_warnings.append(_warn(
                        "requirements_txt",
                        f"skipping '{name}' — no version pin (== required)",
                        lineno,
                    ))
                    continue

                raw_warnings.append(_warn(
                    "requirements_txt",
                    f"skipping unrecognized line '{line[:60]}'",
                    lineno,
                ))

    return packages, raw_warnings


# ── CycloneDX JSON ───────────────────────────────────────────────────────────

def _parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Parse a PURL into (ecosystem, name, version|None) or None on failure."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?")[0].split("#")[0]
    if "/" not in body:
        return None
    purl_type, rest = body.split("/", 1)
    if "@" in rest:
        name_path, version = rest.rsplit("@", 1)
        version = version or None
    else:
        name_path, version = rest, None

    # URL-decode common sequences (%40 → @, %2F → /)
    name = name_path.replace("%40", "@").replace("%2F", "/").replace("%2f", "/")
    return purl_type.lower(), name, version


def _parse_cyclonedx_json(path: Path) -> tuple[list[dict], list[dict]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Not a valid CycloneDX JSON file: {exc}") from exc

    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(
            f"Not a valid CycloneDX JSON file: "
            f"bomFormat={data.get('bomFormat')!r}"
        )

    packages: list[dict] = []
    raw_warnings: list[dict] = []
    seen: set[str] = set()

    for idx, comp in enumerate(data.get("components", [])):
        name    = (comp.get("name")    or "").strip()
        version = (comp.get("version") or "").strip()
        purl    = (comp.get("purl")    or "").strip()

        if not name:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"component at index {idx}: skipping — no name field",
            ))
            continue

        if not purl:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"component '{name}': skipping — cannot determine ecosystem "
                f"(no purl field)",
            ))
            continue

        parsed = _parse_purl(purl)
        if parsed is None:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"component '{name}': skipping — malformed purl '{purl}'",
            ))
            continue

        eco, purl_name, purl_version = parsed
        if eco not in _SUPPORTED_ECOSYSTEMS:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"component '{name}': skipping — unsupported ecosystem '{eco}' "
                f"(supported: {', '.join(sorted(_SUPPORTED_ECOSYSTEMS))})",
            ))
            continue

        # purl version takes priority; fall back to component version field
        resolved_version = purl_version or version
        if not resolved_version:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"component '{name}': skipping — no version present "
                f"(latest not fetched in v1)",
            ))
            continue

        resolved_name = purl_name or name
        key = f"{eco}:{resolved_name}:{resolved_version}"
        if key in seen:
            raw_warnings.append(_warn(
                "cyclonedx",
                f"skipping duplicate '{key}' (first occurrence kept)",
            ))
            continue
        seen.add(key)
        packages.append({
            "ecosystem": eco,
            "name":      resolved_name,
            "version":   resolved_version,
        })

    return packages, raw_warnings


# ── plain CSV ─────────────────────────────────────────────────────────────────

def _parse_plain_csv(path: Path) -> tuple[list[dict], list[dict]]:
    packages: list[dict] = []
    raw_warnings: list[dict] = []
    seen: set[str] = set()

    with open(path, newline="", encoding="utf-8") as fh:
        reader = _csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError("CSV file appears to be empty or has no header row")

        header_lower = {f.strip().lower() for f in reader.fieldnames}
        required     = {"ecosystem", "name", "version"}
        missing      = required - header_lower
        if missing:
            raise ValueError(
                f"CSV missing required column(s): {', '.join(sorted(missing))}"
            )

        for rownum, row in enumerate(reader, 2):
            # Normalise field access: lowercase keys, strip all values
            nr        = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
            ecosystem = nr.get("ecosystem", "").lower()  # always lowercase
            name      = nr.get("name", "")
            version   = nr.get("version", "")

            if not name:
                raw_warnings.append(_warn(
                    "csv", f"row {rownum}: skipping — name is empty"
                ))
                continue
            if not version:
                raw_warnings.append(_warn(
                    "csv", f"row {rownum}: skipping '{name}' — version is empty"
                ))
                continue
            if ecosystem not in _SUPPORTED_ECOSYSTEMS:
                raw_warnings.append(_warn(
                    "csv",
                    f"row {rownum}: skipping '{name}' — unsupported ecosystem "
                    f"'{ecosystem}' "
                    f"(supported: {', '.join(sorted(_SUPPORTED_ECOSYSTEMS))})",
                ))
                continue

            key = f"{ecosystem}:{name}:{version}"
            if key in seen:
                raw_warnings.append(_warn(
                    "csv",
                    f"row {rownum}: skipping duplicate '{key}' "
                    f"(first occurrence kept)",
                ))
                continue
            seen.add(key)
            packages.append({
                "ecosystem": ecosystem,
                "name":      name,
                "version":   version,
            })

    return packages, raw_warnings


# ── format detection ──────────────────────────────────────────────────────────

def detect_format(path: Path) -> str:
    """Detect the input format from filename and content.

    Returns one of: ``'requirements_txt'``, ``'cyclonedx_json'``, ``'csv'``.
    Raises ``ValueError`` for unrecognized formats.
    """
    path      = Path(path)
    name_low  = path.name.lower()

    # requirements.txt: filename heuristic takes priority over extension
    if name_low == "requirements.txt" or (
        name_low.endswith(".txt") and "require" in name_low
    ):
        return "requirements_txt"

    # JSON: verify it contains a CycloneDX bomFormat marker
    if name_low.endswith(".json"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if '"bomFormat"' in text and "CycloneDX" in text:
                return "cyclonedx_json"
        except OSError:
            pass
        raise ValueError(
            f"JSON file '{path.name}' does not appear to be a CycloneDX SBOM "
            f"(missing bomFormat/CycloneDX marker)"
        )

    if name_low.endswith(".csv"):
        return "csv"

    raise ValueError(
        f"Unrecognized input format for '{path.name}'. "
        "Supported: requirements.txt (.txt), CycloneDX JSON (.json), CSV (.csv)"
    )


# ── public API ────────────────────────────────────────────────────────────────

def parse(path: Path) -> tuple[list[dict], list[str]]:
    """Parse an input file into a normalized package list.

    Parameters
    ----------
    path:
        Path to a requirements.txt, CycloneDX JSON, or plain CSV file.

    Returns
    -------
    packages:
        List of ``{"ecosystem": str, "name": str, "version": str}`` dicts.
        Every entry has all three keys populated with non-empty strings.
        Duplicates (same ecosystem:name:version) are deduplicated; the first
        occurrence is kept and subsequent ones produce a warning.
    warnings:
        Human-readable strings describing skipped or unsupported entries.
        Each warning corresponds to exactly one dropped entry.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    fmt = detect_format(path)

    if fmt == "requirements_txt":
        pkgs, raw = _parse_requirements_txt(path)
    elif fmt == "cyclonedx_json":
        pkgs, raw = _parse_cyclonedx_json(path)
    else:  # csv
        pkgs, raw = _parse_plain_csv(path)

    return pkgs, [_fmt(w) for w in raw]
