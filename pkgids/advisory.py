"""Best-effort advisory enrichment via OSV.dev.

Always returns a normalized summary dict — never raises.
"""

from __future__ import annotations

import json

import requests

# OSV ecosystem identifiers keyed by pkgids ecosystem name.
_OSV_ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "npm":  "npm",
}


def _empty(error: str | None = None) -> dict:
    return {
        "advisory_hit":       False,
        "advisory_source":    None,
        "advisory_count":     0,
        "advisory_ids":       [],
        "advisory_summaries": [],
        "advisory_error":     error,
    }


def query_osv(
    ecosystem: str,
    name: str,
    version: str,
    timeout: int = 10,
) -> dict:
    """Query OSV.dev for known advisories affecting *ecosystem*:*name*@*version*.

    Returns a normalized summary dict with keys:
        advisory_hit       — True if at least one vulnerability was found
        advisory_source    — "osv" on success, None on failure
        advisory_count     — number of vulnerabilities returned
        advisory_ids       — list of OSV/CVE/GHSA identifiers
        advisory_summaries — list of short human-readable summaries
        advisory_error     — error message string if the lookup failed, else None

    Never raises; all errors are captured into *advisory_error*.
    """
    osv_eco = _OSV_ECOSYSTEMS.get(ecosystem.lower())
    if not osv_eco:
        return _empty(f"unsupported ecosystem for advisory lookup: {ecosystem!r}")

    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": osv_eco},
    }
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.Timeout:
        return _empty(f"OSV query timed out after {timeout}s")
    except requests.RequestException as exc:
        return _empty(f"OSV request failed: {exc}")
    except (json.JSONDecodeError, ValueError) as exc:
        return _empty(f"OSV response parse error: {exc}")

    vulns = data.get("vulns") or []

    ids: list[str] = []
    summaries: list[str] = []
    for v in vulns:
        vid = v.get("id", "")
        if vid:
            ids.append(vid)
        for alias in v.get("aliases") or []:
            if alias and alias not in ids:
                ids.append(alias)
        s = v.get("summary") or v.get("details", "")
        if s:
            summaries.append(s[:200])

    return {
        "advisory_hit":       bool(vulns),
        "advisory_source":    "osv",
        "advisory_count":     len(vulns),
        "advisory_ids":       ids,
        "advisory_summaries": summaries,
        "advisory_error":     None,
    }
