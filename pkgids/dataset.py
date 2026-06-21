"""Fetch malicious-package metadata from the OpenSSF malicious-packages dataset.

Records come from https://github.com/ossf/malicious-packages, which stores
OSV-format JSON under osv/malicious/<ecosystem>/<package>/<id>.json.

No package artifacts are downloaded or executed here — only JSON metadata is read.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

_GITHUB_API = "https://api.github.com"
_REPO       = "ossf/malicious-packages"
_CACHE_DIR  = Path(__file__).parent.parent / "data"


# ── internal helpers ──────────────────────────────────────────────────────────

def _cache_path(ecosystem: str) -> Path:
    _CACHE_DIR.mkdir(exist_ok=True)
    return _CACHE_DIR / f"malicious_{ecosystem}.json"


def _api_get(url: str, token: str | None) -> dict | list:
    """GET a GitHub API URL and return parsed JSON."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    # Back off if approaching the unauthenticated rate limit (60 req/hr)
    remaining = int(resp.headers.get("X-RateLimit-Remaining", 60))
    if remaining < 3:
        reset_ts = int(resp.headers.get("X-RateLimit-Reset", 0))
        wait = max(1.0, reset_ts - time.time()) + 2
        print(f"[dataset] rate limit low ({remaining} left); sleeping {wait:.0f}s",
              flush=True)
        time.sleep(wait)
    return resp.json()


def _raw_get(url: str, token: str | None) -> dict | list:
    """GET a raw file URL (raw.githubusercontent.com) and return parsed JSON."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _extract_record(ecosystem: str, dir_name: str, osv: dict) -> dict:
    """Build a record dict from one OSV JSON document."""
    affected  = osv.get("affected") or []
    pkg_info  = affected[0].get("package", {}) if affected else {}
    versions  = affected[0].get("versions") or [] if affected else []

    name    = pkg_info.get("name") or dir_name
    version = versions[0] if versions else None

    summary = osv.get("summary") or ""
    if not summary:
        details = osv.get("details") or ""
        summary = details[:140].replace("\n", " ")

    return {
        "ecosystem": ecosystem,
        "name":      name,
        "version":   version,
        "osv_id":    osv.get("id", ""),
        "summary":   summary,
    }


# ── public API ────────────────────────────────────────────────────────────────

def fetch(
    ecosystem: str,
    limit: int = 50,
    refresh: bool = False,
    token: str | None = None,
) -> list[dict]:
    """Return up to *limit* malicious-package records for *ecosystem*.

    Reads from the OpenSSF malicious-packages GitHub repository via the GitHub
    API.  Results are cached to ``data/malicious_<ecosystem>.json``; pass
    ``refresh=True`` to force a re-fetch.

    Authentication
    --------------
    Pass a GitHub personal access token via *token* or set ``GITHUB_TOKEN``
    in the environment to raise the rate limit from 60 to 5 000 req/hr.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    cache = _cache_path(ecosystem)

    # Use the cache if it has enough records
    if cache.exists() and not refresh:
        cached: list[dict] = json.loads(cache.read_text())
        if len(cached) >= limit:
            return cached[:limit]

    print(f"[dataset] fetching {ecosystem} malicious-packages metadata ...", flush=True)

    # List the ecosystem directory (first 100 package dirs — enough for small limits)
    dir_url = (
        f"{_GITHUB_API}/repos/{_REPO}/contents/osv/malicious/{ecosystem}"
        f"?per_page=100"
    )
    try:
        entries = _api_get(dir_url, token)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(
            f"Cannot list {ecosystem} packages from OpenSSF repo (HTTP {status})"
        ) from exc

    pkg_dirs = [e for e in entries
                if isinstance(e, dict) and e.get("type") == "dir"]

    records: list[dict] = []
    for pkg_dir in pkg_dirs:
        if len(records) >= limit:
            break

        dir_name = pkg_dir["name"]

        # List OSV files inside this package directory
        try:
            files = _api_get(pkg_dir["url"], token)
        except Exception as exc:
            print(f"[dataset]   skip {dir_name}: {exc}", flush=True)
            continue

        if not isinstance(files, list):
            continue

        # Grab the first .json file
        for f in files:
            if not isinstance(f, dict) or not f.get("name", "").endswith(".json"):
                continue
            download_url = f.get("download_url")
            if not download_url:
                continue
            try:
                osv = _raw_get(download_url, token)
                if isinstance(osv, dict):
                    records.append(_extract_record(ecosystem, dir_name, osv))
            except Exception as exc:
                print(f"[dataset]   skip {dir_name}/{f['name']}: {exc}", flush=True)
            break

        time.sleep(0.15)   # be a polite citizen with the unauthenticated API

    cache.write_text(json.dumps(records, indent=2))
    print(f"[dataset] cached {len(records)} records -> {cache}", flush=True)
    return records[:limit]
