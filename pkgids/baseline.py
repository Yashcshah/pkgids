"""Behavioral baseline: extract, store, and retrieve per-version behavior profiles.

Profiles are stored in Supabase (two tables: packages, behavior_profiles).
Credentials are read from environment variables or a .env file in the project root.

Typical workflow
----------------
    from pkgids.baseline import push_profile, get_profile, list_versions

    # After a detonation run:
    profile_id = push_profile(summary, run_dir=Path(summary["run_dir"]))

    # Compare versions:
    from pkgids.diff import diff_profiles
    old = get_profile("pypi", "requests", "2.28.0")
    new = get_profile("pypi", "requests", "2.29.0")
    result = diff_profiles(old, new)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_SHELL_BASENAMES: frozenset[str] = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "ash",
})


# ── .env loader ───────────────────────────────────────────────────────────────

def _load_dotenv() -> None:
    """Load .env from the project root into os.environ (does not overwrite)."""
    dotenv = Path(__file__).parent.parent / ".env"
    if not dotenv.exists():
        return
    for raw in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


# ── Supabase client ───────────────────────────────────────────────────────────

def _get_client():
    """Return a lazily-initialized Supabase client.

    Credentials are read from (in priority order):
        SUPABASE_URL / SUPABASE_KEY
        NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
    """
    _load_dotenv()
    from supabase import create_client  # imported lazily so tests don't require it

    url = (os.environ.get("SUPABASE_URL") or
           os.environ.get("NEXT_PUBLIC_SUPABASE_URL") or "")
    key = (os.environ.get("SUPABASE_KEY") or
           os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY") or "")

    if not url or not key:
        raise RuntimeError(
            "Supabase credentials missing.\n"
            "Set SUPABASE_URL + SUPABASE_KEY in .env or as environment variables.\n"
            "Schema: run migrations/001_baseline_schema.sql then "
            "migrations/002_add_risk_delta.sql in the Supabase SQL editor.\n"
            "See the 'Supabase Setup' section in README.md for full instructions."
        )
    return create_client(url, key)


# ── profile extraction (pure, no DB) ─────────────────────────────────────────

def extract_profile(
    summary: dict,
    run_dir: Path | None = None,
) -> dict:
    """Build a flat behavior profile dict from a ``capture.run()`` summary.

    This function is pure (no network / DB calls) so it is testable in isolation.

    Parameters
    ----------
    summary:
        Return value of ``capture.run()``.
    run_dir:
        Path to the run directory.  When supplied, ``telemetry.jsonl`` and
        ``network.jsonl`` are read to populate derived feature counts.
        When None the profile is built from the in-memory summary only.
    """
    phases = summary.get("phases", {})
    na     = summary.get("network_activity", {})

    # ── Network features from network.jsonl ───────────────────────────────────
    network_entries: list[dict] = []
    if run_dir is not None:
        net_path = Path(run_dir) / "network.jsonl"
        if net_path.exists():
            for raw in net_path.read_text(errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    network_entries.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass

    # DNS query names + HTTP hosts all count as "domains"
    domains: set[str] = set()
    hosts:   set[str] = set()
    ports:   set[int] = set()
    for e in network_entries:
        if q := e.get("query"):
            domains.add(q.rstrip("."))
        if h := e.get("host"):
            domains.add(h)
            hosts.add(h)
        if p := e.get("port"):
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                pass

    # ── Process activity (from phase summaries) ───────────────────────────────
    install_pa = (phases.get("install")          or {}).get("process_activity") or {}
    import_pa  = (phases.get("import")           or {}).get("process_activity") or {}
    submod_pa  = (phases.get("import_submodule") or {}).get("process_activity") or {}

    subprocess_count = (
        (install_pa.get("process_count") or 0) +
        (import_pa.get("process_count")  or 0) +
        (submod_pa.get("process_count")  or 0)
    )
    suspicious_exec_count = (
        len(install_pa.get("suspicious_execs")        or []) +
        len(import_pa.get("suspicious_execs")         or []) +
        len(submod_pa.get("suspicious_execs")         or [])
    )
    sensitive_file_count = (
        len(install_pa.get("sensitive_file_accesses") or []) +
        len(import_pa.get("sensitive_file_accesses")  or []) +
        len(submod_pa.get("sensitive_file_accesses")  or [])
    )

    # Shell command count: suspicious execs whose basename is a shell
    shell_cmd_count = sum(
        1 for pa in (install_pa, import_pa, submod_pa)
        for e in (pa.get("suspicious_execs") or [])
        if (e.get("executable") or "").rsplit("/", 1)[-1] in _SHELL_BASENAMES
    )

    # ── New files created (from telemetry.jsonl) ──────────────────────────────
    new_file_count = 0
    if run_dir is not None:
        tel_path = Path(run_dir) / "telemetry.jsonl"
        if tel_path.exists():
            for raw in tel_path.read_text(errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    e = json.loads(raw)
                    if e.get("event_type") == "file" and e.get("mode") == "create":
                        new_file_count += 1
                except json.JSONDecodeError:
                    pass

    any_suspicious = bool(
        install_pa.get("any_suspicious") or
        import_pa.get("any_suspicious") or
        submod_pa.get("any_suspicious") or
        any(v is True for v in na.values())
    )

    _bait_planted_paths = set(
        (summary.get("sandbox_meta") or {}).get("bait_planted", {}).get("planted_paths") or []
    )
    bait_files_accessed = len({
        acc.get("path")
        for pa in (install_pa, import_pa, submod_pa)
        for acc in (pa.get("sensitive_file_accesses") or [])
        if acc.get("path") in _bait_planted_paths
    }) if _bait_planted_paths else 0

    return {
        "ecosystem":   summary.get("ecosystem"),
        "name":        summary.get("name"),
        "version":     summary.get("version"),
        "run_dir":     str(run_dir) if run_dir else summary.get("run_dir"),

        # Install phase
        "install_status":        (phases.get("install") or {}).get("status"),
        "install_exit_code":     (phases.get("install") or {}).get("exit_code"),
        "install_duration_secs": (phases.get("install") or {}).get("duration_secs"),

        # Import phase
        "import_status":         (phases.get("import") or {}).get("status"),
        "import_exit_code":      (phases.get("import") or {}).get("exit_code"),
        "import_duration_secs":  (phases.get("import") or {}).get("duration_secs"),

        # Import submodule phase (None when absent — backward compat with pre-v1.6 artifacts)
        "import_submodule_status":        (phases.get("import_submodule") or {}).get("status"),
        "import_submodule_exit_code":     (phases.get("import_submodule") or {}).get("exit_code"),
        "import_submodule_duration_secs": (phases.get("import_submodule") or {}).get("duration_secs"),

        # Network features
        "network_domains": sorted(domains),
        "network_hosts":   sorted(hosts),
        "network_ports":   sorted(ports),

        # Subprocess / file features
        "subprocess_count":       subprocess_count,
        "suspicious_exec_count":  suspicious_exec_count,
        "sensitive_file_count":   sensitive_file_count,
        "shell_cmd_count":        shell_cmd_count,
        "new_file_count":         new_file_count,
        "any_suspicious":         any_suspicious,
        "bait_files_accessed":    bait_files_accessed,

        # Full JSONB blobs
        "install_process_activity": install_pa or None,
        "import_process_activity":  import_pa  or None,

        # Verdict (caller sets this; extract_profile leaves it None)
        "prediction": None,
    }


# ── Supabase helpers ──────────────────────────────────────────────────────────

def _upsert_package(client, ecosystem: str, name: str, version: str) -> int:
    """Ensure a packages row exists; return its id."""
    resp = (
        client.table("packages")
        .upsert(
            {"ecosystem": ecosystem, "name": name, "version": version},
            on_conflict="ecosystem,name,version",
        )
        .execute()
    )
    return resp.data[0]["id"]


def _insert_profile(client, package_id: int, profile: dict) -> int:
    """Insert one behavior_profiles row; return its id."""
    row = {
        "package_id":               package_id,
        "run_dir":                  profile.get("run_dir"),
        "install_status":           profile.get("install_status"),
        "install_exit_code":        profile.get("install_exit_code"),
        "install_duration_secs":    profile.get("install_duration_secs"),
        "import_status":            profile.get("import_status"),
        "import_exit_code":         profile.get("import_exit_code"),
        "import_duration_secs":     profile.get("import_duration_secs"),
        "network_domains":          profile.get("network_domains") or [],
        "network_hosts":            profile.get("network_hosts")   or [],
        "network_ports":            profile.get("network_ports")   or [],
        "subprocess_count":         profile.get("subprocess_count",      0),
        "suspicious_exec_count":    profile.get("suspicious_exec_count", 0),
        "sensitive_file_count":     profile.get("sensitive_file_count",  0),
        "shell_cmd_count":          profile.get("shell_cmd_count",       0),
        "new_file_count":           profile.get("new_file_count",        0),
        "any_suspicious":           bool(profile.get("any_suspicious")),
        "install_process_activity": profile.get("install_process_activity"),
        "import_process_activity":  profile.get("import_process_activity"),
        "prediction":               profile.get("prediction"),
    }
    resp = client.table("behavior_profiles").insert(row).execute()
    return resp.data[0]["id"]


# ── public API ────────────────────────────────────────────────────────────────

def push_profile(
    summary: dict,
    run_dir: Path | None = None,
    prediction: str | None = None,
) -> int:
    """Extract a behavior profile from *summary* and push it to Supabase.

    Parameters
    ----------
    summary:
        Return value of ``capture.run()``.
    run_dir:
        Run directory path; enriches the profile with file/telemetry counts.
    prediction:
        ``'benign'`` or ``'malicious'`` from ``validate.predict()``.  When None
        the profile is stored without a verdict (can be back-filled later).

    Returns
    -------
    int
        The ``behavior_profiles.id`` of the newly inserted row.
    """
    profile = extract_profile(summary, run_dir)
    profile["prediction"] = prediction

    client = _get_client()
    eco, name, ver = profile["ecosystem"], profile["name"], profile["version"]

    package_id  = _upsert_package(client, eco, name, ver)
    profile_id  = _insert_profile(client, package_id, profile)

    print(f"[baseline] pushed profile id={profile_id}  {eco}:{name}@{ver}", flush=True)
    return profile_id


def get_profile(
    ecosystem: str,
    name: str,
    version: str,
) -> dict | None:
    """Fetch the most recent behavior profile for *ecosystem:name@version*.

    Returns None if no profile exists for this version.
    """
    client = _get_client()

    # Resolve package_id
    pkg_resp = (
        client.table("packages")
        .select("id")
        .eq("ecosystem", ecosystem)
        .eq("name", name)
        .eq("version", version)
        .limit(1)
        .execute()
    )
    if not pkg_resp.data:
        return None

    package_id = pkg_resp.data[0]["id"]

    prof_resp = (
        client.table("behavior_profiles")
        .select("*")
        .eq("package_id", package_id)
        .order("run_ts", desc=True)
        .limit(1)
        .execute()
    )
    if not prof_resp.data:
        return None

    row = prof_resp.data[0]
    # Attach ecosystem/name/version so callers don't need a second lookup.
    row["ecosystem"] = ecosystem
    row["name"]      = name
    row["version"]   = version
    return row


def list_versions(ecosystem: str, name: str) -> list[dict]:
    """Return all stored versions for *ecosystem:name*, newest run first.

    Each entry: ``{version, run_ts, prediction, any_suspicious, install_status,
    import_status, network_domains, ...}``.
    """
    client = _get_client()

    # Join packages → behavior_profiles via a select with a foreign-key filter.
    pkg_resp = (
        client.table("packages")
        .select("id, version")
        .eq("ecosystem", ecosystem)
        .eq("name", name)
        .execute()
    )
    if not pkg_resp.data:
        return []

    package_ids = {row["id"]: row["version"] for row in pkg_resp.data}
    if not package_ids:
        return []

    prof_resp = (
        client.table("behavior_profiles")
        .select(
            "id, package_id, run_ts, prediction, any_suspicious, "
            "install_status, import_status, "
            "network_domains, subprocess_count, suspicious_exec_count"
        )
        .in_("package_id", list(package_ids.keys()))
        .order("run_ts", desc=True)
        .execute()
    )

    results = []
    for row in prof_resp.data:
        row["version"]   = package_ids.get(row["package_id"])
        row["ecosystem"] = ecosystem
        row["name"]      = name
        results.append(row)
    return results


# ── baseline auto-resolution ──────────────────────────────────────────────────

def get_previous_version(
    ecosystem: str,
    name: str,
    current_version: str,
) -> dict | None:
    """Fetch the profile for the version tested immediately before *current_version*.

    Versions are ordered by ``run_ts`` (most recent first), so "previous" means
    the entry directly after *current_version* in that list (the next-older run).

    Returns None if *current_version* is not found or has no predecessor.
    """
    versions = list_versions(ecosystem, name)
    for i, v in enumerate(versions):
        if v.get("version") == current_version and i + 1 < len(versions):
            prev_ver = versions[i + 1].get("version")
            if prev_ver:
                return get_profile(ecosystem, name, prev_ver)
    return None


def get_known_good(
    ecosystem: str,
    name: str,
) -> dict | None:
    """Fetch the most recent profile predicted benign with no suspicious flags.

    Returns None if no such profile exists.
    """
    client = _get_client()

    pkg_resp = (
        client.table("packages")
        .select("id, version")
        .eq("ecosystem", ecosystem)
        .eq("name", name)
        .execute()
    )
    if not pkg_resp.data:
        return None

    package_ids = {row["id"]: row["version"] for row in pkg_resp.data}

    prof_resp = (
        client.table("behavior_profiles")
        .select("*")
        .in_("package_id", list(package_ids.keys()))
        .eq("prediction", "benign")
        .eq("any_suspicious", False)
        .order("run_ts", desc=True)
        .limit(1)
        .execute()
    )
    if not prof_resp.data:
        return None

    row = prof_resp.data[0]
    row["ecosystem"] = ecosystem
    row["name"]      = name
    row["version"]   = package_ids.get(row["package_id"])
    return row


def get_rolling_baseline(
    ecosystem: str,
    name: str,
    n: int = 5,
) -> dict | None:
    """Build a merged "envelope" profile across the N most recent benign runs.

    Feature aggregation: union of network sets, max of numeric counts.  Any
    behavior within the envelope is expected; exceeding it triggers a diff finding.

    Returns None if no benign profiles exist.
    """
    client = _get_client()

    pkg_resp = (
        client.table("packages")
        .select("id, version")
        .eq("ecosystem", ecosystem)
        .eq("name", name)
        .execute()
    )
    if not pkg_resp.data:
        return None

    package_ids = {row["id"]: row["version"] for row in pkg_resp.data}

    prof_resp = (
        client.table("behavior_profiles")
        .select("*")
        .in_("package_id", list(package_ids.keys()))
        .eq("prediction", "benign")
        .eq("any_suspicious", False)
        .order("run_ts", desc=True)
        .limit(n)
        .execute()
    )
    if not prof_resp.data:
        return None

    profiles = prof_resp.data
    all_domains: set[str] = set()
    all_hosts:   set[str] = set()
    all_ports:   set[int] = set()
    max_subprocess   = 0
    max_susp_exec    = 0
    max_sensitive    = 0
    max_shell        = 0
    max_new_file     = 0

    for p in profiles:
        all_domains.update(p.get("network_domains") or [])
        all_hosts.update(p.get("network_hosts") or [])
        all_ports.update(int(x) for x in (p.get("network_ports") or []))
        max_subprocess = max(max_subprocess, p.get("subprocess_count",      0) or 0)
        max_susp_exec  = max(max_susp_exec,  p.get("suspicious_exec_count", 0) or 0)
        max_sensitive  = max(max_sensitive,  p.get("sensitive_file_count",  0) or 0)
        max_shell      = max(max_shell,      p.get("shell_cmd_count",       0) or 0)
        max_new_file   = max(max_new_file,   p.get("new_file_count",        0) or 0)

    return {
        "ecosystem":              ecosystem,
        "name":                   name,
        "version":                f"rolling_baseline(n={len(profiles)})",
        "network_domains":        sorted(all_domains),
        "network_hosts":          sorted(all_hosts),
        "network_ports":          sorted(all_ports),
        "subprocess_count":       max_subprocess,
        "suspicious_exec_count":  max_susp_exec,
        "sensitive_file_count":   max_sensitive,
        "shell_cmd_count":        max_shell,
        "new_file_count":         max_new_file,
        "any_suspicious":         False,
        "prediction":             "benign",
        "install_process_activity": None,
        "import_process_activity":  None,
    }
