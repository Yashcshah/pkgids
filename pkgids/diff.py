"""Behavioral diff engine: compare two version profiles and flag suspicious deltas.

Severity tiers (highest → lowest):
    critical — strong signal of malicious intent: new domains, obfuscation patterns,
               prediction flip benign→malicious, became_suspicious flag
    high     — significant signal: new install hooks, sensitive file access increase,
               shell command spawn increase, large suspicious-exec spike
    medium   — weaker signal worth investigating: new ports, subprocess count spike,
               phase status regression, event volume increase, minor exec increase
    low      — neutral change: domains removed, prediction cleared, suspicious cleared

Overall verdict:
    suspicious    — any critical or high finding
    needs_review  — medium findings only
    info          — low findings only
    clean         — no findings
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TypedDict

# ── finding severities ────────────────────────────────────────────────────────

_SEV: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# critical(4) or high(3) → suspicious verdict
_SUSPICIOUS_THRESHOLD = 3


class Finding(TypedDict):
    kind:     str
    severity: str   # "critical" | "high" | "medium" | "low"
    message:  str
    detail:   dict


def _finding(kind: str, severity: str, message: str, **detail: object) -> Finding:
    return Finding(kind=kind, severity=severity, message=message, detail=detail)


# ── profile helpers ───────────────────────────────────────────────────────────

def _extract_sensitive_paths(profile: dict) -> set[str]:
    paths: set[str] = set()
    for pa_key in ("install_process_activity", "import_process_activity"):
        pa = profile.get(pa_key) or {}
        for e in (pa.get("sensitive_file_accesses") or []):
            if p := e.get("path"):
                paths.add(str(p))
    return paths


def _extract_process_argvs(profile: dict) -> set[tuple[str, ...]]:
    argvs: set[tuple[str, ...]] = set()
    for pa_key in ("install_process_activity", "import_process_activity"):
        pa = profile.get(pa_key) or {}
        for e in (pa.get("suspicious_execs") or []):
            argv = e.get("argv") or []
            if argv:
                argvs.add(tuple(str(a) for a in argv))
    return argvs


# ── individual diff checks ────────────────────────────────────────────────────

def _diff_network_domains(old: dict, new: dict) -> list[Finding]:
    old_d = set(old.get("network_domains") or [])
    new_d = set(new.get("network_domains") or [])
    findings: list[Finding] = []
    if added := sorted(new_d - old_d):
        findings.append(_finding(
            "new_network_domains", "critical",
            f"New domains contacted: {added}",
            added=added, removed=sorted(old_d - new_d),
        ))
    elif removed := sorted(old_d - new_d):
        findings.append(_finding(
            "removed_network_domains", "low",
            f"Domains no longer contacted: {removed}",
            removed=removed,
        ))
    return findings


def _diff_network_ports(old: dict, new: dict) -> list[Finding]:
    old_p = set(old.get("network_ports") or [])
    new_p = set(new.get("network_ports") or [])
    if added := sorted(new_p - old_p):
        return [_finding(
            "new_network_ports", "medium",
            f"New ports used: {added}",
            added=added,
        )]
    return []


def _diff_suspicious_execs(old: dict, new: dict) -> list[Finding]:
    old_n = int(old.get("suspicious_exec_count") or 0)
    new_n = int(new.get("suspicious_exec_count") or 0)
    if new_n > old_n:
        sev = "high" if new_n > old_n + 1 else "medium"
        return [_finding(
            "suspicious_exec_increase", sev,
            f"Suspicious subprocess count: {old_n} → {new_n}",
            old=old_n, new=new_n, delta=new_n - old_n,
        )]
    return []


def _diff_sensitive_files(old: dict, new: dict) -> list[Finding]:
    old_n = int(old.get("sensitive_file_count") or 0)
    new_n = int(new.get("sensitive_file_count") or 0)
    if new_n > old_n:
        return [_finding(
            "sensitive_file_increase", "high",
            f"Sensitive file accesses: {old_n} → {new_n}",
            old=old_n, new=new_n, delta=new_n - old_n,
        )]
    return []


def _diff_shell_cmds(old: dict, new: dict) -> list[Finding]:
    old_n = int(old.get("shell_cmd_count") or 0)
    new_n = int(new.get("shell_cmd_count") or 0)
    if new_n > old_n:
        return [_finding(
            "shell_cmd_increase", "high",
            f"Shell command spawns: {old_n} → {new_n}",
            old=old_n, new=new_n, delta=new_n - old_n,
        )]
    return []


def _diff_any_suspicious(old: dict, new: dict) -> list[Finding]:
    was = bool(old.get("any_suspicious"))
    now = bool(new.get("any_suspicious"))
    if not was and now:
        return [_finding(
            "became_suspicious", "critical",
            "Package went from clean to suspicious",
            old=was, new=now,
        )]
    if was and not now:
        return [_finding(
            "cleared_suspicious", "low",
            "Package is no longer flagged as suspicious",
            old=was, new=now,
        )]
    return []


def _diff_subprocess_count(old: dict, new: dict) -> list[Finding]:
    old_n = int(old.get("subprocess_count") or 0)
    new_n = int(new.get("subprocess_count") or 0)
    delta = new_n - old_n
    if delta > 5:
        return [_finding(
            "subprocess_count_spike", "medium",
            f"Subprocess count jumped: {old_n} → {new_n}",
            old=old_n, new=new_n, delta=delta,
        )]
    return []


def _diff_phase_status(old: dict, new: dict) -> list[Finding]:
    findings: list[Finding] = []
    for phase in ("install", "import"):
        k = f"{phase}_status"
        old_s = old.get(k)
        new_s = new.get(k)
        if old_s == "ok" and new_s not in ("ok", None):
            findings.append(_finding(
                f"{phase}_status_regression", "medium",
                f"{phase} phase status regressed: {old_s!r} → {new_s!r}",
                old=old_s, new=new_s,
            ))
    return findings


def _diff_prediction(old: dict, new: dict) -> list[Finding]:
    old_p = old.get("prediction")
    new_p = new.get("prediction")
    if old_p == "benign" and new_p == "malicious":
        return [_finding(
            "prediction_flip", "critical",
            "Prediction flipped: benign → malicious",
            old=old_p, new=new_p,
        )]
    if old_p == "malicious" and new_p == "benign":
        return [_finding(
            "prediction_cleared", "low",
            "Prediction cleared: malicious → benign",
            old=old_p, new=new_p,
        )]
    return []


# ── advanced checks ───────────────────────────────────────────────────────────

_HOOK_SCRIPT_NAMES: frozenset[str] = frozenset({
    "setup.py", "__init__.py", "postinstall", "preinstall",
    "post_install", "pre_install", "install.py",
})


def _diff_install_hooks(old: dict, new: dict) -> list[Finding]:
    """Flag new install-hook script invocations that were absent in the baseline."""
    def _hook_scripts(profile: dict) -> set[str]:
        found: set[str] = set()
        for pa_key in ("install_process_activity", "import_process_activity"):
            pa = profile.get(pa_key) or {}
            for e in (pa.get("suspicious_execs") or []):
                for arg in (e.get("argv") or []):
                    basename = str(arg).rsplit("/", 1)[-1].lower()
                    if basename in _HOOK_SCRIPT_NAMES:
                        found.add(str(arg))
        return found

    added = sorted(_hook_scripts(new) - _hook_scripts(old))
    if added:
        return [_finding(
            "new_install_hooks", "high",
            f"New install-hook invocations: {added}",
            added=added,
        )]
    return []


_OBFUSC_KEYWORDS: frozenset[str] = frozenset({
    "base64", "exec(compile", "eval(", "__import__", "chr(",
    "bytes.fromhex", "decode('utf", 'decode("utf',
})
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")


def _is_obfuscated(argv: list) -> bool:
    arg_str = " ".join(str(a) for a in argv)
    if any(kw in arg_str for kw in _OBFUSC_KEYWORDS):
        return True
    return any(_B64_RE.match(str(a)) for a in argv)


def _diff_obfuscation_patterns(old: dict, new: dict) -> list[Finding]:
    """Detect new obfuscated command invocations not present in baseline."""
    def _obfusc_set(profile: dict) -> set[tuple]:
        found: set[tuple] = set()
        for pa_key in ("install_process_activity", "import_process_activity"):
            pa = profile.get(pa_key) or {}
            for e in (pa.get("suspicious_execs") or []):
                argv = e.get("argv") or []
                if _is_obfuscated(argv):
                    found.add(tuple(str(a) for a in argv))
        return found

    new_patterns = sorted(list(a) for a in (_obfusc_set(new) - _obfusc_set(old)))
    if new_patterns:
        return [_finding(
            "new_obfuscation_patterns", "critical",
            f"New obfuscated command(s) detected: {len(new_patterns)} pattern(s)",
            patterns=new_patterns[:5],
            count=len(new_patterns),
        )]
    return []


def _diff_event_volume(old: dict, new: dict) -> list[Finding]:
    """Flag >100% volume increase in subprocess or file-create event counts."""
    findings: list[Finding] = []
    for key, label in (
        ("subprocess_count", "subprocess events"),
        ("new_file_count",   "file-create events"),
    ):
        old_n = int(old.get(key) or 0)
        new_n = int(new.get(key) or 0)
        if old_n == 0:
            continue
        delta = new_n - old_n
        ratio = delta / old_n
        if ratio > 1.0 and delta > 3:
            findings.append(_finding(
                "event_volume_increase", "medium",
                f"{label} increased by {ratio:.0%}: {old_n} → {new_n}",
                key=key, old=old_n, new=new_n, ratio=round(ratio, 2),
            ))
    return findings


# ── behavior fingerprint ──────────────────────────────────────────────────────

def fingerprint(profile: dict) -> str:
    """Return a 16-char hex fingerprint of the profile's key behavior features."""
    features = [
        sorted(profile.get("network_domains") or []),
        sorted(int(p) for p in (profile.get("network_ports") or [])),
        int(profile.get("subprocess_count") or 0),
        int(profile.get("suspicious_exec_count") or 0),
        int(profile.get("sensitive_file_count") or 0),
        int(profile.get("shell_cmd_count") or 0),
        bool(profile.get("any_suspicious")),
    ]
    data = json.dumps(features, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()[:16]


# ── public API ────────────────────────────────────────────────────────────────

_CHECKS = [
    _diff_network_domains,
    _diff_network_ports,
    _diff_suspicious_execs,
    _diff_sensitive_files,
    _diff_shell_cmds,
    _diff_any_suspicious,
    _diff_subprocess_count,
    _diff_phase_status,
    _diff_prediction,
    _diff_install_hooks,
    _diff_obfuscation_patterns,
    _diff_event_volume,
]

_RISK_DELTA: dict[int, str] = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "clean"}


def diff_profiles(old: dict, new: dict) -> dict:
    """Compare two behavior profiles and return a structured diff.

    Parameters
    ----------
    old, new:
        Dicts as returned by ``baseline.get_profile()`` or
        ``baseline.extract_profile()``.  Must both carry at least ``version``.

    Returns
    -------
    dict with keys:
        from_version        — ``old["version"]`` (backward compat)
        to_version          — ``new["version"]`` (backward compat)
        baseline_version    — same as from_version (canonical name)
        candidate_version   — same as to_version (canonical name)
        verdict             — "suspicious" | "needs_review" | "info" | "clean"
        is_suspicious       — True when verdict == "suspicious"
        risk_delta          — "critical" | "high" | "medium" | "low" | "clean"
        findings            — list of Finding dicts (sorted: highest severity first)
        summary             — counts per severity tier + total
        new_domains         — newly contacted domains
        new_sensitive_paths — newly accessed sensitive file paths
        new_processes       — new suspicious process argv lists
        new_ports           — new ports used
        fingerprint_old     — 16-char hex fingerprint of old profile
        fingerprint_new     — 16-char hex fingerprint of new profile
    """
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(old, new))

    findings.sort(key=lambda f: -_SEV.get(f["severity"], 0))

    max_sev = max((_SEV.get(f["severity"], 0) for f in findings), default=0)
    if max_sev >= _SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    elif max_sev == 2:
        verdict = "needs_review"
    elif max_sev == 1:
        verdict = "info"
    else:
        verdict = "clean"

    old_d = set(old.get("network_domains") or [])
    new_d = set(new.get("network_domains") or [])
    old_p = {int(p) for p in (old.get("network_ports") or [])}
    new_p = {int(p) for p in (new.get("network_ports") or [])}

    return {
        "from_version":        old.get("version"),
        "to_version":          new.get("version"),
        "baseline_version":    old.get("version"),
        "candidate_version":   new.get("version"),
        "verdict":             verdict,
        "is_suspicious":       verdict == "suspicious",
        "risk_delta":          _RISK_DELTA.get(max_sev, "clean"),
        "findings":            findings,
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high":     sum(1 for f in findings if f["severity"] == "high"),
            "medium":   sum(1 for f in findings if f["severity"] == "medium"),
            "low":      sum(1 for f in findings if f["severity"] == "low"),
            "total":    len(findings),
        },
        "new_domains":         sorted(new_d - old_d),
        "new_sensitive_paths": sorted(_extract_sensitive_paths(new) - _extract_sensitive_paths(old)),
        "new_processes":       [list(a) for a in sorted(_extract_process_argvs(new) - _extract_process_argvs(old))],
        "new_ports":           sorted(new_p - old_p),
        "fingerprint_old":     fingerprint(old),
        "fingerprint_new":     fingerprint(new),
    }


def push_diff(
    diff: dict,
    ecosystem: str,
    name: str,
    from_profile_id: int | None = None,
    to_profile_id:   int | None = None,
) -> int:
    """Persist a diff result to Supabase and return its id.

    Parameters
    ----------
    diff:
        Return value of ``diff_profiles()``.
    ecosystem, name:
        Package coordinates.
    from_profile_id, to_profile_id:
        ``behavior_profiles.id`` values (optional; for FK linking).
    """
    from .baseline import _get_client

    client = _get_client()
    row = {
        "ecosystem":       ecosystem,
        "name":            name,
        "from_version":    diff["from_version"],
        "to_version":      diff["to_version"],
        "verdict":         diff["verdict"],
        "is_suspicious":   diff["is_suspicious"],
        "findings":        diff["findings"],
        "risk_delta":      diff.get("risk_delta"),
        "from_profile_id": from_profile_id,
        "to_profile_id":   to_profile_id,
    }
    resp = (
        client.table("behavior_diffs")
        .upsert(row, on_conflict="ecosystem,name,from_version,to_version")
        .execute()
    )
    return resp.data[0]["id"]
