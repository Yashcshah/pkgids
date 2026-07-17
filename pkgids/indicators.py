"""Security indicator extraction and MITRE ATT&CK tagging.

Each indicator type has a static definition in ``_CATALOG`` (tactic, technique,
severity, score weight).  ``extract_indicators()`` runs all extractor functions
against a normalized run dict and returns matching Indicator instances sorted
by weight descending (highest threat first).
"""

from __future__ import annotations

import re
from typing import TypedDict


# ── data model ────────────────────────────────────────────────────────────────

class Indicator(TypedDict):
    id:        str    # machine-readable slug e.g. "ssh_key_accessed"
    title:     str    # short human title
    tactic:    str    # ATT&CK tactic slug e.g. "credential-access"
    technique: str    # ATT&CK technique ID e.g. "T1552.004"
    severity:  str    # "critical" | "high" | "medium" | "low"
    weight:    float  # score contribution [0, 1]
    evidence:  dict   # raw supporting data


# ── indicator catalogue ───────────────────────────────────────────────────────

_CATALOG: dict[str, dict] = {
    "dns_query_observed": {
        "title":     "Outbound DNS query observed",
        "tactic":    "command-and-control",
        "technique": "T1071.004",
        "severity":  "medium",
        "weight":    0.30,
    },
    "http_request_observed": {
        "title":     "Outbound HTTP request observed",
        "tactic":    "command-and-control",
        "technique": "T1071.001",
        "severity":  "medium",
        "weight":    0.35,
    },
    "tls_sni_extracted": {
        "title":     "TLS connection with SNI hostname observed",
        "tactic":    "command-and-control",
        "technique": "T1071.001",
        "severity":  "medium",
        "weight":    0.30,
    },
    "shell_spawned_during_install": {
        "title":     "Shell process spawned during install phase",
        "tactic":    "execution",
        "technique": "T1059.004",
        "severity":  "high",
        "weight":    0.65,
    },
    "python_c_flag_used": {
        "title":     "Python inline command executed via -c flag",
        "tactic":    "execution",
        "technique": "T1059.006",
        "severity":  "high",
        "weight":    0.55,
    },
    "base64_command_present": {
        "title":     "Obfuscated or base64-encoded command detected",
        "tactic":    "defense-evasion",
        "technique": "T1027",
        "severity":  "critical",
        "weight":    0.75,
    },
    "sensitive_file_accessed": {
        "title":     "Sensitive file path accessed",
        "tactic":    "credential-access",
        "technique": "T1552.001",
        "severity":  "high",
        "weight":    0.70,
    },
    "env_file_read": {
        "title":     ".env credentials file read",
        "tactic":    "credential-access",
        "technique": "T1552.001",
        "severity":  "high",
        "weight":    0.75,
    },
    "ssh_key_accessed": {
        "title":     "SSH private key file accessed",
        "tactic":    "credential-access",
        "technique": "T1552.004",
        "severity":  "critical",
        "weight":    0.90,
    },
    "subprocess_chain_deep": {
        "title":     "Unusually deep subprocess chain spawned",
        "tactic":    "execution",
        "technique": "T1059",
        "severity":  "medium",
        "weight":    0.40,
    },
    "import_triggered_network": {
        "title":     "Network connection initiated on module import",
        "tactic":    "command-and-control",
        "technique": "T1071",
        "severity":  "high",
        "weight":    0.65,
    },
    "install_timed_out": {
        "title":     "Package install timed out (possible sandbox evasion)",
        "tactic":    "defense-evasion",
        "technique": "T1497.001",
        "severity":  "medium",
        "weight":    0.25,
    },
    "install_hook_executed": {
        "title":     "Install hook script detected in package metadata",
        "tactic":    "persistence",
        "technique": "T1546",
        "severity":  "medium",
        "weight":    0.45,
    },
    "new_behavior_vs_baseline": {
        "title":     "New suspicious behavior compared with stored baseline",
        "tactic":    "defense-evasion",
        "technique": "T1027",
        "severity":  "high",
        "weight":    0.60,
    },
    "exfiltration_unusual_port": {
        "title":     "Outbound connection to non-standard port",
        "tactic":    "exfiltration",
        "technique": "T1048",
        "severity":  "high",
        "weight":    0.70,
    },
    "file_system_discovery": {
        "title":     "File system discovery across home/config directories",
        "tactic":    "discovery",
        "technique": "T1083",
        "severity":  "medium",
        "weight":    0.25,
    },
    "bait_probe": {
        "title":     "Synthetic bait file opened (probe)",
        "tactic":    "credential-access",
        "technique": "T1552.001",
        "severity":  "medium",
        "weight":    0.50,
    },
    "bait_enumeration": {
        "title":     "Synthetic bait credential files enumerated",
        "tactic":    "credential-access",
        "technique": "T1552.001",
        "severity":  "high",
        "weight":    0.75,
    },
    "bait_credential_harvest": {
        "title":     "Synthetic bait credentials harvested (all files accessed)",
        "tactic":    "credential-access",
        "technique": "T1552.001",
        "severity":  "critical",
        "weight":    0.90,
    },
}

# ── pattern constants ─────────────────────────────────────────────────────────

_SHELL_BASENAMES: frozenset[str] = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh",
})
_STANDARD_PORTS: frozenset[int] = frozenset({53, 80, 443, 8080, 8443})
_ENV_RE  = re.compile(r"(^|[/\\])\.env($|[^/\\])", re.IGNORECASE)
_SSH_RE  = re.compile(r"(^|[/\\])\.ssh[/\\]", re.IGNORECASE)
_OBFUSC_KW: frozenset[str] = frozenset({
    "base64", "exec(compile", "eval(", "__import__", "chr(",
    "bytes.fromhex", "decode('utf", 'decode("utf',
})
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
_DISCOVERY_RE = re.compile(
    r"^(/home/[^/]+|/root|/etc|/var(?:/lib|/config)?|/tmp|\.config|\.local)",
    re.IGNORECASE,
)
_DISCOVERY_THRESHOLD = 5


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_obfuscated(argv: list) -> bool:
    arg_str = " ".join(str(a) for a in argv)
    if any(kw in arg_str for kw in _OBFUSC_KW):
        return True
    return any(_B64_RE.match(str(a)) for a in argv)


def _ind(id_: str, **evidence: object) -> Indicator:
    meta = _CATALOG[id_]
    return Indicator(
        id=id_,
        title=meta["title"],
        tactic=meta["tactic"],
        technique=meta["technique"],
        severity=meta["severity"],
        weight=meta["weight"],
        evidence=dict(evidence),
    )


# ── individual extractors ─────────────────────────────────────────────────────

def _extract_dns(norm: dict) -> list[Indicator]:
    queries = norm.get("network", {}).get("dns_queries", [])
    if not queries:
        return []
    return [_ind("dns_query_observed",
                 queries=[e.get("query") for e in queries[:10]],
                 count=len(queries))]


def _extract_http(norm: dict) -> list[Indicator]:
    reqs = norm.get("network", {}).get("http_requests", [])
    if not reqs:
        return []
    return [_ind("http_request_observed",
                 hosts=[e.get("host") for e in reqs[:10]],
                 count=len(reqs))]


def _extract_tls(norm: dict) -> list[Indicator]:
    sessions = norm.get("network", {}).get("tls_sessions", [])
    if not sessions:
        return []
    return [_ind("tls_sni_extracted",
                 sni_names=[e.get("sni") for e in sessions[:10]],
                 count=len(sessions))]


def _extract_shell_spawn(norm: dict) -> list[Indicator]:
    execs = norm.get("phases", {}).get("install", {}).get("suspicious_execs") or []
    shell_execs = [
        e for e in execs
        if (e.get("executable") or "").rsplit("/", 1)[-1] in _SHELL_BASENAMES
    ]
    if not shell_execs:
        return []
    return [_ind("shell_spawned_during_install",
                 commands=[e.get("argv") for e in shell_execs[:5]],
                 phase="install")]


def _extract_python_c(norm: dict) -> list[Indicator]:
    phases = norm.get("phases", {})
    found: list[list] = []
    primary_phase: str | None = None
    for phase_name in ("install", "import"):
        execs = phases.get(phase_name, {}).get("suspicious_execs") or []
        hits  = [
            e for e in execs
            if (e.get("executable") or "").rsplit("/", 1)[-1].startswith("python")
            and any(str(a) == "-c" for a in (e.get("argv") or []))
        ]
        if hits and primary_phase is None:
            primary_phase = phase_name
        found.extend(e.get("argv") for e in hits[:5])
    if not found:
        return []
    return [_ind("python_c_flag_used",
                 commands=found[:5],
                 phase=primary_phase or "install")]


def _extract_obfuscation(norm: dict) -> list[Indicator]:
    phases = norm.get("phases", {})
    obfusc: list[dict] = []
    primary_phase: str | None = None
    for phase_name in ("install", "import"):
        execs = phases.get(phase_name, {}).get("suspicious_execs") or []
        hits  = [e for e in execs if _is_obfuscated(e.get("argv") or [])]
        if hits and primary_phase is None:
            primary_phase = phase_name
        obfusc.extend(hits)
    if not obfusc:
        return []
    return [_ind("base64_command_present",
                 commands=[e.get("argv") for e in obfusc[:5]],
                 count=len(obfusc),
                 phase=primary_phase or "install")]


def _extract_sensitive_file(norm: dict) -> list[Indicator]:
    sens = norm.get("telemetry", {}).get("sensitive_file_events", [])
    if not sens:
        return []
    paths = sorted({e.get("path") for e in sens if e.get("path")})
    return [_ind("sensitive_file_accessed", paths=paths[:20], count=len(sens))]


def _extract_env_file(norm: dict) -> list[Indicator]:
    sens = norm.get("telemetry", {}).get("sensitive_file_events", [])
    hits = [e for e in sens if _ENV_RE.search(e.get("path") or "")]
    if not hits:
        return []
    return [_ind("env_file_read",
                 paths=[e.get("path") for e in hits[:5]])]


def _extract_ssh_key(norm: dict) -> list[Indicator]:
    sens = norm.get("telemetry", {}).get("sensitive_file_events", [])
    hits = [e for e in sens if _SSH_RE.search(e.get("path") or "")]
    if not hits:
        return []
    return [_ind("ssh_key_accessed",
                 paths=[e.get("path") for e in hits[:5]])]


def _extract_subprocess_chain(norm: dict) -> list[Indicator]:
    phases  = norm.get("phases", {})
    install = int(phases.get("install", {}).get("process_count") or 0)
    import_ = int(phases.get("import",  {}).get("process_count") or 0)
    total   = install + import_
    if total <= 10:
        return []
    return [_ind("subprocess_chain_deep", subprocess_count=total, threshold=10)]


def _extract_import_network(norm: dict) -> list[Indicator]:
    conns = norm.get("network", {}).get("import_phase_connections", [])
    if not conns:
        return []
    return [_ind("import_triggered_network",
                 connections=conns[:5], count=len(conns),
                 phase="import")]


def _extract_install_timeout(norm: dict) -> list[Indicator]:
    status = norm.get("phases", {}).get("install", {}).get("status")
    if status != "timed_out":
        return []
    dur = norm.get("phases", {}).get("install", {}).get("duration_secs")
    return [_ind("install_timed_out", duration_secs=dur, phase="install")]


def _extract_install_hooks(norm: dict) -> list[Indicator]:
    hooks = norm.get("metadata", {}).get("install_hooks") or []
    if not hooks:
        return []
    return [_ind("install_hook_executed", hooks=hooks, phase="install")]


def _extract_baseline_diff(norm: dict) -> list[Indicator]:
    diff = norm.get("diff")
    if not diff or not diff.get("is_suspicious"):
        return []
    return [_ind("new_behavior_vs_baseline",
                 from_version=diff.get("from_version"),
                 to_version=diff.get("to_version"),
                 risk_delta=diff.get("risk_delta"),
                 new_domains=diff.get("new_domains", []),
                 new_ports=diff.get("new_ports", []))]


def _extract_file_discovery(norm: dict) -> list[Indicator]:
    file_ev = norm.get("telemetry", {}).get("file_events", [])
    paths   = [e.get("path", "") for e in file_ev if e.get("path")]
    hits    = [p for p in paths if _DISCOVERY_RE.match(p)]
    if len(hits) < _DISCOVERY_THRESHOLD:
        return []
    unique_dirs = sorted({"/".join(p.split("/")[:3]) for p in hits})
    return [_ind("file_system_discovery",
                 path_count=len(hits),
                 sample_dirs=unique_dirs[:5])]


def _extract_unusual_ports(norm: dict) -> list[Indicator]:
    network = norm.get("network", {})
    candidates = network.get("http_requests", []) + network.get("tls_sessions", [])
    unusual = [
        {"host": e.get("host"), "port": e.get("port")}
        for e in candidates
        if e.get("port") is not None and int(e["port"]) not in _STANDARD_PORTS
    ]
    if not unusual:
        return []
    return [_ind("exfiltration_unusual_port", connections=unusual[:5])]


def _extract_bait_access(norm: dict) -> list[Indicator]:
    planted = norm.get("bait_planted") or {}
    planted_paths = set(planted.get("planted_paths") or [])
    if not planted_paths:
        return []
    sens = norm.get("telemetry", {}).get("sensitive_file_events", [])
    accessed = {
        ev.get("path") for ev in sens
        if ev.get("path") in planted_paths
    }
    n = len(accessed)
    if n == 0:
        return []
    if n == 1:
        id_ = "bait_probe"
    elif n <= 3:
        id_ = "bait_enumeration"
    else:
        id_ = "bait_credential_harvest"
    return [_ind(id_, accessed_paths=sorted(accessed), total_planted=len(planted_paths))]


# ── public API ────────────────────────────────────────────────────────────────

_EXTRACTORS = [
    _extract_dns,
    _extract_http,
    _extract_tls,
    _extract_shell_spawn,
    _extract_python_c,
    _extract_obfuscation,
    _extract_sensitive_file,
    _extract_env_file,
    _extract_ssh_key,
    _extract_subprocess_chain,
    _extract_import_network,
    _extract_install_timeout,
    _extract_install_hooks,
    _extract_baseline_diff,
    _extract_file_discovery,
    _extract_unusual_ports,
    _extract_bait_access,
]


def extract_indicators(normalized: dict) -> list[Indicator]:
    """Derive security indicators from a normalized run dict.

    Each matched indicator maps to a MITRE ATT&CK tactic and technique and
    carries a weight used by ``score.score()`` for probabilistic combination.

    Returns a list sorted by weight descending (highest threat first).
    """
    indicators: list[Indicator] = []
    for extractor in _EXTRACTORS:
        indicators.extend(extractor(normalized))
    indicators.sort(key=lambda i: -i["weight"])
    return indicators


def catalog() -> dict[str, dict]:
    """Return a copy of the full indicator type catalogue."""
    return {k: dict(v) for k, v in _CATALOG.items()}
