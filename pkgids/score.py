"""Maliciousness scoring: additive point model mapping indicators to a 0–100 score.

Scoring weights (per Direction 4 spec):
    sensitive file / credential read     +25   outbound network beacon         +20
    subprocess shell / encoded command   +15   new suspicious baseline delta   +20
    install timeout / hook               +10   combo bonus (network + secret)  +25

Verdict thresholds (dynamic behavioral evidence only):
     0         no_malicious_behavior_observed  — no indicators detected
     1 – 24   low_risk                         — weak signals, below suspicious
    25 – 49   suspicious
    50 – 74   likely_malicious
    75 – 100  malicious

Note: "benign" is intentionally absent from the score-based verdict.
Zero dynamic signal means the sandbox observed nothing — not that the
package is proven safe.  Advisory intelligence (see advisory.py) may
further elevate the analyst-facing final_verdict in reporting.
"""

from __future__ import annotations

# ── per-indicator additive weights ────────────────────────────────────────────

_WEIGHTS: dict[str, int] = {
    # credential access
    "sensitive_file_accessed":       25,
    "ssh_key_accessed":              25,
    "env_file_read":                 25,
    # command-and-control / exfiltration
    "http_request_observed":         20,
    "dns_query_observed":            20,
    "import_triggered_network":      20,
    "new_behavior_vs_baseline":      20,
    "exfiltration_unusual_port":     20,
    # execution / evasion
    "tls_sni_extracted":             15,
    "shell_spawned_during_install":  15,
    "python_c_flag_used":            15,
    "base64_command_present":        15,
    # low-signal / supportive
    "subprocess_chain_deep":         10,
    "install_timed_out":             10,
    "install_hook_executed":         10,
    "file_system_discovery":         10,
}

# Indicator IDs that represent credential / secret-file access
_CREDENTIAL_IDS: frozenset[str] = frozenset({
    "sensitive_file_accessed", "ssh_key_accessed", "env_file_read",
})

# Indicator IDs that represent outbound network activity
_NETWORK_IDS: frozenset[str] = frozenset({
    "http_request_observed", "tls_sni_extracted",
    "import_triggered_network", "exfiltration_unusual_port",
})

# Combo bonus: outbound beacon observed alongside credential-file read
_EXFIL_COMBO_BONUS: int = 25

# ── verdict thresholds ────────────────────────────────────────────────────────

_THRESHOLDS: list[tuple[int, str]] = [
    (75, "malicious"),
    (50, "likely_malicious"),
    (25, "suspicious"),
    (1,  "low_risk"),
]


def score(indicators: list[dict]) -> int:
    """Additive maliciousness score clamped to [0, 100].

    Parameters
    ----------
    indicators:
        List of Indicator dicts (each must have an ``id`` key).

    Returns
    -------
    int in [0, 100].
    """
    if not indicators:
        return 0

    ids   = {i["id"] for i in indicators}
    total = sum(_WEIGHTS.get(i["id"], 0) for i in indicators)

    # Combo bonus: network beacon observed alongside a credential-file read
    if _CREDENTIAL_IDS & ids and _NETWORK_IDS & ids:
        total += _EXFIL_COMBO_BONUS

    return max(0, min(100, total))


def confidence(indicators: list[dict]) -> float:
    """Estimate confidence as a float in [0.0, 1.0].

    Reflects signal count and corroboration across tactic domains:
    - Single DNS query only              → ~0.18 (low)
    - File read + exec + HTTP request    → ~0.75+ (high)
    - Diff-only (no runtime evidence)    → 0.50   (medium)
    """
    if not indicators:
        return 0.0

    ids = {i["id"] for i in indicators}

    # Diff-only: regression signal without direct runtime observations
    if ids == {"new_behavior_vs_baseline"}:
        return 0.50

    n       = len(indicators)
    tactics = {i.get("tactic", "") for i in indicators}

    base      = min(n * 0.10, 0.60)             # 0.10 per indicator, cap 0.60
    diversity = min(len(tactics) * 0.08, 0.25)  # each unique tactic adds 0.08

    has_cred    = "credential-access"   in tactics
    has_network = bool({"command-and-control", "exfiltration"} & tactics)
    has_exec    = "execution"           in tactics

    if has_cred and has_network:
        corr = 0.15
    elif has_exec and has_network:
        corr = 0.08
    else:
        corr = 0.0

    return min(round(base + diversity + corr, 2), 1.0)


def score_breakdown(indicators: list[dict]) -> dict:
    """Per-indicator point contributions for the Verdict Rationale section.

    Returns
    -------
    dict with keys:
        items       — list of {id, title, severity, tactic, technique, phase, points}
                      sorted by points descending
        combo_bonus — _EXFIL_COMBO_BONUS if network + credential indicators both present
        total       — final clamped score (same as score(indicators))
    """
    if not indicators:
        return {"items": [], "combo_bonus": 0, "total": 0}

    ids = {i["id"] for i in indicators}
    items = []
    for ind in indicators:
        pts = _WEIGHTS.get(ind["id"], 0)
        if pts == 0:
            continue
        items.append({
            "id":        ind["id"],
            "title":     ind.get("title", ind["id"]),
            "severity":  ind.get("severity", "low"),
            "tactic":    ind.get("tactic", ""),
            "technique": ind.get("technique", ""),
            "phase":     (ind.get("evidence") or {}).get("phase", ""),
            "points":    pts,
        })
    items.sort(key=lambda x: -x["points"])

    combo = bool(_CREDENTIAL_IDS & ids and _NETWORK_IDS & ids)
    return {
        "items":       items,
        "combo_bonus": _EXFIL_COMBO_BONUS if combo else 0,
        "total":       score(indicators),
    }


def verdict(malice_score: int) -> str:
    """Map an additive score (0–100) to a behavioral verdict string.

    Returns
    -------
    "malicious"                      — score ≥ 75
    "likely_malicious"               — score ≥ 50
    "suspicious"                     — score ≥ 25
    "low_risk"                       — score 1–24
    "no_malicious_behavior_observed" — score 0 (no indicators detected)

    "benign" is deliberately absent: zero dynamic signal means the sandbox
    observed nothing, not that the package is proven safe.
    """
    if malice_score == 0:
        return "no_malicious_behavior_observed"
    for threshold, label in _THRESHOLDS:
        if malice_score >= threshold:
            return label
    return "no_malicious_behavior_observed"
