"""Structured reporting pipeline.

The report answers six analyst questions:
  1. What happened?            — narrative executive summary
  2. In which phase?           — per-indicator phase badge (install / import)
  3. Which process did it?     — process attribution from analyze.py correlations
  4. What file or secret?      — sensitive files + "followed by network" flag
  5. What host or domain?      — deduplicated domain list + responsible process
  6. Why was the verdict?      — score breakdown table (indicator → +N pts)
  7. How does this differ?     — baseline diff section

Pipeline
--------
1. ``normalize(run_dir)``   — read artifacts + run cross-stream analysis
2. ``build_report(norm)``   — indicators → score → narrative → breakdown
3. ``build_html_report()``  — six-question HTML page
4. ``report()``             — convenience wrapper
"""

from __future__ import annotations

import html as _html
import json
import shutil
from pathlib import Path

# Files copied into every portable export bundle (order preserved in HTML).
_ARTIFACT_NAMES = (
    "run.json",
    "metadata.json",
    "network.jsonl",
    "telemetry.jsonl",
    "behavior_profile.json",
    "diff.json",
    "correlations.json",
    "report.json",
    "capture.pcap",
)


# ── JSONL reader ──────────────────────────────────────────────────────────────

def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for raw in path.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return out


# ── normalization ─────────────────────────────────────────────────────────────

def normalize(
    run_dir: str | Path,
    diff: dict | None = None,
) -> dict:
    """Read all run artifacts and produce a single normalized data dict.

    Also runs ``analyze.analyze()`` to get cross-stream correlation data
    (which process initiated each network connection, file-before-exfil pairs,
    etc.).  Missing files or analysis errors are tolerated gracefully.
    """
    run_dir = Path(run_dir)

    # ── run.json ──────────────────────────────────────────────────────────────
    run_data: dict = {}
    try:
        run_data = json.loads((run_dir / "run.json").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # ── metadata.json ─────────────────────────────────────────────────────────
    # Primary location: run_dir/metadata.json (written there for some workflows).
    # Fallback: artifact dir derived from run.json's "artifact" field (the
    # standard location written by fetch.py).
    metadata: dict = {}
    _meta_path = run_dir / "metadata.json"
    if not _meta_path.exists():
        _artifact_str = run_data.get("artifact", "")
        if _artifact_str:
            _meta_path = Path(_artifact_str).parent / "metadata.json"
    try:
        metadata = json.loads(_meta_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # ── network.jsonl ─────────────────────────────────────────────────────────
    net  = _read_jsonl(run_dir / "network.jsonl")
    dns  = [e for e in net if e.get("type") == "dns"]
    http = [e for e in net if e.get("type") == "http"]
    tls  = [e for e in net if e.get("type") == "tls"]

    # ── telemetry.jsonl ───────────────────────────────────────────────────────
    tel         = _read_jsonl(run_dir / "telemetry.jsonl")
    exec_ev     = [e for e in tel if e.get("event_type") == "exec"]
    file_ev     = [e for e in tel if e.get("event_type") == "file"]
    socket_ev   = [e for e in tel if e.get("event_type") == "socket"]
    sens_ev     = [e for e in file_ev if e.get("sensitive")]
    import_conn = [e for e in socket_ev if e.get("phase") == "import"]

    # ── cross-stream correlation (analyze.py) ─────────────────────────────────
    correlations: dict = {}
    try:
        from .analyze import analyze as _analyze
        correlations = _analyze(run_dir)
    except Exception:
        pass

    # ── phase normalization ───────────────────────────────────────────────────
    phases_raw = run_data.get("phases", {})

    def _phase(key: str) -> dict:
        ph = phases_raw.get(key) or {}
        pa = ph.get("process_activity") or {}
        return {
            "status":           ph.get("status"),
            "exit_code":        ph.get("exit_code"),
            "duration_secs":    ph.get("duration_secs"),
            "process_count":    int(pa.get("process_count") or 0),
            "suspicious_execs": pa.get("suspicious_execs") or [],
            "sensitive_files":  pa.get("sensitive_file_accesses") or [],
            "any_suspicious":   bool(pa.get("any_suspicious")),
        }

    triggers_raw: list[dict] = run_data.get("triggers", [])

    return {
        "run": {
            "ecosystem": run_data.get("ecosystem"),
            "name":      run_data.get("name"),
            "version":   run_data.get("version"),
            "run_dir":   str(run_dir),
        },
        "metadata":  metadata,
        "advisory":  metadata.get("advisory") or {},
        "phases": {
            "install": _phase("install"),
            "import":  _phase("import"),
        },
        "triggers": triggers_raw,
        "network": {
            "dns_queries":              dns,
            "http_requests":            http,
            "tls_sessions":             tls,
            "import_phase_connections": import_conn,
        },
        "telemetry": {
            "exec_events":           exec_ev,
            "file_events":           file_ev,
            "socket_events":         socket_ev,
            "sensitive_file_events": sens_ev,
        },
        "event_counts": {
            "dns_queries":           len(dns),
            "http_requests":         len(http),
            "tls_sessions":          len(tls),
            "exec_events":           len(exec_ev),
            "file_events":           len(file_ev),
            "sensitive_file_events": len(sens_ev),
            "socket_events":         len(socket_ev),
        },
        "correlations": correlations,
        "diff": diff,
    }


# ── tactic formatting ─────────────────────────────────────────────────────────

_TACTIC_NAMES: dict[str, str] = {
    "command-and-control": "Command and Control",
    "credential-access":   "Credential Access",
    "execution":           "Execution",
    "defense-evasion":     "Defense Evasion",
    "persistence":         "Persistence",
    "exfiltration":        "Exfiltration",
    "discovery":           "Discovery",
    "collection":          "Collection",
    "initial-access":      "Initial Access",
}


def _format_tactic(tactic: str) -> str:
    return _TACTIC_NAMES.get(
        tactic,
        " ".join(w.capitalize() for w in tactic.replace("-", " ").split()),
    )


# ── phase summary (spec JSON format) ─────────────────────────────────────────

def _phases_summary(normalized: dict) -> dict:
    phases  = normalized.get("phases", {})
    network = normalized.get("network", {})
    has_any_network = (
        bool(network.get("dns_queries"))
        or bool(network.get("http_requests"))
        or bool(network.get("tls_sessions"))
    )
    result: dict = {}
    for name in ("install", "import"):
        ph      = phases.get(name, {})
        net_act = (
            bool(network.get("import_phase_connections"))
            if name == "import"
            else has_any_network
        )
        result[name] = {
            "exit_code":            ph.get("exit_code"),
            "status":               ph.get("status"),
            "network_activity":     net_act,
            "process_count":        ph.get("process_count", 0),
            "sensitive_file_reads": len(ph.get("sensitive_files", [])),
            "duration_secs":        ph.get("duration_secs"),
            "any_suspicious":       ph.get("any_suspicious", False),
        }
    return result


# ── narrative summary ─────────────────────────────────────────────────────────

def _build_narrative(
    indicators: list[dict],
    network: dict,
    telemetry: dict,
    correlations: dict,
) -> list[str]:
    """Generate plain-English sentences answering 'What happened?'

    Returns a list of 1–5 sentences, ordered from most critical to least.
    """
    sentences: list[str] = []

    all_targets = sorted({
        *(e.get("query") for e in network.get("dns_queries", [])),
        *(e.get("host")  for e in network.get("http_requests", [])),
        *(e.get("sni")   for e in network.get("tls_sessions", [])),
    } - {None})

    sens_paths = sorted({
        e.get("path") for e in telemetry.get("sensitive_file_events", [])
        if e.get("path")
    })

    file_exfil   = correlations.get("file_before_exfil", [])
    shell_net    = correlations.get("shell_before_network", [])
    sub_payloads = correlations.get("subprocess_payloads", [])

    # Most critical: file-before-exfil (direct exfiltration evidence)
    if file_exfil:
        files   = [p["file_read"].get("path", "?") for p in file_exfil[:2]]
        targets = [
            str(n.get("dst_ip", ""))
            for pair in file_exfil[:1]
            for n in pair.get("following_network", [])
            if n.get("dst_ip")
        ]
        dest = f" to {targets[0]}" if targets else ""
        sentences.append(
            f"Sensitive file access was immediately followed by outbound network "
            f"activity{dest} — a strong indicator of credential exfiltration "
            f"({', '.join(files)})."
        )

    # Shell spawn → network (C2 beacon or download)
    elif shell_net:
        n = len(shell_net)
        sentences.append(
            f"Shell command{'s' if n != 1 else ''} were executed and followed "
            f"by outbound network connections ({n} occurrence{'s' if n != 1 else ''})."
        )

    # Outbound network (no exfil correlation)
    if all_targets:
        if len(all_targets) == 1:
            sentences.append(
                f"The package made an outbound connection to {all_targets[0]}."
            )
        else:
            short = ", ".join(all_targets[:3])
            more  = f" and {len(all_targets) - 3} more" if len(all_targets) > 3 else ""
            sentences.append(
                f"The package contacted {len(all_targets)} external host"
                f"{'s' if len(all_targets) != 1 else ''}: {short}{more}."
            )

    # Sensitive file access (without exfil correlation already mentioned)
    if sens_paths and not file_exfil:
        if len(sens_paths) == 1:
            sentences.append(
                f"A sensitive file was accessed: {sens_paths[0]}."
            )
        else:
            short = ", ".join(sens_paths[:2])
            more  = f" and {len(sens_paths) - 2} more" if len(sens_paths) > 2 else ""
            sentences.append(
                f"{len(sens_paths)} sensitive files were accessed: {short}{more}."
            )

    # Subprocess chain spawned by installer
    if sub_payloads and not file_exfil and not shell_net:
        n = len(sub_payloads)
        sentences.append(
            f"The installer spawned {n} suspicious child "
            f"process{'es' if n != 1 else ''} during execution."
        )

    if not sentences:
        if not indicators:
            sentences.append(
                "No suspicious behavior was detected during install or import."
            )
        else:
            sentences.append(
                "Behavioral indicators were detected; see the findings below."
            )

    return sentences


# ── report builder ────────────────────────────────────────────────────────────

_BELOW_SUSPICIOUS: frozenset[str] = frozenset({
    "no_malicious_behavior_observed",
    "low_risk",
})


def _advisory_status(advisory: dict) -> str:
    """Summarise advisory enrichment as a single status string.

    "none"         — OSV query succeeded but no advisories matched this version
    "advisory_hit" — OSV returned one or more matching advisories
    "lookup_failed" — the OSV query failed or timed out (advisory_error is set)
    """
    if advisory.get("advisory_error"):
        return "lookup_failed"
    if advisory.get("advisory_hit"):
        return "advisory_hit"
    return "none"


def _combine_verdicts(behavioral_verdict: str, advisory_hit: bool) -> tuple[str, str]:
    """Return (final_verdict, verdict_basis).

    verdict_basis is one of: "dynamic" | "advisory" | "both"

    Advisory intelligence can only escalate, never lower:
    - no signal + advisory hit → "known_vulnerable"   (basis: "advisory")
    - low risk  + advisory hit → "known_vulnerable"   (basis: "advisory")
    - suspicious+ advisory hit → "suspicious"         (basis: "both")
    - higher    + advisory hit → unchanged            (basis: "both")
    - no advisory hit          → behavioral verdict   (basis: "dynamic")
    """
    if not advisory_hit:
        return behavioral_verdict, "dynamic"
    if behavioral_verdict in _BELOW_SUSPICIOUS:
        return "known_vulnerable", "advisory"
    return behavioral_verdict, "both"


def build_report(normalized: dict) -> dict:
    """Derive indicators, score, verdict, narrative, and score breakdown.

    Score is an additive integer in [0, 100]; confidence is a float in [0, 1].

    Three explicitly separated verdict fields are present in the output:

        behavioral_verdict — runtime evidence only (install/import/telemetry/network)
        advisory_status    — advisory-only status: "none" | "advisory_hit" | "lookup_failed"
        final_verdict      — combined analyst-facing verdict
        verdict            — alias for final_verdict (backward compat)
        verdict_basis      — how final_verdict was derived: "dynamic" | "advisory" | "both"
    """
    from .indicators import extract_indicators
    from .score import (
        score           as _score,
        confidence      as _conf,
        verdict         as _verdict,
        score_breakdown as _breakdown,
    )

    indicators          = extract_indicators(normalized)
    malice_score        = _score(indicators)
    behavioral_verdict  = _verdict(malice_score)
    conf_val            = _conf(indicators)
    breakdown           = _breakdown(indicators)

    advisory     = normalized.get("advisory") or {}
    adv_status   = _advisory_status(advisory)
    advisory_hit = bool(advisory.get("advisory_hit"))
    final_verdict, verdict_basis = _combine_verdicts(behavioral_verdict, advisory_hit)

    raw_tactics    = sorted({i["tactic"] for i in indicators})
    attack_tactics = [_format_tactic(t) for t in raw_tactics]
    techniques     = sorted({i["technique"] for i in indicators})

    run = normalized.get("run", {})
    narrative = _build_narrative(
        indicators,
        normalized.get("network", {}),
        normalized.get("telemetry", {}),
        normalized.get("correlations", {}),
    )
    if advisory_hit:
        ids_str = ", ".join(advisory.get("advisory_ids", [])[:5]) or "unknown"
        count   = advisory.get("advisory_count", 0)
        src     = advisory.get("advisory_source") or "unknown"
        narrative.append(
            f"Advisory intelligence ({src}): {count} known advisory record(s) "
            f"found for this package version ({ids_str}). "
            f"The sandbox did not observe the malicious behavior trigger during "
            f"this run — absence of runtime evidence does not clear the advisory."
        )

    # Per-trigger verdicts — lightweight: reuse existing extract/score on a
    # filtered view of telemetry keyed by the trigger's telemetry phase.
    _trigger_to_tel_phase = {
        "install":           "install",
        "install_with_deps": "install",
        "import_root":       "import",
        "import_submodule":  "import",
    }
    tel         = normalized.get("telemetry", {})
    net         = normalized.get("network", {})
    trigger_verdicts: list[dict] = []
    for trig in normalized.get("triggers", []):
        tid       = trig.get("trigger_id", "")
        tel_phase = _trigger_to_tel_phase.get(tid, tid)
        is_import = "import" in tid

        # Slice telemetry down to events from this trigger's phase.
        trig_exec   = [e for e in tel.get("exec_events",   []) if e.get("phase") == tel_phase]
        trig_file   = [e for e in tel.get("file_events",   []) if e.get("phase") == tel_phase]
        trig_socket = [e for e in tel.get("socket_events", []) if e.get("phase") == tel_phase]
        trig_sens   = [e for e in trig_file if e.get("sensitive")]

        pa = trig.get("process_activity") or {}
        trig_norm = {
            "run":      normalized.get("run"),
            "metadata": normalized.get("metadata"),
            "advisory": {},
            "phases": {
                tel_phase: {
                    "status":           trig.get("status"),
                    "exit_code":        trig.get("exit_code"),
                    "duration_secs":    None,
                    "process_count":    int(pa.get("process_count") or 0),
                    "suspicious_execs": pa.get("suspicious_execs") or [],
                    "sensitive_files":  pa.get("sensitive_file_accesses") or [],
                    "any_suspicious":   bool(pa.get("any_suspicious")),
                }
            },
            "network": {
                "dns_queries":              net.get("dns_queries",   []) if not is_import else [],
                "http_requests":            net.get("http_requests", []) if not is_import else [],
                "tls_sessions":             net.get("tls_sessions",  []) if not is_import else [],
                "import_phase_connections": net.get("import_phase_connections", []) if is_import else [],
            },
            "telemetry": {
                "exec_events":           trig_exec,
                "file_events":           trig_file,
                "socket_events":         trig_socket,
                "sensitive_file_events": trig_sens,
            },
            "event_counts":  {},
            "correlations":  {},
            "diff":          None,
        }
        trig_inds  = extract_indicators(trig_norm)
        trig_score = _score(trig_inds)
        trig_bv    = _verdict(trig_score)
        trigger_verdicts.append({
            "trigger_id":         tid,
            "phase_label":        trig.get("phase_label", tid),
            "status":             trig.get("status", "unknown"),
            "network_activity":   bool(trig.get("network_activity")),
            "process_activity":   pa,
            "behavioral_verdict": trig_bv,
            "score":              trig_score,
            "indicators":         trig_inds,
        })

    return {
        # public spec schema
        "package": {
            "ecosystem": run.get("ecosystem"),
            "name":      run.get("name"),
            "version":   run.get("version"),
        },
        # three explicitly separated verdict layers
        "behavioral_verdict": behavioral_verdict,
        "advisory_status":    adv_status,
        "final_verdict":      final_verdict,
        "verdict":            final_verdict,   # backward-compat alias
        "verdict_basis":      verdict_basis,
        "advisory":           advisory,
        "score":           malice_score,
        "confidence":      conf_val,
        "attack_tactics":  attack_tactics,
        "techniques":      techniques,
        "indicators":      indicators,
        "narrative":       narrative,
        "score_breakdown": breakdown,
        "summary": {
            "indicator_count": len(indicators),
            "critical": sum(1 for i in indicators if i["severity"] == "critical"),
            "high":     sum(1 for i in indicators if i["severity"] == "high"),
            "medium":   sum(1 for i in indicators if i["severity"] == "medium"),
            "low":      sum(1 for i in indicators if i["severity"] == "low"),
        },
        "trigger_verdicts": trigger_verdicts,
        "phases":        _phases_summary(normalized),
        "event_counts":  normalized.get("event_counts", {}),
        "metadata":      normalized.get("metadata", {}),
        "diff":          normalized.get("diff"),
        # internal keys for HTML renderer (not written to JSON output)
        "_run":           run,
        "_phases_detail": normalized.get("phases", {}),
        "_network":       normalized.get("network", {}),
        "_telemetry":     normalized.get("telemetry", {}),
        "_correlations":  normalized.get("correlations", {}),
        "_trigger_verdicts": trigger_verdicts,
    }


# ── HTML renderer ─────────────────────────────────────────────────────────────

_VERDICT_COLOR: dict[str, str] = {
    "malicious":                      "#c0392b",
    "likely_malicious":               "#e74c3c",
    "suspicious":                     "#e67e22",
    "known_vulnerable":               "#8e44ad",
    "low_risk":                       "#27ae60",
    "no_malicious_behavior_observed": "#7f8c8d",
    # kept for any legacy report dicts passed directly to build_html_report()
    "benign":                         "#27ae60",
}
_SEV_COLOR: dict[str, str] = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f39c12",
    "low":      "#2980b9",
}
_PHASE_COLOR: dict[str, str] = {
    "install": "#8e44ad",
    "import":  "#2471a3",
}
_THREAT_CLASS: dict[str, str] = {
    "malicious":                      "malicious",
    "likely_malicious":               "likely",
    "suspicious":                     "suspicious",
    "known_vulnerable":               "vulnerable",
    "low_risk":                       "benign",
    "no_malicious_behavior_observed": "benign",
    "benign":                         "benign",
}
_TACTIC_ID: dict[str, str] = {
    "Command and Control": "TA0011",
    "Execution":           "TA0002",
    "Persistence":         "TA0003",
    "Discovery":           "TA0007",
    "Credential Access":   "TA0006",
    "Defense Evasion":     "TA0005",
    "Exfiltration":        "TA0010",
    "Collection":          "TA0009",
    "Initial Access":      "TA0001",
    "Lateral Movement":    "TA0008",
    "Privilege Escalation":"TA0004",
    "Impact":              "TA0040",
    "Resource Development":"TA0042",
    "Reconnaissance":      "TA0043",
}


def _build_trigger_breakdown_section(
    trigger_verdicts: list[dict],
    e,  # html.escape
    verdict_color: dict[str, str],
) -> str:
    """Render the Trigger Breakdown HTML section (empty string when no triggers)."""
    if not trigger_verdicts:
        return ""
    rows = ""
    for tv in trigger_verdicts:
        bv     = tv.get("behavioral_verdict", "no_malicious_behavior_observed")
        color  = verdict_color.get(bv, "#7f8c8d")
        status = tv.get("status", "unknown")
        net    = "yes" if tv.get("network_activity") else "no"
        pa     = tv.get("process_activity") or {}
        procs  = pa.get("process_count", 0)
        susp   = "yes" if pa.get("any_suspicious") else "no"
        sc     = tv.get("score", 0)
        rows += (
            f'<tr>'
            f'<td><code>{e(tv.get("trigger_id",""))}</code>'
            f' <span class="dim">{e(tv.get("phase_label",""))}</span></td>'
            f'<td>{e(status)}</td>'
            f'<td>{net}</td>'
            f'<td class="t-num">{procs}</td>'
            f'<td><span style="color:{color};font-weight:600">'
            f'{e(bv.replace("_"," ").title())}</span></td>'
            f'<td class="t-num">{sc}</td>'
            f'</tr>\n'
        )
    return f"""
  <section class="section">
    <header><h2>Trigger breakdown</h2><span class="q">multi-trigger comparison</span></header>
    <div class="body">
      <table>
        <thead><tr>
          <th>Trigger</th><th>Status</th><th>Network</th>
          <th class="t-num">Processes</th><th>Behavioral verdict</th>
          <th class="t-num">Score</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </section>"""


def build_html_report(  # noqa: C901
    report_dict: dict,
    *,
    artifact_prefix: str | None = None,
) -> str:
    """Render a structured report as a self-contained HTML page.

    Sections are ordered around the six analyst questions:
      1. What happened?       → Executive Summary (narrative)
      2. Why this verdict?    → Score Breakdown table
      3. ATT&CK Tactics       → tactic chips + techniques
      4. What were indicators?→ Indicators table (phase-tagged)
      5. In which phase?      → Process Tree per phase
      6. What host/domain?    → Domains Contacted (+ process attribution)
      7. What file/secret?    → Sensitive Files (+ exfil flag)
      8. How does it differ?  → Behavior Delta
      9. Event Counts
     10. Raw Artifacts
    """
    e = _html.escape

    pkg             = report_dict.get("package") or report_dict.get("_run") or {}
    verdict_str     = report_dict.get("verdict", "unknown")
    behavioral_verdict = report_dict.get("behavioral_verdict",
                            report_dict.get("dynamic_verdict", verdict_str))
    adv_status      = report_dict.get("advisory_status", "none")
    verdict_basis   = report_dict.get("verdict_basis", "dynamic")
    advisory        = report_dict.get("advisory") or {}
    score_val       = int(report_dict.get("score", 0))
    confidence      = float(report_dict.get("confidence", 0.0))
    tactics         = report_dict.get("attack_tactics") or []
    techniques      = report_dict.get("techniques", [])
    indicators      = report_dict.get("indicators", [])
    summary         = report_dict.get("summary", {})
    event_counts    = report_dict.get("event_counts", {})
    phases          = report_dict.get("phases", {})
    metadata        = report_dict.get("metadata", {})
    diff            = report_dict.get("diff")
    narrative       = report_dict.get("narrative", [])
    breakdown       = report_dict.get("score_breakdown", {})

    phases_detail    = report_dict.get("_phases_detail", {})
    network          = report_dict.get("_network", {})
    telemetry        = report_dict.get("_telemetry", {})
    correlations     = report_dict.get("_correlations", {})
    run_detail       = report_dict.get("_run", pkg)
    trigger_verdicts = report_dict.get("_trigger_verdicts") or report_dict.get("trigger_verdicts", [])

    eco     = pkg.get("ecosystem") or "?"
    name    = pkg.get("name")      or "?"
    version = pkg.get("version")   or "?"
    pkg_id  = f"{e(eco)}:{e(name)}@{e(version)}"
    vcolor  = _VERDICT_COLOR.get(verdict_str, "#7f8c8d")
    verdict_label = verdict_str.replace("_", " ").upper()

    # ── helpers ───────────────────────────────────────────────────────────────
    def _pill(severity: str) -> str:
        cls = severity.lower() if severity.lower() in ("critical","high","medium","low") else "low"
        short = {"critical":"crit","high":"high","medium":"med","low":"low"}.get(cls, cls)
        return f'<span class="pill {cls}">{short}</span>'

    def _ptag(phase: str) -> str:
        if not phase:
            return '<span class="dim">—</span>'
        cls = phase if phase in ("install", "import") else ""
        cls_attr = f' class="ptag {cls}"' if cls else ' class="ptag"'
        return f'<span{cls_attr}>{e(phase)}</span>'

    def _meter_zone(s: int) -> str:
        if s >= 75: return "z4"
        if s >= 50: return "z3"
        if s >= 25: return "z2"
        return "z1"

    # ── 1. Narrative ──────────────────────────────────────────────────────────
    narrative_html = "\n".join(f"<p>{e(s)}</p>" for s in narrative) \
        or '<p class="muted">No summary available.</p>'
    verdict_summary = e(narrative[0]) if narrative else "No behavioral summary available."

    # ── 1b. Advisory / verdict breakdown section ──────────────────────────────
    adv_hit    = advisory.get("advisory_hit", False)
    adv_count  = advisory.get("advisory_count", 0)
    adv_src    = advisory.get("advisory_source") or "osv"
    adv_err    = advisory.get("advisory_error")
    adv_ids    = advisory.get("advisory_ids") or []
    adv_sums   = advisory.get("advisory_summaries") or []
    bv_color   = _VERDICT_COLOR.get(behavioral_verdict, "#7f8c8d")
    fv_color   = _VERDICT_COLOR.get(verdict_str, "#7f8c8d")
    basis_desc = {
        "dynamic":  "behavioral evidence only",
        "advisory": "advisory intelligence (no runtime trigger observed)",
        "both":     "behavioral evidence + advisory intelligence",
    }.get(verdict_basis, verdict_basis)

    adv_dot_color = "#c0392b" if adv_hit else ("#e67e22" if adv_err else "#27ae60")
    adv_note_txt  = (
        f"{e(adv_src)} · {adv_count} {'advisory' if adv_count == 1 else 'advisories'}"
        if not adv_err else f"lookup failed — {e(adv_err)}"
    )
    adv_label = (
        "HIT" if adv_hit else ("LOOKUP FAILED" if adv_err else "None")
    )

    adv_id_cells = "".join(
        f'<tr><td><code>{e(i)}</code></td>'
        f'<td class="ev">{e(s)}</td></tr>\n'
        for i, s in zip(adv_ids, adv_sums + [""] * len(adv_ids))
    )
    adv_table = (
        f'<table style="margin-top:14px"><thead><tr>'
        f'<th>ID / Alias</th><th>Summary</th></tr></thead>'
        f'<tbody>{adv_id_cells}</tbody></table>'
    ) if adv_id_cells else ""

    advisory_section = f"""
  <section class="section">
    <header><h2>Verdict breakdown</h2><span class="q">three-layer analysis</span></header>
    <div class="body">
      <div class="layers">
        <div class="layer">
          <label>Behavioral</label>
          <div class="val">
            <span class="mini-dot" style="background:{bv_color}"></span>
            {e(behavioral_verdict.replace("_"," ").title())}
          </div>
          <div class="note">from sandbox trace</div>
        </div>
        <div class="layer">
          <label>Advisory</label>
          <div class="val">
            <span class="mini-dot" style="background:{adv_dot_color}"></span>
            {e(adv_label)}
          </div>
          <div class="note">{adv_note_txt}</div>
        </div>
        <div class="layer final">
          <label>Final verdict</label>
          <div class="val">
            <span class="mini-dot" style="background:var(--threat)"></span>
            {e(verdict_str.replace("_"," ").title())}
          </div>
          <div class="note">basis: {e(basis_desc)}</div>
        </div>
      </div>
      <div class="basis-row">
        <span><b>Advisory source</b> · {e(adv_src)}</span>
        <span><b>Advisory count</b> · {adv_count}</span>
        <span><b>Verdict basis</b> · {e(basis_desc)}</span>
        {'<span style="color:#c0392b"><b>Lookup error</b> · ' + e(adv_err) + '</span>' if adv_err else ''}
      </div>
      {adv_table}
    </div>
  </section>"""

    # severity legend chips for hero
    sev_legend = ""
    for sev_name, sev_var in (("critical","--crit"),("high","--high"),("medium","--med"),("low","--low")):
        cnt = summary.get(sev_name, 0)
        zero_cls = " zero" if not cnt else ""
        sev_legend += (
            f'<div class="item{zero_cls}">'
            f'<span class="dot" style="background:var({sev_var})"></span>'
            f'{cnt} <b>{sev_name}</b></div>\n'
        )

    # ── 2. Score Breakdown ────────────────────────────────────────────────────
    bd_rows = ""
    for item in breakdown.get("items", []):
        sev  = item.get("severity", "low")
        ph   = item.get("phase", "")
        bd_rows += (
            f'<tr>'
            f'<td>{_pill(sev)}</td>'
            f'<td class="finding">{e(item.get("title",""))}</td>'
            f'<td class="dim">{e(item.get("tactic",""))}</td>'
            f'<td>{_ptag(ph)}</td>'
            f'<td class="t-num">+{item.get("points",0)}</td>'
            f'</tr>\n'
        )
    if breakdown.get("combo_bonus", 0):
        bd_rows += (
            f'<tr class="combo-row">'
            f'<td colspan="3"><em>Exfiltration combo bonus</em>'
            f' <small>(network observed after credential-file access)</small></td>'
            f'<td></td>'
            f'<td class="t-num">+{breakdown["combo_bonus"]}</td>'
            f'</tr>\n'
        )
    bd_rows += (
        f'<tr class="total-row">'
        f'<td colspan="4">Total score</td>'
        f'<td class="t-num">{score_val} / 100</td>'
        f'</tr>\n'
    )
    if not breakdown.get("items"):
        bd_rows = '<tr><td colspan="5" class="empty">No scoring contributions — no indicators detected.</td></tr>'

    # ── 3. ATT&CK tactics ─────────────────────────────────────────────────────
    tactic_chips = "".join(
        f'<span class="tactic">{e(t)} <span class="k">{e(_TACTIC_ID.get(t,""))}</span></span>'
        for t in tactics
    ) or '<span class="muted">none detected</span>'
    tech_row = (
        '<div class="tech-row">'
        '<span class="lbl dim">techniques</span>'
        + "".join(f'<code>{e(t)}</code>' for t in techniques)
        + "</div>"
    ) if techniques else ""

    # ── 4. Indicators table ───────────────────────────────────────────────────
    ind_rows = ""
    for ind in indicators:
        ev  = e(json.dumps(ind["evidence"], separators=(",", ":")))[:120]
        ph  = (ind.get("evidence") or {}).get("phase", "")
        ind_rows += (
            f'<tr>'
            f'<td>{_pill(ind["severity"])}</td>'
            f'<td class="finding">{e(ind["title"])}</td>'
            f'<td><code>{e(ind["technique"])}</code></td>'
            f'<td class="dim">{e(ind["tactic"])}</td>'
            f'<td>{_ptag(ph)}</td>'
            f'<td class="ev">{ev}</td>'
            f'</tr>\n'
        )
    if not ind_rows:
        ind_rows = '<tr><td colspan="6" class="empty">No indicators found</td></tr>'

    # ── 5. Process tree ───────────────────────────────────────────────────────
    proc_html = ""
    for ph_name, ph in phases_detail.items():
        execs = ph.get("suspicious_execs") or []
        proc_html += (
            f'<div class="phase-group">'
            f'<div class="phase-head">{_ptag(ph_name)}'
            f'<span class="name">{e(ph_name)} phase</span>'
            f'<span class="rule"></span></div>\n'
        )
        if execs:
            for ex in execs[:20]:
                argv = " ".join(str(a) for a in (ex.get("argv") or []))
                proc_html += (
                    f'<div class="proc-line"><code>{e(argv[:160])}</code></div>\n'
                )
        else:
            proc_html += '<div class="proc-empty">no suspicious processes recorded</div>\n'
        proc_html += '</div>\n'

    # Subprocess payload correlation
    sub_payloads = correlations.get("subprocess_payloads", [])
    if sub_payloads:
        proc_html += '<div class="corr-heading">Payload attribution</div>\n'
        for sp in sub_payloads[:5]:
            payload = sp.get("payload_exec", {})
            parent  = sp.get("potential_parent", {})
            p_argv  = " ".join(str(a) for a in (payload.get("argv") or []))
            par_exe = (parent or {}).get("exe", "?") if parent else "(unknown)"
            proc_html += (
                f'<div class="proc-line">'
                f'<span class="ptag" style="background:#c0392b;color:#fff;border-color:#c0392b">payload</span> '
                f'<code>{e(p_argv[:100])}</code> '
                f'<span class="dim">← spawned by {e(par_exe)}</span>'
                f'</div>\n'
            )

    # ── 6. Domains contacted (+ responsible process) ──────────────────────────
    # Build a lookup: dst_ip → process name from correlations
    proc_by_ip: dict[str, str] = {}
    for conn in correlations.get("network_attributed", []):
        ip  = conn.get("host") or conn.get("dst_ip") or ""
        rp  = conn.get("responsible_process")
        if ip and rp:
            exe = (rp.get("argv") or [rp.get("exe", "?")])[0]
            proc_by_ip[ip] = str(exe)

    domain_rows = ""
    seen: set[tuple] = set()
    for ev in network.get("dns_queries", []):
        key = ("dns", ev.get("query", ""))
        if key not in seen:
            seen.add(key)
            proc = proc_by_ip.get(ev.get("query", ""), "")
            domain_rows += (
                f'<tr><td>{e(ev.get("query","?"))}</td>'
                f'<td>DNS</td>'
                f'<td class="muted">{e(proc)}</td></tr>\n'
            )
    for ev in network.get("http_requests", []):
        key = ("http", ev.get("host", ""), str(ev.get("port", "")))
        if key not in seen:
            seen.add(key)
            host = ev.get("host", "?")
            port_str = f':{ev["port"]}' if ev.get("port") and ev["port"] not in (80,) else ""
            proc = proc_by_ip.get(host, "")
            domain_rows += (
                f'<tr><td>{e(host)}{e(port_str)}</td>'
                f'<td>HTTP</td>'
                f'<td class="muted">{e(proc)}</td></tr>\n'
            )
    for ev in network.get("tls_sessions", []):
        key = ("tls", ev.get("sni", ""))
        if key not in seen:
            seen.add(key)
            sni  = ev.get("sni", "?")
            proc = proc_by_ip.get(sni, "")
            domain_rows += (
                f'<tr><td>{e(sni)}</td>'
                f'<td>TLS/SNI</td>'
                f'<td class="muted">{e(proc)}</td></tr>\n'
            )
    if not domain_rows:
        domain_rows = '<tr><td colspan="3" class="muted">No outbound connections recorded</td></tr>'

    # ── 7. Sensitive files (+ exfil flag) ─────────────────────────────────────
    # Build set of paths that appeared in a file-before-exfil pair
    exfil_paths: set[str] = {
        pair["file_read"].get("path", "")
        for pair in correlations.get("file_before_exfil", [])
        if pair.get("file_read")
    }

    sens_rows = ""
    seen_paths: set[str] = set()
    for ev in telemetry.get("sensitive_file_events", []):
        path = ev.get("path", "")
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        mode      = ev.get("mode") or ev.get("flags") or "read"
        exfil_tag = (
            '<span class="phase-badge" style="background:#c0392b" '
            'title="Followed by network activity within 5s">→ network</span>'
            if path in exfil_paths else ""
        )
        sens_rows += (
            f'<tr><td><code>{e(path)}</code></td>'
            f'<td>{e(str(mode))}</td>'
            f'<td>{exfil_tag}</td></tr>\n'
        )
    if not sens_rows:
        sens_rows = '<tr><td colspan="3" class="muted">No sensitive files accessed</td></tr>'

    # ── 8. Behavior delta ─────────────────────────────────────────────────────
    diff_section = ""
    if diff:
        nd = ", ".join(e(d) for d in (diff.get("new_domains") or [])) or "none"
        np = ", ".join(str(p) for p in (diff.get("new_ports") or []))   or "none"
        findings_list = diff.get("findings") or []
        finding_rows = "".join(
            f'<tr>'
            f'<td><span class="sev-badge sev-{e(f.get("severity","low"))}">'
            f'{e(f.get("severity","low"))}</span></td>'
            f'<td class="finding-kind">{e(f.get("kind",""))}</td>'
            f'<td class="finding-msg">{e(f.get("message",""))}</td>'
            f'</tr>\n'
            for f in findings_list[:10]
        )
        overflow_note = (
            f'<p class="muted" style="font-size:11px;margin-top:6px">'
            f'{e(str(len(findings_list) - 10))} more finding(s) — see diff.json</p>'
            if len(findings_list) > 10 else ""
        )
        findings_table = (
            f'<table class="diff-findings-table">{finding_rows}</table>{overflow_note}'
            if findings_list else ""
        )
        diff_section = f"""
  <section class="section">
    <header><h2>How does this differ from prior versions?</h2><span class="q">behavior delta</span></header>
    <div class="body">
      <table class="diff-table">
        <tr><td>From version</td><td>{e(str(diff.get("from_version") or "—"))}</td></tr>
        <tr><td>To version</td><td>{e(str(diff.get("to_version") or "—"))}</td></tr>
        <tr><td>Risk delta</td><td><strong>{e(str(diff.get("risk_delta") or "—"))}</strong></td></tr>
        <tr><td>New domains</td><td>{nd}</td></tr>
        <tr><td>New ports</td><td>{np}</td></tr>
      </table>
      {findings_table}
    </div>
  </section>"""

    # ── 9. Event counts → stat-grid cells ────────────────────────────────────
    stat_cells = ""
    for k, v in event_counts.items():
        zero_cls = " zero" if not v else ""
        stat_cells += (
            f'<div class="stat{zero_cls}">'
            f'<div class="n">{v}</div>'
            f'<div class="k">{e(k.replace("_"," "))}</div>'
            f'</div>\n'
        )
    if not stat_cells:
        stat_cells = '<div class="stat zero"><div class="n">0</div><div class="k">no events</div></div>'

    # ── 10. Raw artifact links ─────────────────────────────────────────────────
    _file_ico = (
        '<svg class="ico" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
        '<path d="M3 2h6l4 4v8H3z"/><path d="M9 2v4h4"/></svg>'
    )
    run_dir_str    = run_detail.get("run_dir", "")
    artifact_links = ""
    if run_dir_str:
        for fname in _ARTIFACT_NAMES:
            fpath  = Path(run_dir_str).resolve() / fname
            # Portable exports pass a relative prefix; otherwise fall back to
            # an absolute file:// URI (server-local only).
            if artifact_prefix is not None:
                href = f"{artifact_prefix}{fname}"
            else:
                href = fpath.as_uri()
            if fpath.exists():
                artifact_links += (
                    f'<li>{_file_ico}<a href="{e(href)}">{e(fname)}</a></li>\n'
                )
            else:
                artifact_links += (
                    f'<li class="empty-art">{_file_ico}'
                    f'<a href="{e(href)}">{e(fname)}</a>'
                    f'<span class="badge">missing</span></li>\n'
                )

    # ── metadata ───────────────────────────────────────────────────────────────
    hooks     = metadata.get("install_hooks") or []
    hooks_str = ", ".join(e(h) for h in hooks) if hooks else "none"
    file_cnt  = metadata.get("file_count", "—")
    phase_rows = ""
    for ph_name, ph in phases.items():
        status = ph.get("status") or "—"
        exit_c = ph.get("exit_code")
        dur    = ph.get("duration_secs")
        susp   = "yes" if ph.get("any_suspicious") else "no"
        net    = "yes" if ph.get("network_activity") else "no"
        sens   = ph.get("sensitive_file_reads", 0)
        status_color = (
            "var(--crit)" if status in ("failed","error") else
            "var(--med)"  if status == "timed_out" else
            "var(--muted)"
        )
        phase_rows += (
            f'<tr>'
            f'<td>{_ptag(ph_name)}</td>'
            f'<td style="color:{status_color}">{e(status)}</td>'
            f'<td class="t-num">{exit_c if exit_c is not None else "—"}</td>'
            f'<td class="t-num">{"%.1fs" % dur if dur is not None else "—"}</td>'
            f'<td>{net}</td>'
            f'<td class="t-num">{sens}</td>'
            f'<td class="dim">{susp}</td></tr>\n'
        )

    # ── threat / meter ─────────────────────────────────────────────────────────
    threat_cls  = _THREAT_CLASS.get(verdict_str, "likely")
    active_zone = _meter_zone(score_val)
    run_id      = run_detail.get("run_dir", "").rsplit("/", 1)[-1] or "—"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pkgids report — {pkg_id}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{{
  --ink:#181b20;--ink-2:#41474f;--muted:#8a929c;--faint:#b7bdc5;
  --line:#e5e8ec;--line-2:#eef0f3;--paper:#f5f6f8;--card:#ffffff;--tint:#f8f9fb;
  --crit:#a51d1d;--crit-t:#fbecec;
  --high:#b5560c;--high-t:#fbf0e6;
  --med:#8a6410; --med-t:#faf3e1;
  --low:#245e9e; --low-t:#eaf1f9;
  --ok:#2c6e49;  --ok-t:#e8f2ec;
  --vuln:#6d28d9;--vuln-t:#ede9fe;
  --threat:var(--high);--threat-t:var(--high-t);
  --shadow:0 1px 2px rgba(20,26,34,.04),0 1px 3px rgba(20,26,34,.06);
}}
body[data-threat="benign"]{{--threat:var(--ok);--threat-t:var(--ok-t)}}
body[data-threat="suspicious"]{{--threat:var(--med);--threat-t:var(--med-t)}}
body[data-threat="likely"]{{--threat:var(--high);--threat-t:var(--high-t)}}
body[data-threat="malicious"]{{--threat:var(--crit);--threat-t:var(--crit-t)}}
body[data-threat="vulnerable"]{{--threat:var(--vuln);--threat-t:var(--vuln-t)}}
*,*::before,*::after{{box-sizing:border-box}}
html{{-webkit-text-size-adjust:100%}}
body{{margin:0;background:var(--paper);color:var(--ink);
  font-family:"IBM Plex Sans",system-ui,sans-serif;
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}}
.mono{{font-family:"IBM Plex Mono",ui-monospace,monospace}}
.sheet{{max-width:1040px;margin:0 auto;padding:0 26px 72px}}
/* masthead */
.masthead{{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;
  padding:26px 0 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}}
.brand{{display:flex;align-items:center;gap:11px}}
.brand .glyph{{width:30px;height:30px;border-radius:7px;flex:none;
  background:var(--ink);color:#fff;display:grid;place-items:center;
  font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:15px}}
.brand .wordmark{{font-family:"IBM Plex Mono",monospace;font-weight:600;
  font-size:15px;letter-spacing:.02em}}
.brand .tagline{{font-size:12px;color:var(--muted);letter-spacing:.02em;margin-top:1px}}
.run-meta{{text-align:right;font-size:12px;color:var(--muted);line-height:1.7}}
.run-meta b{{color:var(--ink-2);font-weight:600}}
/* hero */
.hero{{display:grid;grid-template-columns:1.55fr 1fr;gap:0;
  background:var(--card);border:1px solid var(--line);border-radius:12px;
  margin-top:22px;box-shadow:var(--shadow);overflow:hidden}}
.hero-main{{padding:26px 28px 24px;border-left:4px solid var(--threat)}}
.eyebrow{{font-family:"IBM Plex Mono",monospace;font-size:11px;
  letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}}
.pkg-id{{font-family:"IBM Plex Mono",monospace;font-size:15px;color:var(--ink-2);
  word-break:break-all;margin-bottom:18px}}
.pkg-id .eco{{color:var(--muted)}}
.verdict-flag{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
.threat-dot{{width:12px;height:12px;border-radius:50%;flex:none;background:var(--threat);
  box-shadow:0 0 0 4px var(--threat-t)}}
.verdict-label{{font-size:26px;font-weight:700;letter-spacing:-.01em;line-height:1.1;color:var(--ink)}}
.verdict-basis{{font-size:12.5px;color:var(--muted);margin-top:2px}}
.verdict-summary{{font-size:14.5px;color:var(--ink-2);margin:0 0 20px;max-width:56ch}}
.verdict-summary b{{color:var(--ink);font-weight:600}}
.facts{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;
  background:var(--line-2);border:1px solid var(--line-2);border-radius:8px;overflow:hidden}}
.fact{{background:var(--card);padding:10px 13px}}
.fact label{{display:block;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--muted);margin-bottom:3px;font-weight:500}}
.fact span{{font-size:14px;font-weight:600;color:var(--ink)}}
/* score panel */
.hero-score{{padding:26px 26px 24px;background:var(--tint);
  display:flex;flex-direction:column;gap:18px;border-left:1px solid var(--line)}}
.score-num{{display:flex;align-items:baseline;gap:8px}}
.score-num .big{{font-family:"IBM Plex Mono",monospace;font-size:44px;font-weight:600;
  line-height:1;color:var(--threat);letter-spacing:-.02em}}
.score-num .den{{font-family:"IBM Plex Mono",monospace;font-size:18px;color:var(--faint)}}
.score-num .cap{{margin-left:auto;font-size:11px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);text-align:right;line-height:1.5}}
.score-num .cap b{{display:block;color:var(--ink-2);font-size:13px;font-weight:600;
  letter-spacing:0;text-transform:none}}
.meter{{margin-top:2px}}
.meter-track{{display:flex;height:8px;border-radius:5px;overflow:hidden;gap:2px}}
.meter-track i{{flex:1;opacity:.28}}
.meter-track i.z1{{background:var(--ok)}}
.meter-track i.z2{{background:var(--med)}}
.meter-track i.z3{{background:var(--high)}}
.meter-track i.z4{{background:var(--crit)}}
.meter-track i.on{{opacity:1}}
.meter-scale{{position:relative;height:16px;margin-top:7px}}
.meter-needle{{position:absolute;top:-14px;width:2px;height:15px;background:var(--ink);
  transform:translateX(-1px)}}
.meter-needle::after{{content:"";position:absolute;top:-4px;left:-3px;width:8px;height:8px;
  border-radius:50%;background:var(--ink)}}
.meter-labels{{display:flex;justify-content:space-between;font-size:10px;color:var(--muted);
  font-family:"IBM Plex Mono",monospace;letter-spacing:.02em}}
.sev-legend{{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;padding-top:16px;
  border-top:1px solid var(--line)}}
.sev-legend .item{{display:flex;align-items:center;gap:6px;color:var(--ink-2)}}
.sev-legend .item b{{font-family:"IBM Plex Mono",monospace;font-weight:600}}
.sev-legend .dot{{width:8px;height:8px;border-radius:2px;flex:none}}
.sev-legend .item.zero{{color:var(--faint)}}
.sev-legend .item.zero .dot{{background:var(--faint)!important}}
/* sections */
main{{counter-reset:sec}}
.section{{background:var(--card);border:1px solid var(--line);border-radius:12px;
  margin-top:16px;box-shadow:var(--shadow);overflow:hidden;break-inside:avoid}}
.section>header{{display:flex;align-items:baseline;gap:12px;padding:16px 24px 14px;
  border-bottom:1px solid var(--line-2)}}
.section>header::before{{counter-increment:sec;content:counter(sec,decimal-leading-zero);
  font-family:"IBM Plex Mono",monospace;font-size:12px;font-weight:600;color:var(--threat);
  letter-spacing:.04em}}
.section>header h2{{margin:0;font-size:15px;font-weight:600;letter-spacing:-.005em;color:var(--ink)}}
.section>header .q{{margin-left:auto;font-size:11.5px;color:var(--muted);
  font-family:"IBM Plex Mono",monospace;letter-spacing:.02em}}
.body{{padding:18px 24px 22px}}
.lead{{font-size:14.5px;color:var(--ink-2);margin:0 0 4px;max-width:70ch}}
p{{margin:.4em 0;line-height:1.55;color:var(--ink-2)}}
/* verdict breakdown layers */
.layers{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:6px}}
.layer{{border:1px solid var(--line);border-radius:9px;padding:13px 15px;background:var(--tint)}}
.layer.final{{border-color:var(--threat);background:var(--threat-t)}}
.layer label{{display:block;font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--muted);margin-bottom:7px;font-weight:600}}
.layer .val{{font-size:15px;font-weight:600;color:var(--ink);display:flex;align-items:center;gap:7px}}
.layer .note{{font-size:11.5px;color:var(--muted);margin-top:5px}}
.mini-dot{{width:8px;height:8px;border-radius:50%;flex:none}}
.basis-row{{font-size:12.5px;color:var(--muted);margin-top:14px;display:flex;gap:22px;flex-wrap:wrap}}
.basis-row span b{{color:var(--ink-2);font-weight:600}}
/* tables */
table{{width:100%;border-collapse:collapse;font-size:13.5px}}
thead th{{text-align:left;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);font-weight:600;padding:0 12px 8px;border-bottom:1px solid var(--line)}}
tbody td{{padding:11px 12px;border-bottom:1px solid var(--line-2);vertical-align:middle;color:var(--ink-2)}}
tbody tr:last-child td{{border-bottom:none}}
td:first-child,th:first-child{{padding-left:2px}}
td:last-child,th:last-child{{padding-right:2px}}
.t-num{{text-align:right;font-family:"IBM Plex Mono",monospace;color:var(--ink);font-weight:500}}
.finding{{color:var(--ink);font-weight:500}}
.combo-row td{{background:var(--med-t);font-style:italic;color:var(--med)}}
.total-row td{{border-top:1.5px solid var(--line);padding-top:13px;color:var(--ink);font-weight:600}}
.total-row .t-num{{font-size:15px;color:var(--threat);font-weight:600}}
.dim{{color:var(--muted)}}
.empty{{color:var(--faint);font-style:normal;padding:14px 2px}}
/* severity pills */
.pill{{display:inline-flex;align-items:center;gap:5px;font-family:"IBM Plex Mono",monospace;
  font-size:10.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  padding:3px 9px 3px 7px;border-radius:20px;border:1px solid transparent;white-space:nowrap}}
.pill::before{{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}}
.pill.critical{{color:var(--crit);background:var(--crit-t)}}
.pill.high{{color:var(--high);background:var(--high-t)}}
.pill.medium{{color:var(--med);background:var(--med-t)}}
.pill.low{{color:var(--low);background:var(--low-t)}}
/* phase tags */
.ptag{{display:inline-block;font-family:"IBM Plex Mono",monospace;font-size:10.5px;font-weight:500;
  letter-spacing:.04em;padding:2px 8px;border-radius:5px;border:1px solid var(--line);color:var(--ink-2)}}
.ptag.install{{color:#6b3fa0;border-color:#e5daf2;background:#f7f2fc}}
.ptag.import{{color:#1f6f8b;border-color:#d5e9ef;background:#eff7fa}}
code,.code{{font-family:"IBM Plex Mono",monospace;font-size:12px;background:var(--tint);
  border:1px solid var(--line);padding:1px 6px;border-radius:5px;color:var(--ink-2);word-break:break-all}}
.ev{{font-family:"IBM Plex Mono",monospace;font-size:11.5px;color:var(--muted);
  max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
/* ATT&CK */
.tactic-row{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}}
.tactic{{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:500;
  color:var(--ink-2);background:var(--tint);border:1px solid var(--line);border-radius:7px;padding:6px 12px}}
.tactic .k{{font-family:"IBM Plex Mono",monospace;font-size:10px;color:var(--muted);letter-spacing:.03em}}
.tech-row{{display:flex;flex-wrap:wrap;gap:7px;align-items:center;font-size:12px;color:var(--muted)}}
.tech-row .lbl{{font-family:"IBM Plex Mono",monospace;letter-spacing:.04em}}
/* process tree */
.phase-group{{margin-bottom:14px}}
.phase-group:last-child{{margin-bottom:0}}
.phase-head{{display:flex;align-items:center;gap:9px;margin-bottom:8px}}
.phase-head .name{{font-family:"IBM Plex Mono",monospace;font-size:12px;font-weight:600;
  letter-spacing:.04em;text-transform:uppercase;color:var(--ink-2)}}
.phase-head .rule{{flex:1;height:1px;background:var(--line-2)}}
.proc-line{{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--ink-2);
  padding:2px 0 2px 20px;white-space:pre-wrap;word-break:break-all}}
.proc-empty{{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--faint);
  padding-left:18px;position:relative}}
.proc-empty::before{{content:"└";position:absolute;left:2px;color:var(--line)}}
.corr-heading{{font-weight:600;font-size:12px;color:var(--ink-2);
  margin-top:14px;border-top:1px dashed var(--line);padding-top:8px}}
/* stat grid */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:1px;
  background:var(--line-2);border:1px solid var(--line-2);border-radius:9px;overflow:hidden}}
.stat{{background:var(--card);padding:14px 12px;text-align:center}}
.stat .n{{font-family:"IBM Plex Mono",monospace;font-size:22px;font-weight:600;color:var(--ink)}}
.stat.zero .n{{color:var(--faint)}}
.stat .k{{font-size:10.5px;color:var(--muted);margin-top:3px;letter-spacing:.02em;line-height:1.3}}
/* artifacts */
.arts{{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:1fr 1fr;gap:2px 24px}}
.arts li{{display:flex;align-items:center;gap:9px;padding:7px 2px;border-bottom:1px solid var(--line-2)}}
.ico{{width:15px;height:15px;flex:none;color:var(--muted)}}
.arts a{{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--ink-2);
  text-decoration:none;font-weight:500}}
.arts a:hover{{color:var(--threat);text-decoration:underline}}
.arts li.empty-art a{{color:var(--faint)}}
.arts .badge{{margin-left:auto;font-size:10px;font-family:"IBM Plex Mono",monospace;
  color:var(--faint);letter-spacing:.04em}}
/* diff */
.diff-table td:first-child{{font-weight:600;color:var(--ink-2);width:130px}}
.sev-badge{{font-size:10px;font-family:"IBM Plex Mono",monospace;font-weight:600;
  letter-spacing:.04em;border-radius:4px;padding:2px 6px;text-transform:uppercase;white-space:nowrap}}
.sev-badge.sev-critical{{background:var(--threat);color:#fff}}
.sev-badge.sev-high{{background:#e67e22;color:#fff}}
.sev-badge.sev-medium{{background:#f0b429;color:#1a1a1a}}
.sev-badge.sev-low{{background:var(--tint);color:var(--ink-2)}}
.diff-findings-table{{width:100%;border-collapse:collapse;margin-top:12px}}
.diff-findings-table td{{padding:5px 8px;border-bottom:1px solid var(--line-2);font-size:12.5px;
  vertical-align:top}}
.diff-findings-table tr:last-child td{{border-bottom:none}}
.diff-findings-table .finding-kind{{font-family:"IBM Plex Mono",monospace;font-size:11px;
  color:var(--ink-2);white-space:nowrap;padding-right:12px}}
.diff-findings-table .finding-msg{{color:var(--ink)}}
/* footer */
.report-footer{{display:flex;justify-content:space-between;align-items:center;gap:16px;
  margin-top:26px;padding-top:16px;border-top:1px solid var(--line);
  font-size:11.5px;color:var(--muted);font-family:"IBM Plex Mono",monospace;flex-wrap:wrap}}
@media(max-width:820px){{
  .hero{{grid-template-columns:1fr}}
  .hero-score{{border-left:none;border-top:1px solid var(--line)}}
  .layers{{grid-template-columns:1fr}}
  .stat-grid{{grid-template-columns:repeat(4,1fr)}}
  .facts{{grid-template-columns:repeat(2,1fr)}}
  .arts{{grid-template-columns:1fr}}
}}
@page{{size:A4;margin:14mm}}
@media print{{
  body{{background:#fff;font-size:11px}}
  .sheet{{max-width:none;padding:0}}
  .section,.hero{{box-shadow:none;break-inside:avoid}}
}}
</style>
</head>
<body data-threat="{threat_cls}">
<div class="sheet">

<header class="masthead">
  <div class="brand">
    <div class="glyph">&#9670;</div>
    <div>
      <div class="wordmark">pkgids</div>
      <div class="tagline">package install &amp; behavior analysis</div>
    </div>
  </div>
  <div class="run-meta">
    <div>run <b>{e(run_id)}</b></div>
    <div>engine v0.1.0 &middot; sandbox trace</div>
  </div>
</header>

<section class="hero">
  <div class="hero-main">
    <div class="eyebrow">Verdict</div>
    <div class="pkg-id"><span class="eco">{e(eco)}:</span>{e(name)}<b>@{e(version)}</b></div>
    <div class="verdict-flag">
      <span class="threat-dot"></span>
      <div>
        <div class="verdict-label">{e(verdict_str.replace("_"," ").title())}</div>
        <div class="verdict-basis">{e(basis_desc)}</div>
      </div>
    </div>
    <p class="verdict-summary">{verdict_summary}</p>
    <div class="facts">
      <div class="fact"><label>Ecosystem</label><span>{e(eco.title())}</span></div>
      <div class="fact"><label>Package</label><span>{e(name)}</span></div>
      <div class="fact"><label>Version</label><span class="mono">{e(version)}</span></div>
      <div class="fact"><label>Indicators</label><span class="mono">{summary.get("indicator_count",0)}</span></div>
      <div class="fact"><label>Install hook</label><span>{hooks_str}</span></div>
      <div class="fact"><label>Files in artifact</label><span class="mono">{file_cnt}</span></div>
    </div>
  </div>
  <aside class="hero-score">
    <div>
      <div class="score-num">
        <span class="big">{score_val}</span><span class="den">/100</span>
        <span class="cap">threat score<b>{e(verdict_str.replace("_"," ").title())} band</b></span>
      </div>
      <div class="meter">
        <div class="meter-track">
          <i class="z1{' on' if active_zone=='z1' else ''}"></i>
          <i class="z2{' on' if active_zone=='z2' else ''}"></i>
          <i class="z3{' on' if active_zone=='z3' else ''}"></i>
          <i class="z4{' on' if active_zone=='z4' else ''}"></i>
        </div>
        <div class="meter-scale"><div class="meter-needle" style="left:{score_val}%"></div></div>
        <div class="meter-labels"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
      </div>
    </div>
    <div>
      <div class="score-num" style="margin-bottom:2px">
        <span class="cap" style="margin-left:0;text-align:left">confidence</span>
        <span class="mono" style="margin-left:auto;font-size:20px;font-weight:600;color:var(--ink)">{confidence:.2f}</span>
      </div>
    </div>
    <div class="sev-legend">
      {sev_legend}
    </div>
  </aside>
</section>

<main>

{advisory_section}

  <section class="section">
    <header><h2>Score breakdown</h2><span class="q">why this verdict</span></header>
    <div class="body">
      <table>
        <thead><tr>
          <th>Severity</th><th>Finding</th><th>Tactic</th><th>Phase</th><th class="t-num">Points</th>
        </tr></thead>
        <tbody>{bd_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <header><h2>ATT&amp;CK mapping</h2><span class="q">tactics &amp; techniques</span></header>
    <div class="body">
      <div class="tactic-row">{tactic_chips}</div>
      {tech_row}
    </div>
  </section>

  <section class="section">
    <header><h2>Indicators</h2><span class="q">detailed findings</span></header>
    <div class="body">
      <table>
        <thead><tr>
          <th>Sev</th><th>Indicator</th><th>Technique</th>
          <th>Tactic</th><th>Phase</th><th>Evidence</th>
        </tr></thead>
        <tbody>{ind_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <header><h2>Process tree</h2><span class="q">by phase</span></header>
    <div class="body">
      {proc_html if proc_html else '<span class="dim">No phase data</span>'}
    </div>
  </section>

  <section class="section">
    <header><h2>Network activity</h2><span class="q">hosts &amp; domains contacted</span></header>
    <div class="body">
      <table>
        <thead><tr>
          <th>Domain / Host</th><th>Protocol</th><th>Initiated by</th>
        </tr></thead>
        <tbody>{domain_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <header><h2>Sensitive file access</h2><span class="q">files &amp; secrets touched</span></header>
    <div class="body">
      <table>
        <thead><tr><th>Path</th><th>Mode</th><th>Flags</th></tr></thead>
        <tbody>{sens_rows}</tbody>
      </table>
    </div>
  </section>
  {diff_section}
  {_build_trigger_breakdown_section(trigger_verdicts, e, _VERDICT_COLOR)}

  <section class="section">
    <header><h2>Phase summary</h2><span class="q">execution lifecycle</span></header>
    <div class="body">
      <table>
        <thead><tr>
          <th>Phase</th><th>Status</th><th class="t-num">Exit</th><th class="t-num">Duration</th>
          <th>Network</th><th class="t-num">Sensitive reads</th><th>Suspicious</th>
        </tr></thead>
        <tbody>{phase_rows if phase_rows else
                '<tr><td colspan="7" class="empty">No phase data</td></tr>'}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <header><h2>Event counts</h2><span class="q">raw telemetry volume</span></header>
    <div class="body">
      <div class="stat-grid">{stat_cells}</div>
    </div>
  </section>

  <section class="section">
    <header><h2>Raw artifacts</h2><span class="q">run {e(run_id)}</span></header>
    <div class="body">
      {f'<ul class="arts">{artifact_links}</ul>'
        if artifact_links else '<span class="dim">Run directory not available</span>'}
    </div>
  </section>

  <footer class="report-footer">
    <span>pkgids &middot; package install &amp; behavior analysis</span>
    <span>generated {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
  </footer>

</main>
</div>
</body>
</html>"""


# ── portable export bundle ────────────────────────────────────────────────────

def export_bundle(
    run_dir: str | Path,
    report_dict: dict,
    *,
    export_root: str | Path | None = None,
) -> Path:
    """Copy run artifacts into a self-contained, portable export directory.

    Layout::

        <export_root>/<run-id>/
            report.html        ← portable HTML (relative artifact links)
            report.json        ← public report fields
            artifacts/
                run.json
                telemetry.jsonl
                … (all files that exist in run_dir)

    Parameters
    ----------
    run_dir:
        The run directory produced by ``capture.run()``.
    report_dict:
        Pre-built report dict from ``build_report()`` / ``report()``.
    export_root:
        Parent directory for the bundle.  Defaults to
        ``<run_dir>/../../exports/`` (i.e. a sibling of ``runs/``).

    Returns
    -------
    Path
        The bundle directory that was created / updated.
    """
    run_dir  = Path(run_dir).resolve()
    run_id   = run_dir.name
    if export_root is None:
        export_root = run_dir.parent.parent / "exports"
    bundle_dir = Path(export_root) / run_id
    art_dir    = bundle_dir / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)

    # Copy every artifact that exists in the run directory.
    for fname in _ARTIFACT_NAMES:
        src = run_dir / fname
        if src.exists():
            shutil.copy2(src, art_dir / fname)

    # Write portable report.json (no private _ keys).
    public = {k: v for k, v in report_dict.items() if not k.startswith("_")}
    (bundle_dir / "report.json").write_text(
        json.dumps(public, indent=2, default=str), encoding="utf-8"
    )

    # Write portable HTML — artifact hrefs are relative to the bundle root.
    (bundle_dir / "report.html").write_text(
        build_html_report(report_dict, artifact_prefix="artifacts/"),
        encoding="utf-8",
    )

    return bundle_dir


# ── main entry point ──────────────────────────────────────────────────────────

def report(
    run_dir: str | Path,
    *,
    diff: dict | None = None,
    output_json: str | Path | None = None,
    output_html: str | Path | None = None,
) -> dict:
    """Full reporting pipeline: normalize → indicators → score → narrative → outputs.

    Parameters
    ----------
    run_dir:
        Directory produced by ``capture.run()``.
    diff:
        Optional ``diff_profiles()`` result.
    output_json:
        If given, write the JSON report to this path (private _ keys excluded).
    output_html:
        If given, write the HTML report to this path.

    Returns
    -------
    dict
        Full structured report (includes internal ``_`` prefixed keys for HTML).
    """
    run_dir = Path(run_dir)
    norm = normalize(run_dir, diff=diff)
    rep  = build_report(norm)

    # ── write behavior_profile.json ───────────────────────────────────────────
    # extract_profile() is pure (no Supabase); safe to call unconditionally.
    _run_json = run_dir / "run.json"
    if _run_json.exists():
        try:
            from .baseline import extract_profile as _ep
            _profile = _ep(json.loads(_run_json.read_text()), run_dir)
            (run_dir / "behavior_profile.json").write_text(
                json.dumps(_profile, indent=2, default=str), encoding="utf-8"
            )
        except Exception as _exc:
            print(f"[report] warning: could not write behavior_profile.json: {_exc}",
                  flush=True)

    # ── write diff.json ───────────────────────────────────────────────────────
    if diff is not None:
        try:
            (run_dir / "diff.json").write_text(
                json.dumps(diff, indent=2, default=str), encoding="utf-8"
            )
        except Exception as _exc:
            print(f"[report] warning: could not write diff.json: {_exc}", flush=True)

    if output_json:
        public = {k: v for k, v in rep.items() if not k.startswith("_")}
        Path(output_json).write_text(
            json.dumps(public, indent=2, default=str), encoding="utf-8"
        )

    if output_html:
        Path(output_html).write_text(build_html_report(rep), encoding="utf-8")

    return rep
