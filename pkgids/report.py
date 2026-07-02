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
from pathlib import Path


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


def build_html_report(report_dict: dict) -> str:  # noqa: C901
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

    phases_detail = report_dict.get("_phases_detail", {})
    network       = report_dict.get("_network", {})
    telemetry     = report_dict.get("_telemetry", {})
    correlations  = report_dict.get("_correlations", {})
    run_detail    = report_dict.get("_run", pkg)

    eco     = pkg.get("ecosystem") or "?"
    name    = pkg.get("name")      or "?"
    version = pkg.get("version")   or "?"
    pkg_id  = f"{e(eco)}:{e(name)}@{e(version)}"
    vcolor  = _VERDICT_COLOR.get(verdict_str, "#7f8c8d")
    verdict_label = verdict_str.replace("_", " ").upper()

    # ── 1. Narrative ──────────────────────────────────────────────────────────
    narrative_html = "\n".join(f"<p>{e(s)}</p>" for s in narrative) \
        or '<p class="muted">No summary available.</p>'

    # ── 1b. Advisory section ──────────────────────────────────────────────────
    adv_hit    = advisory.get("advisory_hit", False)
    adv_count  = advisory.get("advisory_count", 0)
    adv_src    = advisory.get("advisory_source") or "—"
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
    adv_status_label = {
        "none":         "None",
        "advisory_hit": "HIT",
        "lookup_failed": "LOOKUP FAILED",
    }.get(adv_status, adv_status.upper())
    adv_status_color = {
        "none":         "#27ae60",
        "advisory_hit": "#c0392b",
        "lookup_failed": "#e67e22",
    }.get(adv_status, "#7f8c8d")

    adv_id_cells = "".join(
        f'<tr><td><code>{e(i)}</code></td>'
        f'<td class="ev">{e(s)}</td></tr>\n'
        for i, s in zip(adv_ids, adv_sums + [""] * len(adv_ids))
    ) or '<tr><td colspan="2" class="muted">No advisories found</td></tr>'

    advisory_section = f"""
  <section>
    <h2>Verdict Breakdown <span class="q">Three-layer analysis</span></h2>
    <div class="meta" style="margin-bottom:12px">
      <div class="meta-item"><label>Behavioral verdict</label>
        <span style="color:{bv_color};font-weight:700">
          {e(behavioral_verdict.replace('_',' ').upper())}</span></div>
      <div class="meta-item"><label>Advisory status</label>
        <span style="color:{adv_status_color};font-weight:700">
          {e(adv_status_label)}</span></div>
      <div class="meta-item"><label>Final verdict</label>
        <span style="color:{fv_color};font-weight:700">
          {e(verdict_str.replace('_',' ').upper())}</span></div>
      <div class="meta-item"><label>Verdict basis</label>
        <span>{e(basis_desc)}</span></div>
      <div class="meta-item"><label>Advisory source</label><span>{e(adv_src)}</span></div>
      <div class="meta-item"><label>Advisory count</label><span>{adv_count}</span></div>
      {'<div class="meta-item"><label>Lookup error</label>'
       f'<span style="color:#c0392b">{e(adv_err)}</span></div>' if adv_err else ''}
    </div>
    <table>
      <thead><tr><th>ID / Alias</th><th>Summary</th></tr></thead>
      <tbody>{adv_id_cells}</tbody>
    </table>
  </section>"""

    sev_chips = ""
    if summary.get("critical"):
        sev_chips += f'<span class="sev-chip critical">{summary["critical"]} critical</span> '
    if summary.get("high"):
        sev_chips += f'<span class="sev-chip high">{summary["high"]} high</span> '
    if summary.get("medium"):
        sev_chips += f'<span class="sev-chip medium">{summary["medium"]} medium</span> '
    if summary.get("low"):
        sev_chips += f'<span class="sev-chip low">{summary["low"]} low</span>'

    # ── 2. Score Breakdown ────────────────────────────────────────────────────
    bd_rows = ""
    for item in breakdown.get("items", []):
        sc = _SEV_COLOR.get(item.get("severity", "low"), "#999")
        ph = item.get("phase", "")
        ph_badge = (
            f'<span class="phase-badge" style="background:{_PHASE_COLOR.get(ph,"#999")}">'
            f'{e(ph)}</span>'
            if ph else ""
        )
        bd_rows += (
            f'<tr>'
            f'<td><span class="sev" style="background:{sc}">{e(item.get("severity",""))}</span></td>'
            f'<td>{e(item.get("title",""))}</td>'
            f'<td>{e(item.get("tactic",""))}</td>'
            f'<td>{ph_badge}</td>'
            f'<td class="pts">+{item.get("points",0)}</td>'
            f'</tr>\n'
        )
    if breakdown.get("combo_bonus", 0):
        bd_rows += (
            f'<tr class="combo-row">'
            f'<td colspan="3"><em>Exfiltration combo bonus</em>'
            f' <small>(network observed after credential-file access)</small></td>'
            f'<td></td>'
            f'<td class="pts">+{breakdown["combo_bonus"]}</td>'
            f'</tr>\n'
        )
    bd_rows += (
        f'<tr class="total-row">'
        f'<td colspan="4"><strong>Total score</strong></td>'
        f'<td class="pts"><strong>{score_val}/100</strong></td>'
        f'</tr>\n'
    )
    if not breakdown.get("items"):
        bd_rows = '<tr><td colspan="5" class="muted">No scoring contributions — no indicators detected.</td></tr>'

    # ── 3. ATT&CK tactics ─────────────────────────────────────────────────────
    tactic_chips = "".join(
        f'<span class="chip">{e(t)}</span>' for t in tactics
    ) or '<span class="muted">none detected</span>'
    tech_row = (
        '<div class="tech-row">Techniques: '
        + " ".join(f'<code>{e(t)}</code>' for t in techniques)
        + "</div>"
    ) if techniques else ""

    # ── 4. Indicators table ───────────────────────────────────────────────────
    ind_rows = ""
    for ind in indicators:
        sc  = _SEV_COLOR.get(ind["severity"], "#7f8c8d")
        ev  = e(json.dumps(ind["evidence"], separators=(",", ":")))[:120]
        ph  = (ind.get("evidence") or {}).get("phase", "")
        ph_badge = (
            f'<span class="phase-badge" style="background:{_PHASE_COLOR.get(ph,"#999")}">'
            f'{e(ph)}</span>'
            if ph else '<span class="muted">—</span>'
        )
        ind_rows += (
            f'<tr>'
            f'<td><span class="sev" style="background:{sc}">{e(ind["severity"])}</span></td>'
            f'<td>{e(ind["title"])}</td>'
            f'<td><code>{e(ind["technique"])}</code></td>'
            f'<td>{e(ind["tactic"])}</td>'
            f'<td>{ph_badge}</td>'
            f'<td class="ev">{ev}</td>'
            f'</tr>\n'
        )
    if not ind_rows:
        ind_rows = '<tr><td colspan="6" class="muted">No indicators found</td></tr>'

    # ── 5. Process tree ───────────────────────────────────────────────────────
    proc_html = ""
    for ph_name, ph in phases_detail.items():
        pc = _PHASE_COLOR.get(ph_name, "#999")
        execs = ph.get("suspicious_execs") or []
        proc_html += (
            f'<div class="pt-phase" style="color:{pc}">'
            f'{e(ph_name)} phase</div>\n'
        )
        if execs:
            for ex in execs[:20]:
                argv = " ".join(str(a) for a in (ex.get("argv") or []))
                proc_html += (
                    f'<div class="pt-proc">&#x2514;&#x2500; '
                    f'<code>{e(argv[:160])}</code></div>\n'
                )
        else:
            proc_html += (
                '<div class="pt-proc muted">(no suspicious processes)</div>\n'
            )

    # Subprocess payload correlation
    sub_payloads = correlations.get("subprocess_payloads", [])
    if sub_payloads:
        proc_html += "<div class='corr-heading'>Payload attribution</div>\n"
        for sp in sub_payloads[:5]:
            payload = sp.get("payload_exec", {})
            parent  = sp.get("potential_parent", {})
            p_argv  = " ".join(str(a) for a in (payload.get("argv") or []))
            par_exe = (parent or {}).get("exe", "?") if parent else "(unknown)"
            proc_html += (
                f'<div class="pt-proc">'
                f'<span class="phase-badge" style="background:#c0392b">payload</span> '
                f'<code>{e(p_argv[:100])}</code> '
                f'<span class="muted">← spawned by {e(par_exe)}</span>'
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
        diff_section = f"""
  <section>
    <h2>&#x2198; How does this differ from prior versions?</h2>
    <table>
      <tr><th>From version</th><td>{e(str(diff.get("from_version") or "—"))}</td></tr>
      <tr><th>To version</th><td>{e(str(diff.get("to_version") or "—"))}</td></tr>
      <tr><th>Risk delta</th><td><strong>{e(str(diff.get("risk_delta") or "—"))}</strong></td></tr>
      <tr><th>New domains</th><td>{nd}</td></tr>
      <tr><th>New ports</th><td>{np}</td></tr>
    </table>
  </section>"""

    # ── 9. Event counts ───────────────────────────────────────────────────────
    count_rows = "".join(
        f'<tr><td>{e(k.replace("_", " "))}</td><td>{v}</td></tr>\n'
        for k, v in event_counts.items()
    ) or '<tr><td colspan="2" class="muted">No events</td></tr>'

    # ── 10. Raw artifact links ─────────────────────────────────────────────────
    run_dir_str    = run_detail.get("run_dir", "")
    artifact_links = ""
    if run_dir_str:
        for fname in (
            "run.json", "metadata.json", "network.jsonl", "telemetry.jsonl",
            "behavior_profile.json", "diff.json", "correlations.json",
            "report.json", "capture.pcap",
        ):
            fpath = Path(run_dir_str).resolve() / fname
            href  = fpath.as_uri()
            exists_hint = "" if fpath.exists() else ' class="muted"'
            artifact_links += (
                f'<li{exists_hint}><a href="{e(href)}">{e(fname)}</a></li>\n'
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
        phase_rows += (
            f'<tr><td>{e(ph_name)}</td><td>{e(status)}</td>'
            f'<td>{exit_c if exit_c is not None else "—"}</td>'
            f'<td>{"%.1fs" % dur if dur is not None else "—"}</td>'
            f'<td>{net}</td><td>{sens}</td><td>{susp}</td></tr>\n'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>pkgids report — {pkg_id}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box}}
    body{{font-family:system-ui,sans-serif;margin:0;padding:0;
          background:#f4f5f7;color:#222;font-size:14px}}
    header{{background:#1a1a2e;color:#eee;padding:24px 32px}}
    header h1{{margin:0 0 4px;font-size:.85rem;font-weight:400;
               letter-spacing:.08em;color:#999;text-transform:uppercase}}
    .pkg-id{{font-size:1.4rem;font-weight:700;margin-bottom:12px;
              word-break:break-all}}
    .badge{{display:inline-block;padding:4px 16px;border-radius:4px;
             font-weight:700;font-size:.85rem;color:#fff;background:{vcolor};
             text-transform:uppercase;letter-spacing:.08em}}
    .score-row{{margin-top:12px;display:flex;align-items:center;gap:10px;
                flex-wrap:wrap}}
    .bar-bg{{background:#333;border-radius:4px;height:8px;width:200px}}
    .bar-fg{{background:{vcolor};border-radius:4px;height:8px;width:{score_val}%}}
    .score-label{{color:#ccc;font-size:.88rem}}
    .conf{{color:#888;font-size:.80rem}}
    main{{max-width:1100px;margin:0 auto;padding:20px 28px}}
    section{{background:#fff;border-radius:6px;padding:18px 22px;
              margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.07)}}
    h2{{margin:0 0 12px;font-size:.92rem;color:#333;
         border-bottom:1px solid #eee;padding-bottom:7px;font-weight:700}}
    h2 .q{{color:#999;font-size:.78rem;font-weight:400;margin-left:6px}}
    p{{margin:.4em 0;line-height:1.55;color:#333}}
    .sev-chips{{margin-top:8px}}
    .sev-chip{{display:inline-block;padding:2px 10px;border-radius:10px;
               font-size:.75rem;font-weight:700;color:#fff;margin-right:4px}}
    .sev-chip.critical{{background:#c0392b}}
    .sev-chip.high{{background:#e67e22}}
    .sev-chip.medium{{background:#f39c12}}
    .sev-chip.low{{background:#2980b9}}
    .chip{{display:inline-block;background:#e8eaf6;color:#3949ab;
            border-radius:12px;padding:3px 12px;font-size:.78rem;
            margin:2px;font-weight:600}}
    .tech-row{{font-size:.78rem;color:#666;margin-top:8px}}
    table{{width:100%;border-collapse:collapse;font-size:.82rem}}
    th{{text-align:left;color:#666;font-weight:600;
         border-bottom:2px solid #eee;padding:5px 7px}}
    td{{padding:5px 7px;border-bottom:1px solid #f0f0f0;vertical-align:middle}}
    tr:last-child td{{border-bottom:none}}
    tr.combo-row td{{background:#fff8e1;font-style:italic;color:#7f6000}}
    tr.total-row td{{background:#f8f8f8;font-weight:700;border-top:2px solid #ddd}}
    .pts{{text-align:right;font-weight:600;color:#2c3e50;font-family:monospace}}
    .sev{{display:inline-block;color:#fff;font-size:.68rem;font-weight:700;
           padding:2px 7px;border-radius:3px;text-transform:uppercase}}
    .phase-badge{{display:inline-block;color:#fff;font-size:.68rem;font-weight:700;
                   padding:2px 7px;border-radius:3px;text-transform:uppercase}}
    .ev{{color:#666;font-size:.75rem;max-width:260px;
          overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
    code{{background:#f0f0f0;padding:1px 5px;border-radius:3px;
           font-size:.82em;word-break:break-all}}
    .muted{{color:#aaa}}
    .meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}
    .meta-item label{{font-size:.72rem;color:#888;display:block;margin-bottom:2px}}
    .meta-item span{{font-weight:600;font-size:.9rem}}
    .pt-phase{{font-weight:700;font-size:.78rem;margin-top:10px;
               letter-spacing:.04em;text-transform:uppercase}}
    .pt-proc{{font-family:monospace;font-size:.78rem;color:#333;
               padding:2px 0 2px 16px;white-space:pre-wrap;word-break:break-all}}
    .corr-heading{{font-weight:600;font-size:.78rem;color:#555;
                    margin-top:14px;border-top:1px dashed #ddd;padding-top:8px}}
    .artifacts{{list-style:none;padding:0;margin:0}}
    .artifacts li{{margin:4px 0}}
    .artifacts a{{color:#3949ab;font-family:monospace;font-size:.82rem}}
    .artifacts li.muted a{{color:#bbb}}
  </style>
</head>
<body>
<header>
  <h1>pkgids security report</h1>
  <div class="pkg-id">{pkg_id}</div>
  <div class="badge">{e(verdict_label)}</div>
  <div class="score-row">
    <div class="bar-bg"><div class="bar-fg"></div></div>
    <span class="score-label">score: {score_val}/100</span>
    <span class="conf">confidence: {confidence:.2f}</span>
  </div>
</header>
<main>

  <section>
    <h2>What happened? <span class="q">executive summary</span></h2>
    {narrative_html}
    <div class="sev-chips">{sev_chips}</div>
    <div style="margin-top:10px" class="meta">
      <div class="meta-item"><label>Ecosystem</label><span>{e(eco)}</span></div>
      <div class="meta-item"><label>Package</label><span>{e(name)}</span></div>
      <div class="meta-item"><label>Version</label><span>{e(version)}</span></div>
      <div class="meta-item"><label>Indicators</label>
        <span>{summary.get("indicator_count",0)}</span></div>
      <div class="meta-item"><label>Install hooks</label><span>{hooks_str}</span></div>
      <div class="meta-item"><label>Files in artifact</label><span>{file_cnt}</span></div>
    </div>
  </section>
  {advisory_section}
  <section>
    <h2>Why was this verdict assigned? <span class="q">score breakdown</span></h2>
    <table>
      <thead><tr>
        <th>Severity</th><th>Finding</th><th>Tactic</th><th>Phase</th><th>Points</th>
      </tr></thead>
      <tbody>{bd_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>ATT&amp;CK Tactics</h2>
    {tactic_chips}
    {tech_row}
  </section>

  <section>
    <h2>What were the indicators?</h2>
    <table>
      <thead><tr>
        <th>Sev</th><th>Indicator</th><th>Technique</th>
        <th>Tactic</th><th>Phase</th><th>Evidence</th>
      </tr></thead>
      <tbody>{ind_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>In which phase did it happen? <span class="q">process tree</span></h2>
    {proc_html if proc_html else '<span class="muted">No phase data</span>'}
  </section>

  <section>
    <h2>Which host or domain was contacted?</h2>
    <table>
      <thead><tr>
        <th>Domain / Host</th><th>Protocol</th><th>Initiated by</th>
      </tr></thead>
      <tbody>{domain_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Which file or secret was touched?</h2>
    <table>
      <thead><tr>
        <th>Path</th><th>Mode</th><th>Flags</th>
      </tr></thead>
      <tbody>{sens_rows}</tbody>
    </table>
  </section>

  <section>
    <h2>Phase Summary</h2>
    <table>
      <thead><tr>
        <th>Phase</th><th>Status</th><th>Exit</th><th>Duration</th>
        <th>Network</th><th>Sensitive reads</th><th>Suspicious</th>
      </tr></thead>
      <tbody>{phase_rows if phase_rows else
              '<tr><td colspan="7" class="muted">No phase data</td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>Event Counts</h2>
    <table>
      <thead><tr><th>Event type</th><th>Count</th></tr></thead>
      <tbody>{count_rows}</tbody>
    </table>
  </section>
  {diff_section}
  <section>
    <h2>Raw Artifacts</h2>
    {f'<ul class="artifacts">{artifact_links}</ul>'
      if artifact_links else '<span class="muted">Run directory not available</span>'}
  </section>

</main>
</body>
</html>"""


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
