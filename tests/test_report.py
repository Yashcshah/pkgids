"""Unit tests for pkgids/report.py — normalization, report building, HTML output."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from pkgids.report import normalize, build_report, build_html_report, report


# ── fixtures / helpers ────────────────────────────────────────────────────────

def _write(tmp_path: Path, name: str, data) -> None:
    (tmp_path / name).write_text(
        json.dumps(data) if isinstance(data, (dict, list)) else data,
        encoding="utf-8",
    )


def _write_jsonl(tmp_path: Path, name: str, rows: list[dict]) -> None:
    (tmp_path / name).write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8"
    )


def _minimal_run(tmp_path: Path, **overrides) -> None:
    run = {
        "ecosystem": "pypi",
        "name": "requests",
        "version": "2.28.0",
        "phases": {
            "install": {"status": "ok", "exit_code": 0, "duration_secs": 1.2,
                        "process_activity": {"process_count": 2,
                                              "suspicious_execs": [],
                                              "sensitive_file_accesses": [],
                                              "any_suspicious": False}},
            "import":  {"status": "ok", "exit_code": 0, "duration_secs": 0.3,
                        "process_activity": {"process_count": 1,
                                              "suspicious_execs": [],
                                              "sensitive_file_accesses": [],
                                              "any_suspicious": False}},
        },
    }
    run.update(overrides)
    _write(tmp_path, "run.json", run)


# ── normalize() ───────────────────────────────────────────────────────────────

class TestNormalize:
    def test_returns_required_keys(self, tmp_path: Path):
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        for key in ("run", "metadata", "phases", "network", "telemetry", "event_counts", "diff"):
            assert key in norm, f"missing key: {key}"

    def test_run_fields_extracted(self, tmp_path: Path):
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        assert norm["run"]["ecosystem"] == "pypi"
        assert norm["run"]["name"]      == "requests"
        assert norm["run"]["version"]   == "2.28.0"

    def test_missing_run_json_returns_empty_run(self, tmp_path: Path):
        norm = normalize(tmp_path)
        assert norm["run"]["ecosystem"] is None

    def test_network_jsonl_parsed(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write_jsonl(tmp_path, "network.jsonl", [
            {"type": "dns",  "query": "example.com"},
            {"type": "http", "host": "api.example.com", "port": 80},
            {"type": "tls",  "sni": "secure.example.com"},
        ])
        norm = normalize(tmp_path)
        assert len(norm["network"]["dns_queries"])   == 1
        assert len(norm["network"]["http_requests"]) == 1
        assert len(norm["network"]["tls_sessions"])  == 1

    def test_bad_jsonl_lines_skipped(self, tmp_path: Path):
        _minimal_run(tmp_path)
        (tmp_path / "network.jsonl").write_text(
            '{"type":"dns","query":"ok.com"}\nnot json\n{"type":"dns","query":"also.ok"}\n',
            encoding="utf-8",
        )
        norm = normalize(tmp_path)
        assert len(norm["network"]["dns_queries"]) == 2

    def test_telemetry_sensitive_events(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write_jsonl(tmp_path, "telemetry.jsonl", [
            {"event_type": "exec",   "executable": "/bin/sh",     "argv": ["sh"]},
            {"event_type": "file",   "path": "/etc/passwd",        "sensitive": True},
            {"event_type": "socket", "dst_ip": "1.2.3.4",          "phase": "import"},
        ])
        norm = normalize(tmp_path)
        assert len(norm["telemetry"]["exec_events"])           == 1
        assert len(norm["telemetry"]["sensitive_file_events"]) == 1
        assert len(norm["network"]["import_phase_connections"]) == 1

    def test_import_phase_connections_filter(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write_jsonl(tmp_path, "telemetry.jsonl", [
            {"event_type": "socket", "dst_ip": "1.2.3.4", "phase": "install"},
            {"event_type": "socket", "dst_ip": "2.3.4.5", "phase": "import"},
        ])
        norm = normalize(tmp_path)
        assert len(norm["network"]["import_phase_connections"]) == 1
        assert norm["network"]["import_phase_connections"][0]["dst_ip"] == "2.3.4.5"

    def test_phase_process_count_mapped(self, tmp_path: Path):
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        assert norm["phases"]["install"]["process_count"] == 2

    def test_diff_passed_through(self, tmp_path: Path):
        _minimal_run(tmp_path)
        diff = {"is_suspicious": True, "risk_delta": "critical"}
        norm = normalize(tmp_path, diff=diff)
        assert norm["diff"] is diff

    def test_event_counts_populated(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write_jsonl(tmp_path, "network.jsonl", [
            {"type": "dns", "query": "x.com"},
            {"type": "dns", "query": "y.com"},
        ])
        norm = normalize(tmp_path)
        assert norm["event_counts"]["dns_queries"] == 2

    def test_metadata_json_loaded(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write(tmp_path, "metadata.json", {"file_count": 12, "install_hooks": ["setup.py:install"]})
        norm = normalize(tmp_path)
        assert norm["metadata"]["file_count"] == 12

    def test_missing_metadata_returns_empty_dict(self, tmp_path: Path):
        _minimal_run(tmp_path)
        assert normalize(tmp_path)["metadata"] == {}

    def test_phase_timed_out_status(self, tmp_path: Path):
        _minimal_run(tmp_path, phases={
            "install": {"status": "timed_out", "exit_code": -1, "duration_secs": 120.0,
                        "process_activity": {}},
            "import":  {"status": "ok", "exit_code": 0, "duration_secs": 0.1,
                        "process_activity": {}},
        })
        norm = normalize(tmp_path)
        assert norm["phases"]["install"]["status"] == "timed_out"


# ── build_report() ────────────────────────────────────────────────────────────

class TestBuildReport:
    def _clean_norm(self) -> dict:
        return {
            "run":      {"ecosystem": "pypi", "name": "safe-pkg", "version": "1.0.0",
                         "run_dir": ""},
            "metadata": {},
            "phases":   {
                "install": {"status": "ok", "exit_code": 0, "duration_secs": 1.0,
                            "process_count": 1, "suspicious_execs": [],
                            "sensitive_files": [], "any_suspicious": False},
                "import":  {"status": "ok", "exit_code": 0, "duration_secs": 0.1,
                            "process_count": 1, "suspicious_execs": [],
                            "sensitive_files": [], "any_suspicious": False},
            },
            "network":  {"dns_queries": [], "http_requests": [],
                         "tls_sessions": [], "import_phase_connections": []},
            "telemetry": {"exec_events": [], "file_events": [],
                          "socket_events": [], "sensitive_file_events": []},
            "event_counts": {},
            "diff": None,
        }

    def test_required_keys_present(self):
        rep = build_report(self._clean_norm())
        for k in ("package", "verdict", "score", "confidence",
                   "attack_tactics", "techniques", "indicators",
                   "summary", "event_counts", "phases", "metadata", "diff"):
            assert k in rep

    def test_score_is_int(self):
        rep = build_report(self._clean_norm())
        assert isinstance(rep["score"], int)

    def test_confidence_is_float(self):
        rep = build_report(self._clean_norm())
        assert isinstance(rep["confidence"], float)

    def test_clean_package_no_malicious_behavior(self):
        rep = build_report(self._clean_norm())
        assert rep["verdict"]         == "no_malicious_behavior_observed"
        assert rep["dynamic_verdict"] == "no_malicious_behavior_observed"
        assert rep["verdict_basis"]   == "dynamic"
        assert rep["score"]           == 0

    def test_clean_package_confidence_zero(self):
        rep = build_report(self._clean_norm())
        assert rep["confidence"] == 0.0

    def test_clean_package_no_indicators(self):
        rep = build_report(self._clean_norm())
        assert rep["indicators"] == []
        assert rep["summary"]["indicator_count"] == 0

    def test_package_field_present(self):
        rep = build_report(self._clean_norm())
        assert rep["package"]["name"]      == "safe-pkg"
        assert rep["package"]["ecosystem"] == "pypi"
        assert rep["package"]["version"]   == "1.0.0"

    def test_attack_tactics_formatted_title_case(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"] = [{"query": "x.com"}]
        rep = build_report(norm)
        assert "Command and Control" in rep["attack_tactics"]

    def test_attack_tactics_sorted(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"]              = [{"query": "x.com"}]
        norm["network"]["import_phase_connections"] = [{"dst_ip": "1.2.3.4"}]
        rep = build_report(norm)
        assert rep["attack_tactics"] == sorted(rep["attack_tactics"])

    def test_ssh_key_yields_high_score(self):
        norm = self._clean_norm()
        norm["telemetry"]["sensitive_file_events"] = [
            {"event_type": "file", "path": "/root/.ssh/id_rsa", "sensitive": True}
        ]
        rep = build_report(norm)
        assert rep["score"] >= 25

    def test_full_exfil_is_malicious(self):
        norm = self._clean_norm()
        norm["telemetry"]["sensitive_file_events"] = [
            {"path": "/root/.ssh/id_rsa", "sensitive": True}
        ]
        norm["network"]["http_requests"] = [{"host": "evil.com", "port": 80}]
        rep = build_report(norm)
        assert rep["verdict"] == "malicious"

    def test_phases_summary_has_network_activity_bool(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"] = [{"query": "x.com"}]
        rep = build_report(norm)
        assert rep["phases"]["install"]["network_activity"] is True

    def test_phases_summary_no_network(self):
        rep = build_report(self._clean_norm())
        assert rep["phases"]["install"]["network_activity"] is False

    def test_summary_severity_counts_sum_to_total(self):
        norm = self._clean_norm()
        norm["telemetry"]["sensitive_file_events"] = [
            {"path": "/root/.ssh/id_rsa", "sensitive": True}
        ]
        rep = build_report(norm)
        counted = (rep["summary"]["critical"] + rep["summary"]["high"]
                   + rep["summary"]["medium"] + rep["summary"]["low"])
        assert counted == rep["summary"]["indicator_count"]

    def test_tactics_deduplicated(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"]   = [{"query": "x.com"}]
        norm["network"]["http_requests"] = [{"host": "x.com", "port": 80}]
        rep = build_report(norm)
        assert len(rep["attack_tactics"]) == len(set(rep["attack_tactics"]))

    def test_likely_malicious_verdict_possible(self):
        norm = self._clean_norm()
        norm["phases"]["install"]["suspicious_execs"] = [
            {"executable": "/bin/bash", "argv": ["bash", "-c", "id"], "pid": 1}
        ]
        norm["network"]["dns_queries"] = [{"query": "x.com"}]
        rep = build_report(norm)
        assert rep["verdict"] in ("suspicious", "likely_malicious", "malicious")

    def test_diff_included_in_report(self):
        norm = self._clean_norm()
        diff = {"is_suspicious": False, "risk_delta": "clean"}
        norm["diff"] = diff
        rep = build_report(norm)
        assert rep["diff"] == diff

    def test_narrative_is_list_of_strings(self):
        rep = build_report(self._clean_norm())
        assert isinstance(rep["narrative"], list)
        assert all(isinstance(s, str) for s in rep["narrative"])

    def test_clean_run_narrative_mentions_no_suspicious(self):
        rep = build_report(self._clean_norm())
        joined = " ".join(rep["narrative"]).lower()
        assert "no suspicious" in joined or "not detected" in joined or "detected" in joined

    def test_score_breakdown_present(self):
        rep = build_report(self._clean_norm())
        assert "score_breakdown" in rep
        bd = rep["score_breakdown"]
        assert "items" in bd
        assert "combo_bonus" in bd
        assert "total" in bd

    def test_score_breakdown_total_matches_score(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"] = [{"query": "x.com"}]
        rep = build_report(norm)
        assert rep["score_breakdown"]["total"] == rep["score"]

    def test_narrative_mentions_domain_when_network_present(self):
        norm = self._clean_norm()
        norm["network"]["dns_queries"] = [{"query": "evil.com"}]
        rep = build_report(norm)
        joined = " ".join(rep["narrative"])
        assert "evil.com" in joined

    def test_narrative_mentions_sensitive_file(self):
        norm = self._clean_norm()
        norm["telemetry"]["sensitive_file_events"] = [
            {"path": "/root/.ssh/id_rsa", "sensitive": True}
        ]
        rep = build_report(norm)
        joined = " ".join(rep["narrative"])
        assert "/root/.ssh/id_rsa" in joined

    def test_correlations_key_in_normalized(self):
        # build_report uses normalized dict with correlations key
        norm = self._clean_norm()
        norm["correlations"] = {}
        rep = build_report(norm)
        assert "_correlations" in rep

    # ── advisory enrichment ───────────────────────────────────────────────────

    def _advisory_norm(self, advisory: dict) -> dict:
        norm = self._clean_norm()
        norm["advisory"] = advisory
        return norm

    def _hit_advisory(self) -> dict:
        return {
            "advisory_hit":       True,
            "advisory_source":    "osv",
            "advisory_count":     1,
            "advisory_ids":       ["PYSEC-2022-999", "CVE-2022-34501"],
            "advisory_summaries": ["Remote code execution via malicious setup.py"],
            "advisory_error":     None,
        }

    def test_advisory_hit_no_dynamic_signal_gives_known_vulnerable(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        assert rep["verdict"]       == "known_vulnerable"
        assert rep["verdict_basis"] == "advisory"

    def test_advisory_hit_dynamic_verdict_preserved(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        assert rep["dynamic_verdict"] == "no_malicious_behavior_observed"

    def test_advisory_field_in_report(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        adv = rep["advisory"]
        assert adv["advisory_hit"]    is True
        assert adv["advisory_count"]  == 1
        assert "PYSEC-2022-999"       in adv["advisory_ids"]
        assert "CVE-2022-34501"       in adv["advisory_ids"]

    def test_no_advisory_hit_verdict_stays_dynamic(self):
        no_hit = {
            "advisory_hit": False, "advisory_source": "osv",
            "advisory_count": 0, "advisory_ids": [], "advisory_summaries": [],
            "advisory_error": None,
        }
        rep = build_report(self._advisory_norm(no_hit))
        assert rep["verdict"]       == "no_malicious_behavior_observed"
        assert rep["verdict_basis"] == "dynamic"

    def test_advisory_hit_mentioned_in_narrative(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        full = " ".join(rep["narrative"])
        assert "advisory" in full.lower()
        assert "PYSEC-2022-999" in full or "CVE-2022-34501" in full

    def test_advisory_missing_from_norm_does_not_crash(self):
        norm = self._clean_norm()
        # no "advisory" key at all
        rep = build_report(norm)
        assert rep["verdict_basis"] == "dynamic"

    def test_advisory_error_does_not_elevate_verdict(self):
        error_adv = {
            "advisory_hit": False, "advisory_source": None,
            "advisory_count": 0, "advisory_ids": [], "advisory_summaries": [],
            "advisory_error": "OSV query timed out",
        }
        rep = build_report(self._advisory_norm(error_adv))
        assert rep["verdict"]       == "no_malicious_behavior_observed"
        assert rep["verdict_basis"] == "dynamic"


# ── build_html_report() ───────────────────────────────────────────────────────

class TestBuildHtmlReport:
    def _rep(self, **overrides) -> dict:
        base = {
            "package":       {"ecosystem": "pypi", "name": "mypkg", "version": "1.0.0"},
            "_run":          {"ecosystem": "pypi", "name": "mypkg", "version": "1.0.0",
                              "run_dir": ""},
            "verdict":         "no_malicious_behavior_observed",
            "dynamic_verdict": "no_malicious_behavior_observed",
            "verdict_basis":   "dynamic",
            "advisory":        {},
            "score":           0,
            "confidence":    0.0,
            "attack_tactics": [],
            "techniques":    [],
            "indicators":    [],
            "narrative":     ["No suspicious behavior was detected."],
            "score_breakdown": {"items": [], "combo_bonus": 0, "total": 0},
            "summary":       {"indicator_count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "event_counts":  {"dns_queries": 0},
            "phases":        {"install": {"status": "ok", "exit_code": 0,
                                          "duration_secs": 1.0, "any_suspicious": False,
                                          "network_activity": False, "sensitive_file_reads": 0}},
            "_phases_detail": {"install": {"status": "ok", "exit_code": 0,
                                           "any_suspicious": False, "suspicious_execs": []}},
            "_network":      {"dns_queries": [], "http_requests": [],
                              "tls_sessions": [], "import_phase_connections": []},
            "_telemetry":    {"sensitive_file_events": []},
            "_correlations": {},
            "metadata":      {},
            "diff":          None,
        }
        base.update(overrides)
        return base

    # ── basic structure ───────────────────────────────────────────────────────

    def test_returns_string(self):
        assert isinstance(build_html_report(self._rep()), str)

    def test_doctype_present(self):
        assert build_html_report(self._rep()).strip().startswith("<!DOCTYPE html>")

    def test_package_name_in_html(self):
        assert "mypkg" in build_html_report(self._rep())

    def test_score_displayed_as_integer(self):
        html = build_html_report(self._rep(score=72))
        assert "72" in html

    def test_confidence_displayed_as_float(self):
        html = build_html_report(self._rep(confidence=0.87))
        assert "0.87" in html

    # ── verdict colors ────────────────────────────────────────────────────────

    def test_malicious_verdict_red(self):
        html = build_html_report(self._rep(verdict="malicious", score=90))
        assert "#c0392b" in html

    def test_likely_malicious_verdict_color(self):
        html = build_html_report(self._rep(verdict="likely_malicious", score=60))
        assert "#e74c3c" in html

    def test_suspicious_verdict_orange(self):
        html = build_html_report(self._rep(verdict="suspicious", score=30))
        assert "#e67e22" in html

    def test_low_risk_verdict_green(self):
        html = build_html_report(self._rep(verdict="low_risk", score=10))
        assert "#27ae60" in html

    def test_no_malicious_behavior_observed_verdict_grey(self):
        html = build_html_report(self._rep(verdict="no_malicious_behavior_observed", score=0))
        assert "#7f8c8d" in html

    def test_known_vulnerable_verdict_purple(self):
        html = build_html_report(self._rep(verdict="known_vulnerable", score=0))
        assert "#8e44ad" in html

    # ── six-question sections ─────────────────────────────────────────────────

    def test_what_happened_section(self):
        assert "What happened" in build_html_report(self._rep())

    def test_why_verdict_section(self):
        assert "Why was this verdict" in build_html_report(self._rep())

    def test_in_which_phase_section(self):
        assert "In which phase" in build_html_report(self._rep())

    def test_what_host_section(self):
        assert "Which host or domain" in build_html_report(self._rep())

    def test_what_file_section(self):
        assert "Which file or secret" in build_html_report(self._rep())

    def test_raw_artifacts_section_present(self):
        assert "Raw Artifacts" in build_html_report(self._rep())

    # ── narrative ─────────────────────────────────────────────────────────────

    def test_narrative_rendered(self):
        rep = self._rep(narrative=["The package contacted evil.com during install."])
        html = build_html_report(rep)
        assert "The package contacted evil.com during install." in html

    def test_empty_narrative_shows_fallback(self):
        rep = self._rep(narrative=[])
        assert "No summary available" in build_html_report(rep)

    # ── score breakdown ───────────────────────────────────────────────────────

    def test_score_breakdown_rows_rendered(self):
        bd = {
            "items": [{"id": "ssh_key_accessed", "title": "SSH key", "severity": "critical",
                        "tactic": "credential-access", "technique": "T1552.004",
                        "phase": "install", "points": 25}],
            "combo_bonus": 25,
            "total": 50,
        }
        html = build_html_report(self._rep(score_breakdown=bd))
        assert "SSH key" in html
        assert "+25" in html

    def test_combo_bonus_row_shown(self):
        bd = {
            "items": [{"id": "ssh_key_accessed", "title": "SSH key", "severity": "critical",
                        "tactic": "credential-access", "technique": "T1552.004",
                        "phase": "install", "points": 25}],
            "combo_bonus": 25,
            "total": 70,
        }
        html = build_html_report(self._rep(score_breakdown=bd))
        assert "exfiltration combo bonus" in html.lower()

    def test_no_items_shows_fallback(self):
        bd = {"items": [], "combo_bonus": 0, "total": 0}
        html = build_html_report(self._rep(score_breakdown=bd))
        assert "No scoring contributions" in html

    # ── indicators with phase badges ──────────────────────────────────────────

    def test_indicator_row_with_phase(self):
        ind = {"id": "ssh_key_accessed", "title": "SSH key",
               "tactic": "credential-access", "technique": "T1552.004",
               "severity": "critical", "weight": 0.9,
               "evidence": {"paths": ["/root/.ssh/id_rsa"], "phase": "install"}}
        html = build_html_report(self._rep(
            indicators=[ind],
            summary={"indicator_count": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        ))
        assert "install" in html
        assert "T1552.004" in html
        assert "SSH key" in html

    def test_attack_tactics_rendered(self):
        html = build_html_report(self._rep(attack_tactics=["Execution", "Credential Access"]))
        assert "Execution" in html
        assert "Credential Access" in html

    def test_no_indicators_fallback(self):
        assert "No indicators found" in build_html_report(self._rep())

    # ── domains + process attribution ─────────────────────────────────────────

    def test_domains_rendered_from_network(self):
        rep = self._rep()
        rep["_network"]["dns_queries"] = [{"query": "evil.com"}]
        html = build_html_report(rep)
        assert "evil.com" in html

    def test_http_host_rendered(self):
        rep = self._rep()
        rep["_network"]["http_requests"] = [{"host": "c2.attacker.io", "port": 4444}]
        html = build_html_report(rep)
        assert "c2.attacker.io" in html

    def test_process_attribution_from_correlations(self):
        rep = self._rep()
        rep["_correlations"] = {
            "network_attributed": [
                {"host": "evil.com", "responsible_process": {"exe": "/bin/curl",
                                                              "argv": ["/bin/curl", "evil.com"]}}
            ]
        }
        rep["_network"]["http_requests"] = [{"host": "evil.com", "port": 80}]
        html = build_html_report(rep)
        assert "/bin/curl" in html

    # ── sensitive files + exfil flag ──────────────────────────────────────────

    def test_sensitive_files_rendered(self):
        rep = self._rep()
        rep["_telemetry"]["sensitive_file_events"] = [
            {"path": "/root/.ssh/id_rsa", "sensitive": True, "mode": "read"}
        ]
        html = build_html_report(rep)
        assert "/root/.ssh/id_rsa" in html

    def test_exfil_flag_shown_when_file_precedes_network(self):
        rep = self._rep()
        rep["_telemetry"]["sensitive_file_events"] = [
            {"path": "/root/.ssh/id_rsa", "sensitive": True}
        ]
        rep["_correlations"] = {
            "file_before_exfil": [
                {"file_read": {"path": "/root/.ssh/id_rsa"},
                 "following_network": [{"dst_ip": "1.2.3.4", "src": "syscall"}]}
            ]
        }
        html = build_html_report(rep)
        assert "→ network" in html

    # ── diff / behavior delta ─────────────────────────────────────────────────

    def test_diff_section_rendered(self):
        diff = {"from_version": "1.0.0", "to_version": "1.0.1",
                "risk_delta": "critical", "new_domains": ["evil.com"], "new_ports": [4444]}
        html = build_html_report(self._rep(diff=diff))
        assert "How does this differ" in html
        assert "evil.com" in html
        assert "4444" in html

    def test_no_diff_no_diff_section(self):
        assert "How does this differ" not in build_html_report(self._rep(diff=None))

    # ── process tree ──────────────────────────────────────────────────────────

    def test_process_tree_shows_suspicious_execs(self):
        rep = self._rep()
        rep["_phases_detail"] = {
            "install": {"suspicious_execs": [
                {"executable": "/bin/bash", "argv": ["bash", "-c", "id"]}
            ]},
        }
        html = build_html_report(rep)
        assert "bash" in html

    def test_subprocess_payload_attribution(self):
        rep = self._rep()
        rep["_correlations"] = {
            "subprocess_payloads": [{
                "payload_exec":     {"argv": ["/bin/curl", "evil.com"]},
                "potential_parent": {"exe": "/usr/bin/pip3"},
            }]
        }
        html = build_html_report(rep)
        assert "payload" in html.lower()
        assert "/bin/curl" in html

    # ── XSS safety ───────────────────────────────────────────────────────────

    def test_xss_safe_package_name(self):
        rep = self._rep()
        rep["package"]["name"] = "<script>alert(1)</script>"
        rep["_run"]["name"]    = "<script>alert(1)</script>"
        html = build_html_report(rep)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ── report() end-to-end ───────────────────────────────────────────────────────

class TestReport:
    def test_report_returns_dict(self, tmp_path: Path):
        _minimal_run(tmp_path)
        rep = report(tmp_path)
        assert isinstance(rep, dict)
        assert "verdict" in rep

    def test_report_score_is_int(self, tmp_path: Path):
        _minimal_run(tmp_path)
        assert isinstance(report(tmp_path)["score"], int)

    def test_report_confidence_is_float(self, tmp_path: Path):
        _minimal_run(tmp_path)
        assert isinstance(report(tmp_path)["confidence"], float)

    def test_report_writes_json(self, tmp_path: Path):
        _minimal_run(tmp_path)
        out = tmp_path / "report.json"
        report(tmp_path, output_json=out)
        data = json.loads(out.read_text())
        assert "verdict" in data
        assert "package" in data

    def test_json_excludes_private_keys(self, tmp_path: Path):
        _minimal_run(tmp_path)
        out = tmp_path / "report.json"
        report(tmp_path, output_json=out)
        data = json.loads(out.read_text())
        assert not any(k.startswith("_") for k in data)

    def test_report_writes_html(self, tmp_path: Path):
        _minimal_run(tmp_path)
        out = tmp_path / "report.html"
        report(tmp_path, output_html=out)
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "In which phase" in html

    def test_report_with_diff(self, tmp_path: Path):
        _minimal_run(tmp_path)
        diff = {"is_suspicious": True, "risk_delta": "high",
                "from_version": "1.0.0", "to_version": "1.0.1",
                "new_domains": ["bad.com"], "new_ports": []}
        rep = report(tmp_path, diff=diff)
        assert rep["diff"] == diff

    def test_nonexistent_dir_tolerates_missing_files(self):
        norm = normalize("/nonexistent/dir/that/does/not/exist")
        assert norm["run"]["ecosystem"] is None
        assert norm["network"]["dns_queries"] == []

    def test_import_network_surfaced(self, tmp_path: Path):
        _minimal_run(tmp_path)
        _write_jsonl(tmp_path, "telemetry.jsonl", [
            {"event_type": "socket", "dst_ip": "10.0.0.1", "phase": "import"},
        ])
        rep = report(tmp_path)
        ids = [i["id"] for i in rep["indicators"]]
        assert "import_triggered_network" in ids

    def test_install_timeout_surfaced(self, tmp_path: Path):
        _minimal_run(tmp_path, phases={
            "install": {"status": "timed_out", "exit_code": -1, "duration_secs": 120.0,
                        "process_activity": {}},
            "import":  {"status": "ok", "exit_code": 0, "duration_secs": 0.1,
                        "process_activity": {}},
        })
        rep = report(tmp_path)
        ids = [i["id"] for i in rep["indicators"]]
        assert "install_timed_out" in ids

    def test_report_writes_behavior_profile_json(self, tmp_path: Path):
        _minimal_run(tmp_path)
        report(tmp_path)
        assert (tmp_path / "behavior_profile.json").exists()

    def test_report_behavior_profile_json_is_valid(self, tmp_path: Path):
        _minimal_run(tmp_path)
        report(tmp_path)
        raw = (tmp_path / "behavior_profile.json").read_text()
        profile = json.loads(raw)
        for field in ("ecosystem", "name", "version",
                      "install_status", "import_status", "any_suspicious"):
            assert field in profile, f"behavior_profile.json missing field: {field}"

    def test_report_no_behavior_profile_without_run_json(self, tmp_path: Path):
        # report() with a directory that has no run.json should not crash
        # and should not produce behavior_profile.json
        _minimal_run(tmp_path)
        (tmp_path / "run.json").unlink()
        report(tmp_path)
        assert not (tmp_path / "behavior_profile.json").exists()

    def test_report_writes_diff_json(self, tmp_path: Path):
        _minimal_run(tmp_path)
        diff = {"added": ["x"], "removed": [], "changed": {}}
        report(tmp_path, diff=diff)
        assert (tmp_path / "diff.json").exists()
        saved = json.loads((tmp_path / "diff.json").read_text())
        assert saved["added"] == ["x"]

    def test_report_no_diff_json_when_diff_is_none(self, tmp_path: Path):
        _minimal_run(tmp_path)
        report(tmp_path, diff=None)
        assert not (tmp_path / "diff.json").exists()
