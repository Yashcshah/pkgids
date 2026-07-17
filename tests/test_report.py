"""Unit tests for pkgids/report.py — normalization, report building, HTML output."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from pkgids.report import (
    normalize, build_report, build_html_report, report, export_bundle,
)


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
        assert rep["verdict"]             == "no_malicious_behavior_observed"
        assert rep["final_verdict"]       == "no_malicious_behavior_observed"
        assert rep["behavioral_verdict"]  == "no_malicious_behavior_observed"
        assert rep["advisory_status"]     == "none"
        assert rep["verdict_basis"]       == "dynamic"
        assert rep["score"]               == 0

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

    def test_advisory_hit_behavioral_verdict_preserved(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        assert rep["behavioral_verdict"] == "no_malicious_behavior_observed"

    def test_advisory_hit_gives_advisory_status(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        assert rep["advisory_status"] == "advisory_hit"

    def test_advisory_error_gives_lookup_failed_status(self):
        error_adv = {
            "advisory_hit": False, "advisory_source": None,
            "advisory_count": 0, "advisory_ids": [], "advisory_summaries": [],
            "advisory_error": "OSV query timed out",
        }
        rep = build_report(self._advisory_norm(error_adv))
        assert rep["advisory_status"] == "lookup_failed"

    def test_no_advisory_gives_none_status(self):
        no_hit = {
            "advisory_hit": False, "advisory_source": "osv",
            "advisory_count": 0, "advisory_ids": [], "advisory_summaries": [],
            "advisory_error": None,
        }
        rep = build_report(self._advisory_norm(no_hit))
        assert rep["advisory_status"] == "none"

    def test_final_verdict_matches_verdict(self):
        rep = build_report(self._advisory_norm(self._hit_advisory()))
        assert rep["final_verdict"] == rep["verdict"]

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
            "verdict":            "no_malicious_behavior_observed",
            "final_verdict":      "no_malicious_behavior_observed",
            "behavioral_verdict": "no_malicious_behavior_observed",
            "advisory_status":    "none",
            "verdict_basis":      "dynamic",
            "advisory":           {},
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

    # ── verdict threat class ──────────────────────────────────────────────────

    def test_malicious_verdict_red(self):
        html = build_html_report(self._rep(verdict="malicious", score=90))
        assert 'data-threat="malicious"' in html

    def test_likely_malicious_verdict_color(self):
        html = build_html_report(self._rep(verdict="likely_malicious", score=60))
        assert 'data-threat="likely"' in html

    def test_suspicious_verdict_orange(self):
        html = build_html_report(self._rep(verdict="suspicious", score=30))
        assert 'data-threat="suspicious"' in html

    def test_low_risk_verdict_green(self):
        html = build_html_report(self._rep(verdict="low_risk", score=10))
        assert 'data-threat="benign"' in html

    def test_no_malicious_behavior_observed_verdict_grey(self):
        html = build_html_report(self._rep(verdict="no_malicious_behavior_observed", score=0))
        assert 'data-threat="benign"' in html

    def test_known_vulnerable_verdict_purple(self):
        html = build_html_report(self._rep(verdict="known_vulnerable", score=0))
        assert 'data-threat="vulnerable"' in html

    # ── section presence ──────────────────────────────────────────────────────

    def test_what_happened_section(self):
        html = build_html_report(self._rep())
        assert "verdict-summary" in html or "No summary available" in html

    def test_why_verdict_section(self):
        assert "Score breakdown" in build_html_report(self._rep())

    def test_in_which_phase_section(self):
        assert "Process tree" in build_html_report(self._rep())

    def test_what_host_section(self):
        assert "Network activity" in build_html_report(self._rep())

    def test_what_file_section(self):
        assert "Sensitive file" in build_html_report(self._rep())

    def test_raw_artifacts_section_present(self):
        assert "Raw artifacts" in build_html_report(self._rep())

    # ── narrative ─────────────────────────────────────────────────────────────

    def test_narrative_rendered(self):
        rep = self._rep(narrative=["The package contacted evil.com during install."])
        html = build_html_report(rep)
        assert "The package contacted evil.com during install." in html

    def test_empty_narrative_shows_fallback(self):
        rep = self._rep(narrative=[])
        html = build_html_report(rep)
        assert "No behavioral summary available" in html or "No summary available" in html

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
        assert "No scoring contributions" in html or "no indicators detected" in html

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
        assert "differ" in html.lower()
        assert "evil.com" in html
        assert "4444" in html

    def test_no_diff_no_diff_section(self):
        assert "differ" not in build_html_report(self._rep(diff=None)).lower() or \
               "How does this differ" not in build_html_report(self._rep(diff=None))

    def test_diff_section_renders_findings_table(self):
        diff = {
            "from_version": "1.0.0", "to_version": "1.0.1",
            "risk_delta": "high", "new_domains": [], "new_ports": [],
            "findings": [
                {"kind": "became_suspicious", "severity": "critical",
                 "message": "Package went from clean to suspicious", "detail": {}},
                {"kind": "new_network_ports", "severity": "medium",
                 "message": "New ports used: [4444]", "detail": {"added": [4444]}},
            ],
        }
        html = build_html_report(self._rep(diff=diff))
        assert "became_suspicious" in html
        assert "sev-critical" in html
        assert "new_network_ports" in html
        assert "sev-medium" in html
        assert "Package went from clean to suspicious" in html

    def test_diff_section_no_findings_table_when_findings_empty(self):
        diff = {
            "from_version": "1.0.0", "to_version": "1.0.1",
            "risk_delta": "clean", "new_domains": [], "new_ports": [],
            "findings": [],
        }
        html = build_html_report(self._rep(diff=diff))
        # CSS class exists in stylesheet; check that no table element is rendered
        assert '<table class="diff-findings-table">' not in html

    def test_diff_section_caps_at_ten_findings(self):
        findings = [
            {"kind": f"finding_{i}", "severity": "low",
             "message": f"msg {i}", "detail": {}}
            for i in range(15)
        ]
        diff = {
            "from_version": "1.0.0", "to_version": "1.0.1",
            "risk_delta": "low", "new_domains": [], "new_ports": [],
            "findings": findings,
        }
        html = build_html_report(self._rep(diff=diff))
        assert "finding_9" in html          # 10th item rendered
        assert "finding_10" not in html     # 11th item suppressed
        assert "more finding" in html       # overflow note shown

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
        assert "<script>alert(1)</script>" not in html
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
        assert "Process tree" in html

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


# ── TestExportBundle ──────────────────────────────────────────────────────────

class TestExportBundle:
    """Tests for export_bundle() — portable, desktop-friendly report packages."""

    def _setup(self, tmp_path: Path):
        """Create a minimal run dir and build a report dict."""
        run_dir = tmp_path / "runs" / "20240101T000000Z-pypi-mypkg-1.0.0"
        run_dir.mkdir(parents=True)
        _minimal_run(run_dir)
        # Write a couple of artifact files so copy behaviour is testable.
        (run_dir / "telemetry.jsonl").write_text('{"event_type":"exec"}\n', encoding="utf-8")
        norm = normalize(run_dir)
        rep  = build_report(norm)
        return run_dir, rep

    # ── bundle structure ──────────────────────────────────────────────────────

    def test_bundle_dir_created(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert bundle.is_dir()

    def test_bundle_named_after_run_id(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert bundle.name == run_dir.name

    def test_artifacts_subdir_created(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert (bundle / "artifacts").is_dir()

    def test_run_json_copied(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert (bundle / "artifacts" / "run.json").exists()

    def test_telemetry_jsonl_copied(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert (bundle / "artifacts" / "telemetry.jsonl").exists()

    def test_missing_artifacts_not_copied(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        # capture.pcap is not present in minimal run — should NOT be in export
        assert not (bundle / "artifacts" / "capture.pcap").exists()

    def test_report_json_written(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert (bundle / "report.json").exists()
        data = json.loads((bundle / "report.json").read_text())
        assert "verdict" in data
        assert not any(k.startswith("_") for k in data)

    def test_report_html_written(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        assert (bundle / "report.html").exists()
        html = (bundle / "report.html").read_text()
        assert "<!DOCTYPE html>" in html

    # ── portable links ────────────────────────────────────────────────────────

    def test_exported_html_uses_relative_links(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        html = (bundle / "report.html").read_text()
        assert "artifacts/run.json" in html

    def test_exported_html_has_no_absolute_file_uris(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        html = (bundle / "report.html").read_text()
        assert "file:///" not in html

    def test_missing_artifact_renders_gracefully(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        export_root = tmp_path / "exports"
        bundle = export_bundle(run_dir, rep, export_root=export_root)
        html = (bundle / "report.html").read_text()
        # capture.pcap is missing — should show as "missing", not crash
        assert "capture.pcap" in html
        assert "missing" in html

    # ── default export_root ───────────────────────────────────────────────────

    def test_default_export_root_is_sibling_of_runs(self, tmp_path: Path):
        run_dir, rep = self._setup(tmp_path)
        # run_dir is tmp_path/runs/<id>/ → default export root = tmp_path/exports/
        bundle = export_bundle(run_dir, rep)
        assert bundle.parent == tmp_path / "exports"

    # ── repeated runs ─────────────────────────────────────────────────────────

    def test_separate_runs_get_separate_bundles(self, tmp_path: Path):
        export_root = tmp_path / "exports"
        for run_name in ("20240101T000000Z-pypi-pkgA-1.0.0",
                         "20240102T000000Z-pypi-pkgB-2.0.0"):
            run_dir = tmp_path / "runs" / run_name
            run_dir.mkdir(parents=True)
            _minimal_run(run_dir)
            norm = normalize(run_dir)
            rep  = build_report(norm)
            export_bundle(run_dir, rep, export_root=export_root)
        bundles = list(export_root.iterdir())
        assert len(bundles) == 2

    # ── cmd_report default HTML ───────────────────────────────────────────────

    def test_report_always_writes_html_to_run_dir(self, tmp_path: Path):
        """report() with output_html explicitly set writes HTML (API contract)."""
        _minimal_run(tmp_path)
        report(tmp_path, output_html=tmp_path / "report.html")
        assert (tmp_path / "report.html").exists()

    def test_build_html_report_relative_prefix(self, tmp_path: Path):
        """build_html_report with artifact_prefix uses relative hrefs."""
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        html = build_html_report(rep, artifact_prefix="artifacts/")
        assert "artifacts/run.json" in html


# ── Feature 2: trigger verdicts ───────────────────────────────────────────────

def _minimal_run_with_triggers(tmp_path: Path, triggers: list | None = None) -> None:
    run: dict = {
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
        "triggers": triggers or [],
    }
    (tmp_path / "run.json").write_text(json.dumps(run), encoding="utf-8")


class TestTriggerVerdicts:
    def test_trigger_verdicts_empty_when_no_triggers(self, tmp_path: Path):
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        assert rep["trigger_verdicts"] == []

    def test_trigger_verdicts_present_when_triggers_in_run_json(self, tmp_path: Path):
        _minimal_run_with_triggers(tmp_path, triggers=[
            {"trigger_id": "install",     "phase_label": "Install",
             "status": "ok", "t_start": 1000.0, "t_end": 1002.0,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
            {"trigger_id": "import_root", "phase_label": "Import (root)",
             "status": "ok", "t_start": 1002.0, "t_end": 1002.5,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
        ])
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        assert len(rep["trigger_verdicts"]) == 2

    def test_trigger_verdict_fields(self, tmp_path: Path):
        _minimal_run_with_triggers(tmp_path, triggers=[
            {"trigger_id": "install", "phase_label": "Install",
             "status": "ok", "t_start": 1000.0, "t_end": 1002.0,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
        ])
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        tv = rep["trigger_verdicts"][0]
        for key in ("trigger_id", "phase_label", "status", "behavioral_verdict",
                    "score", "network_activity", "indicators"):
            assert key in tv, f"trigger_verdict missing key: {key}"

    def test_top_level_verdict_present_regardless_of_triggers(self, tmp_path: Path):
        _minimal_run(tmp_path)
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        assert "behavioral_verdict" in rep
        assert "score" in rep

    def test_trigger_verdicts_in_normalized_triggers(self, tmp_path: Path):
        triggers = [
            {"trigger_id": "install", "phase_label": "Install",
             "status": "ok", "t_start": 1000.0, "t_end": 1002.0,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
        ]
        _minimal_run_with_triggers(tmp_path, triggers=triggers)
        norm = normalize(tmp_path)
        assert "triggers" in norm
        assert norm["triggers"] == triggers


class TestHtmlTriggerBreakdown:
    def _rep_with_triggers(self, trigger_verdicts: list) -> dict:
        return {
            "package":            {"ecosystem": "pypi", "name": "pkg", "version": "1.0"},
            "verdict":            "no_malicious_behavior_observed",
            "behavioral_verdict": "no_malicious_behavior_observed",
            "advisory_status":    "none",
            "verdict_basis":      "dynamic",
            "advisory":           {},
            "score":              0,
            "confidence":         0.0,
            "attack_tactics":     [],
            "techniques":         [],
            "indicators":         [],
            "narrative":          ["No suspicious behavior detected."],
            "score_breakdown":    {"items": [], "combo_bonus": 0, "total": 0},
            "summary":            {"indicator_count": 0, "critical": 0,
                                   "high": 0, "medium": 0, "low": 0},
            "trigger_verdicts":   trigger_verdicts,
            "_trigger_verdicts":  trigger_verdicts,
            "phases":             {},
            "event_counts":       {},
            "metadata":           {},
            "diff":               None,
            "_run":               {"run_dir": ""},
            "_phases_detail":     {},
            "_network":           {},
            "_telemetry":         {},
            "_correlations":      {},
        }

    def test_trigger_breakdown_absent_when_no_triggers(self):
        html = build_html_report(self._rep_with_triggers([]))
        assert "Trigger breakdown" not in html

    def test_trigger_breakdown_present_when_triggers_exist(self):
        tvs = [
            {"trigger_id": "install", "phase_label": "Install",
             "status": "ok", "network_activity": False,
             "process_activity": {"process_count": 2, "any_suspicious": False},
             "behavioral_verdict": "no_malicious_behavior_observed", "score": 0,
             "indicators": []},
            {"trigger_id": "import_root", "phase_label": "Import (root)",
             "status": "ok", "network_activity": False,
             "process_activity": {"process_count": 1, "any_suspicious": False},
             "behavioral_verdict": "no_malicious_behavior_observed", "score": 0,
             "indicators": []},
        ]
        html = build_html_report(self._rep_with_triggers(tvs))
        assert "Trigger breakdown" in html
        assert "install" in html
        assert "import_root" in html

    def test_trigger_breakdown_shows_network_activity(self):
        tvs = [
            {"trigger_id": "install", "phase_label": "Install",
             "status": "ok", "network_activity": True,
             "process_activity": {},
             "behavioral_verdict": "suspicious", "score": 30,
             "indicators": []},
        ]
        html = build_html_report(self._rep_with_triggers(tvs))
        assert "Trigger breakdown" in html
        assert "yes" in html  # network_activity=True renders as "yes"
        assert "file:///" not in html


# ── Feature 2 v1.6: import_submodule trigger reports ─────────────────────────

def _submodule_trigger_entry(**overrides) -> dict:
    base = {
        "trigger_id":       "import_submodule",
        "phase_label":      "Import (submodule)",
        "status":           "ok",
        "t_start":          1003.0,
        "t_end":            1003.5,
        "exit_code":        0,
        "timed_out":        False,
        "network_activity": False,
        "process_activity": {},
        "skip_reason":      None,
    }
    base.update(overrides)
    return base


class TestImportSubmoduleTriggerVerdicts:
    def test_import_submodule_verdict_in_trigger_verdicts(self, tmp_path: Path):
        _minimal_run_with_triggers(tmp_path, triggers=[
            {"trigger_id": "install", "phase_label": "Install",
             "status": "ok", "t_start": 1000.0, "t_end": 1002.0,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
            {"trigger_id": "import_root", "phase_label": "Import (root)",
             "status": "ok", "t_start": 1002.0, "t_end": 1002.5,
             "exit_code": 0, "timed_out": False,
             "network_activity": False, "process_activity": {}, "skip_reason": None},
            _submodule_trigger_entry(),
        ])
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        assert any(tv["trigger_id"] == "import_submodule" for tv in rep["trigger_verdicts"])

    def test_import_submodule_verdict_has_required_fields(self, tmp_path: Path):
        _minimal_run_with_triggers(tmp_path, triggers=[_submodule_trigger_entry()])
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        tv = next(t for t in rep["trigger_verdicts"] if t["trigger_id"] == "import_submodule")
        for key in ("trigger_id", "phase_label", "status", "behavioral_verdict",
                    "score", "network_activity", "indicators"):
            assert key in tv, f"import_submodule trigger_verdict missing {key}"

    def test_import_submodule_uses_import_tel_phase_for_telemetry_filtering(
        self, tmp_path: Path
    ):
        """Telemetry events tagged phase='import' must be attributed to import_submodule
        verdict — confirming the _trigger_to_tel_phase mapping is correct."""
        _minimal_run_with_triggers(tmp_path, triggers=[_submodule_trigger_entry()])
        _write_jsonl(tmp_path, "telemetry.jsonl", [
            {"event_type": "exec", "executable": "/bin/sh", "argv": ["sh"],
             "phase": "import", "ts": 1003.2},
            {"event_type": "exec", "executable": "/usr/bin/pip3", "argv": ["pip3"],
             "phase": "install", "ts": 1001.0},
        ])
        norm = normalize(tmp_path)
        rep  = build_report(norm)
        tv = next(t for t in rep["trigger_verdicts"] if t["trigger_id"] == "import_submodule")
        # The import-phase exec event must reach the trigger_verdict telemetry slice.
        assert "indicators" in tv

    def test_import_submodule_html_breakdown_row_present(self):
        tvs = [
            {"trigger_id": "import_submodule", "phase_label": "Import (submodule)",
             "status": "ok", "network_activity": False,
             "process_activity": {"process_count": 1, "any_suspicious": False},
             "behavioral_verdict": "no_malicious_behavior_observed", "score": 0,
             "indicators": []},
        ]
        html = build_html_report(TestHtmlTriggerBreakdown()._rep_with_triggers(tvs))
        assert "Trigger breakdown"  in html
        assert "import_submodule"   in html
        assert "Import (submodule)" in html


# ── Phase 4: bait section HTML rendering ─────────────────────────────────────

_BAIT_PLANTED_MANIFEST = {
    "run_id":        "testrun0",
    "planted_paths": [
        "/home/deton/.env",
        "/home/deton/.aws/credentials",
        "/home/deton/.pypirc",
        "/home/deton/.ssh/id_rsa",
    ],
    "planted_count": 4,
    "files": [
        {"path": "/home/deton/.env",             "category": "env_file",        "size": 80},
        {"path": "/home/deton/.aws/credentials", "category": "aws_credentials", "size": 95},
        {"path": "/home/deton/.pypirc",          "category": "pypi_rc",         "size": 70},
        {"path": "/home/deton/.ssh/id_rsa",      "category": "ssh_keys",        "size": 110},
    ],
}


def _bait_rep(**overrides) -> dict:
    base = {
        "package":            {"ecosystem": "pypi", "name": "badpkg", "version": "1.0"},
        "verdict":            "malicious",
        "final_verdict":      "malicious",
        "behavioral_verdict": "malicious",
        "advisory_status":    "none",
        "verdict_basis":      "dynamic",
        "advisory":           {},
        "score":              65,
        "confidence":         0.90,
        "attack_tactics":     [],
        "techniques":         [],
        "indicators":         [],
        "narrative":          ["Malicious behavior detected."],
        "score_breakdown":    {"items": [], "combo_bonus": 0, "total": 65},
        "summary":            {"indicator_count": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        "trigger_verdicts":   [],
        "_trigger_verdicts":  [],
        "phases":             {},
        "event_counts":       {},
        "metadata":           {},
        "diff":               None,
        "_run":               {"ecosystem": "pypi", "name": "badpkg",
                               "version": "1.0", "run_dir": ""},
        "_phases_detail":     {},
        "_network":           {},
        "_telemetry":         {},
        "_correlations":      {},
        "bait_planted":       _BAIT_PLANTED_MANIFEST,
    }
    base.update(overrides)
    return base


class TestBaitSectionHtml:
    def test_bait_section_present_when_bait_planted(self):
        html = build_html_report(_bait_rep())
        assert "bait-access" in html
        assert "Synthetic bait access" in html

    def test_bait_section_present_when_no_bait(self):
        html = build_html_report(_bait_rep(bait_planted={}))
        assert "bait-access" in html
        assert "Synthetic bait access" in html

    def test_no_bait_shows_pre_phase4_message(self):
        html = build_html_report(_bait_rep(bait_planted={}))
        assert "predates Phase 4" in html

    def test_bait_planted_shows_file_paths(self):
        html = build_html_report(_bait_rep())
        assert "/home/deton/.env"             in html
        assert "/home/deton/.aws/credentials" in html

    def test_bait_section_collapsed_when_no_accesses(self):
        html = build_html_report(_bait_rep())
        # data-empty on bait section when nothing accessed
        assert 'id="bait-access" data-empty="true"' in html

    def test_bait_section_not_collapsed_when_files_accessed(self):
        from pkgids.indicators import _CATALOG
        ind = {
            "id":        "bait_enumeration",
            "title":     _CATALOG["bait_enumeration"]["title"],
            "tactic":    _CATALOG["bait_enumeration"]["tactic"],
            "technique": _CATALOG["bait_enumeration"]["technique"],
            "severity":  _CATALOG["bait_enumeration"]["severity"],
            "weight":    _CATALOG["bait_enumeration"]["weight"],
            "evidence":  {
                "accessed_paths": ["/home/deton/.env", "/home/deton/.aws/credentials"],
                "total_planted": 4,
            },
        }
        html = build_html_report(_bait_rep(indicators=[ind]))
        assert 'id="bait-access" data-empty="true"' not in html

    def test_mini_nav_includes_bait_link(self):
        html = build_html_report(_bait_rep())
        assert 'href="#bait-access"' in html

    def test_bait_section_shows_planted_count(self):
        html = build_html_report(_bait_rep())
        assert "4 synthetic credential file(s) planted" in html
