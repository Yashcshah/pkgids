"""Unit tests for pkgids/score.py — additive point scoring model."""

from __future__ import annotations

import pytest

from pkgids.score import score, confidence, verdict, _WEIGHTS, _EXFIL_COMBO_BONUS


def _ind(id_: str, tactic: str = "execution") -> dict:
    return {"id": id_, "tactic": tactic, "weight": 0.5}


# ── score() ───────────────────────────────────────────────────────────────────

class TestScore:
    def test_empty_returns_zero(self):
        assert score([]) == 0

    def test_returns_int(self):
        assert isinstance(score([_ind("install_timed_out")]), int)

    def test_single_credential_indicator(self):
        assert score([_ind("ssh_key_accessed", "credential-access")]) == 25

    def test_single_network_indicator(self):
        assert score([_ind("dns_query_observed", "command-and-control")]) == 20

    def test_single_low_signal(self):
        assert score([_ind("install_timed_out", "defense-evasion")]) == 10

    def test_additive_two_indicators(self):
        inds = [
            _ind("install_timed_out",  "defense-evasion"),   # 10
            _ind("install_hook_executed", "persistence"),     # 10
        ]
        assert score(inds) == 20

    def test_combo_bonus_network_plus_credential(self):
        # Combo requires HTTP/TLS (not bare DNS) alongside a credential read
        inds = [
            _ind("http_request_observed", "command-and-control"),  # 20
            _ind("ssh_key_accessed",      "credential-access"),    # 25
        ]
        # 20 + 25 + 25 combo bonus = 70
        assert score(inds) == 20 + 25 + _EXFIL_COMBO_BONUS

    def test_combo_bonus_only_once(self):
        # Two credential + two network: bonus should only be applied once
        inds = [
            _ind("dns_query_observed",       "command-and-control"),
            _ind("http_request_observed",    "command-and-control"),
            _ind("ssh_key_accessed",         "credential-access"),
            _ind("env_file_read",            "credential-access"),
        ]
        expected = 20 + 20 + 25 + 25 + _EXFIL_COMBO_BONUS
        assert score(inds) == min(100, expected)

    def test_no_combo_without_network(self):
        # Credential only → no bonus
        inds = [_ind("ssh_key_accessed", "credential-access")]
        assert score(inds) == 25

    def test_no_combo_without_credential(self):
        # Network only → no bonus
        inds = [_ind("http_request_observed", "command-and-control")]
        assert score(inds) == 20

    def test_clamped_at_100(self):
        inds = [_ind(k, "execution") for k in _WEIGHTS]
        assert score(inds) == 100

    def test_order_independent(self):
        a = score([_ind("ssh_key_accessed", "credential-access"),
                   _ind("dns_query_observed", "command-and-control")])
        b = score([_ind("dns_query_observed", "command-and-control"),
                   _ind("ssh_key_accessed", "credential-access")])
        assert a == b

    def test_unknown_indicator_id_contributes_zero(self):
        assert score([{"id": "completely_unknown", "tactic": "execution"}]) == 0

    def test_shell_exec_weight(self):
        assert score([_ind("shell_spawned_during_install", "execution")]) == 15

    def test_obfuscation_weight(self):
        assert score([_ind("base64_command_present", "defense-evasion")]) == 15

    def test_baseline_delta_weight(self):
        assert score([_ind("new_behavior_vs_baseline", "defense-evasion")]) == 20


# ── confidence() ─────────────────────────────────────────────────────────────

class TestConfidence:
    def test_empty_returns_zero(self):
        assert confidence([]) == 0.0

    def test_returns_float(self):
        assert isinstance(confidence([_ind("x", "execution")]), float)

    def test_diff_only_returns_0_5(self):
        ind = {"id": "new_behavior_vs_baseline", "tactic": "defense-evasion"}
        assert confidence([ind]) == 0.50

    def test_single_dns_low_confidence(self):
        ind = {"id": "dns_query_observed", "tactic": "command-and-control"}
        c = confidence([ind])
        assert c < 0.40  # single weak signal → low confidence

    def test_three_diverse_tactics_high_confidence(self):
        inds = [
            {"id": "sensitive_file_accessed", "tactic": "credential-access"},
            {"id": "shell_spawned_during_install", "tactic": "execution"},
            {"id": "http_request_observed", "tactic": "command-and-control"},
        ]
        c = confidence(inds)
        assert c >= 0.65

    def test_cred_plus_network_gets_corroboration_bonus(self):
        with_cred_net = [
            {"id": "ssh_key_accessed",      "tactic": "credential-access"},
            {"id": "dns_query_observed",     "tactic": "command-and-control"},
        ]
        without = [
            {"id": "install_hook_executed",  "tactic": "persistence"},
            {"id": "subprocess_chain_deep",  "tactic": "execution"},
        ]
        assert confidence(with_cred_net) > confidence(without)

    def test_capped_at_1_0(self):
        inds = [{"id": "x", "tactic": "execution"}] * 20
        assert confidence(inds) <= 1.0

    def test_non_diff_single_indicator_not_0_5(self):
        ind = {"id": "ssh_key_accessed", "tactic": "credential-access"}
        assert confidence([ind]) != 0.50

    def test_more_indicators_higher_confidence(self):
        one   = confidence([{"id": "a", "tactic": "execution"}])
        three = confidence([{"id": "a", "tactic": "execution"},
                            {"id": "b", "tactic": "credential-access"},
                            {"id": "c", "tactic": "command-and-control"}])
        assert three > one

    def test_diversity_matters(self):
        same_tactic = [{"id": "a", "tactic": "execution"},
                       {"id": "b", "tactic": "execution"},
                       {"id": "c", "tactic": "execution"}]
        diff_tactic = [{"id": "a", "tactic": "execution"},
                       {"id": "b", "tactic": "credential-access"},
                       {"id": "c", "tactic": "command-and-control"}]
        assert confidence(diff_tactic) > confidence(same_tactic)


# ── verdict() ─────────────────────────────────────────────────────────────────

class TestVerdict:
    def test_0_is_benign(self):
        assert verdict(0) == "benign"

    def test_24_is_benign(self):
        assert verdict(24) == "benign"

    def test_25_is_suspicious(self):
        assert verdict(25) == "suspicious"

    def test_49_is_suspicious(self):
        assert verdict(49) == "suspicious"

    def test_50_is_likely_malicious(self):
        assert verdict(50) == "likely_malicious"

    def test_74_is_likely_malicious(self):
        assert verdict(74) == "likely_malicious"

    def test_75_is_malicious(self):
        assert verdict(75) == "malicious"

    def test_100_is_malicious(self):
        assert verdict(100) == "malicious"

    def test_four_tier_coverage(self):
        results = {verdict(s) for s in [0, 25, 50, 75]}
        assert results == {"benign", "suspicious", "likely_malicious", "malicious"}


# ── score + verdict integration ────────────────────────────────────────────────

class TestScoreVerdictIntegration:
    def test_ssh_key_alone_is_suspicious(self):
        # 25 points → suspicious (≥ 25)
        s = score([{"id": "ssh_key_accessed", "tactic": "credential-access"}])
        assert verdict(s) == "suspicious"

    def test_ssh_key_plus_network_is_likely_malicious(self):
        # 25 + 20 + 25 combo = 70 → likely_malicious (≥ 50)
        inds = [
            {"id": "ssh_key_accessed",       "tactic": "credential-access"},
            {"id": "http_request_observed",  "tactic": "command-and-control"},
        ]
        s = score(inds)
        assert verdict(s) == "likely_malicious"

    def test_single_low_signal_is_benign(self):
        s = score([{"id": "install_timed_out", "tactic": "defense-evasion"}])
        assert verdict(s) == "benign"

    def test_full_exfil_chain_is_malicious(self):
        inds = [
            {"id": "sensitive_file_accessed",     "tactic": "credential-access"},
            {"id": "http_request_observed",        "tactic": "command-and-control"},
            {"id": "shell_spawned_during_install", "tactic": "execution"},
        ]
        s = score(inds)
        assert verdict(s) == "malicious"


# ── score_breakdown() ─────────────────────────────────────────────────────────

from pkgids.score import score_breakdown


class TestScoreBreakdown:
    def test_empty_returns_zero_total(self):
        bd = score_breakdown([])
        assert bd["total"] == 0
        assert bd["items"] == []
        assert bd["combo_bonus"] == 0

    def test_items_contain_required_fields(self):
        ind = {"id": "install_timed_out", "tactic": "defense-evasion",
               "title": "Install timed out", "severity": "medium",
               "technique": "T1497.001", "evidence": {"phase": "install"}}
        bd = score_breakdown([ind])
        assert len(bd["items"]) == 1
        item = bd["items"][0]
        for field in ("id", "title", "severity", "tactic", "technique", "phase", "points"):
            assert field in item, f"missing {field}"

    def test_points_match_weight(self):
        ind = {"id": "ssh_key_accessed", "tactic": "credential-access",
               "title": "SSH key", "severity": "critical",
               "technique": "T1552.004", "evidence": {}}
        bd = score_breakdown([ind])
        assert bd["items"][0]["points"] == 25

    def test_items_sorted_descending(self):
        inds = [
            {"id": "install_timed_out",  "tactic": "t", "title": "", "severity": "medium",
             "technique": "", "evidence": {}},
            {"id": "ssh_key_accessed",   "tactic": "t", "title": "", "severity": "critical",
             "technique": "", "evidence": {}},
        ]
        bd = score_breakdown(inds)
        pts = [i["points"] for i in bd["items"]]
        assert pts == sorted(pts, reverse=True)

    def test_combo_bonus_when_cred_and_network(self):
        inds = [
            {"id": "ssh_key_accessed",      "tactic": "credential-access",
             "title": "", "severity": "critical", "technique": "", "evidence": {}},
            {"id": "http_request_observed", "tactic": "command-and-control",
             "title": "", "severity": "medium",   "technique": "", "evidence": {}},
        ]
        bd = score_breakdown(inds)
        assert bd["combo_bonus"] == 25

    def test_no_combo_without_network(self):
        ind = {"id": "ssh_key_accessed", "tactic": "credential-access",
               "title": "", "severity": "critical", "technique": "", "evidence": {}}
        bd = score_breakdown([ind])
        assert bd["combo_bonus"] == 0

    def test_total_matches_score(self):
        inds = [
            {"id": "dns_query_observed",   "tactic": "command-and-control",
             "title": "", "severity": "medium", "technique": "", "evidence": {}},
            {"id": "install_timed_out",    "tactic": "defense-evasion",
             "title": "", "severity": "medium", "technique": "", "evidence": {}},
        ]
        assert score_breakdown(inds)["total"] == score(inds)

    def test_phase_extracted_from_evidence(self):
        ind = {"id": "shell_spawned_during_install", "tactic": "execution",
               "title": "", "severity": "high", "technique": "",
               "evidence": {"phase": "install"}}
        bd = score_breakdown([ind])
        assert bd["items"][0]["phase"] == "install"

    def test_unknown_id_excluded_from_items(self):
        ind = {"id": "completely_unknown_indicator", "tactic": "x",
               "title": "", "severity": "low", "technique": "", "evidence": {}}
        bd = score_breakdown([ind])
        assert bd["items"] == []
