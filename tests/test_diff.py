"""Unit tests for pkgids/diff.py — behavioral diff engine."""

from __future__ import annotations

import pytest

from pkgids.diff import diff_profiles, fingerprint, _is_obfuscated


# ── helpers ───────────────────────────────────────────────────────────────────

def _profile(
    version="1.0.0",
    network_domains=None,
    network_ports=None,
    suspicious_exec_count=0,
    sensitive_file_count=0,
    shell_cmd_count=0,
    subprocess_count=0,
    any_suspicious=False,
    install_status="ok",
    import_status="ok",
    prediction="benign",
    install_pa=None,
    import_pa=None,
    new_file_count=0,
) -> dict:
    return {
        "version":               version,
        "network_domains":       network_domains or [],
        "network_ports":         network_ports   or [],
        "suspicious_exec_count": suspicious_exec_count,
        "sensitive_file_count":  sensitive_file_count,
        "shell_cmd_count":       shell_cmd_count,
        "subprocess_count":      subprocess_count,
        "any_suspicious":        any_suspicious,
        "install_status":        install_status,
        "import_status":         import_status,
        "prediction":            prediction,
        "install_process_activity": install_pa,
        "import_process_activity":  import_pa,
        "new_file_count":        new_file_count,
    }


def _findings_of_kind(result: dict, kind: str) -> list[dict]:
    return [f for f in result["findings"] if f["kind"] == kind]


# ── clean baseline ────────────────────────────────────────────────────────────

class TestDiffClean:
    def test_identical_profiles_are_clean(self):
        old = _profile("1.0")
        new = _profile("1.1")
        r = diff_profiles(old, new)
        assert r["verdict"] == "clean"
        assert r["is_suspicious"] is False
        assert r["findings"] == []
        assert r["summary"]["total"] == 0

    def test_from_to_version_in_result(self):
        r = diff_profiles(_profile("1.0"), _profile("1.1"))
        assert r["from_version"] == "1.0"
        assert r["to_version"]   == "1.1"

    def test_canonical_version_aliases(self):
        r = diff_profiles(_profile("1.0"), _profile("1.1"))
        assert r["baseline_version"]  == "1.0"
        assert r["candidate_version"] == "1.1"

    def test_risk_delta_clean_when_no_findings(self):
        r = diff_profiles(_profile("1.0"), _profile("1.1"))
        assert r["risk_delta"] == "clean"


# ── network domains ────────────────────────────────────────────────────────────

class TestDiffNetworkDomains:
    def test_new_domain_is_critical(self):
        old = _profile(network_domains=[])
        new = _profile(network_domains=["evil.com"])
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"
        f = _findings_of_kind(r, "new_network_domains")
        assert len(f) == 1
        assert "evil.com" in f[0]["detail"]["added"]

    def test_removed_domain_is_low(self):
        old = _profile(network_domains=["cdn.lib.io"])
        new = _profile(network_domains=[])
        r   = diff_profiles(old, new)
        assert r["verdict"] == "info"
        f = _findings_of_kind(r, "removed_network_domains")
        assert len(f) == 1
        assert f[0]["severity"] == "low"

    def test_same_domains_no_finding(self):
        old = _profile(network_domains=["cdn.lib.io"])
        new = _profile(network_domains=["cdn.lib.io"])
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_network_domains") == []

    def test_multiple_new_domains_single_finding(self):
        old = _profile(network_domains=["a.com"])
        new = _profile(network_domains=["a.com", "b.com", "c.com"])
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "new_network_domains")
        assert len(f) == 1
        assert sorted(f[0]["detail"]["added"]) == ["b.com", "c.com"]

    def test_new_domains_in_canonical_field(self):
        old = _profile(network_domains=["a.com"])
        new = _profile(network_domains=["a.com", "evil.com"])
        r   = diff_profiles(old, new)
        assert r["new_domains"] == ["evil.com"]

    def test_risk_delta_critical_on_new_domain(self):
        old = _profile(network_domains=[])
        new = _profile(network_domains=["c2.bad"])
        r   = diff_profiles(old, new)
        assert r["risk_delta"] == "critical"


# ── network ports ─────────────────────────────────────────────────────────────

class TestDiffNetworkPorts:
    def test_new_port_is_medium(self):
        old = _profile(network_ports=[80])
        new = _profile(network_ports=[80, 4444])
        r   = diff_profiles(old, new)
        assert r["verdict"] == "needs_review"
        f   = _findings_of_kind(r, "new_network_ports")
        assert f[0]["severity"] == "medium"
        assert 4444 in f[0]["detail"]["added"]

    def test_same_ports_no_finding(self):
        old = _profile(network_ports=[443])
        new = _profile(network_ports=[443])
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_network_ports") == []

    def test_new_ports_in_canonical_field(self):
        old = _profile(network_ports=[80])
        new = _profile(network_ports=[80, 8080])
        r   = diff_profiles(old, new)
        assert r["new_ports"] == [8080]


# ── suspicious execs ──────────────────────────────────────────────────────────

class TestDiffSuspiciousExecs:
    def test_single_increase_is_medium(self):
        old = _profile(suspicious_exec_count=0)
        new = _profile(suspicious_exec_count=1)
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "suspicious_exec_increase")
        assert len(f) == 1
        assert f[0]["severity"] == "medium"

    def test_large_increase_is_high(self):
        old = _profile(suspicious_exec_count=0)
        new = _profile(suspicious_exec_count=3)
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "suspicious_exec_increase")
        assert f[0]["severity"] == "high"

    def test_large_increase_verdict_suspicious(self):
        old = _profile(suspicious_exec_count=0)
        new = _profile(suspicious_exec_count=3)
        assert diff_profiles(old, new)["verdict"] == "suspicious"

    def test_no_change_no_finding(self):
        old = _profile(suspicious_exec_count=1)
        new = _profile(suspicious_exec_count=1)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "suspicious_exec_increase") == []

    def test_decrease_no_finding(self):
        old = _profile(suspicious_exec_count=2)
        new = _profile(suspicious_exec_count=0)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "suspicious_exec_increase") == []


# ── sensitive file accesses ───────────────────────────────────────────────────

class TestDiffSensitiveFiles:
    def test_new_sensitive_access_is_high(self):
        old = _profile(sensitive_file_count=0)
        new = _profile(sensitive_file_count=1)
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"
        f   = _findings_of_kind(r, "sensitive_file_increase")
        assert f[0]["severity"] == "high"

    def test_decrease_no_finding(self):
        old = _profile(sensitive_file_count=2)
        new = _profile(sensitive_file_count=1)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "sensitive_file_increase") == []

    def test_new_sensitive_paths_extracted(self):
        pa = {
            "sensitive_file_accesses": [{"path": "/etc/passwd", "access_type": "read"}],
            "suspicious_execs": [],
        }
        old = _profile(sensitive_file_count=0)
        new = _profile(sensitive_file_count=1, install_pa=pa)
        r   = diff_profiles(old, new)
        assert "/etc/passwd" in r["new_sensitive_paths"]


# ── shell command spawns ──────────────────────────────────────────────────────

class TestDiffShellCmds:
    def test_new_shell_spawn_is_high(self):
        old = _profile(shell_cmd_count=0)
        new = _profile(shell_cmd_count=1)
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"
        f   = _findings_of_kind(r, "shell_cmd_increase")
        assert f[0]["severity"] == "high"


# ── any_suspicious flip ───────────────────────────────────────────────────────

class TestDiffAnySuspicious:
    def test_clean_to_suspicious_is_critical(self):
        old = _profile(any_suspicious=False)
        new = _profile(any_suspicious=True)
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"
        f   = _findings_of_kind(r, "became_suspicious")
        assert f[0]["severity"] == "critical"

    def test_suspicious_to_clean_is_low(self):
        old = _profile(any_suspicious=True)
        new = _profile(any_suspicious=False)
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "cleared_suspicious")
        assert f[0]["severity"] == "low"

    def test_both_clean_no_finding(self):
        assert _findings_of_kind(
            diff_profiles(_profile(any_suspicious=False), _profile(any_suspicious=False)),
            "became_suspicious"
        ) == []


# ── subprocess count spike ────────────────────────────────────────────────────

class TestDiffSubprocessCount:
    def test_spike_over_threshold_is_medium(self):
        old = _profile(subprocess_count=2)
        new = _profile(subprocess_count=10)
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "subprocess_count_spike")
        assert len(f) == 1
        assert f[0]["severity"] == "medium"

    def test_small_increase_no_finding(self):
        old = _profile(subprocess_count=2)
        new = _profile(subprocess_count=5)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "subprocess_count_spike") == []


# ── phase status regression ───────────────────────────────────────────────────

class TestDiffPhaseStatus:
    def test_install_ok_to_failed_is_medium(self):
        old = _profile(install_status="ok")
        new = _profile(install_status="failed")
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "install_status_regression")
        assert f[0]["severity"] == "medium"

    def test_import_ok_to_timed_out_is_medium(self):
        old = _profile(import_status="ok")
        new = _profile(import_status="timed_out")
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "import_status_regression")
        assert len(f) == 1

    def test_already_failed_no_regression_finding(self):
        old = _profile(install_status="failed")
        new = _profile(install_status="failed")
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "install_status_regression") == []


# ── prediction flip ───────────────────────────────────────────────────────────

class TestDiffPrediction:
    def test_benign_to_malicious_is_critical(self):
        old = _profile(prediction="benign")
        new = _profile(prediction="malicious")
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"
        f   = _findings_of_kind(r, "prediction_flip")
        assert f[0]["severity"] == "critical"

    def test_malicious_to_benign_is_low(self):
        old = _profile(prediction="malicious")
        new = _profile(prediction="benign")
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "prediction_cleared")
        assert f[0]["severity"] == "low"

    def test_both_benign_no_finding(self):
        r = diff_profiles(_profile(prediction="benign"), _profile(prediction="benign"))
        assert _findings_of_kind(r, "prediction_flip") == []


# ── install hooks ─────────────────────────────────────────────────────────────

class TestDiffInstallHooks:
    def _pa_with_hook(self, hook_arg: str) -> dict:
        return {
            "suspicious_execs": [
                {"executable": "/usr/bin/python3", "argv": ["python3", hook_arg], "pid": 1}
            ],
            "sensitive_file_accesses": [],
        }

    def test_new_setup_py_invocation_is_high(self):
        old = _profile()
        new = _profile(install_pa=self._pa_with_hook("setup.py"))
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "new_install_hooks")
        assert len(f) == 1
        assert f[0]["severity"] == "high"
        assert r["verdict"] == "suspicious"

    def test_postinstall_script_flagged(self):
        old = _profile()
        new = _profile(import_pa=self._pa_with_hook("postinstall"))
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "new_install_hooks")
        assert len(f) == 1

    def test_hook_present_in_both_no_finding(self):
        pa = self._pa_with_hook("setup.py")
        old = _profile(install_pa=pa)
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_install_hooks") == []

    def test_non_hook_script_no_finding(self):
        pa = {
            "suspicious_execs": [
                {"executable": "/usr/bin/curl", "argv": ["curl", "http://x.com"], "pid": 1}
            ],
            "sensitive_file_accesses": [],
        }
        old = _profile()
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_install_hooks") == []


# ── obfuscation patterns ──────────────────────────────────────────────────────

class TestDiffObfuscationPatterns:
    def _pa_with_argv(self, argv: list) -> dict:
        return {
            "suspicious_execs": [{"executable": "/usr/bin/python3", "argv": argv, "pid": 1}],
            "sensitive_file_accesses": [],
        }

    def test_base64_keyword_in_argv_is_critical(self):
        pa = self._pa_with_argv(["python3", "-c", "import base64; exec(base64.b64decode('...'))"])
        old = _profile()
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "new_obfuscation_patterns")
        assert len(f) == 1
        assert f[0]["severity"] == "critical"
        assert r["verdict"] == "suspicious"
        assert r["risk_delta"] == "critical"

    def test_exec_compile_flagged(self):
        pa = self._pa_with_argv(["python3", "-c", "exec(compile(open('x').read(),'x','exec'))"])
        old = _profile()
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_obfuscation_patterns") != []

    def test_long_b64_blob_flagged(self):
        blob = "A" * 50  # long base64-ish string
        pa = self._pa_with_argv(["python3", "-c", blob])
        old = _profile()
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_obfuscation_patterns") != []

    def test_obfuscation_in_both_no_finding(self):
        pa = self._pa_with_argv(["python3", "-c", "import base64; exec(base64.b64decode('x'))"])
        old = _profile(install_pa=pa)
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_obfuscation_patterns") == []

    def test_clean_argv_no_finding(self):
        pa = self._pa_with_argv(["python3", "setup.py", "install"])
        old = _profile()
        new = _profile(install_pa=pa)
        # setup.py triggers install_hooks, NOT obfuscation
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "new_obfuscation_patterns") == []


# ── event volume increase ─────────────────────────────────────────────────────

class TestDiffEventVolume:
    def test_subprocess_volume_spike_is_medium(self):
        old = _profile(subprocess_count=4)
        new = _profile(subprocess_count=10)  # +150%, delta=6 > 3
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "event_volume_increase")
        assert any(e["detail"]["key"] == "subprocess_count" for e in f)
        assert f[0]["severity"] == "medium"

    def test_file_create_volume_spike_is_medium(self, tmp_path):
        old = _profile(new_file_count=3)
        new = _profile(new_file_count=10)  # +233%, delta=7 > 3
        r   = diff_profiles(old, new)
        f   = _findings_of_kind(r, "event_volume_increase")
        assert any(e["detail"]["key"] == "new_file_count" for e in f)

    def test_small_ratio_no_finding(self):
        old = _profile(subprocess_count=10)
        new = _profile(subprocess_count=13)  # only +30%
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "event_volume_increase") == []

    def test_zero_baseline_skipped(self):
        # ratio undefined when old=0 — no spurious finding
        old = _profile(subprocess_count=0)
        new = _profile(subprocess_count=20)
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "event_volume_increase") == []

    def test_small_absolute_delta_no_finding(self):
        # ratio > 100% but absolute delta ≤ 3
        old = _profile(subprocess_count=1)
        new = _profile(subprocess_count=3)   # +200% but delta=2 ≤ 3
        r   = diff_profiles(old, new)
        assert _findings_of_kind(r, "event_volume_increase") == []


# ── verdict and severity ordering ────────────────────────────────────────────

class TestDiffVerdict:
    def test_critical_beats_medium(self):
        # new domain (critical) + new port (medium) → suspicious
        old = _profile()
        new = _profile(network_domains=["evil.com"], network_ports=[4444])
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"

    def test_high_alone_yields_suspicious(self):
        old = _profile(sensitive_file_count=0)
        new = _profile(sensitive_file_count=1)  # high severity
        r   = diff_profiles(old, new)
        assert r["verdict"] == "suspicious"

    def test_only_medium_yields_needs_review(self):
        old = _profile(subprocess_count=1)
        new = _profile(subprocess_count=10)   # medium spike
        r   = diff_profiles(old, new)
        assert r["verdict"] == "needs_review"

    def test_findings_sorted_highest_sev_first(self):
        old = _profile(subprocess_count=1)
        new = _profile(subprocess_count=10, network_domains=["x.com"], shell_cmd_count=1)
        r   = diff_profiles(old, new)
        sev_order = [_SEV_RANK(f["severity"]) for f in r["findings"]]
        assert sev_order == sorted(sev_order, reverse=True)

    def test_summary_counts_correct(self):
        old = _profile(subprocess_count=1)
        new = _profile(subprocess_count=10, network_domains=["evil.com"])
        r   = diff_profiles(old, new)
        assert r["summary"]["critical"] >= 1
        assert r["summary"]["medium"]   >= 1
        assert r["summary"]["total"]    == len(r["findings"])

    def test_summary_has_all_tier_keys(self):
        r = diff_profiles(_profile(), _profile())
        for k in ("critical", "high", "medium", "low", "total"):
            assert k in r["summary"]


def _SEV_RANK(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 0)


# ── canonical output fields ───────────────────────────────────────────────────

class TestDiffCanonicalOutput:
    def test_new_processes_populated(self):
        pa = {
            "suspicious_execs": [
                {"executable": "/bin/sh", "argv": ["sh", "-c", "id"], "pid": 1}
            ],
            "sensitive_file_accesses": [],
        }
        old = _profile()
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert ["sh", "-c", "id"] in r["new_processes"]

    def test_new_processes_empty_when_same(self):
        pa = {
            "suspicious_execs": [{"executable": "/bin/sh", "argv": ["sh"], "pid": 1}],
            "sensitive_file_accesses": [],
        }
        old = _profile(install_pa=pa)
        new = _profile(install_pa=pa)
        r   = diff_profiles(old, new)
        assert r["new_processes"] == []

    def test_risk_delta_levels(self):
        assert diff_profiles(_profile(), _profile())["risk_delta"] == "clean"
        assert diff_profiles(
            _profile(subprocess_count=1), _profile(subprocess_count=10)
        )["risk_delta"] == "medium"
        assert diff_profiles(
            _profile(shell_cmd_count=0), _profile(shell_cmd_count=1)
        )["risk_delta"] == "high"
        assert diff_profiles(
            _profile(network_domains=[]), _profile(network_domains=["x.com"])
        )["risk_delta"] == "critical"

    def test_fingerprint_fields_present(self):
        r = diff_profiles(_profile("1.0"), _profile("1.1"))
        assert len(r["fingerprint_old"]) == 16
        assert len(r["fingerprint_new"]) == 16

    def test_fingerprints_same_when_profiles_identical(self):
        p = _profile("1.0")
        r = diff_profiles(p, {**p, "version": "1.1"})
        assert r["fingerprint_old"] == r["fingerprint_new"]

    def test_fingerprints_differ_when_behavior_differs(self):
        old = _profile(network_domains=[])
        new = _profile(network_domains=["evil.com"])
        r   = diff_profiles(old, new)
        assert r["fingerprint_old"] != r["fingerprint_new"]


# ── fingerprint function ──────────────────────────────────────────────────────

class TestFingerprint:
    def test_same_profile_same_hash(self):
        p = _profile(network_domains=["a.com"], network_ports=[443], subprocess_count=2)
        assert fingerprint(p) == fingerprint(p)

    def test_different_domains_different_hash(self):
        p1 = _profile(network_domains=["a.com"])
        p2 = _profile(network_domains=["b.com"])
        assert fingerprint(p1) != fingerprint(p2)

    def test_returns_16_hex_chars(self):
        h = fingerprint(_profile())
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_profile_produces_hash(self):
        h = fingerprint({})
        assert len(h) == 16


# ── obfuscation helper ────────────────────────────────────────────────────────

class TestIsObfuscated:
    def test_base64_keyword(self):
        assert _is_obfuscated(["python3", "-c", "import base64; exec(...)"])

    def test_exec_compile(self):
        assert _is_obfuscated(["python3", "-c", "exec(compile(x,'f','exec'))"])

    def test_long_b64_blob(self):
        assert _is_obfuscated(["python3", "-c", "A" * 50])

    def test_clean_argv_not_obfuscated(self):
        assert not _is_obfuscated(["pip", "install", "requests"])

    def test_short_b64_like_string_not_flagged(self):
        assert not _is_obfuscated(["python3", "A" * 10])  # under 40 chars


# ── import_submodule phase regression ────────────────────────────────────────

class TestDiffImportSubmodulePhase:
    def test_regression_detected_when_both_present(self):
        old = {**_profile("1.0"), "import_submodule_status": "ok"}
        new = {**_profile("1.1"), "import_submodule_status": "failed"}
        r = diff_profiles(old, new)
        f = _findings_of_kind(r, "import_submodule_status_regression")
        assert len(f) == 1
        assert f[0]["severity"] == "medium"

    def test_finding_detail_contains_old_and_new(self):
        old = {**_profile("1.0"), "import_submodule_status": "ok"}
        new = {**_profile("1.1"), "import_submodule_status": "timed_out"}
        r = diff_profiles(old, new)
        f = _findings_of_kind(r, "import_submodule_status_regression")[0]
        assert f["detail"]["old"] == "ok"
        assert f["detail"]["new"] == "timed_out"

    def test_no_finding_when_absent_in_both(self):
        r = diff_profiles(_profile("1.0"), _profile("1.1"))
        assert _findings_of_kind(r, "import_submodule_status_regression") == []

    def test_no_finding_when_absent_in_old_present_ok_in_new(self):
        # First run with import_submodule trigger — not a regression
        new = {**_profile("1.1"), "import_submodule_status": "ok"}
        r = diff_profiles(_profile("1.0"), new)
        assert _findings_of_kind(r, "import_submodule_status_regression") == []

    def test_no_finding_when_absent_in_old_and_failed_in_new(self):
        # v1 design: absence in old → skip check entirely
        new = {**_profile("1.1"), "import_submodule_status": "failed"}
        r = diff_profiles(_profile("1.0"), new)
        assert _findings_of_kind(r, "import_submodule_status_regression") == []

    def test_no_finding_when_old_already_failed(self):
        old = {**_profile("1.0"), "import_submodule_status": "failed"}
        new = {**_profile("1.1"), "import_submodule_status": "failed"}
        r = diff_profiles(old, new)
        assert _findings_of_kind(r, "import_submodule_status_regression") == []

    def test_no_finding_when_status_recovers(self):
        old = {**_profile("1.0"), "import_submodule_status": "failed"}
        new = {**_profile("1.1"), "import_submodule_status": "ok"}
        r = diff_profiles(old, new)
        assert _findings_of_kind(r, "import_submodule_status_regression") == []

    def test_does_not_affect_existing_install_import_checks(self):
        old = _profile("1.0", install_status="ok")
        new = _profile("1.1", install_status="failed")
        r = diff_profiles(old, new)
        assert _findings_of_kind(r, "install_status_regression") != []
        assert _findings_of_kind(r, "import_submodule_status_regression") == []
