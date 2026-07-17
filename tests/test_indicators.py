"""Unit tests for pkgids/indicators.py — security indicator extraction."""

from __future__ import annotations

import pytest

from pkgids.indicators import extract_indicators, catalog, _is_obfuscated


# ── normalized-dict builder ───────────────────────────────────────────────────

def _norm(
    dns_queries=None,
    http_requests=None,
    tls_sessions=None,
    install_execs=None,
    import_execs=None,
    install_process_count=0,
    import_process_count=0,
    sensitive_file_events=None,
    file_events=None,
    import_socket_events=None,
    install_status="ok",
    install_duration=2.1,
    install_hooks=None,
    diff=None,
) -> dict:
    return {
        "run": {},
        "metadata": {"install_hooks": install_hooks or []},
        "phases": {
            "install": {
                "status":           install_status,
                "exit_code":        0,
                "duration_secs":    install_duration,
                "process_count":    install_process_count,
                "suspicious_execs": install_execs or [],
                "sensitive_files":  [],
                "any_suspicious":   False,
            },
            "import": {
                "status":           "ok",
                "exit_code":        0,
                "duration_secs":    0.3,
                "process_count":    import_process_count,
                "suspicious_execs": import_execs or [],
                "sensitive_files":  [],
                "any_suspicious":   False,
            },
        },
        "network": {
            "dns_queries":             dns_queries or [],
            "http_requests":           http_requests or [],
            "tls_sessions":            tls_sessions or [],
            "import_phase_connections": import_socket_events or [],
        },
        "telemetry": {
            "exec_events":           [],
            "file_events":           file_events or [],
            "socket_events":         [],
            "sensitive_file_events": sensitive_file_events or [],
        },
        "event_counts": {},
        "diff": diff,
    }


def _ids(indicators: list[dict]) -> list[str]:
    return [i["id"] for i in indicators]


# ── DNS ───────────────────────────────────────────────────────────────────────

class TestExtractDns:
    def test_dns_query_produces_indicator(self):
        norm = _norm(dns_queries=[{"type": "dns", "query": "evil.com"}])
        ids  = _ids(extract_indicators(norm))
        assert "dns_query_observed" in ids

    def test_no_dns_no_indicator(self):
        ids = _ids(extract_indicators(_norm()))
        assert "dns_query_observed" not in ids

    def test_evidence_contains_query(self):
        norm = _norm(dns_queries=[{"query": "c2.bad"}])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "dns_query_observed")
        assert "c2.bad" in ind["evidence"]["queries"]

    def test_tactic_is_command_and_control(self):
        norm = _norm(dns_queries=[{"query": "x.com"}])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "dns_query_observed")
        assert ind["tactic"] == "command-and-control"
        assert ind["technique"] == "T1071.004"


# ── HTTP ─────────────────────────────────────────────────────────────────────

class TestExtractHttp:
    def test_http_request_produces_indicator(self):
        norm = _norm(http_requests=[{"type": "http", "host": "x.com", "port": 80}])
        assert "http_request_observed" in _ids(extract_indicators(norm))

    def test_no_http_no_indicator(self):
        assert "http_request_observed" not in _ids(extract_indicators(_norm()))

    def test_evidence_hosts(self):
        norm = _norm(http_requests=[{"host": "attacker.io", "port": 80}])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "http_request_observed")
        assert "attacker.io" in ind["evidence"]["hosts"]


# ── TLS ──────────────────────────────────────────────────────────────────────

class TestExtractTls:
    def test_tls_session_produces_indicator(self):
        norm = _norm(tls_sessions=[{"type": "tls", "sni": "secure.evil.com"}])
        assert "tls_sni_extracted" in _ids(extract_indicators(norm))

    def test_sni_in_evidence(self):
        norm = _norm(tls_sessions=[{"sni": "c2.secure.io"}])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "tls_sni_extracted")
        assert "c2.secure.io" in ind["evidence"]["sni_names"]


# ── shell spawn ───────────────────────────────────────────────────────────────

class TestExtractShellSpawn:
    def _bash_exec(self, argv=None):
        return {"executable": "/bin/bash", "argv": argv or ["bash", "-c", "id"], "pid": 1}

    def test_bash_during_install_flagged(self):
        norm = _norm(install_execs=[self._bash_exec()])
        assert "shell_spawned_during_install" in _ids(extract_indicators(norm))

    def test_shell_during_import_not_flagged_by_this_indicator(self):
        # only install phase triggers this specific indicator
        norm = _norm(import_execs=[self._bash_exec()])
        assert "shell_spawned_during_install" not in _ids(extract_indicators(norm))

    def test_dash_is_shell(self):
        exec_ = {"executable": "/bin/dash", "argv": ["dash"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        assert "shell_spawned_during_install" in _ids(extract_indicators(norm))

    def test_curl_is_not_shell(self):
        exec_ = {"executable": "/usr/bin/curl", "argv": ["curl", "http://x.com"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        assert "shell_spawned_during_install" not in _ids(extract_indicators(norm))

    def test_severity_is_high(self):
        norm = _norm(install_execs=[self._bash_exec()])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "shell_spawned_during_install")
        assert ind["severity"] == "high"
        assert ind["tactic"] == "execution"


# ── python -c ─────────────────────────────────────────────────────────────────

class TestExtractPythonC:
    def _python_c_exec(self, code="print(1)"):
        return {"executable": "/usr/bin/python3", "argv": ["python3", "-c", code], "pid": 1}

    def test_python_c_flagged(self):
        norm = _norm(install_execs=[self._python_c_exec()])
        assert "python_c_flag_used" in _ids(extract_indicators(norm))

    def test_python_without_c_not_flagged(self):
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "setup.py"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        assert "python_c_flag_used" not in _ids(extract_indicators(norm))

    def test_works_in_import_phase_too(self):
        norm = _norm(import_execs=[self._python_c_exec()])
        assert "python_c_flag_used" in _ids(extract_indicators(norm))


# ── obfuscation ───────────────────────────────────────────────────────────────

class TestExtractObfuscation:
    def _obfusc_exec(self, code):
        return {"executable": "/usr/bin/python3", "argv": ["python3", "-c", code], "pid": 1}

    def test_base64_import_flagged(self):
        exec_ = self._obfusc_exec("import base64; exec(base64.b64decode('abc'))")
        norm  = _norm(install_execs=[exec_])
        assert "base64_command_present" in _ids(extract_indicators(norm))

    def test_exec_compile_flagged(self):
        exec_ = self._obfusc_exec("exec(compile(open('x').read(),'x','exec'))")
        norm  = _norm(install_execs=[exec_])
        assert "base64_command_present" in _ids(extract_indicators(norm))

    def test_long_b64_blob_as_argument(self):
        blob  = "A" * 50
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "-c", blob], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        assert "base64_command_present" in _ids(extract_indicators(norm))

    def test_clean_exec_not_flagged(self):
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "setup.py"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        assert "base64_command_present" not in _ids(extract_indicators(norm))

    def test_severity_critical(self):
        exec_ = self._obfusc_exec("import base64; exec(...)")
        norm  = _norm(install_execs=[exec_])
        ind   = next(i for i in extract_indicators(norm) if i["id"] == "base64_command_present")
        assert ind["severity"] == "critical"


# ── sensitive file ────────────────────────────────────────────────────────────

class TestExtractSensitiveFile:
    def test_sensitive_file_event_produces_indicator(self):
        norm = _norm(sensitive_file_events=[
            {"event_type": "file", "path": "/etc/passwd", "sensitive": True, "mode": "read"}
        ])
        assert "sensitive_file_accessed" in _ids(extract_indicators(norm))

    def test_no_sensitive_files_no_indicator(self):
        assert "sensitive_file_accessed" not in _ids(extract_indicators(_norm()))

    def test_path_in_evidence(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/etc/shadow", "sensitive": True}
        ])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "sensitive_file_accessed")
        assert "/etc/shadow" in ind["evidence"]["paths"]


# ── .env file ─────────────────────────────────────────────────────────────────

class TestExtractEnvFile:
    def test_dotenv_file_produces_indicator(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/app/.env", "sensitive": True}
        ])
        assert "env_file_read" in _ids(extract_indicators(norm))

    def test_env_local_also_matched(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/home/user/.env.local", "sensitive": True}
        ])
        assert "env_file_read" in _ids(extract_indicators(norm))

    def test_env_in_name_but_directory_not_matched(self):
        # /environ/data is not an .env file
        norm = _norm(sensitive_file_events=[
            {"path": "/proc/environ/data", "sensitive": True}
        ])
        assert "env_file_read" not in _ids(extract_indicators(norm))

    def test_no_env_file_no_indicator(self):
        assert "env_file_read" not in _ids(extract_indicators(_norm()))


# ── SSH key ───────────────────────────────────────────────────────────────────

class TestExtractSshKey:
    def test_ssh_id_rsa_produces_critical_indicator(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/root/.ssh/id_rsa", "sensitive": True}
        ])
        ids = _ids(extract_indicators(norm))
        assert "ssh_key_accessed" in ids
        ind = next(i for i in extract_indicators(norm) if i["id"] == "ssh_key_accessed")
        assert ind["severity"] == "critical"
        assert ind["weight"] == 0.90

    def test_authorized_keys_matched(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/home/user/.ssh/authorized_keys", "sensitive": True}
        ])
        assert "ssh_key_accessed" in _ids(extract_indicators(norm))

    def test_non_ssh_sensitive_file_no_ssh_indicator(self):
        norm = _norm(sensitive_file_events=[
            {"path": "/etc/passwd", "sensitive": True}
        ])
        assert "ssh_key_accessed" not in _ids(extract_indicators(norm))


# ── subprocess chain ──────────────────────────────────────────────────────────

class TestExtractSubprocessChain:
    def test_deep_chain_produces_indicator(self):
        norm = _norm(install_process_count=8, import_process_count=5)  # 13 total
        assert "subprocess_chain_deep" in _ids(extract_indicators(norm))

    def test_exactly_at_threshold_no_indicator(self):
        norm = _norm(install_process_count=10)
        assert "subprocess_chain_deep" not in _ids(extract_indicators(norm))

    def test_below_threshold_no_indicator(self):
        norm = _norm(install_process_count=3)
        assert "subprocess_chain_deep" not in _ids(extract_indicators(norm))

    def test_evidence_total_count(self):
        norm = _norm(install_process_count=12)
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "subprocess_chain_deep")
        assert ind["evidence"]["subprocess_count"] == 12


# ── import-triggered network ──────────────────────────────────────────────────

class TestExtractImportNetwork:
    def test_socket_during_import_produces_indicator(self):
        norm = _norm(import_socket_events=[
            {"event_type": "socket", "phase": "import", "dst_ip": "1.2.3.4"}
        ])
        assert "import_triggered_network" in _ids(extract_indicators(norm))

    def test_no_import_sockets_no_indicator(self):
        assert "import_triggered_network" not in _ids(extract_indicators(_norm()))


# ── install timeout ───────────────────────────────────────────────────────────

class TestExtractInstallTimeout:
    def test_timed_out_status_produces_indicator(self):
        norm = _norm(install_status="timed_out", install_duration=120.0)
        assert "install_timed_out" in _ids(extract_indicators(norm))

    def test_ok_status_no_indicator(self):
        norm = _norm(install_status="ok")
        assert "install_timed_out" not in _ids(extract_indicators(norm))

    def test_tactic_defense_evasion(self):
        norm = _norm(install_status="timed_out")
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "install_timed_out")
        assert ind["tactic"] == "defense-evasion"


# ── install hooks ─────────────────────────────────────────────────────────────

class TestExtractInstallHooks:
    def test_hook_in_metadata_produces_indicator(self):
        norm = _norm(install_hooks=["setup.py:install"])
        assert "install_hook_executed" in _ids(extract_indicators(norm))

    def test_empty_hooks_no_indicator(self):
        norm = _norm(install_hooks=[])
        assert "install_hook_executed" not in _ids(extract_indicators(norm))

    def test_hooks_in_evidence(self):
        norm = _norm(install_hooks=["setup.py:install", "custom:post_install"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "install_hook_executed")
        assert "setup.py:install" in ind["evidence"]["hooks"]


# ── baseline diff ─────────────────────────────────────────────────────────────

class TestExtractBaselineDiff:
    def test_suspicious_diff_produces_indicator(self):
        diff = {
            "is_suspicious": True, "verdict": "suspicious",
            "from_version": "1.0.0", "to_version": "1.0.1",
            "risk_delta": "critical",
            "new_domains": ["evil.com"], "new_ports": [4444],
        }
        norm = _norm(diff=diff)
        assert "new_behavior_vs_baseline" in _ids(extract_indicators(norm))

    def test_clean_diff_no_indicator(self):
        diff = {"is_suspicious": False, "verdict": "clean", "risk_delta": "clean"}
        norm = _norm(diff=diff)
        assert "new_behavior_vs_baseline" not in _ids(extract_indicators(norm))

    def test_no_diff_no_indicator(self):
        assert "new_behavior_vs_baseline" not in _ids(extract_indicators(_norm()))

    def test_diff_evidence_contains_domains(self):
        diff = {
            "is_suspicious": True, "from_version": "1.0", "to_version": "1.1",
            "risk_delta": "critical", "new_domains": ["x.bad"], "new_ports": [],
        }
        norm = _norm(diff=diff)
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "new_behavior_vs_baseline")
        assert "x.bad" in ind["evidence"]["new_domains"]


# ── unusual port ──────────────────────────────────────────────────────────────

class TestExtractUnusualPort:
    def test_non_standard_port_flagged(self):
        norm = _norm(http_requests=[{"host": "x.com", "port": 4444}])
        assert "exfiltration_unusual_port" in _ids(extract_indicators(norm))

    def test_port_80_not_unusual(self):
        norm = _norm(http_requests=[{"host": "x.com", "port": 80}])
        assert "exfiltration_unusual_port" not in _ids(extract_indicators(norm))

    def test_port_443_not_unusual(self):
        norm = _norm(tls_sessions=[{"sni": "x.com", "port": 443}])
        assert "exfiltration_unusual_port" not in _ids(extract_indicators(norm))


# ── bait access ──────────────────────────────────────────────────────────────

_PLANTED_PATHS = [
    "/home/deton/.env",
    "/home/deton/.aws/credentials",
    "/home/deton/.pypirc",
    "/home/deton/.ssh/id_rsa",
]


def _norm_bait(accessed: list[str], planted: list[str] | None = None) -> dict:
    planted_paths = planted if planted is not None else _PLANTED_PATHS
    base = _norm(
        sensitive_file_events=[
            {"path": p, "sensitive": True} for p in accessed
        ]
    )
    base["bait_planted"] = {
        "planted_paths": planted_paths,
        "planted_count": len(planted_paths),
        "files": [{"path": p, "category": "test"} for p in planted_paths],
    }
    return base


class TestExtractBaitAccess:
    def test_no_bait_planted_no_indicator(self):
        norm = _norm(sensitive_file_events=[{"path": "/home/deton/.env", "sensitive": True}])
        assert not any(i["id"].startswith("bait_") for i in extract_indicators(norm))

    def test_empty_planted_paths_no_indicator(self):
        norm = _norm_bait(accessed=["/home/deton/.env"], planted=[])
        assert not any(i["id"].startswith("bait_") for i in extract_indicators(norm))

    def test_no_bait_files_accessed_no_indicator(self):
        norm = _norm_bait(accessed=[])
        assert not any(i["id"].startswith("bait_") for i in extract_indicators(norm))

    def test_one_file_accessed_is_bait_probe(self):
        norm = _norm_bait(accessed=["/home/deton/.env"])
        assert "bait_probe" in _ids(extract_indicators(norm))

    def test_two_files_accessed_is_bait_enumeration(self):
        norm = _norm_bait(accessed=["/home/deton/.env", "/home/deton/.aws/credentials"])
        assert "bait_enumeration" in _ids(extract_indicators(norm))

    def test_three_files_accessed_is_bait_enumeration(self):
        norm = _norm_bait(accessed=[
            "/home/deton/.env",
            "/home/deton/.aws/credentials",
            "/home/deton/.pypirc",
        ])
        assert "bait_enumeration" in _ids(extract_indicators(norm))

    def test_four_files_accessed_is_bait_credential_harvest(self):
        norm = _norm_bait(accessed=_PLANTED_PATHS)
        assert "bait_credential_harvest" in _ids(extract_indicators(norm))

    def test_exactly_one_bait_indicator_fires(self):
        norm = _norm_bait(accessed=_PLANTED_PATHS)
        bait_ids = [i["id"] for i in extract_indicators(norm) if i["id"].startswith("bait_")]
        assert len(bait_ids) == 1

    def test_non_bait_sensitive_file_does_not_trigger(self):
        norm = _norm_bait(accessed=["/home/deton/.bashrc"])
        assert not any(i["id"].startswith("bait_") for i in extract_indicators(norm))

    def test_evidence_contains_accessed_paths(self):
        norm = _norm_bait(accessed=["/home/deton/.env"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "bait_probe")
        assert "/home/deton/.env" in ind["evidence"]["accessed_paths"]

    def test_evidence_contains_total_planted(self):
        norm = _norm_bait(accessed=["/home/deton/.env"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "bait_probe")
        assert ind["evidence"]["total_planted"] == len(_PLANTED_PATHS)

    def test_bait_probe_is_medium_severity(self):
        norm = _norm_bait(accessed=["/home/deton/.env"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "bait_probe")
        assert ind["severity"] == "medium"

    def test_bait_enumeration_is_high_severity(self):
        norm = _norm_bait(accessed=["/home/deton/.env", "/home/deton/.aws/credentials"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "bait_enumeration")
        assert ind["severity"] == "high"

    def test_bait_credential_harvest_is_critical(self):
        norm = _norm_bait(accessed=_PLANTED_PATHS)
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "bait_credential_harvest")
        assert ind["severity"] == "critical"


# ── clean run ─────────────────────────────────────────────────────────────────

class TestCleanRun:
    def test_benign_normalized_has_no_indicators(self):
        assert extract_indicators(_norm()) == []


# ── ordering ──────────────────────────────────────────────────────────────────

class TestOrdering:
    def test_sorted_by_weight_descending(self):
        norm = _norm(
            dns_queries=[{"query": "x.com"}],
            sensitive_file_events=[{"path": "/root/.ssh/id_rsa", "sensitive": True}],
        )
        inds    = extract_indicators(norm)
        weights = [i["weight"] for i in inds]
        assert weights == sorted(weights, reverse=True)


# ── catalog ───────────────────────────────────────────────────────────────────

class TestCatalog:
    def test_catalog_returns_dict(self):
        c = catalog()
        assert isinstance(c, dict)
        assert len(c) > 10

    def test_each_entry_has_required_fields(self):
        for k, v in catalog().items():
            assert "title" in v, k
            assert "tactic" in v, k
            assert "technique" in v, k
            assert "severity" in v, k
            assert "weight" in v, k
            assert 0.0 < v["weight"] <= 1.0, k


# ── obfuscation helper ────────────────────────────────────────────────────────

class TestIsObfuscated:
    def test_base64_keyword_detected(self):
        assert _is_obfuscated(["python3", "-c", "import base64"])

    def test_eval_detected(self):
        assert _is_obfuscated(["python3", "-c", "eval(x)"])

    def test_long_b64_blob_detected(self):
        assert _is_obfuscated(["python3", "A" * 50])

    def test_clean_argv_not_obfuscated(self):
        assert not _is_obfuscated(["pip", "install", "requests==2.28.0"])

    def test_short_b64_not_flagged(self):
        assert not _is_obfuscated(["python3", "Ab1+"])  # only 4 chars


# ── file system discovery ─────────────────────────────────────────────────────

class TestFileSystemDiscovery:
    def _home_files(self, n: int) -> list[dict]:
        return [{"event_type": "file", "path": f"/home/user/dir{i}/config.cfg"}
                for i in range(n)]

    def test_five_home_files_produces_indicator(self):
        norm = _norm(file_events=self._home_files(5))
        assert "file_system_discovery" in _ids(extract_indicators(norm))

    def test_four_home_files_below_threshold(self):
        norm = _norm(file_events=self._home_files(4))
        assert "file_system_discovery" not in _ids(extract_indicators(norm))

    def test_etc_files_trigger_indicator(self):
        evs = [{"event_type": "file", "path": f"/etc/subdir{i}/file"} for i in range(5)]
        norm = _norm(file_events=evs)
        assert "file_system_discovery" in _ids(extract_indicators(norm))

    def test_tmp_files_trigger_indicator(self):
        evs = [{"event_type": "file", "path": f"/tmp/f{i}.dat"} for i in range(5)]
        norm = _norm(file_events=evs)
        assert "file_system_discovery" in _ids(extract_indicators(norm))

    def test_usr_lib_files_not_triggered(self):
        # /usr/lib is not a discovery-relevant path
        evs = [{"event_type": "file", "path": f"/usr/lib/python3/pkg{i}.py"} for i in range(10)]
        norm = _norm(file_events=evs)
        assert "file_system_discovery" not in _ids(extract_indicators(norm))

    def test_evidence_contains_path_count(self):
        norm = _norm(file_events=self._home_files(7))
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "file_system_discovery")
        assert ind["evidence"]["path_count"] == 7

    def test_tactic_is_discovery(self):
        norm = _norm(file_events=self._home_files(5))
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "file_system_discovery")
        assert ind["tactic"] == "discovery"
        assert ind["technique"] == "T1083"

    def test_no_file_events_no_indicator(self):
        assert "file_system_discovery" not in _ids(extract_indicators(_norm()))


# ── phase attribution ─────────────────────────────────────────────────────────

class TestPhaseAttribution:
    """Evidence dicts must carry a ``phase`` key so the HTML report can show phase badges."""

    def test_shell_spawn_phase_is_install(self):
        exec_ = {"executable": "/bin/bash", "argv": ["bash", "-c", "id"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        ind   = next(i for i in extract_indicators(norm) if i["id"] == "shell_spawned_during_install")
        assert ind["evidence"].get("phase") == "install"

    def test_install_hook_phase_is_install(self):
        norm = _norm(install_hooks=["setup.py:install"])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "install_hook_executed")
        assert ind["evidence"].get("phase") == "install"

    def test_install_timeout_phase_is_install(self):
        norm = _norm(install_status="timed_out", install_duration=120.0)
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "install_timed_out")
        assert ind["evidence"].get("phase") == "install"

    def test_import_network_phase_is_import(self):
        norm = _norm(import_socket_events=[{"dst_ip": "1.2.3.4"}])
        ind  = next(i for i in extract_indicators(norm) if i["id"] == "import_triggered_network")
        assert ind["evidence"].get("phase") == "import"

    def test_python_c_install_phase_when_only_install(self):
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "-c", "x"], "pid": 1}
        norm  = _norm(install_execs=[exec_])
        ind   = next(i for i in extract_indicators(norm) if i["id"] == "python_c_flag_used")
        assert ind["evidence"].get("phase") == "install"

    def test_python_c_import_phase_when_only_import(self):
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "-c", "x"], "pid": 1}
        norm  = _norm(import_execs=[exec_])
        ind   = next(i for i in extract_indicators(norm) if i["id"] == "python_c_flag_used")
        assert ind["evidence"].get("phase") == "import"

    def test_python_c_install_takes_priority_over_import(self):
        exec_ = {"executable": "/usr/bin/python3", "argv": ["python3", "-c", "x"], "pid": 1}
        norm  = _norm(install_execs=[exec_], import_execs=[exec_])
        ind   = next(i for i in extract_indicators(norm) if i["id"] == "python_c_flag_used")
        assert ind["evidence"].get("phase") == "install"
