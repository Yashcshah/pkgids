"""Unit tests for pkgids/telemetry.py — strace log parsing and classification."""

from __future__ import annotations

import pytest

from pkgids.telemetry import (
    MALICIOUS_EXEC_INDICATORS,
    _parse_strace_line,
    check_sensitive_path,
    iter_phase_jsonl,
    parse_strace_log,
    summarise_telemetry,
    # backwards-compat shims
    parse_strace_execve,
    summarise_process_telemetry,
)


# ── helper: build a synthetic strace line ─────────────────────────────────────

def _line(pid: int, syscall_body: str, retval: int = 0,
          ts: float = 1_700_000_000.0) -> str:
    """Build one strace -ttt -f output line."""
    return f"{pid} {ts:.6f} {syscall_body} = {retval}\n"


def _execve(pid, path, argv_str, ts=1_700_000_000.0):
    body = f'execve("{path}", [{argv_str}], 0x7fff /* 17 vars */)'
    return _line(pid, body, ts=ts)


def _openat(pid, path, flags="O_RDONLY", retval=3, ts=1_700_000_000.0):
    body = f'openat(AT_FDCWD, "{path}", {flags})'
    return _line(pid, body, retval, ts=ts)


def _connect_v4(pid, ip, port, retval=-1, ts=1_700_000_000.0):
    body = (f'connect(4, {{sa_family=AF_INET, sin_port=htons({port}), '
            f'sin_addr=inet_addr("{ip}")}}, 16)')
    return _line(pid, body, retval, ts=ts)


def _socket_line(pid, family="AF_INET", sock_type="SOCK_STREAM",
                 proto="IPPROTO_TCP", retval=4, ts=1_700_000_000.0):
    return _line(pid, f"socket({family}, {sock_type}, {proto})", retval, ts=ts)


# ── MALICIOUS_EXEC_INDICATORS ─────────────────────────────────────────────────

class TestMaliciousExecIndicators:
    @pytest.mark.parametrize("name", [
        "curl", "wget", "nc", "bash", "sh", "openssl", "base64",
        "chmod", "chown", "python3", "node",
    ])
    def test_known_indicators_present(self, name):
        assert name in MALICIOUS_EXEC_INDICATORS

    @pytest.mark.parametrize("name", ["pip3", "npm", "python3.12", "python3-config"])
    def test_tool_names_not_in_set(self, name):
        assert name not in MALICIOUS_EXEC_INDICATORS


# ── check_sensitive_path ──────────────────────────────────────────────────────

class TestCheckSensitivePath:
    def test_ssh_key_detected(self):
        ok, cat = check_sensitive_path("/home/deton/.ssh/id_rsa")
        assert ok and cat == "ssh_keys"

    def test_ssh_dir_detected(self):
        ok, cat = check_sensitive_path("/root/.ssh/authorized_keys")
        assert ok

    def test_aws_credentials(self):
        ok, cat = check_sensitive_path("/home/user/.aws/credentials")
        assert ok and cat == "aws_credentials"

    def test_npmrc(self):
        ok, cat = check_sensitive_path("/home/user/.npmrc")
        assert ok and cat == "npm_rc"

    def test_pypirc(self):
        ok, cat = check_sensitive_path("/home/user/.pypirc")
        assert ok and cat == "pypi_rc"

    def test_gitconfig(self):
        ok, cat = check_sensitive_path("/home/user/.gitconfig")
        assert ok and cat == "git_config"

    def test_etc_passwd(self):
        ok, cat = check_sensitive_path("/etc/passwd")
        assert ok and cat == "system_passwd"

    def test_etc_shadow(self):
        ok, cat = check_sensitive_path("/etc/shadow")
        assert ok and cat == "system_shadow"

    def test_bashrc(self):
        ok, cat = check_sensitive_path("/home/user/.bashrc")
        assert ok and cat == "shell_rc"

    def test_env_file(self):
        ok, cat = check_sensitive_path("/app/.env")
        assert ok and cat == "env_file"

    def test_proc_environ(self):
        ok, cat = check_sensitive_path("/proc/self/environ")
        assert ok and cat == "proc_environ"

    def test_proc_pid_environ(self):
        ok, cat = check_sensitive_path("/proc/12345/environ")
        assert ok and cat == "proc_environ"

    def test_github_workflow(self):
        ok, cat = check_sensitive_path("/repo/.github/workflows/deploy.yml")
        assert ok and cat == "ci_secrets"

    def test_docker_config(self):
        ok, cat = check_sensitive_path("/root/.docker/config.json")
        assert ok and cat == "docker_config"

    def test_innocent_path_not_sensitive(self):
        ok, _ = check_sensitive_path("/usr/lib/python3/dist-packages/six.py")
        assert not ok

    def test_scratch_site_packages_not_sensitive(self):
        ok, _ = check_sensitive_path("/scratch/site-packages/six/__init__.py")
        assert not ok

    def test_case_insensitive_matching(self):
        ok, _ = check_sensitive_path("/home/user/.SSH/id_rsa")
        assert ok


# ── _parse_strace_line ────────────────────────────────────────────────────────

class TestParseStraceLine:
    def test_basic_line_parsed(self):
        line = "12345 1700000000.123456 execve(\"/bin/sh\", [\"sh\"], 0x1) = 0"
        pl = _parse_strace_line(line)
        assert pl is not None
        assert pl["pid"] == 12345
        assert abs(pl["ts"] - 1700000000.123456) < 1e-5
        assert pl["syscall"] == "execve"
        assert pl["retval"] == 0

    def test_line_without_timestamp_parsed(self):
        line = '12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        pl = _parse_strace_line(line)
        assert pl is not None
        assert pl["ts"] is None
        assert pl["syscall"] == "openat"
        assert pl["retval"] == 3

    def test_negative_retval(self):
        line = '12345 1700000000.0 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = -1'
        pl = _parse_strace_line(line)
        assert pl["retval"] == -1

    def test_unfinished_line_returns_none(self):
        line = '12345 1700000000.0 openat(AT_FDCWD, "/etc/ld.so.cache", <unfinished ...>'
        assert _parse_strace_line(line) is None

    def test_resumed_line_returns_none(self):
        line = '12345 1700000000.0 <... openat resumed>) = 3'
        assert _parse_strace_line(line) is None

    def test_exit_notice_returns_none(self):
        assert _parse_strace_line("12345 +++ exited with 0 +++") is None

    def test_signal_line_returns_none(self):
        line = "12345 --- SIGTERM {si_signo=SIGTERM, si_code=SI_USER} ---"
        assert _parse_strace_line(line) is None

    def test_args_raw_extracted_correctly(self):
        line = '12345 1700000000.0 openat(AT_FDCWD, "/tmp/x", O_WRONLY|O_CREAT, 0644) = 4'
        pl = _parse_strace_line(line)
        assert "/tmp/x" in pl["args_raw"]
        assert "O_WRONLY" in pl["args_raw"]

    def test_nested_parens_in_connect_handled(self):
        line = ('12345 1700000000.0 connect(4, {sa_family=AF_INET, '
                'sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = -1')
        pl = _parse_strace_line(line)
        assert pl is not None
        assert pl["syscall"] == "connect"


# ── parse_strace_log — process events ────────────────────────────────────────

class TestParseStraceLogProcess:
    def test_empty_string_returns_empty(self):
        result = parse_strace_log("")
        assert result["process_events"] == []

    def test_single_execve_parsed(self):
        text = _execve(100, "/usr/bin/pip3", '"pip3", "install", "six"')
        events = parse_strace_log(text)["process_events"]
        assert len(events) == 1
        e = events[0]
        assert e["pid"] == 100
        assert e["executable"] == "/usr/bin/pip3"
        assert e["basename"] == "pip3"
        assert e["argv"] == ["pip3", "install", "six"]
        assert e["suspicious"] is False

    def test_suspicious_curl_spawn_detected(self):
        text = _execve(200, "/usr/bin/curl", '"curl", "http://evil.com"')
        events = parse_strace_log(text)["process_events"]
        assert events[0]["suspicious"] is True

    def test_suspicious_bash_spawn_detected(self):
        text = _execve(300, "/bin/bash", '"bash", "-c", "id"')
        events = parse_strace_log(text)["process_events"]
        assert events[0]["suspicious"] is True

    def test_duplicate_pid_executable_deduplicated(self):
        line = _execve(100, "/usr/bin/pip3", '"pip3"')
        events = parse_strace_log(line + line)["process_events"]
        assert len(events) == 1

    def test_execveat_parsed(self):
        line = _line(100, 'execveat(AT_FDCWD, "/bin/sh", ["sh", "-c", "id"], 0x1, 0)')
        events = parse_strace_log(line)["process_events"]
        assert len(events) == 1
        assert events[0]["basename"] == "sh"
        assert events[0]["suspicious"] is True

    def test_multiple_distinct_processes(self):
        text = (
            _execve(100, "/usr/bin/pip3", '"pip3"') +
            _execve(101, "/usr/bin/python3", '"python3"') +
            _execve(102, "/usr/bin/curl", '"curl"')
        )
        events = parse_strace_log(text)["process_events"]
        assert len(events) == 3

    def test_exit_notice_not_counted(self):
        text = _execve(100, "/usr/bin/pip3", '"pip3"') + "100 +++ exited with 0 +++\n"
        events = parse_strace_log(text)["process_events"]
        assert len(events) == 1


# ── parse_strace_log — file events ───────────────────────────────────────────

class TestParseStraceLogFile:
    def test_non_sensitive_read_skipped(self):
        text = _openat(100, "/usr/lib/python3/six.py", "O_RDONLY")
        assert parse_strace_log(text)["file_events"] == []

    def test_sensitive_read_included(self):
        text = _openat(100, "/home/user/.ssh/id_rsa", "O_RDONLY")
        events = parse_strace_log(text)["file_events"]
        assert len(events) == 1
        e = events[0]
        assert e["path"] == "/home/user/.ssh/id_rsa"
        assert e["access_type"] == "read"
        assert e["sensitive"] is True
        assert e["sensitive_category"] == "ssh_keys"

    def test_write_to_non_sensitive_path_included(self):
        text = _openat(100, "/tmp/output.txt", "O_WRONLY", retval=5)
        events = parse_strace_log(text)["file_events"]
        assert len(events) == 1
        assert events[0]["access_type"] == "write"
        assert events[0]["sensitive"] is False

    def test_create_flag_detected(self):
        text = _openat(100, "/tmp/new.txt", "O_WRONLY|O_CREAT|O_TRUNC", retval=5)
        events = parse_strace_log(text)["file_events"]
        assert events[0]["access_type"] == "create"

    def test_open_syscall_parsed(self):
        line = _line(100, 'open("/tmp/x", O_WRONLY)', retval=4)
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["access_type"] == "write"

    def test_unlink_always_included(self):
        line = _line(100, 'unlink("/tmp/somefile")')
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["access_type"] == "delete"
        assert events[0]["path"] == "/tmp/somefile"

    def test_rename_included(self):
        line = _line(100, 'rename("/tmp/old", "/tmp/new")')
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["access_type"] == "rename"
        assert events[0]["dest_path"] == "/tmp/new"

    def test_mkdir_included(self):
        line = _line(100, 'mkdir("/tmp/newdir", 0755)')
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["access_type"] == "create"

    def test_chmod_always_included(self):
        line = _line(100, 'chmod("/tmp/script.sh", 0755)')
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["syscall"] == "chmod"
        assert events[0]["mode"] == "755"

    def test_chown_always_included(self):
        line = _line(100, 'chown("/tmp/file", 0, 0)')
        events = parse_strace_log(line)["file_events"]
        assert len(events) == 1
        assert events[0]["syscall"] == "chown"
        assert events[0]["uid"] == 0
        assert events[0]["gid"] == 0

    def test_chmod_on_sensitive_path_flagged(self):
        line = _line(100, 'chmod("/home/user/.ssh/id_rsa", 0600)')
        ev = parse_strace_log(line)["file_events"][0]
        assert ev["sensitive"] is True
        assert ev["sensitive_category"] == "ssh_keys"

    def test_etc_passwd_read_is_sensitive(self):
        text = _openat(100, "/etc/passwd", "O_RDONLY")
        events = parse_strace_log(text)["file_events"]
        assert len(events) == 1
        assert events[0]["sensitive_category"] == "system_passwd"

    def test_proc_environ_read_is_sensitive(self):
        text = _openat(100, "/proc/self/environ", "O_RDONLY")
        events = parse_strace_log(text)["file_events"]
        assert len(events) == 1
        assert events[0]["sensitive_category"] == "proc_environ"


# ── parse_strace_log — socket events ─────────────────────────────────────────

class TestParseStraceLogSocket:
    def test_connect_ipv4_parsed(self):
        text = _connect_v4(100, "1.2.3.4", 80)
        events = parse_strace_log(text)["socket_events"]
        assert len(events) == 1
        e = events[0]
        assert e["syscall"] == "connect"
        assert e["family"] == "AF_INET"
        assert e["dest_ip"] == "1.2.3.4"
        assert e["dest_port"] == 80

    def test_connect_ipv6_parsed(self):
        line = _line(100,
                     'connect(4, {sa_family=AF_INET6, sin6_port=htons(443), '
                     'sin6_addr=inet6_addr("::1")}, 28)', retval=-1)
        events = parse_strace_log(line)["socket_events"]
        assert len(events) == 1
        e = events[0]
        assert e["family"] == "AF_INET6"
        assert e["dest_ip"] == "::1"
        assert e["dest_port"] == 443

    def test_socket_creation_inet_included(self):
        text = _socket_line(100, "AF_INET", "SOCK_STREAM", "IPPROTO_TCP")
        events = parse_strace_log(text)["socket_events"]
        assert len(events) == 1
        assert events[0]["syscall"] == "socket"
        assert events[0]["family"] == "AF_INET"

    def test_socket_unix_skipped(self):
        text = _socket_line(100, "AF_UNIX", "SOCK_STREAM", "0")
        assert parse_strace_log(text)["socket_events"] == []

    def test_socket_netlink_skipped(self):
        text = _socket_line(100, "AF_NETLINK", "SOCK_RAW", "0")
        assert parse_strace_log(text)["socket_events"] == []

    def test_failed_connect_still_recorded(self):
        text = _connect_v4(100, "8.8.8.8", 443, retval=-1)
        events = parse_strace_log(text)["socket_events"]
        assert len(events) == 1
        assert events[0]["retval"] == -1


# ── parse_strace_log — control events ────────────────────────────────────────

class TestParseStraceLogControl:
    def test_kill_recorded(self):
        line = _line(100, "kill(12346, SIGTERM)")
        events = parse_strace_log(line)["control_events"]
        assert len(events) == 1
        e = events[0]
        assert e["syscall"] == "kill"
        assert e["target_pid"] == 12346
        assert e["signal"] == "SIGTERM"

    def test_ptrace_recorded(self):
        line = _line(100, "ptrace(PTRACE_ATTACH, 999, NULL, NULL)")
        events = parse_strace_log(line)["control_events"]
        assert len(events) == 1
        assert events[0]["syscall"] == "ptrace"


# ── summarise_telemetry ───────────────────────────────────────────────────────

class TestSummariseTelemetry:
    def _parsed(self, process=None, files=None, sockets=None, control=None):
        return {
            "process_events":  process  or [],
            "file_events":     files    or [],
            "socket_events":   sockets  or [],
            "control_events":  control  or [],
        }

    def test_all_empty_returns_benign(self):
        r = summarise_telemetry(self._parsed())
        assert r["process_count"] == 0
        assert r["any_suspicious"] is False
        assert r["suspicious_execs"] == []
        assert r["sensitive_file_accesses"] == []
        assert r["socket_connections"] == []
        assert r["control_events"] == []

    def test_telemetry_limited_propagated(self):
        r = summarise_telemetry(self._parsed(), telemetry_limited_process=True)
        assert r["telemetry_limited_process"] is True

    def test_suspicious_exec_triggers_any_suspicious(self):
        procs = [{"pid": 1, "executable": "/usr/bin/curl", "basename": "curl",
                  "argv": ["curl"], "suspicious": True, "syscall": "execve", "ts": 0.0}]
        r = summarise_telemetry(self._parsed(process=procs))
        assert r["any_suspicious"] is True
        assert len(r["suspicious_execs"]) == 1
        assert r["suspicious_execs"][0]["executable"] == "/usr/bin/curl"

    def test_benign_exec_does_not_trigger_any_suspicious(self):
        procs = [{"pid": 1, "executable": "/usr/bin/pip3", "basename": "pip3",
                  "argv": ["pip3"], "suspicious": False, "syscall": "execve", "ts": 0.0}]
        r = summarise_telemetry(self._parsed(process=procs))
        assert r["any_suspicious"] is False

    def test_sensitive_file_access_triggers_any_suspicious(self):
        files = [{
            "pid": 1, "ts": 0.0, "syscall": "openat",
            "path": "/home/deton/.ssh/id_rsa", "access_type": "read",
            "sensitive": True, "sensitive_category": "ssh_keys",
        }]
        r = summarise_telemetry(self._parsed(files=files))
        assert r["any_suspicious"] is True
        assert len(r["sensitive_file_accesses"]) == 1

    def test_non_sensitive_write_does_not_trigger_any_suspicious(self):
        files = [{
            "pid": 1, "ts": 0.0, "syscall": "openat",
            "path": "/tmp/output.txt", "access_type": "write",
            "sensitive": False, "sensitive_category": None,
        }]
        r = summarise_telemetry(self._parsed(files=files))
        assert r["any_suspicious"] is False

    def test_ptrace_triggers_any_suspicious(self):
        ctrl = [{"pid": 1, "ts": 0.0, "syscall": "ptrace"}]
        r = summarise_telemetry(self._parsed(control=ctrl))
        assert r["any_suspicious"] is True

    def test_kill_does_not_trigger_any_suspicious(self):
        ctrl = [{"pid": 1, "ts": 0.0, "syscall": "kill",
                 "target_pid": 2, "signal": "SIGTERM"}]
        r = summarise_telemetry(self._parsed(control=ctrl))
        assert r["any_suspicious"] is False

    def test_socket_connection_in_summary(self):
        sockets = [{
            "pid": 1, "ts": 0.0, "syscall": "connect",
            "family": "AF_INET", "dest_ip": "1.2.3.4", "dest_port": 80,
        }]
        r = summarise_telemetry(self._parsed(sockets=sockets))
        assert len(r["socket_connections"]) == 1
        assert r["socket_connections"][0]["dest_ip"] == "1.2.3.4"

    def test_socket_without_dest_ip_excluded_from_connections(self):
        sockets = [{"pid": 1, "ts": 0.0, "syscall": "socket",
                    "family": "AF_INET", "dest_ip": None, "dest_port": None}]
        r = summarise_telemetry(self._parsed(sockets=sockets))
        assert r["socket_connections"] == []

    def test_process_count_accurate(self):
        procs = [
            {"pid": 1, "executable": "/usr/bin/pip3", "basename": "pip3",
             "argv": [], "suspicious": False, "syscall": "execve", "ts": 0.0},
            {"pid": 2, "executable": "/usr/bin/python3", "basename": "python3",
             "argv": [], "suspicious": True, "syscall": "execve", "ts": 0.0},
        ]
        r = summarise_telemetry(self._parsed(process=procs))
        assert r["process_count"] == 2


# ── integrated end-to-end: mixed log ─────────────────────────────────────────

class TestParseStraceLogIntegrated:
    def test_mixed_log_all_categories_parsed(self):
        text = (
            _execve(100, "/usr/bin/pip3",  '"pip3", "install", "evil"') +
            _execve(101, "/usr/bin/curl",  '"curl", "http://evil.com"') +
            _openat(101, "/home/deton/.ssh/id_rsa", "O_RDONLY") +
            _connect_v4(101, "1.2.3.4", 443) +
            _line(101, "kill(100, SIGTERM)")
        )
        result = parse_strace_log(text)

        assert len(result["process_events"])  == 2   # pip3 + curl
        assert len(result["file_events"])     == 1   # ssh key read
        assert len(result["socket_events"])  == 1   # connect
        assert len(result["control_events"]) == 1   # kill

        r = summarise_telemetry(result)
        assert r["any_suspicious"] is True
        execs = {e["executable"] for e in r["suspicious_execs"]}
        assert "/usr/bin/curl" in execs

    def test_benign_pip_install_minimal_events(self):
        # Typical pip install: only benign reads of stdlib + scratch writes.
        text = (
            _execve(100, "/usr/bin/pip3", '"pip3", "install", "six"') +
            _openat(100, "/usr/lib/python3/six.py", "O_RDONLY") +
            _openat(100, "/scratch/site-packages/six.py", "O_WRONLY|O_CREAT", retval=5)
        )
        result = parse_strace_log(text)
        # Non-sensitive read skipped; write to scratch included
        assert len(result["file_events"]) == 1
        assert result["file_events"][0]["access_type"] == "create"

        r = summarise_telemetry(result)
        assert r["any_suspicious"] is False


# ── parse_strace_log — sensitive_only filter ─────────────────────────────────

class TestParseStraceLogSensitiveOnly:
    def test_write_excluded_when_sensitive_only(self):
        text = _openat(100, "/tmp/output.txt", "O_WRONLY", retval=5)
        result = parse_strace_log(text, sensitive_only=True)
        assert result["file_events"] == []

    def test_sensitive_read_kept_when_sensitive_only(self):
        text = _openat(100, "/home/user/.ssh/id_rsa", "O_RDONLY")
        result = parse_strace_log(text, sensitive_only=True)
        assert len(result["file_events"]) == 1
        assert result["file_events"][0]["sensitive"] is True

    def test_process_events_unaffected_by_sensitive_only(self):
        text = _execve(100, "/usr/bin/curl", '"curl"')
        result = parse_strace_log(text, sensitive_only=True)
        assert len(result["process_events"]) == 1

    def test_sensitive_only_false_keeps_writes(self):
        text = _openat(100, "/tmp/x.txt", "O_WRONLY", retval=5)
        result = parse_strace_log(text, sensitive_only=False)
        assert len(result["file_events"]) == 1


# ── iter_phase_jsonl ──────────────────────────────────────────────────────────

class TestIterPhaseJsonl:
    """Tests for the normalized telemetry.jsonl record schema."""

    def _parse(self, text: str) -> dict:
        return parse_strace_log(text)

    # exec record schema
    def test_exec_schema_keys(self):
        parsed = self._parse(_execve(100, "/usr/bin/pip3", '"pip3"'))
        recs = list(iter_phase_jsonl(parsed, "install"))
        assert len(recs) == 1
        r = recs[0]
        assert r["event_type"] == "exec"
        assert r["phase"]      == "install"
        assert r["pid"]        == 100
        assert r["exe"]        == "/usr/bin/pip3"
        assert r["argv"]       == ["pip3"]
        assert "ts"            in r
        assert "ppid"          in r       # always present (None until fork tracing)
        assert r["ppid"]       is None

    def test_exec_suspicious_flag_carried(self):
        parsed = self._parse(_execve(100, "/usr/bin/curl", '"curl"'))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["suspicious"] is True

    # file record schema
    def test_file_read_schema(self):
        parsed = self._parse(_openat(100, "/home/user/.ssh/id_rsa", "O_RDONLY"))
        recs = list(iter_phase_jsonl(parsed, "install"))
        assert len(recs) == 1
        r = recs[0]
        assert r["event_type"] == "file"
        assert r["op"]         == "openat"
        assert r["path"]       == "/home/user/.ssh/id_rsa"
        assert r["mode"]       == "read"
        assert r["sensitive"]  is True
        assert r["sensitive_category"] == "ssh_keys"

    def test_file_write_mode_field(self):
        parsed = self._parse(_openat(100, "/tmp/x.txt", "O_WRONLY", retval=5))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["mode"] == "write"

    def test_file_create_mode_field(self):
        parsed = self._parse(_openat(100, "/tmp/x.txt", "O_WRONLY|O_CREAT", retval=5))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["mode"] == "create"

    def test_chmod_carries_chmod_mode(self):
        parsed = self._parse(_line(100, 'chmod("/tmp/script.sh", 0755)'))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "file"
        assert r["op"]         == "chmod"
        assert r["mode"]       == "chmod"
        assert r["chmod_mode"] == "755"

    def test_chown_carries_uid_gid(self):
        parsed = self._parse(_line(100, 'chown("/tmp/file", 0, 0)'))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "file"
        assert r["uid"]        == 0
        assert r["gid"]        == 0

    def test_rename_carries_dest_path(self):
        parsed = self._parse(_line(100, 'rename("/tmp/old", "/tmp/new")'))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "file"
        assert r["dest_path"]  == "/tmp/new"

    # socket record schema
    def test_socket_connect_schema(self):
        parsed = self._parse(_connect_v4(100, "1.2.3.4", 80))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "socket"
        assert r["op"]         == "connect"
        assert r["dst_ip"]     == "1.2.3.4"
        assert r["dst_port"]   == 80
        assert r["family"]     == "AF_INET"

    def test_socket_creation_schema(self):
        parsed = self._parse(_socket_line(100, "AF_INET", "SOCK_STREAM", "IPPROTO_TCP"))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "socket"
        assert r["op"]         == "socket"
        assert r["dst_ip"]     is None
        assert r["dst_port"]   is None

    def test_protocol_tcp_from_sock_stream(self):
        parsed = self._parse(_socket_line(100, "AF_INET", "SOCK_STREAM", "IPPROTO_TCP"))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["protocol"] == "tcp"

    def test_protocol_udp_from_sock_dgram(self):
        parsed = self._parse(_socket_line(100, "AF_INET", "SOCK_DGRAM", "IPPROTO_UDP"))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["protocol"] == "udp"

    def test_protocol_none_for_connect_without_sock_type(self):
        # connect() events have no sock_type in the internal schema → protocol=None
        parsed = self._parse(_connect_v4(100, "1.2.3.4", 80))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["protocol"] is None

    # control record schema
    def test_kill_schema(self):
        parsed = self._parse(_line(100, "kill(99, SIGTERM)"))
        r = list(iter_phase_jsonl(parsed, "install"))[0]
        assert r["event_type"] == "control"
        assert r["op"]         == "kill"
        assert r["target_pid"] == 99
        assert r["signal"]     == "SIGTERM"

    def test_ptrace_schema(self):
        parsed = self._parse(_line(100, "ptrace(PTRACE_ATTACH, 999, NULL, NULL)"))
        r = list(iter_phase_jsonl(parsed, "import"))[0]
        assert r["event_type"] == "control"
        assert r["op"]         == "ptrace"
        assert r["phase"]      == "import"

    # ordering and phase propagation
    def test_phase_propagated_to_all_records(self):
        text = (
            _execve(100, "/usr/bin/pip3", '"pip3"') +
            _openat(100, "/home/user/.ssh/id_rsa", "O_RDONLY") +
            _connect_v4(100, "1.2.3.4", 80) +
            _line(100, "kill(99, SIGTERM)")
        )
        parsed = parse_strace_log(text)
        recs = list(iter_phase_jsonl(parsed, "myPhase"))
        assert all(r["phase"] == "myPhase" for r in recs)

    def test_empty_parsed_yields_nothing(self):
        assert list(iter_phase_jsonl({}, "install")) == []

    def test_record_order_exec_file_socket_control(self):
        text = (
            _execve(100, "/usr/bin/pip3", '"pip3"') +
            _openat(100, "/home/user/.ssh/id_rsa", "O_RDONLY") +
            _connect_v4(100, "1.2.3.4", 80) +
            _line(100, "kill(99, SIGTERM)")
        )
        parsed = parse_strace_log(text)
        recs = list(iter_phase_jsonl(parsed, "install"))
        types = [r["event_type"] for r in recs]
        assert types == ["exec", "file", "socket", "control"]


# ── backwards-compat shims ────────────────────────────────────────────────────

class TestBackwardsCompatShims:
    def test_parse_strace_execve_returns_list(self):
        text = _execve(100, "/usr/bin/curl", '"curl", "http://evil.com"')
        events = parse_strace_execve(text)
        assert isinstance(events, list)
        assert events[0]["suspicious"] is True

    def test_summarise_process_telemetry_returns_dict(self):
        events = [{"pid": 1, "executable": "/usr/bin/curl", "basename": "curl",
                   "argv": ["curl"], "suspicious": True, "syscall": "execve", "ts": 0.0}]
        r = summarise_process_telemetry(events)
        assert r["any_suspicious"] is True
        assert "suspicious_execs" in r
