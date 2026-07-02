"""Unit tests for pkgids/analyze.py — cross-stream correlation logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgids.analyze import (
    CORRELATION_WINDOW_SECS,
    _attribute_connections,
    _file_before_exfil,
    _network_attributed,
    _read_jsonl,
    _shell_before_network,
    _subprocess_payloads,
    analyze,
)


# ── fixtures / helpers ────────────────────────────────────────────────────────

TS = 1_700_000_000.0


def _exec_ev(pid: int, exe: str, ts: float = TS, suspicious: bool = False,
             phase: str = "install") -> dict:
    return {
        "event_type": "exec", "phase": phase,
        "pid": pid, "ppid": None,
        "exe": exe, "argv": [exe.rsplit("/", 1)[-1]],
        "suspicious": suspicious, "ts": ts,
    }


def _file_ev(pid: int, path: str, mode: str = "read",
             sensitive: bool = False, ts: float = TS,
             phase: str = "install") -> dict:
    return {
        "event_type": "file", "phase": phase,
        "pid": pid, "op": "openat", "path": path,
        "mode": mode, "sensitive": sensitive,
        "sensitive_category": "ssh_keys" if sensitive else None,
        "ts": ts,
    }


def _socket_ev(pid: int, dst_ip: str = "1.2.3.4", dst_port: int = 80,
               ts: float = TS, op: str = "connect",
               phase: str = "install") -> dict:
    return {
        "event_type": "socket", "phase": phase,
        "pid": pid, "op": op,
        "dst_ip": dst_ip, "dst_port": dst_port,
        "protocol": "tcp", "family": "AF_INET",
        "ts": ts,
    }


def _net_ev(host: str = "evil.com", port: int = 80, ts: float = TS) -> dict:
    return {"ts": ts, "type": "http", "host": host, "port": port}


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def _make_run_dir(tmp_path: Path,
                  telemetry: list[dict] | None = None,
                  network: list[dict] | None = None) -> Path:
    d = tmp_path / "run"
    d.mkdir(parents=True, exist_ok=True)
    if telemetry is not None:
        _write_jsonl(d / "telemetry.jsonl", telemetry)
    if network is not None:
        _write_jsonl(d / "network.jsonl", network)
    return d


# ── _read_jsonl ───────────────────────────────────────────────────────────────

class TestReadJsonl:
    def test_reads_valid_records(self, tmp_path):
        f = tmp_path / "x.jsonl"
        f.write_text('{"a": 1}\n{"b": 2}\n')
        assert _read_jsonl(f) == [{"a": 1}, {"b": 2}]

    def test_missing_file_returns_empty(self, tmp_path):
        assert _read_jsonl(tmp_path / "nope.jsonl") == []

    def test_bad_line_skipped(self, tmp_path):
        f = tmp_path / "x.jsonl"
        f.write_text('not-json\n{"a": 1}\n')
        assert _read_jsonl(f) == [{"a": 1}]

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "x.jsonl"
        f.write_text("")
        assert _read_jsonl(f) == []


# ── _attribute_connections ────────────────────────────────────────────────────

class TestAttributeConnections:
    def test_attributed_by_pid(self):
        telemetry = [
            _exec_ev(100, "/usr/bin/curl", ts=TS),
            _socket_ev(100, "1.2.3.4", 443, ts=TS + 0.5),
        ]
        pid_map = {100: telemetry[0]}
        result = _attribute_connections(telemetry, pid_map)
        assert len(result) == 1
        assert result[0]["initiated_by"]["exe"] == "/usr/bin/curl"
        assert result[0]["dst_ip"] == "1.2.3.4"
        assert result[0]["dst_port"] == 443

    def test_unknown_pid_yields_none_process(self):
        telemetry = [_socket_ev(999, "1.2.3.4", 80, ts=TS)]
        result = _attribute_connections(telemetry, {})
        assert len(result) == 1
        assert result[0]["initiated_by"] is None

    def test_socket_creation_skipped(self):
        telemetry = [_socket_ev(100, "1.2.3.4", 80, op="socket")]
        result = _attribute_connections(telemetry, {})
        assert result == []

    def test_connect_without_dst_ip_skipped(self):
        ev = {**_socket_ev(100, "1.2.3.4", 80), "dst_ip": None}
        result = _attribute_connections([ev], {})
        assert result == []

    def test_multiple_pids_each_attributed_separately(self):
        telemetry = [
            _exec_ev(100, "/usr/bin/curl",  ts=TS),
            _exec_ev(101, "/usr/bin/wget",  ts=TS),
            _socket_ev(100, "1.1.1.1", 80,  ts=TS + 0.1),
            _socket_ev(101, "2.2.2.2", 443, ts=TS + 0.2),
        ]
        pid_map = {100: telemetry[0], 101: telemetry[1]}
        result = _attribute_connections(telemetry, pid_map)
        assert len(result) == 2
        exes = {r["initiated_by"]["exe"] for r in result}
        assert exes == {"/usr/bin/curl", "/usr/bin/wget"}


# ── _network_attributed ───────────────────────────────────────────────────────

class TestNetworkAttributed:
    def test_network_event_attributed_to_preceding_exec(self):
        exec_ev = _exec_ev(100, "/usr/bin/curl", ts=TS)
        net_ev  = _net_ev(ts=TS + 1.0)
        result  = _network_attributed([exec_ev], [net_ev], {100: exec_ev})
        assert len(result) == 1
        assert result[0]["responsible_process"]["exe"] == "/usr/bin/curl"

    def test_exec_outside_window_not_attributed(self):
        exec_ev = _exec_ev(100, "/usr/bin/curl", ts=TS)
        net_ev  = _net_ev(ts=TS + CORRELATION_WINDOW_SECS + 1.0)
        result  = _network_attributed([exec_ev], [net_ev], {100: exec_ev})
        assert result[0]["responsible_process"] is None

    def test_no_exec_before_network_yields_none(self):
        net_ev = _net_ev(ts=TS)
        result = _network_attributed([], [net_ev], {})
        assert result[0]["responsible_process"] is None

    def test_network_event_carries_original_fields(self):
        net_ev = _net_ev(host="evil.com", ts=TS + 1.0)
        exec_ev = _exec_ev(100, "/usr/bin/curl", ts=TS)
        result = _network_attributed([exec_ev], [net_ev], {100: exec_ev})
        assert result[0]["host"] == "evil.com"


# ── _file_before_exfil ────────────────────────────────────────────────────────

class TestFileBeforeExfil:
    def test_sensitive_read_before_network_detected(self):
        tel = [
            _file_ev(100, "/home/deton/.ssh/id_rsa", mode="read",
                     sensitive=True, ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 1.0),
        ]
        result = _file_before_exfil(tel, [])
        assert len(result) == 1
        assert result[0]["file_read"]["path"] == "/home/deton/.ssh/id_rsa"
        assert len(result[0]["following_network"]) == 1

    def test_file_outside_window_not_paired(self):
        tel = [
            _file_ev(100, "/home/user/.ssh/id_rsa", mode="read",
                     sensitive=True, ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + CORRELATION_WINDOW_SECS + 1.0),
        ]
        result = _file_before_exfil(tel, [])
        assert result == []

    def test_non_sensitive_read_not_paired(self):
        tel = [
            _file_ev(100, "/tmp/x.txt", mode="read", sensitive=False, ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 0.5),
        ]
        result = _file_before_exfil(tel, [])
        assert result == []

    def test_fakeinternet_network_entry_used(self):
        tel = [
            _file_ev(100, "/home/user/.ssh/id_rsa", mode="read",
                     sensitive=True, ts=TS),
        ]
        net = [_net_ev(host="evil.com", ts=TS + 1.0)]
        result = _file_before_exfil(tel, net)
        assert len(result) == 1
        assert result[0]["following_network"][0]["src"] == "fakeinternet"

    def test_write_not_considered_for_exfil_source(self):
        tel = [
            _file_ev(100, "/home/user/.ssh/id_rsa", mode="write",
                     sensitive=True, ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 0.5),
        ]
        result = _file_before_exfil(tel, [])
        assert result == []


# ── _shell_before_network ─────────────────────────────────────────────────────

class TestShellBeforeNetwork:
    def test_bash_exec_before_network_detected(self):
        tel = [
            _exec_ev(100, "/bin/bash", ts=TS, suspicious=True),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 0.5),
        ]
        result = _shell_before_network(tel, [])
        assert len(result) == 1
        assert result[0]["shell_exec"]["exe"] == "/bin/bash"

    def test_non_shell_exec_not_matched(self):
        tel = [
            _exec_ev(100, "/usr/bin/pip3", ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 0.5),
        ]
        result = _shell_before_network(tel, [])
        assert result == []

    def test_shell_outside_window_not_matched(self):
        tel = [
            _exec_ev(100, "/bin/sh", ts=TS),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + CORRELATION_WINDOW_SECS + 1.0),
        ]
        result = _shell_before_network(tel, [])
        assert result == []

    def test_fakeinternet_entry_counts_as_network(self):
        tel = [_exec_ev(100, "/bin/bash", ts=TS, suspicious=True)]
        net = [_net_ev(ts=TS + 1.0)]
        result = _shell_before_network(tel, net)
        assert len(result) == 1


# ── _subprocess_payloads ──────────────────────────────────────────────────────

class TestSubprocessPayloads:
    def test_suspicious_after_pip3_is_payload(self):
        tel = [
            _exec_ev(100, "/usr/bin/pip3", ts=TS, suspicious=False),
            _exec_ev(101, "/usr/bin/curl", ts=TS + 1.0, suspicious=True),
        ]
        result = _subprocess_payloads(tel)
        assert len(result) == 1
        assert result[0]["payload_exec"]["exe"]       == "/usr/bin/curl"
        assert result[0]["potential_parent"]["exe"]   == "/usr/bin/pip3"

    def test_no_suspicious_execs_returns_empty(self):
        tel = [_exec_ev(100, "/usr/bin/pip3", ts=TS)]
        assert _subprocess_payloads(tel) == []

    def test_same_pid_not_treated_as_parent(self):
        tel = [_exec_ev(100, "/usr/bin/curl", ts=TS, suspicious=True)]
        result = _subprocess_payloads(tel)
        assert result[0]["potential_parent"] is None

    def test_most_recent_non_suspicious_exec_is_parent(self):
        tel = [
            _exec_ev(100, "/usr/bin/pip3",   ts=TS,       suspicious=False),
            _exec_ev(101, "/usr/bin/python3", ts=TS + 0.5, suspicious=True),
            _exec_ev(102, "/usr/bin/curl",    ts=TS + 0.6, suspicious=True),
        ]
        # pip3 at TS should be parent for both (it's the only non-suspicious prior exec)
        result = _subprocess_payloads(tel)
        assert len(result) == 2
        parents = {r["potential_parent"]["exe"] for r in result if r["potential_parent"]}
        assert "/usr/bin/pip3" in parents


# ── analyze() — end-to-end ────────────────────────────────────────────────────

class TestAnalyze:
    def test_empty_run_dir_returns_all_empty_lists(self, tmp_path):
        run_dir = _make_run_dir(tmp_path)
        result  = analyze(run_dir)
        assert result["connections_attributed"]  == []
        assert result["file_before_exfil"]       == []
        assert result["shell_before_network"]    == []
        assert result["subprocess_payloads"]     == []
        assert result["summary"]["total_telemetry_events"] == 0

    def test_writes_correlations_json(self, tmp_path):
        run_dir = _make_run_dir(tmp_path)
        analyze(run_dir)
        assert (run_dir / "correlations.json").exists()

    def test_correlations_json_is_valid(self, tmp_path):
        run_dir = _make_run_dir(tmp_path)
        analyze(run_dir)
        data = json.loads((run_dir / "correlations.json").read_text())
        assert "summary" in data

    def test_full_malicious_scenario(self, tmp_path):
        """pip3 spawns curl; curl reads ssh key then connects out."""
        tel = [
            _exec_ev(100, "/usr/bin/pip3",  ts=TS,       suspicious=False),
            _exec_ev(101, "/usr/bin/curl",  ts=TS + 0.5, suspicious=True),
            _file_ev(101, "/home/deton/.ssh/id_rsa", mode="read",
                     sensitive=True, ts=TS + 0.6),
            _socket_ev(101, "1.2.3.4", 443, ts=TS + 0.7),
        ]
        run_dir = _make_run_dir(tmp_path, telemetry=tel)
        result  = analyze(run_dir)

        # Connection attributed to curl
        assert len(result["connections_attributed"]) == 1
        assert result["connections_attributed"][0]["initiated_by"]["exe"] == "/usr/bin/curl"

        # SSH key read before exfil
        assert len(result["file_before_exfil"]) == 1

        # curl is a subprocess payload
        assert len(result["subprocess_payloads"]) == 1
        assert result["subprocess_payloads"][0]["potential_parent"]["exe"] == "/usr/bin/pip3"

    def test_summary_counts_are_accurate(self, tmp_path):
        tel = [
            _exec_ev(100, "/usr/bin/curl", ts=TS, suspicious=True),
            _socket_ev(100, "1.2.3.4", 80, ts=TS + 0.5),
        ]
        net = [_net_ev(ts=TS + 0.5)]
        run_dir = _make_run_dir(tmp_path, telemetry=tel, network=net)
        result  = analyze(run_dir)
        assert result["summary"]["total_telemetry_events"] == 2
        assert result["summary"]["total_network_events"]   == 1
        assert result["summary"]["attributed_connections"] == 1

    def test_missing_telemetry_jsonl_handled(self, tmp_path):
        run_dir = _make_run_dir(tmp_path, network=[_net_ev()])
        result  = analyze(run_dir)
        assert result["summary"]["total_telemetry_events"] == 0
        assert result["summary"]["total_network_events"]   == 1
