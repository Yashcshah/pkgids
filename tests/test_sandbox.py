"""Integration tests for sandbox.py — require Docker + pkgids-sandbox image."""

import subprocess

import pytest

from pkgids.sandbox import _container_exists, _write_resolv_conf, run_in_sandbox
from tests.conftest import requires_sandbox


# ── _write_resolv_conf unit tests (no Docker needed) ─────────────────────────

def test_write_resolv_conf_content(tmp_path):
    p = _write_resolv_conf("10.200.200.2")
    try:
        assert p.read_text() == "nameserver 10.200.200.2\n"
    finally:
        p.unlink(missing_ok=True)


def test_write_resolv_conf_world_readable(tmp_path):
    import stat
    p = _write_resolv_conf("10.200.200.2")
    try:
        mode = p.stat().st_mode
        assert mode & stat.S_IROTH, "resolv.conf must be world-readable"
    finally:
        p.unlink(missing_ok=True)


def test_write_resolv_conf_different_ips():
    for ip in ("1.2.3.4", "10.200.200.2", "192.168.1.1"):
        p = _write_resolv_conf(ip)
        try:
            assert f"nameserver {ip}" in p.read_text()
        finally:
            p.unlink(missing_ok=True)


# ── basic execution ───────────────────────────────────────────────────────────

@requires_sandbox
def test_echo_stdout():
    result = run_in_sandbox(["echo", "hello"])
    assert result["exit_code"] == 0
    assert "hello" in result["stdout"]
    assert result["timed_out"] is False


@requires_sandbox
def test_echo_string_command():
    result = run_in_sandbox("echo hello from sh")
    assert result["exit_code"] == 0
    assert "hello from sh" in result["stdout"]


@requires_sandbox
def test_exit_code_nonzero():
    result = run_in_sandbox(["sh", "-c", "exit 42"])
    assert result["exit_code"] == 42
    assert result["timed_out"] is False


@requires_sandbox
def test_duration_is_positive():
    result = run_in_sandbox(["echo", "hi"])
    assert result["duration_seconds"] > 0


@requires_sandbox
def test_stderr_captured():
    result = run_in_sandbox(["sh", "-c", "echo err >&2"])
    assert "err" in result["stderr"]


# ── workdir mount (read-only) ────────────────────────────────────────────────

@requires_sandbox
def test_workdir_mounted_readonly(tmp_path):
    # Create an explicitly world-traversable dir so 'deton' can reach /work.
    # pytest's tmp_path parents may be 0700 (root-only); a fresh subdir with
    # explicit mode 0755 / 0644 ensures the bind-mount is accessible.
    work_dir = tmp_path / "work"
    work_dir.mkdir(mode=0o755)
    hello = work_dir / "hello.txt"
    hello.write_text("greetings")
    hello.chmod(0o644)
    result = run_in_sandbox(["cat", "/work/hello.txt"], workdir_host=work_dir)
    assert result["exit_code"] == 0
    assert "greetings" in result["stdout"]


@requires_sandbox
def test_workdir_is_readonly(tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir(mode=0o755)
    seed = work_dir / "seed.txt"
    seed.write_text("x")
    seed.chmod(0o644)
    result = run_in_sandbox(
        ["sh", "-c", "echo bad > /work/seed.txt"],
        workdir_host=work_dir,
    )
    # Write must fail; container exits non-zero and host file is untouched
    assert result["exit_code"] != 0
    assert seed.read_text() == "x"


# ── scratch is writable ───────────────────────────────────────────────────────

@requires_sandbox
def test_scratch_writable():
    result = run_in_sandbox(
        ["sh", "-c", "echo data > /scratch/out.txt && cat /scratch/out.txt"]
    )
    assert result["exit_code"] == 0
    assert "data" in result["stdout"]


# ── network isolation ─────────────────────────────────────────────────────────

@requires_sandbox
def test_network_none_blocks_outbound():
    # With --network none, DNS resolution should fail
    result = run_in_sandbox(
        ["sh", "-c", "curl -s --max-time 3 https://example.com || echo BLOCKED"],
        network="none",
    )
    # Either curl is absent (exit != 0 without BLOCKED) or returns BLOCKED
    assert result["exit_code"] != 0 or "BLOCKED" in result["stdout"]


# ── timeout ───────────────────────────────────────────────────────────────────

@requires_sandbox
def test_timeout_sets_timed_out_flag():
    result = run_in_sandbox(["sleep", "60"], timeout=3)
    assert result["timed_out"] is True


@requires_sandbox
def test_timeout_container_removed_afterward():
    result = run_in_sandbox(["sleep", "60"], timeout=3)
    assert result["timed_out"] is True
    name = result["container_name"]
    assert not _container_exists(name), f"container {name!r} still present after timeout"


@requires_sandbox
def test_success_container_removed_afterward():
    result = run_in_sandbox(["echo", "done"])
    assert result["timed_out"] is False
    name = result["container_name"]
    assert not _container_exists(name), f"container {name!r} still present after success"


# ── fake-network DNS resolution (requires fakeinternet appliance) ─────────────

@requires_sandbox
def test_fake_network_dns_resolves_to_appliance():
    """DNS inside the gVisor sandbox must reach the fake-internet appliance.

    The appliance resolves every hostname to its own IP (10.200.200.2 by
    default).  We ask the Python socket API to resolve a canary hostname and
    assert the returned IP matches the configured appliance IP.
    """
    from pkgids import config as _cfg
    fi_ip = _cfg.get().get("fakeinternet", {}).get("ip", "10.200.200.2")

    result = run_in_sandbox(
        ["python3", "-c",
         "import socket; print(socket.gethostbyname('canary-test.example.com'))"],
        network="fake",
    )
    assert result["exit_code"] == 0, (
        f"DNS lookup failed (exit {result['exit_code']}):\n"
        f"stdout: {result['stdout']}\nstderr: {result['stderr']}"
    )
    assert fi_ip in result["stdout"], (
        f"Expected appliance IP {fi_ip!r} in stdout, got: {result['stdout']!r}"
    )


@requires_sandbox
def test_fake_network_dns_appears_in_capture_log():
    """DNS query must produce a log entry in the fakeinternet capture file."""
    import json, time
    from pathlib import Path
    from pkgids.capture import _read_window

    result = run_in_sandbox(
        ["python3", "-c",
         "import socket; socket.gethostbyname('canary-log.example.com')"],
        network="fake",
    )
    assert result["exit_code"] == 0

    capture_log = result.get("capture_log")
    assert capture_log is not None, "capture_log should be set in fake mode"

    # Give the appliance a moment to flush the log entry
    time.sleep(0.5)

    # Use a generous window: the run itself tells us the exact window but here
    # we just want to confirm the entry landed at all.
    entries = _read_window(Path(capture_log), time.time() - 30, time.time())
    dns_entries = [e for e in entries if e.get("type") == "dns"
                   and "canary-log" in e.get("query", "")]
    assert dns_entries, (
        f"No DNS entry for canary-log.example.com in {capture_log}.\n"
        f"All recent entries: {entries}"
    )


# ── input validation ──────────────────────────────────────────────────────────

def test_unsupported_network_raises():
    with pytest.raises(ValueError, match="Unsupported network"):
        run_in_sandbox(["echo", "hi"], network="host")
