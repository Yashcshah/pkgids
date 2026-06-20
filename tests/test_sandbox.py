"""Integration tests for sandbox.py — require Docker + pkgids-sandbox image."""

import subprocess

import pytest

from pkgids.sandbox import _container_exists, run_in_sandbox
from tests.conftest import requires_sandbox


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


# ── input validation ──────────────────────────────────────────────────────────

def test_unsupported_network_raises():
    with pytest.raises(ValueError, match="Unsupported network"):
        run_in_sandbox(["echo", "hi"], network="host")
