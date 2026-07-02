"""Detonation orchestrator: fetch → tcpdump → install → import → collect."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config as _cfg
from . import telemetry as _telemetry
from .fetch import fetch
from .sandbox import (
    exec_in_sandbox,
    read_container_file,
    start_sandbox_container,
    stop_sandbox_container,
)


# ── bridge / tcpdump helpers ─────────────────────────────────────────────────

def _detonet_bridge_iface() -> str:
    """Return the host Linux bridge interface name for the detonet network."""
    fi_cfg = _cfg.get().get("fakeinternet", {})
    network_name = fi_cfg.get("network", "detonet")
    r = subprocess.run(
        ["docker", "network", "inspect", network_name, "--format", "{{.Id}}"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"Cannot inspect docker network {network_name!r}: {r.stderr.strip()}"
        )
    return f"br-{r.stdout.strip()[:12]}"


def _start_tcpdump(iface: str, pcap_path: Path) -> subprocess.Popen:
    return subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", str(pcap_path), "-q", "-U"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop_tcpdump(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait()
        except Exception:
            pass


# ── command builders ──────────────────────────────────────────────────────────

def _install_command(ecosystem: str, artifact_name: str) -> list[str]:
    if ecosystem == "pypi":
        # Install to /scratch/site-packages (tmpfs) so the package is visible
        # to the import phase running in the same container.  --target writes
        # directly to that directory without touching the system site-packages.
        return [
            "pip3", "install",
            "--break-system-packages",
            "--no-build-isolation",
            "--no-deps",
            "--target", "/scratch/site-packages",
            f"/work/{artifact_name}",
        ]
    if ecosystem == "npm":
        return [
            "npm", "install",
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund",
            f"/work/{artifact_name}",
        ]
    raise ValueError(f"Unsupported ecosystem: {ecosystem!r}")


def _top_module_name(ecosystem: str, package_name: str) -> str:
    if ecosystem == "npm":
        return package_name.lstrip("@").split("/")[-1]
    return package_name.replace("-", "_").replace(".", "_")


def _import_command(ecosystem: str, package_name: str) -> list[str]:
    if ecosystem == "pypi":
        mod = _top_module_name(ecosystem, package_name)
        # Prepend /scratch/site-packages so Python finds the package installed
        # by the install phase in the same container.
        return [
            "python3", "-c",
            f"import sys; sys.path.insert(0, '/scratch/site-packages'); import {mod}",
        ]
    if ecosystem == "npm":
        return ["node", "-e", f"require('{package_name}')"]
    raise ValueError(f"Unsupported ecosystem: {ecosystem!r}")


# ── process telemetry helpers ─────────────────────────────────────────────────

_STRACE_SYSCALLS_DEFAULT = ",".join([
    # Process spawning
    "execve", "execveat",
    # File access (writes, creates, deletes, renames; sensitive reads filtered in parser)
    "open", "openat", "unlink", "rename", "mkdir",
    # Permission / ownership changes
    "chmod", "chown",
    # Network connections (attributed to the spawning process)
    "connect", "socket",
    # Process control (suspicious when called from package code)
    "kill", "ptrace",
])


def _with_strace(
    cmd: list[str],
    log_path: str,
    syscalls: str = _STRACE_SYSCALLS_DEFAULT,
    max_arg_len: int = 256,
) -> list[str]:
    """Prepend strace arguments to *cmd* to capture security-relevant syscalls.

    The trace is written to *log_path* inside the container (/scratch/...).
    strace exits with the traced process's exit code so phase exit_code and
    timed_out remain accurate.

    Flags
    -----
    -q             suppress "attached/detached" noise from strace's own stderr
    -f             follow forks (single output file, PID-prefixed lines)
    -ttt           per-line epoch timestamp (seconds.microseconds)
    -s max_arg_len max string length; default 256 prevents path truncation
    -e             config-driven syscall subset (see [telemetry] trace_syscalls)
    -o             write trace to log_path (not stderr)

    If strace itself fails (ptrace denied by a hardened gVisor configuration),
    log_path will be absent or empty — callers detect this via
    ``read_container_file`` returning None and set telemetry_limited_process=True.
    """
    return [
        "strace",
        "-q",
        "-f",
        "-ttt",
        "-s", str(max_arg_len),
        "-e", f"trace={syscalls}",
        "-o", log_path,
    ] + cmd


def _append_telemetry_jsonl(
    path: Path,
    parsed: dict,
    phase: str,
) -> None:
    """Append normalized telemetry records for *phase* to *path* (created if absent)."""
    records = list(_telemetry.iter_phase_jsonl(parsed, phase))
    if not records:
        return
    with open(path, "a") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


# ── run-directory helpers ─────────────────────────────────────────────────────

def _runs_root() -> Path:
    cfg = _cfg.get().get("detonation", {})
    p = Path(cfg.get("runs_dir", "runs"))
    if not p.is_absolute():
        p = Path(__file__).parent.parent / p
    return p


def _make_run_dir(ecosystem: str, name: str, version: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = name.lstrip("@").replace("/", "__")
    run_dir = _runs_root() / f"{ts}-{ecosystem}-{safe}-{version}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# ── log filtering (timestamp-window) ─────────────────────────────────────────

def _read_window(log_path: Path | None, t_start: float, t_end: float) -> list[dict]:
    """Return JSONL entries from *log_path* whose ``ts`` is in [t_start, t_end].

    Entries with a missing or non-numeric ``ts`` are silently skipped so a
    single malformed line never causes a crash.  The caller owns the window
    interpretation — no buffers are added here.
    """
    if not log_path or not log_path.exists():
        return []
    entries: list[dict] = []
    for line in log_path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            ts = float(entry.get("ts", -1))
            if t_start <= ts <= t_end:
                entries.append(entry)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    return entries


def _read_phase_entries(
    capture_log: str | None,
    t_start: float,
    t_end: float,
    fi_logs_dir: Path,
) -> list[dict]:
    """Return fakeinternet entries that belong to this phase's time window.

    Primary path
        Read *capture_log* (keyed by the container's detonet IP) and keep only
        entries whose ``ts`` falls within [t_start, t_end].  Stale entries from
        a recycled IP are automatically excluded by the timestamp filter.

    Fallback path (IP detection failed → capture_log is None)
        Scan *every* .jsonl in fi_logs_dir and keep entries in the same window.
        This guarantees captured traffic is never silently lost.
    """
    if capture_log:
        return _read_window(Path(capture_log), t_start, t_end)

    # IP detection failed: scan all log files, still timestamp-filtered.
    entries: list[dict] = []
    if fi_logs_dir.exists():
        for p in fi_logs_dir.glob("*.jsonl"):
            entries.extend(_read_window(p, t_start, t_end))
    if entries:
        print(
            "[detonate] WARNING: capture_log IP detection failed; "
            "network entries recovered via timestamp-window fallback scan",
            flush=True,
        )
    return entries


# ── bookkeeping ───────────────────────────────────────────────────────────────

def _phase_status(raw: dict, phase_name: str) -> str:
    """Classify an exec-phase result into a human-readable status string.

    Possible values
    ---------------
    ok               — exit_code == 0 and not timed_out
    timed_out        — exec exceeded the timeout
    crashed          — container stopped or was killed during the exec
    module_not_found — import phase only: module was not importable
    failed           — any other non-zero exit code
    """
    if raw.get("timed_out"):
        return "timed_out"

    exit_code = raw.get("exit_code", -1)
    stderr    = raw.get("stderr",    "")
    stdout    = raw.get("stdout",    "")

    # docker exec reports this when the target container has died.
    if exit_code != 0 and "is not running" in stderr:
        return "crashed"

    if exit_code == 0:
        return "ok"

    # Import-specific: distinguish a missing module from a generic failure so
    # callers can decide whether to retry with a different module name.
    if phase_name == "import":
        combined = stdout + stderr
        if "ModuleNotFoundError" in combined or "No module named" in combined:
            return "module_not_found"

    return "failed"


def _has_network(entries: list[dict]) -> bool:
    """Return True if the timestamp-filtered entry list is non-empty."""
    return len(entries) > 0


def _make_phase_record(
    phase_name: str,
    cmd: list[str],
    raw: dict,
    t_start: float,
    t_end: float,
    capture_log: str | None,
    entries: list[dict],
    process_activity: dict | None = None,
) -> dict:
    """Build the canonical per-phase record written to install.json / import.json.

    The t_start / t_end window is the authoritative filter key used downstream
    to correlate network events, syscall events, file-access events, and
    subprocess events with the phase that produced them.

    process_activity (optional)
        Result of telemetry.summarise_process_telemetry().  None for phases
        where process telemetry was not collected (idle sleep phases).
    """
    return {
        "phase":             phase_name,
        "status":            _phase_status(raw, phase_name),
        "t_start":           t_start,
        "t_end":             t_end,
        "command":           cmd,
        "exit_code":         raw["exit_code"],
        "timed_out":         raw["timed_out"],
        "duration_secs":     raw["duration_seconds"],
        "network_activity":  _has_network(entries),
        "telemetry_limited": capture_log is None,
        "capture_log":       capture_log,
        "stdout":            raw["stdout"],
        "stderr":            raw["stderr"],
        "process_activity":  process_activity,
    }


def _make_simple_phase(
    phase_name: str,
    t_start: float,
    t_end: float,
    entries: list[dict],
    capture_log: str | None,
) -> dict:
    """Build a phase record for lifecycle phases that have no exec command.

    Used for startup and shutdown — they have a timing window and network
    visibility but no associated command, stdout, stderr, or exit_code.
    """
    return {
        "phase":             phase_name,
        "status":            "ok",
        "t_start":           t_start,
        "t_end":             t_end,
        "duration_secs":     round(t_end - t_start, 3),
        "network_activity":  _has_network(entries),
        "telemetry_limited": capture_log is None,
        "capture_log":       capture_log,
        "process_activity":  None,
    }


def _phase_summary(record: dict) -> dict:
    """Extract the compact per-phase block written to run.json phases section.

    Strips stdout/stderr/capture_log so run.json stays small; the full record
    lives in install.json / import.json.  t_start and t_end are preserved so
    downstream consumers can filter any event stream without opening the
    individual phase files.
    """
    d = {
        "phase":             record.get("phase"),
        "status":            record.get("status"),
        "t_start":           record.get("t_start"),
        "t_end":             record.get("t_end"),
        "exit_code":         record.get("exit_code"),
        "duration_secs":     record.get("duration_secs"),
        "timed_out":         record.get("timed_out"),
        "network_activity":  record.get("network_activity"),
        "telemetry_limited": record.get("telemetry_limited", False),
        "process_activity":  record.get("process_activity"),
    }
    if "error" in record:
        d["error"] = record["error"]
    return d


def _clear_fakeinternet_logs(fi_logs_dir: Path) -> None:
    """Truncate all .jsonl files in fi_logs_dir to prevent unbounded growth."""
    if not fi_logs_dir.exists():
        return
    cleared = sum(1 for p in fi_logs_dir.glob("*.jsonl") if not p.write_text(""))
    if cleared:
        print(f"[detonate] cleared {cleared} fakeinternet log(s)", flush=True)


# ── public API ────────────────────────────────────────────────────────────────

def run(
    ecosystem: str,
    name: str,
    version: str,
    run_dir: Path | None = None,
    skip_import: bool | None = None,
    artifact_path: Path | None = None,
    post_install_idle_secs: int | None = None,
    post_import_idle_secs: int | None = None,
    skip_import_on_install_failure: bool | None = None,
) -> dict:
    """Full detonation pipeline for one package.

    Steps
    -----
    1.  (opt) clear fakeinternet logs
    2.  fetch()               – download artifact + write metadata.json
    3.  mkdir runs/<id>       – create isolated run directory
    4.  tcpdump               – capture detonet traffic on the host bridge (best-effort)
    5.  [startup]             – start long-lived gVisor container (sleep infinity)
    6.  [install]             – docker exec pip/npm install; package lands in /scratch
    7.  [post_install_idle]   – docker exec sleep N; observe delayed install payloads
    8.  [import]              – docker exec python3/node import; finds package in /scratch
    9.  [post_import_idle]    – docker exec sleep N; observe delayed import payloads
    10. [shutdown]            – stop tcpdump; docker rm -f; clean resolv.conf temp file
    11. network.jsonl         – merge timestamp-filtered entries from all phases
    12. run.json              – write summary with sandbox_meta, phases, network_activity

    All phases share a single gVisor container so that packages installed during
    the install phase are present on the filesystem during the import phase.
    Per-phase [t_start, t_end] windows are the authoritative filter key for
    correlating any event stream (network, syscall, file-access) with the phase
    that produced it.

    The idle phases (post_install_idle, post_import_idle) exist because some
    malware delays network callbacks or subprocess execution by a second or two
    after the trigger event.  Without an idle window those events fall outside
    every named phase window and are silently lost.

    Phase status values
    -------------------
    ok               — completed cleanly
    failed           — non-zero exit code (generic)
    timed_out        — exec hit the timeout wall
    crashed          — container died during the exec
    module_not_found — import phase: module was not importable (name mismatch or
                       install silently failed)
    skipped          — phase was not run; see ``reason`` for why

    Parameters
    ----------
    artifact_path:
        If provided, skip fetch() and use this pre-built local artifact directly.
    post_install_idle_secs:
        Seconds to sleep in-container after install (captures delayed payloads).
        None reads from config.  0 disables the idle phase entirely.
    post_import_idle_secs:
        Seconds to sleep in-container after import. None reads from config. 0 disables.
    skip_import_on_install_failure:
        When True, skip import if install exits non-zero.
        None reads from config (``detonation.skip_import_on_install_failure``).
    """
    cfg     = _cfg.get()
    det_cfg = cfg.get("detonation", {})
    fi_cfg  = cfg.get("fakeinternet", {})
    sbx_cfg = cfg.get("sandbox", {})
    tel_cfg = cfg.get("telemetry", {})

    effective_skip_import: bool = (
        skip_import if skip_import is not None
        else bool(det_cfg.get("skip_import", False))
    )
    eff_post_install_secs: int = (
        post_install_idle_secs if post_install_idle_secs is not None
        else int(det_cfg.get("post_install_idle_secs", 2))
    )
    eff_post_import_secs: int = (
        post_import_idle_secs if post_import_idle_secs is not None
        else int(det_cfg.get("post_import_idle_secs", 2))
    )
    eff_skip_on_fail: bool = (
        skip_import_on_install_failure if skip_import_on_install_failure is not None
        else bool(det_cfg.get("skip_import_on_install_failure", False))
    )
    eff_telemetry:        bool = bool(tel_cfg.get("enabled", True))
    eff_max_arg_len:      int  = int(tel_cfg.get("max_arg_len", 256))
    eff_sensitive_only:   bool = bool(tel_cfg.get("capture_sensitive_only", False))
    _custom_syscalls             = tel_cfg.get("trace_syscalls")
    eff_strace_syscalls:  str  = (
        ",".join(_custom_syscalls) if _custom_syscalls else _STRACE_SYSCALLS_DEFAULT
    )

    fi_logs_dir = Path(fi_cfg.get("logs_dir", "logs/fakeinternet"))
    if not fi_logs_dir.is_absolute():
        fi_logs_dir = Path(__file__).parent.parent / fi_logs_dir

    # ── 1. Optionally clear stale appliance logs ──────────────────────────────
    if det_cfg.get("clear_logs_each_run", False):
        _clear_fakeinternet_logs(fi_logs_dir)

    # ── 2. Fetch (or use local artifact) ─────────────────────────────────────
    if artifact_path is not None:
        artifact = Path(artifact_path)
        if not artifact.exists():
            raise FileNotFoundError(f"local artifact not found: {artifact}")
        print(f"[detonate] using local artifact: {artifact}", flush=True)
    else:
        print(f"[detonate] fetching {ecosystem}:{name}=={version} ...", flush=True)
        artifact = fetch(ecosystem, name, version)
    artifact_dir = artifact.parent

    # ── 3. Run directory ──────────────────────────────────────────────────────
    if run_dir is None:
        run_dir = _make_run_dir(ecosystem, name, version)
    else:
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[detonate] run dir -> {run_dir}", flush=True)

    # ── 4. Start tcpdump (host-side, best-effort) ─────────────────────────────
    tcpdump_proc: subprocess.Popen | None = None
    pcap_path = run_dir / "capture.pcap"
    try:
        iface = _detonet_bridge_iface()
        tcpdump_proc = _start_tcpdump(iface, pcap_path)
        time.sleep(0.3)
        print(f"[detonate] tcpdump started on {iface}", flush=True)
    except Exception as exc:
        print(f"[detonate] WARNING: tcpdump unavailable ({exc}); continuing without pcap", flush=True)

    # Phase records — populated during the try block and in the shutdown finally.
    startup_record:           dict = {}
    install_record:           dict = {}
    post_install_record:      dict = {}
    import_record:            dict = {}
    post_import_record:       dict = {}
    shutdown_record:          dict = {}
    all_network_entries:      list[dict] = []
    capture_log:              str | None = None
    sandbox_info:             dict | None = None
    skip_import_due_to_fail:  bool = False
    skip_import_reason:       str  = "skip_import" if effective_skip_import else ""

    install_cmd = _install_command(ecosystem, artifact.name)
    import_cmd  = _import_command(ecosystem, name)

    try:
        # ── 5. [startup] — start the analysis container ───────────────────────
        print("[detonate] starting analysis container ...", flush=True)
        startup_t0 = time.time()
        try:
            sandbox_info = start_sandbox_container(workdir_host=artifact_dir, network="fake")
        except RuntimeError as exc:
            # Appliance not running, image missing, or other hard startup failure.
            # Record as a failed startup phase; remaining phases are skipped.
            startup_t1     = time.time()
            startup_record = {
                "phase":             "startup",
                "status":            "failed",
                "t_start":           startup_t0,
                "t_end":             startup_t1,
                "duration_secs":     round(startup_t1 - startup_t0, 3),
                "network_activity":  False,
                "telemetry_limited": True,
                "capture_log":       None,
                "error":             str(exc),
            }
            print(f"[detonate] startup failed: {exc}", flush=True)
        else:
            startup_t1  = time.time()
            capture_log = sandbox_info["capture_log"]

            startup_entries = _read_phase_entries(capture_log, startup_t0, startup_t1, fi_logs_dir)
            startup_record  = _make_simple_phase(
                "startup", startup_t0, startup_t1, startup_entries, capture_log
            )
            all_network_entries.extend(startup_entries)
            print(f"[detonate] container {sandbox_info['container_name']} ready", flush=True)

            # ── 6. [install] ──────────────────────────────────────────────────
            print("[detonate] install phase ...", flush=True)
            strace_install_log = "/scratch/strace_install.log"
            install_exec_cmd   = (
                _with_strace(install_cmd, strace_install_log,
                             syscalls=eff_strace_syscalls,
                             max_arg_len=eff_max_arg_len)
                if eff_telemetry else install_cmd
            )
            install_t0  = time.time()
            install_raw = exec_in_sandbox(sandbox_info["container_name"], install_exec_cmd)
            install_t1  = time.time()

            # Read strace log back from /scratch (stays in the container's tmpfs)
            install_proc_limited = not eff_telemetry
            install_parsed: dict = {}
            if eff_telemetry:
                raw_trace = read_container_file(
                    sandbox_info["container_name"], strace_install_log
                )
                if raw_trace:
                    install_parsed = _telemetry.parse_strace_log(
                        raw_trace, sensitive_only=eff_sensitive_only
                    )
                else:
                    install_proc_limited = True
            install_process_activity = _telemetry.summarise_telemetry(
                install_parsed, telemetry_limited_process=install_proc_limited
            )

            install_entries = _read_phase_entries(capture_log, install_t0, install_t1, fi_logs_dir)
            install_record  = _make_phase_record(
                "install", install_cmd, install_raw,
                install_t0, install_t1, capture_log, install_entries,
                process_activity=install_process_activity,
            )
            (run_dir / "install.json").write_text(json.dumps(install_record, indent=2))
            _append_telemetry_jsonl(run_dir / "telemetry.jsonl", install_parsed, "install")
            all_network_entries.extend(install_entries)
            print(f"[detonate] install status={install_record['status']}", flush=True)

            # Check whether install failure should gate the import phase.
            if install_record["status"] != "ok" and eff_skip_on_fail:
                skip_import_due_to_fail = True
                skip_import_reason      = "install_failed"
                print("[detonate] import skipped (install_failed, skip_import_on_install_failure=true)", flush=True)

            # ── 7. [post_install_idle] ────────────────────────────────────────
            if eff_post_install_secs > 0:
                print(f"[detonate] post_install_idle ({eff_post_install_secs}s) ...", flush=True)
                pi_cmd     = ["sleep", str(eff_post_install_secs)]
                pi_t0      = time.time()
                pi_raw     = exec_in_sandbox(sandbox_info["container_name"], pi_cmd)
                pi_t1      = time.time()
                pi_entries = _read_phase_entries(capture_log, pi_t0, pi_t1, fi_logs_dir)
                post_install_record = _make_phase_record(
                    "post_install_idle", pi_cmd, pi_raw,
                    pi_t0, pi_t1, capture_log, pi_entries,
                )
                all_network_entries.extend(pi_entries)

            # ── 8. [import] ───────────────────────────────────────────────────
            run_import = not effective_skip_import and not skip_import_due_to_fail
            if run_import:
                print("[detonate] import phase ...", flush=True)
                strace_import_log = "/scratch/strace_import.log"
                import_exec_cmd   = (
                    _with_strace(import_cmd, strace_import_log,
                                 syscalls=eff_strace_syscalls,
                                 max_arg_len=eff_max_arg_len)
                    if eff_telemetry else import_cmd
                )
                import_t0  = time.time()
                import_raw = exec_in_sandbox(sandbox_info["container_name"], import_exec_cmd)
                import_t1  = time.time()

                import_proc_limited = not eff_telemetry
                import_parsed: dict = {}
                if eff_telemetry:
                    raw_trace = read_container_file(
                        sandbox_info["container_name"], strace_import_log
                    )
                    if raw_trace:
                        import_parsed = _telemetry.parse_strace_log(
                            raw_trace, sensitive_only=eff_sensitive_only
                        )
                    else:
                        import_proc_limited = True
                import_process_activity = _telemetry.summarise_telemetry(
                    import_parsed, telemetry_limited_process=import_proc_limited
                )

                import_entries = _read_phase_entries(capture_log, import_t0, import_t1, fi_logs_dir)
                import_record  = _make_phase_record(
                    "import", import_cmd, import_raw,
                    import_t0, import_t1, capture_log, import_entries,
                    process_activity=import_process_activity,
                )
                (run_dir / "import.json").write_text(json.dumps(import_record, indent=2))
                _append_telemetry_jsonl(run_dir / "telemetry.jsonl", import_parsed, "import")
                all_network_entries.extend(import_entries)
                print(f"[detonate] import status={import_record['status']}", flush=True)

                # ── 9. [post_import_idle] ─────────────────────────────────────
                if eff_post_import_secs > 0:
                    print(f"[detonate] post_import_idle ({eff_post_import_secs}s) ...", flush=True)
                    pm_cmd     = ["sleep", str(eff_post_import_secs)]
                    pm_t0      = time.time()
                    pm_raw     = exec_in_sandbox(sandbox_info["container_name"], pm_cmd)
                    pm_t1      = time.time()
                    pm_entries = _read_phase_entries(capture_log, pm_t0, pm_t1, fi_logs_dir)
                    post_import_record = _make_phase_record(
                        "post_import_idle", pm_cmd, pm_raw,
                        pm_t0, pm_t1, capture_log, pm_entries,
                    )
                    all_network_entries.extend(pm_entries)
            else:
                reason = skip_import_reason or "skip_import"
                print(f"[detonate] import phase skipped ({reason})", flush=True)

    finally:
        # ── 10. [shutdown] — stop tcpdump and remove container ────────────────
        if tcpdump_proc is not None:
            _stop_tcpdump(tcpdump_proc)
            print("[detonate] tcpdump stopped", flush=True)

        if sandbox_info is not None:
            shutdown_t0 = time.time()
            stop_sandbox_container(
                sandbox_info["container_name"],
                sandbox_info.get("_resolv_conf_path"),
            )
            shutdown_t1      = time.time()
            shutdown_entries = _read_phase_entries(
                capture_log, shutdown_t0, shutdown_t1, fi_logs_dir
            )
            shutdown_record  = _make_simple_phase(
                "shutdown", shutdown_t0, shutdown_t1, shutdown_entries, capture_log
            )
            all_network_entries.extend(shutdown_entries)
            print("[detonate] analysis container removed", flush=True)

    # ── 11. Write network.jsonl (all phases, sequential so no overlaps) ───────
    network_jsonl = run_dir / "network.jsonl"
    if all_network_entries:
        with open(network_jsonl, "w") as fh:
            for entry in all_network_entries:
                fh.write(json.dumps(entry) + "\n")

    # ── 12. Write run.json ────────────────────────────────────────────────────
    # Phases in execution order; only phases that actually ran appear.
    phases: dict = {}
    if startup_record:
        phases["startup"]           = _phase_summary(startup_record)

    if install_record:
        phases["install"]           = _phase_summary(install_record)
    if post_install_record:
        phases["post_install_idle"] = _phase_summary(post_install_record)

    if effective_skip_import or skip_import_due_to_fail:
        reason = skip_import_reason or "skip_import"
        phases["import"] = {"status": "skipped", "reason": reason}
    else:
        if import_record:
            phases["import"]           = _phase_summary(import_record)
        if post_import_record:
            phases["post_import_idle"] = _phase_summary(post_import_record)

    if shutdown_record:
        phases["shutdown"] = _phase_summary(shutdown_record)

    # network_activity: True/False per phase; None for skipped/startup-failed phases.
    network_activity = {
        phase_name: pdata.get("network_activity") if isinstance(pdata, dict) else None
        for phase_name, pdata in phases.items()
    }

    # Container snapshot metadata (Direction 6) ────────────────────────────────
    sandbox_meta: dict = {
        "container_name": sandbox_info.get("container_name") if sandbox_info else None,
        "container_id":   sandbox_info.get("container_id")   if sandbox_info else None,
        "sandbox_ip":     sandbox_info.get("sandbox_ip")     if sandbox_info else None,
        "image":          sbx_cfg.get("image",   "pkgids-sandbox:latest"),
        "runtime":        sbx_cfg.get("runtime", "runsc"),
        "env_vars":       {},   # no env vars injected by the current rig
        "install_cmd":    install_cmd,
        "import_cmd":     None if effective_skip_import else import_cmd,
        "module_name":    _top_module_name(ecosystem, name),
    }

    telemetry_jsonl_path = run_dir / "telemetry.jsonl"
    summary: dict = {
        "ecosystem":        ecosystem,
        "name":             name,
        "version":          version,
        "run_dir":          str(run_dir),
        "artifact":         str(artifact),
        "sandbox_meta":     sandbox_meta,
        "phases":           phases,
        "network_activity": network_activity,
        "outputs": {
            "install_json":    str(run_dir / "install.json") if install_record else None,
            "import_json":     (
                None if (effective_skip_import or skip_import_due_to_fail or not import_record)
                else str(run_dir / "import.json")
            ),
            "network_jsonl":   str(network_jsonl) if network_jsonl.exists() else None,
            "telemetry_jsonl": str(telemetry_jsonl_path) if telemetry_jsonl_path.exists() else None,
            "capture_pcap":    str(pcap_path) if pcap_path.exists() else None,
        },
    }
    (run_dir / "run.json").write_text(json.dumps(summary, indent=2))
    print(f"[detonate] run.json -> {run_dir / 'run.json'}", flush=True)
    return summary
