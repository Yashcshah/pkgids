"""Detonation orchestrator: fetch → tcpdump → install → import → collect."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import bait as _bait
from . import config as _cfg
from . import telemetry as _telemetry
from .fetch import fetch
from .sandbox import (
    exec_in_sandbox,
    read_container_file,
    start_sandbox_container,
    stop_sandbox_container,
)
from .triggers import TriggerPlan, TriggerResult


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

def _install_command(ecosystem: str, artifact_name: str,
                     with_deps: bool = False) -> list[str]:
    if ecosystem == "pypi":
        # Install to /scratch/site-packages (tmpfs) so the package is visible
        # to the import phase running in the same container.  --target writes
        # directly to that directory without touching the system site-packages.
        cmd = [
            "pip3", "install",
            "--break-system-packages",
            "--no-build-isolation",
            "--target", "/scratch/site-packages",
        ]
        if not with_deps:
            cmd.append("--no-deps")
        cmd.append(f"/work/{artifact_name}")
        return cmd
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


# ── trigger execution matrix ──────────────────────────────────────────────────

# Maps trigger_id → telemetry phase name used in telemetry.jsonl and install/import.json.
# Must not change: report.py and indicators.py filter by these exact phase strings.
# import_submodule shares "import" so telemetry.jsonl schema stays unchanged.
_TRIGGER_TO_TEL_PHASE: dict[str, str] = {
    "install":           "install",
    "install_with_deps": "install",
    "import_root":       "import",
    "import_submodule":  "import",
}

# Maps trigger_id → key written into run.json["phases"].
# Absent entries fall back to trigger_id, giving import_submodule its own phases key.
_TRIGGER_TO_PHASES_KEY: dict[str, str] = {
    "install":           "install",
    "install_with_deps": "install",
    "import_root":       "import",
    # import_submodule absent → falls back to "import_submodule"
}

# Maps trigger_id → output JSON file stem inside run_dir.
# Absent entries fall back to trigger_id, preventing import.json collision.
_TRIGGER_TO_PHASE_FILE: dict[str, str] = {
    "install":           "install",
    "install_with_deps": "install",
    "import_root":       "import",
    # import_submodule absent → falls back to "import_submodule"
}

# Maps trigger_id → idle phase name written to run.json["phases"] for backward compat.
_TRIGGER_TO_IDLE_PHASE: dict[str, str] = {
    "install":           "post_install_idle",
    "install_with_deps": "post_install_idle",
    "import_root":       "post_import_idle",
    # import_submodule absent → no idle phase (post_delay silently skipped)
}


def _import_submodule_command(submod_dotted: str) -> list[str]:
    """Build the sandbox exec command to import one PyPI submodule."""
    return [
        "python3", "-c",
        f"import sys; sys.path.insert(0, '/scratch/site-packages'); import {submod_dotted}",
    ]


def _discover_submodule(artifact: Path, top_module: str, ecosystem: str) -> str | None:
    """Return the dotted name of one public PyPI submodule, or None.

    Reads file names from artifact.parent/metadata.json (written by fetch.py) when
    available; falls back to reading archive members from the tarball directly.

    Handles both standard layout (pkg-1.0/pkg/utils.py) and src-layout
    (pkg-1.0/src/pkg/utils.py) by scanning all path segments: any segment equal to
    top_module followed by a .py file is a candidate.  Private modules (leading ``_``)
    are excluded.  Returns the first match in alphabetical order, or None when the
    package has no public top-level submodules (e.g. single-file packages like six).

    Always returns None for npm — npm has no standardised submodule-import convention.
    Always returns None on any unexpected error (fail-graceful).
    """
    if ecosystem != "pypi":
        return None
    try:
        meta_path = artifact.parent / "metadata.json"
        if meta_path.exists():
            files: list[str] = json.loads(meta_path.read_text(errors="replace")).get("files", [])
        else:
            files = _archive_members(artifact)

        candidates: list[str] = []
        for member in files:
            # Normalise separators and split into path segments.
            parts = member.replace("\\", "/").split("/")
            # Scan every consecutive (segment, next_segment) pair.
            for i in range(len(parts) - 1):
                if parts[i] != top_module:
                    continue
                stem_py = parts[i + 1]
                if not stem_py.endswith(".py"):
                    continue
                stem = stem_py[:-3]
                # Skip private, dunder, and known metadata files.
                if stem.startswith("_"):
                    continue
                candidates.append(f"{top_module}.{stem}")
        candidates.sort()
        return candidates[0] if candidates else None
    except Exception:
        return None


def _build_trigger_plans(
    ecosystem: str,
    artifact_name: str,
    package_name: str,
    *,
    with_deps: bool = False,
    skip_import: bool = False,
    skip_on_fail: bool = False,
    post_install_secs: int = 0,
    post_import_secs: int = 0,
) -> list[TriggerPlan]:
    """Build the default install + import_root trigger plan list.

    This is the v1.5 default; callers may pass a custom list to run() instead.
    """
    install_tid   = "install_with_deps" if with_deps else "install"
    install_label = "Install (with deps)" if with_deps else "Install"

    plans: list[TriggerPlan] = [
        TriggerPlan(
            trigger_id=install_tid,
            phase_label=install_label,
            command=tuple(_install_command(ecosystem, artifact_name, with_deps=with_deps)),
            timeout=120,
            post_delay=post_install_secs,
        ),
    ]

    if not skip_import:
        requires   = (install_tid,) if skip_on_fail else ()
        dep_reason = "install_failed" if skip_on_fail else None
        plans.append(TriggerPlan(
            trigger_id="import_root",
            phase_label="Import (root)",
            command=tuple(_import_command(ecosystem, package_name)),
            timeout=30,
            post_delay=post_import_secs,
            requires=requires,
            dependency_skip_reason=dep_reason,
        ))

    return plans


def _run_trigger(
    plan: TriggerPlan,
    container_name: str,
    capture_log: str | None,
    fi_logs_dir: Path,
    run_dir: Path,
    eff_telemetry: bool,
    eff_strace_syscalls: str,
    eff_max_arg_len: int,
    eff_sensitive_only: bool,
) -> tuple[TriggerResult, dict | None, list[dict]]:
    """Execute one trigger in the running sandbox container.

    Returns
    -------
    (TriggerResult, post_delay_record | None, all_entries)
        post_delay_record is a _make_phase_record dict for the post_delay sleep
        (written to run.json phases as post_install_idle / post_import_idle).
        all_entries is the union of network entries from the main command + post_delay.
    """
    tel_phase      = _TRIGGER_TO_TEL_PHASE.get(plan.trigger_id, plan.trigger_id)
    strace_log_path = f"/scratch/strace_{plan.trigger_id}.log"

    cmd      = list(plan.command)
    exec_cmd = (
        _with_strace(cmd, strace_log_path,
                     syscalls=eff_strace_syscalls, max_arg_len=eff_max_arg_len)
        if eff_telemetry else cmd
    )

    t0  = time.time()
    raw = exec_in_sandbox(container_name, exec_cmd)
    t1  = time.time()

    # Read strace log for process telemetry
    proc_limited = not eff_telemetry
    parsed: dict = {}
    if eff_telemetry:
        raw_trace = read_container_file(container_name, strace_log_path)
        if raw_trace:
            parsed = _telemetry.parse_strace_log(raw_trace, sensitive_only=eff_sensitive_only)
        else:
            proc_limited = True
    process_activity = _telemetry.summarise_telemetry(parsed, telemetry_limited_process=proc_limited)

    _append_telemetry_jsonl(run_dir / "telemetry.jsonl", parsed, tel_phase)

    entries = _read_phase_entries(capture_log, t0, t1, fi_logs_dir)

    phase_record = _make_phase_record(
        tel_phase, cmd, raw, t0, t1, capture_log, entries,
        process_activity=process_activity,
    )
    file_stem = _TRIGGER_TO_PHASE_FILE.get(plan.trigger_id, plan.trigger_id)
    (run_dir / f"{file_stem}.json").write_text(json.dumps(phase_record, indent=2))

    status = _phase_status(raw, tel_phase)
    result = TriggerResult(
        trigger_id=plan.trigger_id,
        phase_label=plan.phase_label,
        status=status,
        t_start=t0,
        t_end=t1,
        stdout=raw.get("stdout", ""),
        stderr=raw.get("stderr", ""),
        exit_code=raw.get("exit_code"),
        timed_out=bool(raw.get("timed_out", False)),
        network_activity=_has_network(entries),
        process_activity=process_activity,
    )

    all_entries = list(entries)

    # Execute post_delay sleep (replaces separate idle pseudo-phase)
    post_record: dict | None = None
    if plan.post_delay > 0:
        idle_phase_name = _TRIGGER_TO_IDLE_PHASE.get(plan.trigger_id)
        if idle_phase_name:
            idle_cmd     = ["sleep", str(plan.post_delay)]
            idle_t0      = time.time()
            idle_raw     = exec_in_sandbox(container_name, idle_cmd)
            idle_t1      = time.time()
            idle_entries = _read_phase_entries(capture_log, idle_t0, idle_t1, fi_logs_dir)
            post_record  = _make_phase_record(
                idle_phase_name, idle_cmd, idle_raw,
                idle_t0, idle_t1, capture_log, idle_entries,
            )
            all_entries.extend(idle_entries)

    return result, post_record, all_entries


def _trigger_to_phase_entry(
    result: TriggerResult,
    *,
    telemetry_limited: bool,
) -> dict:
    """Build a phases-shim entry from a completed (non-skipped) TriggerResult."""
    phases_key = _TRIGGER_TO_PHASES_KEY.get(result.trigger_id, result.trigger_id)
    return {
        "phase":             phases_key,
        "status":            result.status,
        "t_start":           result.t_start,
        "t_end":             result.t_end,
        "exit_code":         result.exit_code,
        "duration_secs":     round(result.t_end - result.t_start, 3),
        "timed_out":         result.timed_out,
        "network_activity":  result.network_activity,
        "telemetry_limited": telemetry_limited,
        "process_activity":  result.process_activity,
    }


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
    with_deps: bool = False,
    trigger_plans: list[TriggerPlan] | None = None,
    include_submodule: bool = False,
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

    # Build trigger plans now (needs artifact.name) so sandbox_meta can reference them.
    if trigger_plans is None:
        trigger_plans = _build_trigger_plans(
            ecosystem, artifact.name, name,
            with_deps=with_deps,
            skip_import=effective_skip_import,
            skip_on_fail=eff_skip_on_fail,
            post_install_secs=eff_post_install_secs,
            post_import_secs=eff_post_import_secs,
        )

    # Optionally discover and append an import_submodule trigger (PyPI only).
    if include_submodule:
        trigger_plans = list(trigger_plans)
        top_mod = _top_module_name(ecosystem, name)
        submod = _discover_submodule(artifact, top_mod, ecosystem)
        if submod:
            print(f"[detonate] import_submodule discovered: {submod}", flush=True)
            trigger_plans.append(TriggerPlan(
                trigger_id="import_submodule",
                phase_label="Import (submodule)",
                command=tuple(_import_submodule_command(submod)),
                timeout=30,
                post_delay=0,
                requires=("import_root",),
                dependency_skip_reason="import_root_failed",
            ))
        else:
            print(
                f"[detonate] import_submodule: no public submodule found for {top_mod!r}; skipping",
                flush=True,
            )

    _install_plan = next((p for p in trigger_plans if "install" in p.trigger_id), None)
    _import_plan  = next((p for p in trigger_plans if p.trigger_id == "import_root"), None)

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

    # Accumulators — populated during the try block and in the shutdown finally.
    startup_record:     dict       = {}
    shutdown_record:    dict       = {}
    all_network_entries: list[dict] = []
    capture_log:        str | None = None
    sandbox_info:       dict | None = None
    trigger_results:    list[TriggerResult] = []
    post_delay_records: list[dict | None]   = []
    completed_statuses: dict[str, str]      = {}
    _bait_manifest:     _bait.BaitManifest | None = None

    try:
        # ── 5. [startup] — start the analysis container ───────────────────────
        print("[detonate] starting analysis container ...", flush=True)
        startup_t0 = time.time()
        try:
            sandbox_info = start_sandbox_container(workdir_host=artifact_dir, network="fake")
        except RuntimeError as exc:
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

            # ── Phase 4: plant synthetic credential bait ──────────────────────
            _bait_manifest = _bait.plant_bait(
                sandbox_info["container_name"], run_dir.name
            )
            print(
                f"[detonate] bait planted ({len(_bait_manifest.files)} file(s))",
                flush=True,
            )

            # ── 6–9. Execute each trigger in plan order ───────────────────────
            for plan in trigger_plans:
                # Dependency check: skip if any required trigger did not complete ok.
                failed_dep: str | None = None
                for dep in plan.requires:
                    if completed_statuses.get(dep) != "ok":
                        failed_dep = dep
                        break

                if failed_dep is not None:
                    reason = (
                        plan.dependency_skip_reason
                        or f"dependency '{failed_dep}' not ok "
                           f"(status: {completed_statuses.get(failed_dep, 'not_run')})"
                    )
                    print(f"[detonate] {plan.trigger_id} skipped ({reason})", flush=True)
                    empty_pa = _telemetry.summarise_telemetry(
                        {}, telemetry_limited_process=True
                    )
                    skipped = TriggerResult(
                        trigger_id=plan.trigger_id,
                        phase_label=plan.phase_label,
                        status="skipped",
                        t_start=time.time(),
                        t_end=time.time(),
                        stdout="",
                        stderr="",
                        exit_code=None,
                        timed_out=False,
                        network_activity=False,
                        process_activity=empty_pa,
                        skip_reason=reason,
                    )
                    trigger_results.append(skipped)
                    post_delay_records.append(None)
                    completed_statuses[plan.trigger_id] = "skipped"
                    continue

                print(f"[detonate] {plan.phase_label} ({plan.trigger_id}) ...", flush=True)
                result, post_record, entries = _run_trigger(
                    plan,
                    sandbox_info["container_name"],
                    capture_log,
                    fi_logs_dir,
                    run_dir,
                    eff_telemetry,
                    eff_strace_syscalls,
                    eff_max_arg_len,
                    eff_sensitive_only,
                )
                trigger_results.append(result)
                post_delay_records.append(post_record)
                all_network_entries.extend(entries)
                completed_statuses[plan.trigger_id] = result.status
                print(f"[detonate] {plan.trigger_id} status={result.status}", flush=True)

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

    # ── 12. Build phases dict (backward-compat shim) and triggers list ────────
    tel_limited = capture_log is None
    phases: dict = {}
    if startup_record:
        phases["startup"] = _phase_summary(startup_record)

    for t_result, post_record in zip(trigger_results, post_delay_records):
        phases_key = _TRIGGER_TO_PHASES_KEY.get(t_result.trigger_id, t_result.trigger_id)
        if t_result.status == "skipped":
            phases[phases_key] = {
                "status": "skipped",
                "reason": t_result.skip_reason or t_result.trigger_id,
            }
        else:
            phases[phases_key] = _trigger_to_phase_entry(t_result, telemetry_limited=tel_limited)

        if post_record:
            idle_phase = _TRIGGER_TO_IDLE_PHASE.get(t_result.trigger_id)
            if idle_phase:
                phases[idle_phase] = _phase_summary(post_record)

    # Always ensure "import" key exists for backward compat (skipped when not planned).
    if "import" not in phases:
        phases["import"] = {"status": "skipped", "reason": "skip_import"}

    if shutdown_record:
        phases["shutdown"] = _phase_summary(shutdown_record)

    triggers_list = [
        {
            "trigger_id":       r.trigger_id,
            "phase_label":      r.phase_label,
            "status":           r.status,
            "t_start":          r.t_start,
            "t_end":            r.t_end,
            "exit_code":        r.exit_code,
            "timed_out":        r.timed_out,
            "network_activity": r.network_activity,
            "process_activity": r.process_activity,
            "skip_reason":      r.skip_reason,
        }
        for r in trigger_results
    ]

    # ── 13. Write run.json ────────────────────────────────────────────────────
    # network_activity: True/False per phase; None for skipped/startup-failed phases.
    network_activity = {
        phase_name: pdata.get("network_activity") if isinstance(pdata, dict) else None
        for phase_name, pdata in phases.items()
    }

    sandbox_meta: dict = {
        "container_name":      sandbox_info.get("container_name") if sandbox_info else None,
        "container_id":        sandbox_info.get("container_id")   if sandbox_info else None,
        "sandbox_ip":          sandbox_info.get("sandbox_ip")     if sandbox_info else None,
        "image":               sbx_cfg.get("image",   "pkgids-sandbox:latest"),
        "runtime":             sbx_cfg.get("runtime", "runsc"),
        "env_vars":            {},
        "install_cmd":         list(_install_plan.command) if _install_plan else None,
        "import_cmd":          list(_import_plan.command)  if _import_plan  else None,
        "module_name":         _top_module_name(ecosystem, name),
        "install_deps_enabled": (
            _install_plan is not None
            and _install_plan.trigger_id == "install_with_deps"
        ),
        "bait_planted": _bait_manifest.to_dict() if _bait_manifest else {},
    }

    install_json_path         = run_dir / "install.json"
    import_json_path          = run_dir / "import.json"
    import_submodule_json_path = run_dir / "import_submodule.json"
    telemetry_jsonl_path      = run_dir / "telemetry.jsonl"
    summary: dict = {
        "ecosystem":        ecosystem,
        "name":             name,
        "version":          version,
        "run_dir":          str(run_dir),
        "artifact":         str(artifact),
        "sandbox_meta":     sandbox_meta,
        "phases":           phases,
        "triggers":         triggers_list,
        "network_activity": network_activity,
        "outputs": {
            "install_json":          str(install_json_path)          if install_json_path.exists()          else None,
            "import_json":           str(import_json_path)           if import_json_path.exists()           else None,
            "import_submodule_json": str(import_submodule_json_path) if import_submodule_json_path.exists() else None,
            "network_jsonl":         str(network_jsonl)               if network_jsonl.exists()              else None,
            "telemetry_jsonl":       str(telemetry_jsonl_path)       if telemetry_jsonl_path.exists()       else None,
            "capture_pcap":          str(pcap_path)                  if pcap_path.exists()                  else None,
        },
    }
    (run_dir / "run.json").write_text(json.dumps(summary, indent=2))
    print(f"[detonate] run.json -> {run_dir / 'run.json'}", flush=True)
    return summary
