"""Detonation orchestrator: fetch → tcpdump → install → import → collect."""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config as _cfg
from .fetch import fetch
from .sandbox import run_in_sandbox


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
        return [
            "pip3", "install",
            "--break-system-packages",
            "--no-build-isolation",
            "--no-deps",
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
        return ["python3", "-c", f"import {mod}"]
    if ecosystem == "npm":
        return ["node", "-e", f"require('{package_name}')"]
    raise ValueError(f"Unsupported ecosystem: {ecosystem!r}")


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

def _has_network(entries: list[dict]) -> bool:
    """Return True if the timestamp-filtered entry list is non-empty."""
    return len(entries) > 0


def _phase_summary(result: dict, entries: list[dict]) -> dict:
    return {
        "exit_code":        result.get("exit_code"),
        "duration_seconds": result.get("duration_seconds"),
        "timed_out":        result.get("timed_out"),
        "network_activity": _has_network(entries),
    }


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
) -> dict:
    """Full detonation pipeline for one package.

    Steps
    -----
    1. (opt) clear fakeinternet logs
    2. fetch()          – download artifact + write metadata.json
    3. mkdir runs/<id>  – create isolated run directory
    4. tcpdump          – capture detonet traffic on the host bridge (best-effort)
    5. install phase    – pip/npm install inside sandbox, network="fake"
    6. import phase     – python3/node import inside sandbox (best-effort)
    7. stop tcpdump     – flush capture.pcap
    8. network.jsonl    – merge timestamp-filtered entries from both phases
    9. run.json         – write summary; network_activity derived from filtered entries

    The timestamp window [t_start, t_end] recorded around each sandbox call is
    the source of truth for network_activity.  IP recycling in detonet can never
    cause a false positive because stale entries pre-date t_start.
    """
    cfg     = _cfg.get()
    det_cfg = cfg.get("detonation", {})
    fi_cfg  = cfg.get("fakeinternet", {})

    effective_skip_import: bool = (
        skip_import if skip_import is not None
        else bool(det_cfg.get("skip_import", False))
    )

    fi_logs_dir = Path(fi_cfg.get("logs_dir", "logs/fakeinternet"))
    if not fi_logs_dir.is_absolute():
        fi_logs_dir = Path(__file__).parent.parent / fi_logs_dir

    # ── 1. Optionally clear stale appliance logs ──────────────────────────────
    if det_cfg.get("clear_logs_each_run", False):
        _clear_fakeinternet_logs(fi_logs_dir)

    # ── 2. Fetch ──────────────────────────────────────────────────────────────
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

    install_result: dict = {}
    import_result:  dict = {}
    install_entries: list[dict] = []
    import_entries:  list[dict] = []

    try:
        # ── 5. Install phase ──────────────────────────────────────────────────
        print("[detonate] install phase ...", flush=True)
        install_cmd = _install_command(ecosystem, artifact.name)
        install_t0 = time.time()
        raw = run_in_sandbox(install_cmd, workdir_host=artifact_dir, network="fake")
        install_t1 = time.time()

        install_entries = _read_phase_entries(
            raw.get("capture_log"), install_t0, install_t1, fi_logs_dir
        )
        install_result = {
            "command":          install_cmd,
            "stdout":           raw["stdout"],
            "stderr":           raw["stderr"],
            "exit_code":        raw["exit_code"],
            "duration_seconds": raw["duration_seconds"],
            "timed_out":        raw["timed_out"],
            "capture_log":      raw.get("capture_log"),
            "window":           [install_t0, install_t1],
        }
        (run_dir / "install.json").write_text(json.dumps(install_result, indent=2))
        print(f"[detonate] install exit_code={install_result['exit_code']}", flush=True)

        # ── 6. Import phase (best-effort) ─────────────────────────────────────
        if not effective_skip_import:
            print("[detonate] import phase ...", flush=True)
            import_cmd = _import_command(ecosystem, name)
            import_t0 = time.time()
            raw = run_in_sandbox(import_cmd, network="fake")
            import_t1 = time.time()

            import_entries = _read_phase_entries(
                raw.get("capture_log"), import_t0, import_t1, fi_logs_dir
            )
            import_result = {
                "command":          import_cmd,
                "stdout":           raw["stdout"],
                "stderr":           raw["stderr"],
                "exit_code":        raw["exit_code"],
                "duration_seconds": raw["duration_seconds"],
                "timed_out":        raw["timed_out"],
                "capture_log":      raw.get("capture_log"),
                "window":           [import_t0, import_t1],
            }
            (run_dir / "import.json").write_text(json.dumps(import_result, indent=2))
            print(f"[detonate] import exit_code={import_result['exit_code']}", flush=True)
        else:
            print("[detonate] import phase skipped (skip_import=true)", flush=True)

    finally:
        # ── 7. Stop tcpdump ───────────────────────────────────────────────────
        if tcpdump_proc is not None:
            _stop_tcpdump(tcpdump_proc)
            print("[detonate] tcpdump stopped", flush=True)

    # ── 8. Write network.jsonl (timestamp-filtered entries only) ──────────────
    # Phases are sequential so their windows never overlap; no deduplication needed.
    all_entries = install_entries + import_entries
    network_jsonl = run_dir / "network.jsonl"
    if all_entries:
        with open(network_jsonl, "w") as fh:
            for entry in all_entries:
                fh.write(json.dumps(entry) + "\n")

    # ── 9. Write run.json ─────────────────────────────────────────────────────
    summary: dict = {
        "ecosystem": ecosystem,
        "name":      name,
        "version":   version,
        "run_dir":   str(run_dir),
        "artifact":  str(artifact),
        "phases": {
            "install": _phase_summary(install_result, install_entries),
            "import": (
                {"skipped": True}
                if effective_skip_import
                else _phase_summary(import_result, import_entries)
            ),
        },
        "network_activity": {
            "install": _has_network(install_entries),
            "import":  (
                None if effective_skip_import
                else _has_network(import_entries)
            ),
        },
        "outputs": {
            "install_json":  str(run_dir / "install.json"),
            "import_json":   (
                None if effective_skip_import
                else str(run_dir / "import.json")
            ),
            "network_jsonl": str(network_jsonl) if network_jsonl.exists() else None,
            "capture_pcap":  str(pcap_path) if pcap_path.exists() else None,
        },
    }
    (run_dir / "run.json").write_text(json.dumps(summary, indent=2))
    print(f"[detonate] run.json -> {run_dir / 'run.json'}", flush=True)
    return summary
