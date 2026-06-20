"""Detonation orchestrator: fetch → tcpdump → install → import → collect."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config as _cfg
from .fetch import fetch
from .sandbox import run_in_sandbox


# ── bridge / tcpdump helpers ─────────────────────────────────────────────────

def _detonet_bridge_iface() -> str:
    """Return the host Linux bridge interface name for the detonet network.

    Docker names the bridge  br-<first-12-chars-of-network-id>.
    """
    fi_cfg = _cfg.get().get("fakeinternet", {})
    network_name = fi_cfg.get("network", "detonet")
    r = subprocess.run(
        ["docker", "network", "inspect", network_name, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"Cannot inspect docker network {network_name!r}: {r.stderr.strip()}"
        )
    return f"br-{r.stdout.strip()[:12]}"


def _start_tcpdump(iface: str, pcap_path: Path) -> subprocess.Popen:
    """Start tcpdump on *iface* writing to *pcap_path*; return the process."""
    return subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", str(pcap_path), "-q", "-U"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop_tcpdump(proc: subprocess.Popen) -> None:
    """Gracefully stop tcpdump and wait for it to flush the file."""
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
    """Return the in-container install command for *ecosystem*."""
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
    """Best-guess importable name for a package.

    PyPI: ``my-package.ext`` → ``my_package_ext``
    npm:  ``@scope/pkg``     → ``pkg``
    """
    if ecosystem == "npm":
        return package_name.lstrip("@").split("/")[-1]
    return package_name.replace("-", "_").replace(".", "_")


def _import_command(ecosystem: str, package_name: str) -> list[str]:
    """Return the in-container import command for *ecosystem*.

    Best-effort: the package may not be installed in this fresh container
    (install happened in a separate container).  Failure is tolerated.
    """
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


# ── internal bookkeeping ──────────────────────────────────────────────────────

def _collect_fallback_logs(fi_logs_dir: Path, since: float) -> list[Path]:
    """Return every .jsonl in fi_logs_dir modified at or after *since* (epoch).

    Used when a phase's capture_log is None (IP detection failed) so we never
    silently discard captured traffic — any log written during the run window
    is included in network.jsonl.  A 1-second buffer handles filesystem latency.
    """
    if not fi_logs_dir.exists():
        return []
    return sorted(
        (p for p in fi_logs_dir.glob("*.jsonl")
         if p.stat().st_mtime >= since - 1.0),
        key=lambda p: p.stat().st_mtime,
    )


def _has_network(result: dict) -> bool:
    """Return True if the sandbox result has a non-empty capture log."""
    log = result.get("capture_log")
    if not log:
        return False
    p = Path(log)
    return p.exists() and p.stat().st_size > 0


def _phase_summary(result: dict) -> dict:
    return {
        "exit_code":        result.get("exit_code"),
        "duration_seconds": result.get("duration_seconds"),
        "timed_out":        result.get("timed_out"),
        "network_activity": _has_network(result),
    }


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
    1. fetch()          – download artifact + write metadata.json
    2. mkdir runs/<id>  – create isolated run directory
    3. tcpdump          – capture detonet traffic on the host bridge (best-effort)
    4. install phase    – pip/npm install inside sandbox with network="fake"
    5. import phase     – python3/node import inside sandbox (best-effort)
    6. stop tcpdump     – flush capture.pcap
    7. network.jsonl    – copy fake-internet capture log(s) into run dir
    8. run.json         – write summary

    Parameters
    ----------
    skip_import:
        Override config ``detonation.skip_import``.  ``None`` → use config.

    Returns
    -------
    The run.json summary dict.
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

    # ── 1. Fetch ──────────────────────────────────────────────────────────────
    run_start = time.time()   # epoch — used for fallback log collection
    print(f"[detonate] fetching {ecosystem}:{name}=={version} ...", flush=True)
    artifact = fetch(ecosystem, name, version)
    artifact_dir = artifact.parent

    # ── 2. Run directory ──────────────────────────────────────────────────────
    if run_dir is None:
        run_dir = _make_run_dir(ecosystem, name, version)
    else:
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
    print(f"[detonate] run dir → {run_dir}", flush=True)

    # ── 3. Start tcpdump (host-side, best-effort) ─────────────────────────────
    tcpdump_proc: subprocess.Popen | None = None
    pcap_path = run_dir / "capture.pcap"
    try:
        iface = _detonet_bridge_iface()
        tcpdump_proc = _start_tcpdump(iface, pcap_path)
        time.sleep(0.3)   # let tcpdump initialise before traffic starts
        print(f"[detonate] tcpdump started on {iface}", flush=True)
    except Exception as exc:
        print(f"[detonate] WARNING: tcpdump unavailable ({exc}); continuing without pcap", flush=True)

    install_result: dict = {}
    import_result:  dict = {}

    try:
        # ── 4. Install phase ──────────────────────────────────────────────────
        print("[detonate] install phase ...", flush=True)
        install_cmd = _install_command(ecosystem, artifact.name)
        raw = run_in_sandbox(install_cmd, workdir_host=artifact_dir, network="fake")
        install_result = {
            "command":          install_cmd,
            "stdout":           raw["stdout"],
            "stderr":           raw["stderr"],
            "exit_code":        raw["exit_code"],
            "duration_seconds": raw["duration_seconds"],
            "timed_out":        raw["timed_out"],
            "capture_log":      raw.get("capture_log"),
        }
        (run_dir / "install.json").write_text(json.dumps(install_result, indent=2))
        print(f"[detonate] install exit_code={install_result['exit_code']}", flush=True)

        # ── 5. Import phase (best-effort) ─────────────────────────────────────
        if not effective_skip_import:
            print("[detonate] import phase ...", flush=True)
            import_cmd = _import_command(ecosystem, name)
            raw = run_in_sandbox(import_cmd, network="fake")
            import_result = {
                "command":          import_cmd,
                "stdout":           raw["stdout"],
                "stderr":           raw["stderr"],
                "exit_code":        raw["exit_code"],
                "duration_seconds": raw["duration_seconds"],
                "timed_out":        raw["timed_out"],
                "capture_log":      raw.get("capture_log"),
            }
            (run_dir / "import.json").write_text(json.dumps(import_result, indent=2))
            print(f"[detonate] import exit_code={import_result['exit_code']}", flush=True)
        else:
            print("[detonate] import phase skipped (skip_import=true)", flush=True)

    finally:
        # ── 6. Stop tcpdump ───────────────────────────────────────────────────
        if tcpdump_proc is not None:
            _stop_tcpdump(tcpdump_proc)
            print("[detonate] tcpdump stopped", flush=True)

    # ── 7. Aggregate fake-internet logs into network.jsonl ────────────────────
    network_jsonl = run_dir / "network.jsonl"
    seen_logs: set[str] = set()

    def _append_log(src: Path) -> None:
        key = str(src)
        if key in seen_logs or not src.exists():
            return
        seen_logs.add(key)
        if not network_jsonl.exists():
            shutil.copy2(src, network_jsonl)
        else:
            with open(network_jsonl, "a") as out, open(src) as inp:
                out.write(inp.read())

    # Primary path: use capture_log paths returned by each sandbox phase
    for phase_result in (install_result, import_result):
        log = phase_result.get("capture_log")
        if log:
            _append_log(Path(log))

    # Fallback: if no logs were collected (IP detection failed for all phases),
    # grab every .jsonl in fi_logs_dir written during the run window so traffic
    # is never silently lost.
    if not network_jsonl.exists():
        for p in _collect_fallback_logs(fi_logs_dir, run_start):
            _append_log(p)
        if network_jsonl.exists():
            print(
                "[detonate] WARNING: capture_log IP detection failed; "
                "network.jsonl built from fallback logs",
                flush=True,
            )

    # ── 8. Write run.json ─────────────────────────────────────────────────────
    summary: dict = {
        "ecosystem": ecosystem,
        "name":      name,
        "version":   version,
        "run_dir":   str(run_dir),
        "artifact":  str(artifact),
        "phases": {
            "install": _phase_summary(install_result),
            "import": (
                {"skipped": True}
                if effective_skip_import
                else _phase_summary(import_result)
            ),
        },
        "network_activity": {
            "install": _has_network(install_result),
            "import":  (
                None if effective_skip_import
                else _has_network(import_result)
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
    print(f"[detonate] run.json → {run_dir / 'run.json'}", flush=True)
    return summary
