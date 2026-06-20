"""Execute commands inside the pkgids isolation sandbox."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

from . import config as _cfg

_SUPPORTED_NETWORKS = {"none", "default", "fake"}


# ── host-side helpers ─────────────────────────────────────────────────────────

def _make_world_readable(path: Path) -> None:
    """Ensure *path* and its subtree are traversable and readable by any UID.

    Directories get at least r-x for group + other; files get at least r.
    Called automatically on workdir_host before every bind-mount so that the
    unprivileged 'deton' user inside the container can reach the files.
    """
    path.chmod(path.stat().st_mode | 0o555)
    for root, dirs, files in os.walk(path):
        for name in dirs:
            p = Path(root) / name
            p.chmod(p.stat().st_mode | 0o555)
        for name in files:
            p = Path(root) / name
            p.chmod(p.stat().st_mode | 0o444)


def _force_remove(name: str) -> None:
    """Kill and remove a container by name, ignoring errors."""
    subprocess.run(
        ["docker", "rm", "-f", name],
        capture_output=True,
        timeout=15,
    )


def _container_exists(name: str) -> bool:
    """Return True if a container with *name* appears in docker ps -a."""
    r = subprocess.run(
        ["docker", "ps", "-a",
         "--filter", f"name=^/{name}$",
         "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return name in r.stdout.splitlines()


def _container_running(name: str) -> bool:
    """Return True if *name* is currently in the 'running' state."""
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return r.stdout.strip() == "true"


def _container_ip_on_network(container: str, network: str) -> str | None:
    """Return the container's IP address on *network*, or None."""
    # The Go template uses the network name as a map key.
    fmt = "{{{{.NetworkSettings.Networks.{}.IPAddress}}}}".format(network)
    r = subprocess.run(
        ["docker", "inspect", "--format", fmt, container],
        capture_output=True,
        text=True,
        timeout=10,
    )
    ip = r.stdout.strip()
    return ip if ip else None


# ── public API ────────────────────────────────────────────────────────────────

def run_in_sandbox(
    command: list[str] | str,
    workdir_host: Path | None = None,
    network: str = "none",
    timeout: float | None = None,
) -> dict:
    """Run *command* inside the pkgids-sandbox container.

    The container is always removed afterward — on success, timeout, or exception.
    Nothing is installed or persisted on the host.

    Parameters
    ----------
    command:
        Command for the container.  A ``str`` is wrapped as ``["sh", "-c", ...]``;
        a list is passed directly.
    workdir_host:
        Optional host path bind-mounted read-only at ``/work`` inside the
        container.  Permissions are widened to world-readable before mounting.
    network:
        ``"none"``    — air-gap (no networking at all).
        ``"default"`` — Docker bridge (outbound internet).
        ``"fake"``    — isolated detonet; all traffic captured by the
                        fake-internet appliance.  ``pkgids-fakeinternet``
                        must be running before calling with this mode.
    timeout:
        Wall-clock seconds.  Overrides ``sandbox.timeout_secs`` in config.

    Returns
    -------
    dict:
        stdout, stderr, exit_code, timed_out (bool), duration_seconds,
        container_name, capture_log (path to JSONL log, fake mode only).
    """
    if network not in _SUPPORTED_NETWORKS:
        raise ValueError(
            f"Unsupported network {network!r}. "
            f"Supported: {sorted(_SUPPORTED_NETWORKS)}"
        )

    cfg      = _cfg.get()["sandbox"]
    fi_cfg   = _cfg.get().get("fakeinternet", {})

    image             = cfg.get("image",        "pkgids-sandbox:latest")
    runtime           = cfg.get("runtime",      "runsc")
    memory            = cfg.get("memory",       "1g")
    cpus              = str(cfg.get("cpus",      1.0))
    pids_limit        = str(int(cfg.get("pids_limit", 256)))
    effective_timeout = float(
        timeout if timeout is not None else cfg.get("timeout_secs", 120)
    )

    fi_network        = fi_cfg.get("network",        "detonet")
    fi_container      = fi_cfg.get("container_name", "pkgids-fakeinternet")
    fi_ip             = fi_cfg.get("ip",             "10.200.200.2")
    fi_logs_dir       = Path(fi_cfg.get("logs_dir",  "logs/fakeinternet"))
    if not fi_logs_dir.is_absolute():
        fi_logs_dir = Path(__file__).parent.parent / fi_logs_dir

    # ── resolve docker network ────────────────────────────────────────────────
    if network == "none":
        docker_network = "none"
    elif network == "default":
        docker_network = "bridge"
    else:  # "fake"
        if not _container_running(fi_container):
            raise RuntimeError(
                f"fake network requested but '{fi_container}' is not running. "
                f"Run 'make fakeinternet-start' first."
            )
        docker_network = fi_network

    container_name = f"pkgids-{uuid.uuid4().hex[:12]}"
    inner: list[str] = (
        ["sh", "-c", command] if isinstance(command, str) else list(command)
    )

    # --rm is omitted for "fake" mode so we can inspect the container's IP
    # in the finally block (before _force_remove wipes it).
    use_auto_remove = (network != "fake")

    docker_cmd: list[str] = ["docker", "run"]
    if use_auto_remove:
        docker_cmd.append("--rm")
    docker_cmd += [
        "--name",       container_name,
        "--runtime",    runtime,
        "--network",    docker_network,
        "--memory",     memory,
        "--cpus",       cpus,
        "--pids-limit", pids_limit,
        "--user",       "deton",
        "--mount",      "type=tmpfs,target=/scratch,tmpfs-size=256m",
    ]

    if network == "fake":
        docker_cmd += ["--dns", fi_ip]

    if workdir_host is not None:
        wh = Path(workdir_host).resolve()
        _make_world_readable(wh)
        docker_cmd += [
            "--mount",
            f"type=bind,source={wh},target=/work,readonly",
        ]

    docker_cmd += [image] + inner

    timed_out     = False
    capture_log: str | None = None
    t_start       = time.monotonic()

    proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # For fake mode: poll for the container's detonet IP immediately after
    # startup, BEFORE proc.communicate() blocks.  Docker clears NetworkSettings
    # the moment a container exits, so we must read it while it is still running.
    # 30 × 0.1 s = up to 3 s for the container to appear in the network table.
    if network == "fake":
        detonet_ip: str | None = None
        for _ in range(30):
            detonet_ip = _container_ip_on_network(container_name, fi_network)
            if detonet_ip:
                break
            time.sleep(0.1)
        if detonet_ip:
            capture_log = str(fi_logs_dir / f"{detonet_ip}.jsonl")
        else:
            print(
                f"[sandbox] WARNING: could not determine detonet IP for "
                f"{container_name!r} — capture_log will be None",
                flush=True,
            )

    try:
        stdout_b, stderr_b = proc.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_b, stderr_b = proc.communicate()
        timed_out = True
    finally:
        _force_remove(container_name)

    return {
        "stdout":           stdout_b.decode(errors="replace"),
        "stderr":           stderr_b.decode(errors="replace"),
        "exit_code":        proc.returncode,
        "timed_out":        timed_out,
        "duration_seconds": round(time.monotonic() - t_start, 3),
        "container_name":   container_name,
        "capture_log":      capture_log,
    }
