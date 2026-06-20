"""Execute commands inside the pkgids isolation sandbox."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path

from . import config as _cfg

_SUPPORTED_NETWORKS = {"none", "default"}


def _make_world_readable(path: Path) -> None:
    """Ensure *path* and every item in its subtree are readable and traversable
    by any UID.

    Directories get at least r-x for group + other (0o055 OR'd in) so that
    unprivileged users — including the container's 'deton' account — can enter
    and list them.  Regular files get at least r for group + other (0o044).
    This is called automatically on workdir_host before every bind-mount.
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
        Optional host path bind-mounted read-only at ``/work`` inside the container.
    network:
        ``"none"`` (default) — air-gap the container.
        ``"default"`` — Docker bridge (outbound internet).
    timeout:
        Wall-clock seconds.  Overrides the ``sandbox.timeout_secs`` config value.

    Returns
    -------
    dict:
        stdout, stderr, exit_code, timed_out (bool), duration_seconds,
        container_name  (useful for cleanup verification).
    """
    if network not in _SUPPORTED_NETWORKS:
        raise ValueError(
            f"Unsupported network {network!r}. "
            f"Supported: {sorted(_SUPPORTED_NETWORKS)}"
        )

    cfg = _cfg.get()["sandbox"]
    image             = cfg.get("image",        "pkgids-sandbox:latest")
    runtime           = cfg.get("runtime",      "runsc")
    memory            = cfg.get("memory",       "1g")
    cpus              = str(cfg.get("cpus",      1.0))
    pids_limit        = str(int(cfg.get("pids_limit", 256)))
    effective_timeout = float(
        timeout if timeout is not None else cfg.get("timeout_secs", 120)
    )

    docker_network = "bridge" if network == "default" else "none"
    container_name = f"pkgids-{uuid.uuid4().hex[:12]}"

    inner: list[str] = (
        ["sh", "-c", command] if isinstance(command, str) else list(command)
    )

    docker_cmd: list[str] = [
        "docker", "run",
        "--rm",
        "--name",       container_name,
        "--runtime",    runtime,
        "--network",    docker_network,
        "--memory",     memory,
        "--cpus",       cpus,
        "--pids-limit", pids_limit,
        "--user",       "deton",
        # writable in-memory scratch — no host path exposed
        "--mount", "type=tmpfs,target=/scratch,tmpfs-size=256m",
    ]

    if workdir_host is not None:
        wh = Path(workdir_host).resolve()
        _make_world_readable(wh)
        docker_cmd += [
            "--mount",
            f"type=bind,source={wh},target=/work,readonly",
        ]

    docker_cmd += [image] + inner

    timed_out = False
    t_start = time.monotonic()

    proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        stdout_b, stderr_b = proc.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_b, stderr_b = proc.communicate()
        timed_out = True
    finally:
        # Belt-and-suspenders: remove even if --rm already cleaned up.
        _force_remove(container_name)

    return {
        "stdout":           stdout_b.decode(errors="replace"),
        "stderr":           stderr_b.decode(errors="replace"),
        "exit_code":        proc.returncode,
        "timed_out":        timed_out,
        "duration_seconds": round(time.monotonic() - t_start, 3),
        "container_name":   container_name,
    }
