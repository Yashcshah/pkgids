"""Shared pytest fixtures and skip guards."""

import subprocess
import pytest


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        )
        return r.returncode == 0
    except Exception:
        return False


def _image_exists(image: str) -> bool:
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# Evaluated once at collection time; tests are skipped if the environment
# doesn't have Docker running or the sandbox image built.
_SANDBOX_READY = _docker_available() and _image_exists("pkgids-sandbox:latest")

requires_sandbox = pytest.mark.skipif(
    not _SANDBOX_READY,
    reason=(
        "Docker not running or pkgids-sandbox:latest not found — "
        "run 'make sandbox-image' first"
    ),
)
