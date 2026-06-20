"""Execute a package artifact inside an isolated sandbox."""

from pathlib import Path


def run_in_sandbox(
    artifact: Path,
    image: str,
    timeout_secs: int = 120,
    network: str = "none",
) -> dict:
    """Run *artifact* inside a container sandbox and return raw execution data.

    Stub — real sandboxing logic not yet implemented.
    """
    raise NotImplementedError("run_in_sandbox() is not yet implemented")
