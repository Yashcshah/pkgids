"""Fetch a package artifact from its registry."""

from pathlib import Path


def fetch(ecosystem: str, name: str, version: str) -> Path:
    """Download *name*==*version* from *ecosystem* and return the local path.

    Stub — real download logic not yet implemented.
    """
    raise NotImplementedError("fetch() is not yet implemented")
