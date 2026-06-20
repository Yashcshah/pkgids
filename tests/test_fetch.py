"""Integration tests for fetch.py — requires network access."""

import json
from pathlib import Path

import pytest

from pkgids.fetch import fetch

# ── PyPI ─────────────────────────────────────────────────────────────────────

def test_fetch_pypi_artifact_exists(tmp_path):
    artifact = fetch("pypi", "six", "1.16.0", dest=tmp_path)
    assert artifact.exists()
    assert artifact.stat().st_size > 0


def test_fetch_pypi_metadata_exists(tmp_path):
    artifact = fetch("pypi", "six", "1.16.0", dest=tmp_path)
    meta_path = artifact.parent / "metadata.json"
    assert meta_path.exists()


def test_fetch_pypi_metadata_contents(tmp_path):
    artifact = fetch("pypi", "six", "1.16.0", dest=tmp_path)
    meta = json.loads((artifact.parent / "metadata.json").read_text())

    assert meta["ecosystem"] == "pypi"
    assert meta["name"] == "six"
    assert meta["version"] == "1.16.0"
    assert meta["file_count"] > 0
    assert isinstance(meta["files"], list)
    assert meta["sha256"]  # non-empty hash string
    assert "has_setup_py" in meta["install_hooks"]


def test_fetch_pypi_hash_verified(tmp_path):
    # fetch() raises ValueError on mismatch; if it returns, hash passed
    artifact = fetch("pypi", "six", "1.16.0", dest=tmp_path)
    meta = json.loads((artifact.parent / "metadata.json").read_text())
    assert len(meta["sha256"]) == 64  # SHA-256 hex


def test_fetch_pypi_dest_layout(tmp_path):
    artifact = fetch("pypi", "six", "1.16.0", dest=tmp_path)
    # artifact must live under <dest>/pypi/<name>-<version>/
    assert artifact.parent == tmp_path / "pypi" / "six-1.16.0"


# ── npm ──────────────────────────────────────────────────────────────────────

def test_fetch_npm_artifact_exists(tmp_path):
    artifact = fetch("npm", "left-pad", "1.3.0", dest=tmp_path)
    assert artifact.exists()
    assert artifact.stat().st_size > 0


def test_fetch_npm_metadata_exists(tmp_path):
    artifact = fetch("npm", "left-pad", "1.3.0", dest=tmp_path)
    meta_path = artifact.parent / "metadata.json"
    assert meta_path.exists()


def test_fetch_npm_metadata_contents(tmp_path):
    artifact = fetch("npm", "left-pad", "1.3.0", dest=tmp_path)
    meta = json.loads((artifact.parent / "metadata.json").read_text())

    assert meta["ecosystem"] == "npm"
    assert meta["name"] == "left-pad"
    assert meta["version"] == "1.3.0"
    assert meta["file_count"] > 0
    assert isinstance(meta["files"], list)
    assert "preinstall" in meta["install_hooks"]
    assert "postinstall" in meta["install_hooks"]


def test_fetch_npm_hash_verified(tmp_path):
    # If this returns without raising, the integrity / shasum check passed
    artifact = fetch("npm", "left-pad", "1.3.0", dest=tmp_path)
    meta = json.loads((artifact.parent / "metadata.json").read_text())
    assert meta.get("integrity") or meta.get("shasum")


def test_fetch_npm_dest_layout(tmp_path):
    artifact = fetch("npm", "left-pad", "1.3.0", dest=tmp_path)
    assert artifact.parent == tmp_path / "npm" / "left-pad-1.3.0"


# ── error paths ──────────────────────────────────────────────────────────────

def test_fetch_unknown_ecosystem(tmp_path):
    with pytest.raises(ValueError, match="Unsupported ecosystem"):
        fetch("cargo", "serde", "1.0.0", dest=tmp_path)


def test_fetch_pypi_bad_version(tmp_path):
    with pytest.raises(Exception):
        fetch("pypi", "six", "0.0.0.0.0.nonexistent", dest=tmp_path)


def test_fetch_npm_bad_version(tmp_path):
    with pytest.raises(Exception):
        fetch("npm", "left-pad", "999.999.999", dest=tmp_path)
