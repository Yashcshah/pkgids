"""Fetch a package artifact from its registry."""

from __future__ import annotations

import base64
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

import requests

from . import config as _cfg
from .advisory import query_osv as _query_osv


# ── internal helpers ─────────────────────────────────────────────────────────

def _artifacts_root(dest: Path | None) -> Path:
    if dest is not None:
        return dest
    configured = _cfg.get()["paths"]["artifacts_dir"]
    p = Path(configured)
    if not p.is_absolute():
        p = Path(__file__).parent.parent / p
    return p


def _stream_download(url: str, dest: Path, timeout: int = 60) -> dict[str, bytes]:
    """Stream *url* to *dest*; return raw digest bytes keyed by algorithm name."""
    hashers = {
        "sha1":   hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    with requests.get(url, stream=True, timeout=timeout) as resp:
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)
                for h in hashers.values():
                    h.update(chunk)
    return {k: v.digest() for k, v in hashers.items()}


def _tar_members(path: Path) -> list[str]:
    with tarfile.open(path, "r:gz") as tf:
        return tf.getnames()


def _zip_members(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as zf:
        return zf.namelist()


def _archive_members(path: Path) -> list[str]:
    n = path.name.lower()
    if n.endswith(".tar.gz") or n.endswith(".tgz"):
        return _tar_members(path)
    if n.endswith((".whl", ".zip")):
        return _zip_members(path)
    return []


# ── PyPI ─────────────────────────────────────────────────────────────────────

def _fetch_pypi(name: str, version: str, root: Path) -> Path:
    resp = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30)
    resp.raise_for_status()
    data = resp.json()

    urls = data["urls"]
    sdists = [u for u in urls if u["packagetype"] == "sdist"]
    wheels = [u for u in urls if u["packagetype"] == "bdist_wheel"]
    candidates = sdists or wheels
    if not candidates:
        raise ValueError(f"No downloadable artifact for pypi:{name}=={version}")
    entry = candidates[0]

    dest_dir = root / "pypi" / f"{name}-{version}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    artifact = dest_dir / entry["filename"]

    digests = _stream_download(entry["url"], artifact)
    expected = entry["digests"]["sha256"]
    if digests["sha256"].hex() != expected:
        artifact.unlink(missing_ok=True)
        raise ValueError(
            f"SHA256 mismatch for {entry['filename']}: "
            f"expected {expected}, got {digests['sha256'].hex()}"
        )

    members = _archive_members(artifact)
    has_setup_py = any(m == "setup.py" or m.endswith("/setup.py") for m in members)

    info = data["info"]
    metadata = {
        "ecosystem": "pypi",
        "name": name,
        "version": version,
        "filename": entry["filename"],
        "upload_time": entry.get("upload_time"),
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "maintainer": info.get("maintainer"),
        "maintainer_email": info.get("maintainer_email"),
        "files": members,
        "file_count": len(members),
        "install_hooks": {"has_setup_py": has_setup_py},
        "sha256": expected,
        "advisory": _query_osv("pypi", name, version),
    }
    (dest_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return artifact


# ── npm ──────────────────────────────────────────────────────────────────────

def _verify_sri(artifact: Path, integrity: str | None, shasum: str | None,
                digests: dict[str, bytes]) -> None:
    """Verify against dist.integrity (SRI) or dist.shasum (SHA-1 hex)."""
    if integrity:
        algo, b64 = integrity.split("-", 1)
        if algo in digests:
            actual = base64.b64encode(digests[algo]).decode()
            if actual != b64:
                artifact.unlink(missing_ok=True)
                raise ValueError(f"Integrity mismatch: expected {integrity}")
    elif shasum:
        actual = digests["sha1"].hex()
        if actual != shasum:
            artifact.unlink(missing_ok=True)
            raise ValueError(f"SHA1 mismatch: expected {shasum}, got {actual}")


def _npm_install_hooks(artifact: Path) -> tuple[str | None, str | None]:
    """Read package.json inside the tarball; return (preinstall, postinstall)."""
    with tarfile.open(artifact, "r:gz") as tf:
        for member in tf.getmembers():
            name = member.name
            if name == "package/package.json" or (
                name.endswith("/package.json") and name.count("/") <= 2
            ):
                f = tf.extractfile(member)
                if f:
                    pkg = json.loads(f.read())
                    scripts = pkg.get("scripts", {})
                    return scripts.get("preinstall"), scripts.get("postinstall")
    return None, None


def _fetch_npm(name: str, version: str, root: Path) -> Path:
    encoded = name.replace("/", "%2F")
    resp = requests.get(f"https://registry.npmjs.org/{encoded}", timeout=30)
    resp.raise_for_status()
    data = resp.json()

    versions = data.get("versions", {})
    if version not in versions:
        raise ValueError(f"Version {version!r} not found for npm:{name}")
    vdata = versions[version]
    dist = vdata["dist"]

    tarball_url = dist["tarball"]
    integrity = dist.get("integrity")
    shasum = dist.get("shasum")

    # Scoped packages (@scope/name) → safe dir name
    safe_name = name.lstrip("@").replace("/", "__")
    dest_dir = root / "npm" / f"{safe_name}-{version}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = tarball_url.rsplit("/", 1)[-1]
    artifact = dest_dir / filename

    digests = _stream_download(tarball_url, artifact)
    _verify_sri(artifact, integrity, shasum, digests)

    members = _tar_members(artifact)
    preinstall, postinstall = _npm_install_hooks(artifact)

    metadata = {
        "ecosystem": "npm",
        "name": name,
        "version": version,
        "filename": filename,
        "upload_time": data.get("time", {}).get(version),
        "maintainers": vdata.get("maintainers", data.get("maintainers", [])),
        "author": vdata.get("author"),
        "files": members,
        "file_count": len(members),
        "install_hooks": {"preinstall": preinstall, "postinstall": postinstall},
        "integrity": integrity,
        "shasum": shasum,
    }
    (dest_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return artifact


# ── public API ───────────────────────────────────────────────────────────────

def fetch(ecosystem: str, name: str, version: str,
          dest: Path | None = None) -> Path:
    """Download *name*==*version* from *ecosystem*; return the local artifact path.

    Writes metadata.json next to the artifact. Never installs or executes anything.
    Raises ValueError on hash mismatch or unknown ecosystem.
    """
    root = _artifacts_root(dest)
    if ecosystem == "pypi":
        return _fetch_pypi(name, version, root)
    if ecosystem == "npm":
        return _fetch_npm(name, version, root)
    raise ValueError(f"Unsupported ecosystem: {ecosystem!r}")
