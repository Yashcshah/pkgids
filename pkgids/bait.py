"""Phase 4: synthetic credential bait.

Plant harmless marker files in the sandbox before the trigger loop runs.
The telemetry pipeline then detects any accesses through the normal
sensitive-file tracking path — no new trigger ID, no strace changes.

All bait content is marked with the literal strings ``PKGIDSBAIT`` and
``BAIT`` so accidental leakage is immediately recognisable and provably
synthetic.  No real credentials or valid token formats are used.
"""

from __future__ import annotations

import subprocess
from pathlib import PurePosixPath
from typing import NamedTuple

# ── bait file templates ───────────────────────────────────────────────────────
# {tag} is replaced with run_id[:8].upper().  All values are obviously fake:
# PKGIDSBAIT prefix + BAIT keyword, safe to log or commit.

_ENV_TEMPLATE: str = """\
PKGIDSBAIT_{tag}_SECRET=PKGIDSBAIT_FAKE_ENV_CRED_BAIT
PKGIDSBAIT_MARKER=BAIT
DATABASE_URL=pkgidsbait://{tag}:PKGIDSBAIT_FAKE_BAIT_PASSWORD@localhost/baitdb
"""

_AWS_TEMPLATE: str = """\
[default]
aws_access_key_id=PKGIDSBAIT{tag}FAKEKEY
aws_secret_access_key=PKGIDSBAIT{tag}FAKESECRET0000000000000000000000
region=us-east-1-BAIT
"""

_PYPIRC_TEMPLATE: str = """\
[distutils]
index-servers = pypi

[pypi]
username = pkgidsbait-fake
password = PKGIDSBAIT{tag}FAKEPYPITOKEN
"""

_SSH_TEMPLATE: str = """\
-----BEGIN RSA PRIVATE KEY-----
PKGIDSBAIT{tag}THISISASYNTHETICBAITCREDENTIALNOTAREALKEY
PKGIDSBAITFAKEPKGIDSSANDBOXBAITFILESAFETOLOG0000000000
-----END RSA PRIVATE KEY-----
"""

# ── bait file registry ────────────────────────────────────────────────────────
# Extend here to add v2/v3 bait types; all other code adapts automatically.
# Format: container_path → (telemetry_category, template_string)

_BAIT_FILES: dict[str, tuple[str, str]] = {
    "/home/deton/.env":             ("env_file",        _ENV_TEMPLATE),
    "/home/deton/.aws/credentials": ("aws_credentials", _AWS_TEMPLATE),
    "/home/deton/.pypirc":          ("pypi_rc",         _PYPIRC_TEMPLATE),
    "/home/deton/.ssh/id_rsa":      ("ssh_keys",        _SSH_TEMPLATE),
}


# ── data model ────────────────────────────────────────────────────────────────

class BaitFile(NamedTuple):
    path:     str
    category: str
    size:     int   # bytes


class BaitManifest(NamedTuple):
    run_id: str
    files:  list[BaitFile]

    def to_dict(self) -> dict:
        return {
            "run_id":        self.run_id,
            "files":         [{"path": f.path, "category": f.category, "size": f.size}
                               for f in self.files],
            "planted_paths": [f.path for f in self.files],
            "planted_count": len(self.files),
        }


# ── container helpers ─────────────────────────────────────────────────────────

def _write_file_in_container(container_name: str, path: str, content: str) -> None:
    """Write *content* to *path* inside a running Docker container."""
    parent = str(PurePosixPath(path).parent)
    subprocess.run(
        [
            "docker", "exec", "-i", container_name,
            "sh", "-c", f"mkdir -p '{parent}' && cat > '{path}'",
        ],
        input=content.encode(),
        check=True,
        capture_output=True,
        timeout=10,
    )


# ── public API ────────────────────────────────────────────────────────────────

def plant_bait(container_name: str, run_id: str) -> BaitManifest:
    """Plant synthetic credential bait files in *container_name*.

    Each file's content is tagged with ``PKGIDSBAIT`` + the first 8 chars of
    *run_id* (uppercased) so each run's bait is unique and attributable.

    Returns a :class:`BaitManifest` recording every planted file.  The caller
    should store ``manifest.to_dict()`` in ``sandbox_meta["bait_planted"]``
    so the telemetry pipeline can later match accesses against planted paths.
    """
    tag = run_id[:8].upper()
    planted: list[BaitFile] = []
    for path, (category, template) in _BAIT_FILES.items():
        content = template.format(tag=tag)
        _write_file_in_container(container_name, path, content)
        planted.append(BaitFile(path=path, category=category, size=len(content.encode())))
    return BaitManifest(run_id=run_id, files=planted)
