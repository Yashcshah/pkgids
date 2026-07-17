"""Unit tests for pkgids/bait.py — synthetic credential bait planting."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from pkgids.bait import (
    BaitFile,
    BaitManifest,
    _BAIT_FILES,
    _ENV_TEMPLATE,
    _AWS_TEMPLATE,
    _PYPIRC_TEMPLATE,
    _SSH_TEMPLATE,
    plant_bait,
)


# ── _BAIT_FILES registry ──────────────────────────────────────────────────────

class TestBaitFilesRegistry:
    def test_has_four_entries(self):
        assert len(_BAIT_FILES) == 4

    def test_all_paths_are_in_home_deton(self):
        for path in _BAIT_FILES:
            assert path.startswith("/home/deton/"), f"unexpected path: {path}"

    def test_all_paths_are_strings(self):
        for path in _BAIT_FILES:
            assert isinstance(path, str)

    def test_all_categories_are_strings(self):
        for path, (category, template) in _BAIT_FILES.items():
            assert isinstance(category, str) and category, f"empty category for {path}"

    def test_expected_paths_present(self):
        assert "/home/deton/.env"             in _BAIT_FILES
        assert "/home/deton/.aws/credentials" in _BAIT_FILES
        assert "/home/deton/.pypirc"          in _BAIT_FILES
        assert "/home/deton/.ssh/id_rsa"      in _BAIT_FILES

    def test_expected_categories(self):
        categories = {cat for _, (cat, _) in _BAIT_FILES.items()}
        assert "env_file"        in categories
        assert "aws_credentials" in categories
        assert "pypi_rc"         in categories
        assert "ssh_keys"        in categories


# ── template safety ───────────────────────────────────────────────────────────

class TestTemplates:
    _ALL_TEMPLATES = [_ENV_TEMPLATE, _AWS_TEMPLATE, _PYPIRC_TEMPLATE, _SSH_TEMPLATE]

    def test_all_templates_contain_pkgidsbait(self):
        for tmpl in self._ALL_TEMPLATES:
            assert "PKGIDSBAIT" in tmpl

    def test_all_templates_contain_bait_keyword(self):
        for tmpl in self._ALL_TEMPLATES:
            assert "BAIT" in tmpl

    def test_no_real_aws_access_key_prefix(self):
        for tmpl in self._ALL_TEMPLATES:
            assert "AKIA" not in tmpl, "Template must not contain real AWS key prefix AKIA"

    def test_no_real_pypi_token_prefix(self):
        for tmpl in self._ALL_TEMPLATES:
            assert "pypi-" not in tmpl, "Template must not contain real PyPI token prefix"

    def test_templates_use_tag_placeholder(self):
        for tmpl in (_ENV_TEMPLATE, _AWS_TEMPLATE, _PYPIRC_TEMPLATE, _SSH_TEMPLATE):
            assert "{tag}" in tmpl, f"Template missing {{tag}} placeholder: {tmpl[:40]!r}"

    def test_ssh_template_has_fake_pem_headers(self):
        assert "BEGIN RSA PRIVATE KEY" in _SSH_TEMPLATE
        assert "END RSA PRIVATE KEY"   in _SSH_TEMPLATE


# ── BaitManifest.to_dict() ────────────────────────────────────────────────────

class TestBaitManifest:
    def _manifest(self, run_id: str = "abc12345xyz") -> BaitManifest:
        files = [
            BaitFile(path="/home/deton/.env",             category="env_file",        size=80),
            BaitFile(path="/home/deton/.aws/credentials", category="aws_credentials", size=95),
        ]
        return BaitManifest(run_id=run_id, files=files)

    def test_to_dict_has_required_keys(self):
        d = self._manifest().to_dict()
        for key in ("run_id", "files", "planted_paths", "planted_count"):
            assert key in d, f"missing key: {key}"

    def test_to_dict_planted_paths_matches_files(self):
        m   = self._manifest()
        d   = m.to_dict()
        assert d["planted_paths"] == [f.path for f in m.files]

    def test_to_dict_planted_count_matches(self):
        d = self._manifest().to_dict()
        assert d["planted_count"] == 2

    def test_to_dict_run_id_preserved(self):
        d = self._manifest(run_id="deadbeef1234").to_dict()
        assert d["run_id"] == "deadbeef1234"

    def test_to_dict_files_have_path_category_size(self):
        d = self._manifest().to_dict()
        for f in d["files"]:
            assert "path"     in f
            assert "category" in f
            assert "size"     in f


# ── plant_bait() ──────────────────────────────────────────────────────────────

class TestPlantBait:
    def _run_plant(self, run_id: str = "testrun0abcdef"):
        with patch("pkgids.bait.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            manifest = plant_bait("test-container", run_id)
        return manifest, mock_run

    def test_returns_bait_manifest(self):
        manifest, _ = self._run_plant()
        assert isinstance(manifest, BaitManifest)

    def test_manifest_contains_all_bait_files(self):
        manifest, _ = self._run_plant()
        assert len(manifest.files) == len(_BAIT_FILES)

    def test_manifest_paths_match_registry(self):
        manifest, _ = self._run_plant()
        assert {f.path for f in manifest.files} == set(_BAIT_FILES)

    def test_subprocess_called_once_per_file(self):
        _, mock_run = self._run_plant()
        assert mock_run.call_count == len(_BAIT_FILES)

    def test_subprocess_calls_docker_exec(self):
        _, mock_run = self._run_plant()
        for c in mock_run.call_args_list:
            cmd = c.args[0]
            assert cmd[0] == "docker"
            assert cmd[1] == "exec"
            assert "test-container" in cmd

    def test_content_contains_pkgidsbait_marker(self):
        with patch("pkgids.bait.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            plant_bait("ctr", "myrun123xyz")
        for c in mock_run.call_args_list:
            stdin_bytes = c.kwargs.get("input") or b""
            assert b"PKGIDSBAIT" in stdin_bytes

    def test_content_uses_run_id_tag(self):
        run_id = "deadbeef0011"
        expected_tag = run_id[:8].upper()
        with patch("pkgids.bait.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            plant_bait("ctr", run_id)
        all_content = b"".join(
            c.kwargs.get("input", b"") for c in mock_run.call_args_list
        )
        assert expected_tag.encode() in all_content

    def test_manifest_run_id_preserved(self):
        manifest, _ = self._run_plant(run_id="myrunid1234")
        assert manifest.run_id == "myrunid1234"

    def test_file_sizes_are_positive(self):
        manifest, _ = self._run_plant()
        for f in manifest.files:
            assert f.size > 0, f"zero size for {f.path}"
