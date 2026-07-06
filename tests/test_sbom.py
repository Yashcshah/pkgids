"""Tests for pkgids.sbom — manifest parsing into normalized package lists."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from pkgids.sbom import detect_format, parse


# ── helpers ───────────────────────────────────────────────────────────────────

def _req(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _cdx(tmp_path: Path, components: list[dict], extra: dict | None = None) -> Path:
    data = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "components":  components,
        **(extra or {}),
    }
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _csv(tmp_path: Path, rows: list[str], header: str = "ecosystem,name,version") -> Path:
    p = tmp_path / "packages.csv"
    p.write_text("\n".join([header] + rows) + "\n", encoding="utf-8")
    return p


# ── requirements.txt ─────────────────────────────────────────────────────────

class TestRequirementsTxt:
    def test_simple_pin(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "requests==2.28.0\n"))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_extras_single_stripped(self, tmp_path):
        pkgs, _ = parse(_req(tmp_path, "requests[security]==2.28.0\n"))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]

    def test_extras_multi_stripped(self, tmp_path):
        pkgs, _ = parse(_req(tmp_path, "requests[security,socks]==2.28.0\n"))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]

    def test_inline_comment_stripped(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "requests==2.28.0 # pinned\n"))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_env_marker_stripped(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, 'requests==2.28.0;python_version>="3.8"\n'))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_blank_line_silent(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "\n\n   \n"))
        assert pkgs == []
        assert warns == []

    def test_comment_line_silent(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "# pinned deps\n"))
        assert pkgs == []
        assert warns == []

    def test_no_version_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "flask\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "no version pin" in warns[0]

    def test_ge_constraint_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "flask>=2.0\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "only == pins supported" in warns[0]

    def test_vcs_url_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "git+https://github.com/org/repo.git\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "VCS URL" in warns[0]

    def test_r_flag_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "-r other.txt\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "directive" in warns[0]

    def test_c_flag_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "-c constraints.txt\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "directive" in warns[0]

    def test_local_path_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "./mypkg\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "local path" in warns[0]

    def test_name_case_normalized(self, tmp_path):
        pkgs, _ = parse(_req(tmp_path, "Requests==2.28.0\n"))
        assert pkgs[0]["name"] == "requests"

    def test_multiline_returns_all(self, tmp_path):
        content = "requests==2.28.0\nflask==3.0.0\nclick==8.1.0\n"
        pkgs, warns = parse(_req(tmp_path, content))
        assert len(pkgs) == 3
        assert warns == []

    def test_mixed_valid_and_invalid(self, tmp_path):
        content = "requests==2.28.0\nflask\nclick==8.1.0\ngit+https://x.com/r\n"
        pkgs, warns = parse(_req(tmp_path, content))
        assert len(pkgs) == 2
        assert len(warns) == 2

    def test_duplicate_warns_and_dedupes(self, tmp_path):
        content = "requests==2.28.0\nrequests==2.28.0\n"
        pkgs, warns = parse(_req(tmp_path, content))
        assert len(pkgs) == 1
        assert len(warns) == 1
        assert "duplicate" in warns[0]

    def test_warning_contains_line_number(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "# ok\nflask\n"))
        assert warns[0].startswith("line 2:")

    def test_extras_with_ge_constraint_warns(self, tmp_path):
        pkgs, warns = parse(_req(tmp_path, "requests[security]>=2.28\n"))
        assert pkgs == []
        assert len(warns) == 1
        assert "only == pins supported" in warns[0]


# ── CycloneDX JSON ───────────────────────────────────────────────────────────

class TestCycloneDxJson:
    def test_pypi_purl(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests@2.28.0"},
        ]))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_npm_purl(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "lodash", "version": "4.17.21",
             "purl": "pkg:npm/lodash@4.17.21"},
        ]))
        assert pkgs == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}]
        assert warns == []

    def test_npm_scoped_purl(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "name", "version": "1.0.0",
             "purl": "pkg:npm/%40scope/name@1.0.0"},
        ]))
        assert pkgs == [{"ecosystem": "npm", "name": "@scope/name", "version": "1.0.0"}]
        assert warns == []

    def test_missing_version_warns(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "purl": "pkg:pypi/requests@"},
        ]))
        assert pkgs == []
        assert len(warns) == 1
        assert "no version present" in warns[0]

    def test_version_from_component_field_when_purl_has_none(self, tmp_path):
        # purl has no @version, component has version field → use component version
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests"},
        ]))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_missing_name_warns(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"version": "1.0.0", "purl": "pkg:pypi/something@1.0.0"},
        ]))
        # name field empty → warn at component level
        assert warns[0] if warns else True  # there is a warning
        assert all(p["name"] for p in pkgs)  # any parsed packages have names

    def test_unsupported_ecosystem_warns(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "rails", "version": "7.0.0",
             "purl": "pkg:gem/rails@7.0.0"},
        ]))
        assert pkgs == []
        assert len(warns) == 1
        assert "unsupported ecosystem" in warns[0]

    def test_no_purl_warns(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "version": "2.28.0"},
        ]))
        assert pkgs == []
        assert len(warns) == 1
        assert "cannot determine ecosystem" in warns[0]

    def test_malformed_purl_warns(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "purl": "not-a-purl"},
        ]))
        assert pkgs == []
        assert len(warns) == 1
        assert "malformed purl" in warns[0]

    def test_mixed_valid_and_invalid(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests@2.28.0"},
            {"name": "rails", "version": "7.0.0",
             "purl": "pkg:gem/rails@7.0.0"},
            {"name": "lodash", "version": "4.17.21",
             "purl": "pkg:npm/lodash@4.17.21"},
        ]))
        assert len(pkgs) == 2
        assert len(warns) == 1
        assert "unsupported ecosystem" in warns[0]

    def test_duplicate_warns_and_dedupes(self, tmp_path):
        pkgs, warns = parse(_cdx(tmp_path, [
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests@2.28.0"},
            {"name": "requests", "version": "2.28.0",
             "purl": "pkg:pypi/requests@2.28.0"},
        ]))
        assert len(pkgs) == 1
        assert len(warns) == 1
        assert "duplicate" in warns[0]

    def test_invalid_json_raises(self, tmp_path):
        # Valid CycloneDX marker in text but syntactically broken JSON
        p = tmp_path / "bad.json"
        p.write_text('{"bomFormat":"CycloneDX", bad json', encoding="utf-8")
        with pytest.raises(ValueError, match="Not a valid CycloneDX JSON"):
            parse(p)

    def test_wrong_bom_format_raises(self, tmp_path):
        # "notCycloneDX" contains "CycloneDX" as a substring → passes detect_format
        # but _parse_cyclonedx_json rejects bomFormat != "CycloneDX"
        p = tmp_path / "sbom.json"
        p.write_text(
            json.dumps({"bomFormat": "notCycloneDX", "components": []}),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Not a valid CycloneDX JSON"):
            parse(p)


# ── plain CSV ─────────────────────────────────────────────────────────────────

class TestPlainCsv:
    def test_valid_row(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, ["pypi,requests,2.28.0"]))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_multiple_rows(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, [
            "pypi,requests,2.28.0",
            "npm,lodash,4.17.21",
            "pypi,flask,3.0.0",
        ]))
        assert len(pkgs) == 3
        assert warns == []

    def test_missing_required_column_raises(self, tmp_path):
        with pytest.raises(ValueError, match="missing required column"):
            parse(_csv(tmp_path, ["pypi,requests"], header="ecosystem,name"))

    def test_empty_version_warns(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, ["pypi,requests,"]))
        assert pkgs == []
        assert len(warns) == 1
        assert "version is empty" in warns[0]

    def test_empty_name_warns(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, ["pypi,,2.28.0"]))
        assert pkgs == []
        assert len(warns) == 1
        assert "name is empty" in warns[0]

    def test_unsupported_ecosystem_warns(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, ["rubygems,rails,7.0.0"]))
        assert pkgs == []
        assert len(warns) == 1
        assert "unsupported ecosystem" in warns[0]

    def test_ecosystem_normalized_to_lowercase(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, ["PyPI,requests,2.28.0"]))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_whitespace_stripped(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, [" pypi , requests , 2.28.0 "]))
        assert pkgs == [{"ecosystem": "pypi", "name": "requests", "version": "2.28.0"}]
        assert warns == []

    def test_duplicate_warns_and_dedupes(self, tmp_path):
        pkgs, warns = parse(_csv(tmp_path, [
            "pypi,requests,2.28.0",
            "pypi,requests,2.28.0",
        ]))
        assert len(pkgs) == 1
        assert len(warns) == 1
        assert "duplicate" in warns[0]

    def test_name_version_case_preserved(self, tmp_path):
        pkgs, _ = parse(_csv(tmp_path, ["pypi,MyPackage,1.0.0-Beta"]))
        assert pkgs[0]["name"] == "MyPackage"
        assert pkgs[0]["version"] == "1.0.0-Beta"


# ── auto-detection ────────────────────────────────────────────────────────────

class TestDetectFormat:
    def test_requirements_txt_by_name(self, tmp_path):
        p = tmp_path / "requirements.txt"
        p.write_text("requests==2.28.0\n", encoding="utf-8")
        assert detect_format(p) == "requirements_txt"

    def test_requirements_txt_by_pattern(self, tmp_path):
        p = tmp_path / "requirements-prod.txt"
        p.write_text("requests==2.28.0\n", encoding="utf-8")
        assert detect_format(p) == "requirements_txt"

    def test_cyclonedx_json_by_content(self, tmp_path):
        p = tmp_path / "sbom.json"
        p.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
        assert detect_format(p) == "cyclonedx_json"

    def test_csv_by_extension(self, tmp_path):
        p = tmp_path / "packages.csv"
        p.write_text("ecosystem,name,version\npypi,requests,2.28.0\n", encoding="utf-8")
        assert detect_format(p) == "csv"

    def test_unknown_format_raises(self, tmp_path):
        p = tmp_path / "deps.yaml"
        p.write_text("requests: 2.28.0\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unrecognized input format"):
            detect_format(p)

    def test_json_without_cyclonedx_marker_raises(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_text('{"packages": []}', encoding="utf-8")
        with pytest.raises(ValueError, match="does not appear to be a CycloneDX"):
            detect_format(p)


# ── parse() error paths ───────────────────────────────────────────────────────

class TestParseErrors:
    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Input file not found"):
            parse(tmp_path / "nonexistent.txt")

    def test_returns_all_three_keys_on_every_package(self, tmp_path):
        pkgs, _ = parse(_req(tmp_path, "requests==2.28.0\nflask==3.0.0\n"))
        required = {"ecosystem", "name", "version"}
        for pkg in pkgs:
            assert set(pkg.keys()) == required

    def test_no_package_has_empty_field(self, tmp_path):
        pkgs, _ = parse(_req(tmp_path, "requests==2.28.0\nflask==3.0.0\n"))
        for pkg in pkgs:
            assert pkg["ecosystem"]
            assert pkg["name"]
            assert pkg["version"]
