#!/usr/bin/env bash
# corpus/build_all.sh — Build every corpus sdist and write data/corpus_samples.csv.
#
# Usage (from the project root):
#     bash corpus/build_all.sh
# Or (from inside corpus/):
#     bash build_all.sh
#
# Requires: python3 + setuptools on the build host.
# Note: malicious setup.py files make network calls to canary-test.example.com;
# they fail silently on a machine without fakeinternet — that is expected.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$SCRIPT_DIR/dist"
CSV_PATH="$PROJECT_DIR/data/corpus_samples.csv"

mkdir -p "$DIST_DIR"
mkdir -p "$PROJECT_DIR/data"

printf "ecosystem,name,version,expected_label,technique,artifact_path\n" > "$CSV_PATH"
echo "[build_all] output CSV  : $CSV_PATH"
echo "[build_all] sdist dir   : $DIST_DIR"
echo ""

build_sdist() {
    local pkg_dir="$1"
    local name="$2"
    local version="1.0.0"
    local label="$3"
    local technique="$4"

    echo "[build_all] building $name ..."

    # Snapshot existing tarballs BEFORE the build so we can identify the new one.
    # This is robust against setuptools normalising hyphens to underscores
    # (e.g. "canary-http-install" → "canary_http_install-1.0.0.tar.gz").
    local before
    before="$(ls -1 "$DIST_DIR"/*.tar.gz 2>/dev/null | sort || true)"

    # Build in a subshell so the cd does not affect our working directory.
    (
        cd "$pkg_dir"
        python3 -W ignore::DeprecationWarning \
                -W ignore::UserWarning \
                setup.py sdist --dist-dir "$DIST_DIR" -q 2>&1 \
            | grep -vE "^(running|creating|hard linking|copying|Writing)" \
            || true
    )

    # Find the tarball that appeared after the build.
    local after artifact
    after="$(ls -1 "$DIST_DIR"/*.tar.gz 2>/dev/null | sort || true)"
    artifact="$(comm -13 <(echo "$before") <(echo "$after") | head -1)"

    if [[ -z "$artifact" ]]; then
        echo "[build_all]   WARNING: no new .tar.gz found in $DIST_DIR — skipping $name"
        return
    fi

    printf "pypi,%s,%s,%s,%s,%s\n" \
        "$name" "$version" "$label" "$technique" "$artifact" >> "$CSV_PATH"
    echo "[build_all]   -> $artifact"
}

# ── malicious samples ─────────────────────────────────────────────────────────
build_sdist "$SCRIPT_DIR/canary-http-install"    "canary-http-install"    malicious "http-install"
build_sdist "$SCRIPT_DIR/canary-dns-exfil"       "canary-dns-exfil"       malicious "dns-exfil"
build_sdist "$SCRIPT_DIR/canary-env-harvest"     "canary-env-harvest"     malicious "env-harvest"
build_sdist "$SCRIPT_DIR/canary-subprocess"      "canary-subprocess"      malicious "subprocess-spawn"
build_sdist "$SCRIPT_DIR/canary-base64-blob"     "canary-base64-blob"     malicious "base64-obfuscation"
build_sdist "$SCRIPT_DIR/canary-import-callback" "canary-import-callback" malicious "import-callback"

# ── benign control ────────────────────────────────────────────────────────────
build_sdist "$SCRIPT_DIR/benign-clean-control"   "benign-clean-control"   benign    "none"

# ── verify ────────────────────────────────────────────────────────────────────
echo ""
ROW_COUNT=$(tail -n +2 "$CSV_PATH" | grep -c . || true)
echo "[build_all] done — $ROW_COUNT artifact(s) in CSV."
echo "[build_all] CSV written to : $CSV_PATH"
echo "[build_all] Artifacts in   : $DIST_DIR/"
echo ""

if [[ "$ROW_COUNT" -lt 7 ]]; then
    echo "[build_all] WARNING: expected 7 rows, got $ROW_COUNT. Check errors above."
fi

echo "Run the validation harness with:"
echo "  pkgids validate --samples data/corpus_samples.csv --local-artifacts"
