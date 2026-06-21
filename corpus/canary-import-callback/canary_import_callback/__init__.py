"""Import-time HTTP callback — fires when this module is imported."""
import urllib.request

# This runs when user code does `import canary_import_callback`.
# The pkgids two-container pipeline will NOT catch this unless both
# install and import are tested inside the same container.
try:
    urllib.request.urlopen(
        "http://canary-test.example.com/imported",
        timeout=5,
    )
except Exception:
    pass
