"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: import-time callback — the payload is in __init__.py and fires
when user code does `import canary_import_callback`, NOT during pip install.

Detection note: pkgids runs install and import in SEPARATE containers.
The import container is fresh (no package installed), so the import fails
with ModuleNotFoundError and the callback never fires in that container.
This sample is therefore a KNOWN FALSE NEGATIVE in the two-container pipeline,
demonstrating a real detection gap: payloads that only execute at import time
require a combined install+import test in a single container to be caught.
"""
from setuptools import setup

# setup.py itself is clean — no network call here.
setup(
    name="canary-import-callback",
    version="1.0.0",
    description="[CORPUS] Import-time callback — safety research package (known FN)",
    packages=["canary_import_callback"],
)
