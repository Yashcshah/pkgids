"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: subprocess spawn — setup.py spawns a child process that makes
a network call. Demonstrates that the payload is not in the parent process.
Uses python3 (guaranteed present) rather than curl (may be absent).
Sink: canary-test.example.com (fake).
"""
import subprocess
from setuptools import setup

try:
    subprocess.run(
        [
            "python3", "-c",
            (
                "import urllib.request; "
                "urllib.request.urlopen("
                "'http://canary-test.example.com/subprocess', timeout=5)"
            ),
        ],
        timeout=10,
        capture_output=True,
    )
except Exception:
    pass

setup(
    name="canary-subprocess",
    version="1.0.0",
    description="[CORPUS] Subprocess spawn on install — safety research package",
    packages=["canary_subprocess"],
)
