"""
SAFETY RESEARCH PACKAGE — benign control sample.
Does absolutely nothing except install itself.  Expected label: benign.
Used to verify the detector produces zero false positives on a clean package.
"""
from setuptools import setup

setup(
    name="benign-clean-control",
    version="1.0.0",
    description="[CORPUS] Benign control — safety research package",
    packages=["benign_clean_control"],
)
