.PHONY: install test sandbox-image

SANDBOX_IMAGE := pkgids-sandbox

VENV   := .venv
PYTHON := $(VENV)/Scripts/python
PIP    := $(VENV)/Scripts/pip

install:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	$(PIP) install pytest

test:
	$(VENV)/Scripts/pytest -v

sandbox-image:
	docker build -f Dockerfile.sandbox -t $(SANDBOX_IMAGE) .
