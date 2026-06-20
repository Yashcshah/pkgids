# ── targets ───────────────────────────────────────────────────────────────────
.PHONY: install test sandbox-image detonet \
        fakeinternet-image fakeinternet-start fakeinternet-stop demo-fake

# ── Python / Windows paths ────────────────────────────────────────────────────
SANDBOX_IMAGE := pkgids-sandbox
VENV          := .venv
PYTHON        := $(VENV)/bin/python
PIP           := $(VENV)/bin/pip

# ── fake-internet config (must match config.toml [fakeinternet]) ──────────────
DETONET_NAME       := detonet
DETONET_SUBNET     := 10.200.200.0/24
FAKEINTERNET_IMAGE := pkgids-fakeinternet
FAKEINTERNET_NAME  := pkgids-fakeinternet
FAKEINTERNET_IP    := 10.200.200.2
FAKEINTERNET_LOGS  := $(CURDIR)/logs/fakeinternet

# ── Python env ────────────────────────────────────────────────────────────────
install:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	$(PIP) install pytest

test:
	$(VENV)/bin/pytest -v

# ── sandbox image ─────────────────────────────────────────────────────────────
sandbox-image:
	docker build -f Dockerfile.sandbox -t $(SANDBOX_IMAGE) .

# ── detonet: isolated internal bridge, no real internet ───────────────────────
detonet:
	@docker network inspect $(DETONET_NAME) > /dev/null 2>&1 \
	  && echo "Network '$(DETONET_NAME)' already exists — skipping" \
	  || (docker network create \
	        --driver   bridge \
	        --internal \
	        --subnet   $(DETONET_SUBNET) \
	        $(DETONET_NAME) \
	      && echo "Created network '$(DETONET_NAME)' ($(DETONET_SUBNET), internal)")

# ── fake-internet appliance ───────────────────────────────────────────────────
fakeinternet-image:
	docker build \
	  -f infra/fakeinternet/Dockerfile \
	  -t $(FAKEINTERNET_IMAGE) \
	  infra/fakeinternet

fakeinternet-start: detonet fakeinternet-image
	@mkdir -p $(FAKEINTERNET_LOGS)
	@# Remove any stale exited container so it never blocks a restart
	@docker rm -f $(FAKEINTERNET_NAME) 2>/dev/null || true
	@# Check specifically for a running container (not the image of the same name)
	@docker ps -q -f name=^/$(FAKEINTERNET_NAME)$$ | grep -q . \
	  && echo "Container '$(FAKEINTERNET_NAME)' is already running — skipping" \
	  || docker run -d \
	       --name    $(FAKEINTERNET_NAME) \
	       --network $(DETONET_NAME) \
	       --ip      $(FAKEINTERNET_IP) \
	       --restart unless-stopped \
	       -e        FAKEINTERNET_IP=$(FAKEINTERNET_IP) \
	       -v        $(FAKEINTERNET_LOGS):/logs \
	       $(FAKEINTERNET_IMAGE)

fakeinternet-stop:
	docker rm -f $(FAKEINTERNET_NAME) 2>/dev/null || true

# ── demo: DNS + HTTP capture, then confirm no real egress ────────────────────
demo-fake: fakeinternet-start
	@bash scripts/demo-fake.sh
