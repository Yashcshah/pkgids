"""Parse and classify strace-based process, file, and socket telemetry."""

from __future__ import annotations

import re
from typing import Iterator

# ── indicator sets ────────────────────────────────────────────────────────────

# Executables suspicious when spawned from package install/import hooks.
MALICIOUS_EXEC_INDICATORS: frozenset[str] = frozenset({
    # Shell invocation
    "sh", "bash", "dash", "zsh", "ksh", "ash",
    # Network egress
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp",
    # Privilege / attribute manipulation
    "chmod", "chown", "chattr", "install",
    # Encoding / crypto (payload decoding, C2 obfuscation)
    "base64", "openssl", "xxd", "od",
    # Interpreter re-spawning from setup hooks
    "python", "python2", "python3",
    "node", "nodejs",
    "perl", "ruby", "php", "lua",
})

# ── sensitive-path classification ─────────────────────────────────────────────

# Each entry is (category, predicate).  Checked in order; first match wins.
# All comparisons use the lowercased path, so mix of path-suffix and substring.
_SENSITIVE_CHECKS: list[tuple[str, object]] = [
    ("ssh_keys",         lambda p: "/.ssh/" in p or p.endswith("/.ssh")),
    ("aws_credentials",  lambda p: "/.aws/" in p),
    ("npm_rc",           lambda p: p.endswith("/.npmrc")),
    ("pypi_rc",          lambda p: p.endswith("/.pypirc")),
    ("git_config",       lambda p: p.endswith("/.gitconfig") or p.endswith("/.git-credentials")),
    ("system_passwd",    lambda p: p == "/etc/passwd"),
    ("system_shadow",    lambda p: p == "/etc/shadow"),
    ("shell_rc",         lambda p: p.endswith(("/.bashrc", "/.zshrc", "/.profile",
                                               "/.bash_profile", "/.cshrc"))),
    ("env_file",         lambda p: p.endswith("/.env") or "/.env." in p or p == ".env"),
    ("proc_environ",     lambda p: "/proc/" in p and "environ" in p),
    ("ci_secrets",       lambda p: "/.circleci/" in p or "/.github/workflows/" in p),
    ("docker_config",    lambda p: p.endswith("/.docker/config.json")),
    ("credentials_file", lambda p: p.endswith("/credentials") or p.endswith("/secrets")),
]


def check_sensitive_path(path: str) -> tuple[bool, str | None]:
    """Return (is_sensitive, category_or_None) for *path*."""
    p = path.lower()
    for category, check in _SENSITIVE_CHECKS:
        if check(p):
            return True, category
    return False, None


# ── strace line parsing ───────────────────────────────────────────────────────

# Matches the mandatory prefix of every traced line:  PID [TIMESTAMP] SYSCALL(
# The timestamp group is optional so files produced without -ttt still parse.
_LINE_PREFIX_RE = re.compile(
    r"^\s*(\d+)\s+"          # group 1: PID
    r"(?:(\d+\.\d+)\s+)?"   # group 2: timestamp (epoch.usec), optional
    r"(\w+)\("               # group 3: syscall name, consumes the "("
)

# Matches individual quoted strings in argv arrays.
_ARGV_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _parse_argv(raw: str) -> list[str]:
    return [
        m.group(1).replace('\\"', '"').replace("\\\\", "\\")
        for m in _ARGV_ITEM_RE.finditer(raw)
    ]


def _parse_strace_line(line: str) -> dict | None:
    """Parse one strace output line into a structured dict.

    Returns None for unfinished/resumed lines, signal/exit notices, and
    any line that does not match the expected format.

    Returned dict keys: pid (int), ts (float|None), syscall (str),
    args_raw (str), retval (int|None).
    """
    if "<unfinished" in line or "<... " in line:
        return None

    m = _LINE_PREFIX_RE.match(line)
    if not m:
        return None

    pid     = int(m.group(1))
    ts      = float(m.group(2)) if m.group(2) else None
    syscall = m.group(3)

    # Everything after the opening "(" up to " = RETVAL" at end of line.
    # Use rfind(") = ") to handle nested parens (e.g. connect sockaddr structs).
    tail = line[m.end() - 1:]          # includes the "(" we consumed
    close = tail.rfind(") = ")
    if close == -1:
        return None

    args_raw   = tail[1:close]          # between ( and )
    retval_str = tail[close + 4:].strip()

    retval: int | None
    try:
        retval = int(retval_str.split()[0])
    except (ValueError, IndexError):
        retval = None

    return {
        "pid":      pid,
        "ts":       ts,
        "syscall":  syscall,
        "args_raw": args_raw,
        "retval":   retval,
    }


# Prefix that identifies pkgids' own import command injected into the sandbox.
# Any exec whose argv contains this string is pkgids infrastructure, not the
# package under test, and must never be flagged as suspicious.
_PKGIDS_IMPORT_PREFIX = "import sys; sys.path.insert(0, '/scratch/site-packages')"


def _is_framework_exec(argv: list[str]) -> bool:
    """Return True when argv belongs to pkgids itself or pip3 internals.

    Two cases are excluded:
    1. pkgids' own import command — always starts with the site-packages path
       insert that pkgids injects; no malware would use this exact preamble.
    2. Interpreter -c calls whose code argument was truncated by strace — strace
       truncates strings longer than its -s limit (default 32 chars), so pip3's
       long internal python3 -c invocations appear as argv ending at '-c' with
       no following code visible.  Short malicious payloads are never truncated
       and remain detectable; this exclusion only affects already-invisible code.
    """
    if any(_PKGIDS_IMPORT_PREFIX in a for a in argv):
        return True
    # argv[-1] == "-c" means the code argument was truncated away by strace.
    if argv and argv[-1] == "-c":
        return True
    return False


# ── per-syscall handlers ──────────────────────────────────────────────────────

def _handle_execve(pl: dict) -> dict | None:
    """execve / execveat → process_event."""
    args = pl["args_raw"]
    if pl["syscall"] == "execveat":
        # execveat(dirfd, "path", ["argv0", ...], envp, flags)
        m = re.match(r'[^,]+,\s*"([^"]*)",\s*(\[[^\]]*\])', args)
    else:
        # execve("path", ["argv0", ...], envp)
        m = re.match(r'"([^"]*)",\s*(\[[^\]]*\])', args)

    if not m:
        return None

    executable = m.group(1)
    argv       = _parse_argv(m.group(2))
    basename   = executable.rsplit("/", 1)[-1]

    return {
        "kind":       "process",
        "pid":        pl["pid"],
        "ts":         pl["ts"],
        "syscall":    pl["syscall"],
        "executable": executable,
        "basename":   basename,
        "argv":       argv,
        "suspicious": (basename in MALICIOUS_EXEC_INDICATORS
                       and not _is_framework_exec(argv)),
    }


def _classify_open_flags(flags: str) -> str:
    """Map open/openat flags string to a human-readable access type."""
    if "O_CREAT" in flags and ("O_WRONLY" in flags or "O_RDWR" in flags):
        return "create"
    if "O_WRONLY" in flags or "O_RDWR" in flags:
        return "write"
    return "read"


def _make_file_event(pl: dict, syscall: str, path: str,
                     access_type: str, **extra: object) -> dict | None:
    """Build a file_event dict, returning None for non-sensitive reads (noise)."""
    is_sensitive, category = check_sensitive_path(path)

    # Skip reads of non-sensitive paths — pip installs produce thousands of them.
    if access_type == "read" and not is_sensitive:
        return None

    return {
        "kind":             "file",
        "pid":              pl["pid"],
        "ts":               pl["ts"],
        "syscall":          syscall,
        "path":             path,
        "access_type":      access_type,
        "sensitive":        is_sensitive,
        "sensitive_category": category,
        **extra,
    }


def _handle_openat(pl: dict) -> dict | None:
    """openat(dirfd, "path", flags[, mode]) → file_event."""
    m = re.match(r'[^,]+,\s*"([^"]+)",\s*([^,)]+)', pl["args_raw"])
    if not m:
        return None
    return _make_file_event(pl, "openat", m.group(1),
                            _classify_open_flags(m.group(2).strip()))


def _handle_open(pl: dict) -> dict | None:
    """open("path", flags[, mode]) → file_event."""
    m = re.match(r'"([^"]+)",\s*([^,)]+)', pl["args_raw"])
    if not m:
        return None
    return _make_file_event(pl, "open", m.group(1),
                            _classify_open_flags(m.group(2).strip()))


def _handle_unlink(pl: dict) -> dict | None:
    m = re.match(r'"([^"]+)"', pl["args_raw"])
    if not m:
        return None
    return _make_file_event(pl, "unlink", m.group(1), "delete")


def _handle_rename(pl: dict) -> dict | None:
    m = re.match(r'"([^"]+)",\s*"([^"]+)"', pl["args_raw"])
    if not m:
        return None
    # Record source path; include dest as extra so callers can see the full move.
    ev = _make_file_event(pl, "rename", m.group(1), "rename")
    if ev is not None:
        ev["dest_path"] = m.group(2)
    return ev


def _handle_mkdir(pl: dict) -> dict | None:
    m = re.match(r'"([^"]+)"', pl["args_raw"])
    if not m:
        return None
    return _make_file_event(pl, "mkdir", m.group(1), "create")


def _handle_chmod(pl: dict) -> dict | None:
    """chmod("path", mode) — always interesting regardless of path sensitivity."""
    m = re.match(r'"([^"]+)",\s*0?(\d+)', pl["args_raw"])
    if not m:
        return None
    is_sensitive, category = check_sensitive_path(m.group(1))
    return {
        "kind":               "file",
        "pid":                pl["pid"],
        "ts":                 pl["ts"],
        "syscall":            "chmod",
        "path":               m.group(1),
        "access_type":        "chmod",
        "mode":               m.group(2),
        "sensitive":          is_sensitive,
        "sensitive_category": category,
    }


def _handle_chown(pl: dict) -> dict | None:
    """chown("path", uid, gid) — always interesting regardless of path."""
    m = re.match(r'"([^"]+)",\s*(\d+),\s*(\d+)', pl["args_raw"])
    if not m:
        return None
    is_sensitive, category = check_sensitive_path(m.group(1))
    return {
        "kind":               "file",
        "pid":                pl["pid"],
        "ts":                 pl["ts"],
        "syscall":            "chown",
        "path":               m.group(1),
        "access_type":        "chown",
        "uid":                int(m.group(2)),
        "gid":                int(m.group(3)),
        "sensitive":          is_sensitive,
        "sensitive_category": category,
    }


# IPv4 and IPv6 connect destination patterns
_CONNECT_V4_RE = re.compile(
    r"sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
)
_CONNECT_V6_RE = re.compile(
    r"sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),\s*sin6_addr=inet6_addr\(\"([^\"]+)\"\)"
)
_SOCKET_RE = re.compile(r"^(AF_\w+),\s*(\w+),\s*(\w+)")


def _handle_connect(pl: dict) -> dict | None:
    """connect(fd, sockaddr, len) → socket_event for IPv4/IPv6 destinations."""
    args = pl["args_raw"]
    for family, regex in (("AF_INET", _CONNECT_V4_RE), ("AF_INET6", _CONNECT_V6_RE)):
        m = regex.search(args)
        if m:
            return {
                "kind":      "socket",
                "pid":       pl["pid"],
                "ts":        pl["ts"],
                "syscall":   "connect",
                "family":    family,
                "dest_ip":   m.group(2),
                "dest_port": int(m.group(1)),
                "retval":    pl["retval"],
            }
    return None


def _handle_socket(pl: dict) -> dict | None:
    """socket(domain, type, protocol) → socket_event (informational)."""
    m = _SOCKET_RE.match(pl["args_raw"])
    if not m:
        return None
    family = m.group(1)
    # Skip AF_UNIX / AF_LOCAL — local IPC, not network egress.
    if family in ("AF_UNIX", "AF_LOCAL", "AF_NETLINK"):
        return None
    return {
        "kind":      "socket",
        "pid":       pl["pid"],
        "ts":        pl["ts"],
        "syscall":   "socket",
        "family":    family,
        "sock_type": m.group(2),
        "protocol":  m.group(3),
        "dest_ip":   None,
        "dest_port": None,
    }


def _handle_kill(pl: dict) -> dict | None:
    """kill(pid, sig) → control_event (process control from package code)."""
    m = re.match(r"(-?\d+),\s*(\w+)", pl["args_raw"])
    if not m:
        return None
    return {
        "kind":       "control",
        "pid":        pl["pid"],
        "ts":         pl["ts"],
        "syscall":    "kill",
        "target_pid": int(m.group(1)),
        "signal":     m.group(2),
    }


def _handle_ptrace(pl: dict) -> dict | None:
    """ptrace() from package code — always treated as highly suspicious."""
    return {
        "kind":     "control",
        "pid":      pl["pid"],
        "ts":       pl["ts"],
        "syscall":  "ptrace",
        "args_raw": pl["args_raw"],
    }


_HANDLERS: dict[str, object] = {
    "execve":   _handle_execve,
    "execveat": _handle_execve,
    "open":     _handle_open,
    "openat":   _handle_openat,
    "unlink":   _handle_unlink,
    "rename":   _handle_rename,
    "mkdir":    _handle_mkdir,
    "chmod":    _handle_chmod,
    "chown":    _handle_chown,
    "connect":  _handle_connect,
    "socket":   _handle_socket,
    "kill":     _handle_kill,
    "ptrace":   _handle_ptrace,
}


# ── public API ────────────────────────────────────────────────────────────────

def parse_strace_log(raw_text: str, *, sensitive_only: bool = False) -> dict:
    """Parse a strace log (produced with -f -ttt -s256) into structured events.

    Handles logs with or without timestamps (-ttt) for robustness.
    Skips unfinished/resumed lines and non-syscall lines silently.

    Returns
    -------
    dict with three lists:
        process_events  — execve/execveat: pid, ts, executable, argv, suspicious
        file_events     — opens (writes/creates/deletes + sensitive reads),
                          unlinks, renames, mkdirs, chmods, chowns
        socket_events   — connect (IPv4/IPv6) and socket() creation
        control_events  — kill and ptrace calls from package code
    """
    out: dict[str, list[dict]] = {
        "process_events": [],
        "file_events":    [],
        "socket_events":  [],
        "control_events": [],
    }

    seen_exec: set[tuple[int, str]] = set()

    for line in raw_text.splitlines():
        pl = _parse_strace_line(line)
        if pl is None:
            continue

        handler = _HANDLERS.get(pl["syscall"])
        if handler is None:
            continue

        event = handler(pl)
        if event is None:
            continue

        kind = event.pop("kind")

        if kind == "process":
            key = (event["pid"], event["executable"])
            if key in seen_exec:
                continue
            seen_exec.add(key)
            out["process_events"].append(event)
        elif kind == "file":
            out["file_events"].append(event)
        elif kind == "socket":
            out["socket_events"].append(event)
        elif kind == "control":
            out["control_events"].append(event)

    if sensitive_only:
        out["file_events"] = [e for e in out["file_events"] if e.get("sensitive")]

    return out


def summarise_telemetry(
    parsed: dict,
    telemetry_limited_process: bool = False,
) -> dict:
    """Build the compact ``process_activity`` block stored in phase records.

    Parameters
    ----------
    parsed:
        Output of ``parse_strace_log()``.
    telemetry_limited_process:
        True when the strace log was absent/empty (ptrace denied, strace not
        installed, or the container crashed before writing).  Downstream treats
        ``any_suspicious=False`` as a potential false negative in that case.

    ``any_suspicious`` is True when any of:
    * suspicious process spawns (curl, wget, bash, etc.)
    * sensitive file accesses (ssh keys, credentials, /proc/*/environ, …)
    * ptrace calls from package code (always suspicious)
    """
    process_events  = parsed.get("process_events",  [])
    file_events     = parsed.get("file_events",     [])
    socket_events   = parsed.get("socket_events",   [])
    control_events  = parsed.get("control_events",  [])

    suspicious_execs   = [e for e in process_events  if e.get("suspicious")]
    sensitive_files    = [e for e in file_events      if e.get("sensitive")]
    ptrace_events      = [e for e in control_events   if e["syscall"] == "ptrace"]

    any_suspicious = bool(suspicious_execs or sensitive_files or ptrace_events)

    return {
        "process_count":             len(process_events),
        "any_suspicious":            any_suspicious,
        "telemetry_limited_process": telemetry_limited_process,
        "suspicious_execs": [
            {"pid": e["pid"], "executable": e["executable"], "argv": e["argv"]}
            for e in suspicious_execs
        ],
        "sensitive_file_accesses": [
            {
                "pid":               e["pid"],
                "path":              e["path"],
                "access_type":       e["access_type"],
                "sensitive_category": e.get("sensitive_category"),
            }
            for e in sensitive_files
        ],
        "socket_connections": [
            {k: e[k] for k in ("pid", "ts", "syscall", "family",
                                "dest_ip", "dest_port") if k in e}
            for e in socket_events
            if e.get("dest_ip")              # only connect() events with a destination
        ],
        "control_events": [
            {k: e[k] for k in e if k != "args_raw"}  # omit raw strace args
            for e in control_events
        ],
    }


# ── normalized JSONL schema ───────────────────────────────────────────────────

def _infer_protocol(event: dict) -> str | None:
    """Derive 'tcp'/'udp' from SOCK_* type when available; None otherwise."""
    sock_type = event.get("sock_type", "")
    if "SOCK_STREAM" in sock_type:
        return "tcp"
    if "SOCK_DGRAM" in sock_type:
        return "udp"
    return None


def _exec_to_jsonl(event: dict, phase: str) -> dict:
    return {
        "ts":         event.get("ts"),
        "phase":      phase,
        "event_type": "exec",
        "pid":        event["pid"],
        "ppid":       None,   # requires clone/fork tracing; not yet captured
        "exe":        event.get("executable"),
        "argv":       event.get("argv", []),
        "suspicious": event.get("suspicious", False),
    }


def _file_to_jsonl(event: dict, phase: str) -> dict:
    rec: dict = {
        "ts":                 event.get("ts"),
        "phase":              phase,
        "event_type":         "file",
        "pid":                event["pid"],
        "op":                 event.get("syscall"),
        "path":               event.get("path"),
        "sensitive":          event.get("sensitive", False),
        "sensitive_category": event.get("sensitive_category"),
        "mode":               event.get("access_type"),
    }
    # Carry extra fields for specific syscalls without clobbering `mode`.
    if "dest_path" in event:
        rec["dest_path"]   = event["dest_path"]
    if event.get("syscall") == "chmod":
        rec["chmod_mode"]  = event.get("mode")  # permission bits (e.g. "755")
    if event.get("syscall") == "chown":
        rec["uid"]         = event.get("uid")
        rec["gid"]         = event.get("gid")
    return rec


def _socket_to_jsonl(event: dict, phase: str) -> dict:
    return {
        "ts":         event.get("ts"),
        "phase":      phase,
        "event_type": "socket",
        "pid":        event["pid"],
        "op":         event.get("syscall"),
        "dst_ip":     event.get("dest_ip"),
        "dst_port":   event.get("dest_port"),
        "protocol":   _infer_protocol(event),
        "family":     event.get("family"),
    }


def _control_to_jsonl(event: dict, phase: str) -> dict:
    rec: dict = {
        "ts":         event.get("ts"),
        "phase":      phase,
        "event_type": "control",
        "pid":        event["pid"],
        "op":         event.get("syscall"),
    }
    if event.get("syscall") == "kill":
        rec["target_pid"] = event.get("target_pid")
        rec["signal"]     = event.get("signal")
    return rec


def iter_phase_jsonl(parsed: dict, phase: str) -> Iterator[dict]:
    """Yield canonical telemetry.jsonl records from parse_strace_log() output.

    Records are emitted in declaration order: exec → file → socket → control.
    Each record carries the phase name so multi-phase JSONL files stay sortable
    by (phase, ts) without consulting the enclosing run.json.
    """
    for event in parsed.get("process_events", []):
        yield _exec_to_jsonl(event, phase)
    for event in parsed.get("file_events", []):
        yield _file_to_jsonl(event, phase)
    for event in parsed.get("socket_events", []):
        yield _socket_to_jsonl(event, phase)
    for event in parsed.get("control_events", []):
        yield _control_to_jsonl(event, phase)


# ── backwards-compat shims ────────────────────────────────────────────────────
# Kept so callers written before Direction 8 expansion still compile.

def parse_strace_execve(raw_text: str) -> list[dict]:
    """Thin wrapper — returns only the process_events from parse_strace_log()."""
    return parse_strace_log(raw_text)["process_events"]


def summarise_process_telemetry(
    events: list[dict],
    telemetry_limited_process: bool = False,
) -> dict:
    """Thin wrapper — converts a bare process_events list to the full summary."""
    parsed = {
        "process_events": events,
        "file_events":    [],
        "socket_events":  [],
        "control_events": [],
    }
    return summarise_telemetry(parsed, telemetry_limited_process)
