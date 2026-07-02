"""Cross-stream correlation of telemetry.jsonl and network.jsonl.

Answers questions like:
  - Which process initiated a network connection?
  - Which sensitive file was read before exfiltration?
  - Did a shell spawn precede a DNS lookup?
  - Did a subprocess execute the actual payload?
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

CORRELATION_WINDOW_SECS: float = 5.0

_SHELL_BASENAMES: frozenset[str] = frozenset({
    "sh", "bash", "dash", "zsh", "ksh", "ash",
})


# ── I/O helpers ───────────────────────────────────────────────────────────────

def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file and return all parseable records; silently skip bad lines."""
    if not path.exists():
        return []
    out: list[dict] = []
    for raw in path.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return out


# ── correlation helpers ───────────────────────────────────────────────────────

def _attribute_connections(
    telemetry: list[dict],
    pid_last_exec: dict[int, dict],
) -> list[dict]:
    """For each socket connect event, attach the exec record of the same PID."""
    out: list[dict] = []
    for ev in telemetry:
        if ev.get("event_type") != "socket" or ev.get("op") != "connect":
            continue
        if not ev.get("dst_ip"):
            continue
        proc = pid_last_exec.get(ev["pid"])
        out.append({
            "ts":       ev.get("ts"),
            "phase":    ev.get("phase"),
            "pid":      ev["pid"],
            "dst_ip":   ev["dst_ip"],
            "dst_port": ev.get("dst_port"),
            "protocol": ev.get("protocol"),
            "initiated_by": {
                "exe":        proc["exe"]        if proc else None,
                "argv":       proc["argv"]       if proc else None,
                "suspicious": proc["suspicious"] if proc else None,
            } if proc else None,
        })
    return out


def _network_attributed(
    telemetry: list[dict],
    network: list[dict],
    pid_last_exec: dict[int, dict],
) -> list[dict]:
    """For each fakeinternet network entry, attach the closest preceding exec event."""
    # Build a ts-sorted list of all exec events for fast nearest-predecessor search.
    execs = sorted(
        [e for e in telemetry if e.get("event_type") == "exec"],
        key=lambda x: x.get("ts") or 0,
    )
    out: list[dict] = []
    for net in network:
        net_ts = float(net.get("ts") or 0)
        # Closest exec that started before this network event, within the window.
        candidates = [
            e for e in execs
            if (e.get("ts") or 0) <= net_ts
            and net_ts - (e.get("ts") or 0) <= CORRELATION_WINDOW_SECS
        ]
        responsible = max(candidates, key=lambda x: x.get("ts") or 0) if candidates else None
        out.append({**net, "responsible_process": responsible})
    return out


def _file_before_exfil(
    telemetry: list[dict],
    network: list[dict],
) -> list[dict]:
    """Find sensitive file reads that precede network activity within the window.

    Considers both syscall-level socket connects (from telemetry.jsonl) and
    fakeinternet-level network entries (from network.jsonl).
    """
    sensitive_reads = [
        e for e in telemetry
        if e.get("event_type") == "file"
        and e.get("sensitive")
        and e.get("mode") == "read"
    ]
    socket_connects = [
        e for e in telemetry
        if e.get("event_type") == "socket"
        and e.get("op") == "connect"
        and e.get("dst_ip")
    ]
    # Combine both network signal sources; use a minimal common shape.
    net_signals: list[dict] = [
        {"ts": e.get("ts"), "src": "syscall", "dst_ip": e.get("dst_ip"),
         "dst_port": e.get("dst_port"), "pid": e.get("pid")}
        for e in socket_connects
    ] + [
        {"ts": n.get("ts"), "src": "fakeinternet",
         "dst_ip": n.get("host"), "dst_port": n.get("port"), "pid": None}
        for n in network
    ]

    pairs: list[dict] = []
    for read_ev in sensitive_reads:
        read_ts = float(read_ev.get("ts") or 0)
        following = [
            s for s in net_signals
            if s["ts"] is not None
            and 0 <= (float(s["ts"]) - read_ts) <= CORRELATION_WINDOW_SECS
        ]
        if following:
            pairs.append({
                "file_read":         read_ev,
                "following_network": following,
            })
    return pairs


def _shell_before_network(
    telemetry: list[dict],
    network: list[dict],
) -> list[dict]:
    """Find shell exec events that precede network activity within the window."""
    shell_execs = [
        e for e in telemetry
        if e.get("event_type") == "exec"
        and (e.get("exe") or "").rsplit("/", 1)[-1] in _SHELL_BASENAMES
    ]
    socket_connects = [
        e for e in telemetry
        if e.get("event_type") == "socket"
        and e.get("op") == "connect"
        and e.get("dst_ip")
    ]
    net_signals: list[dict] = [
        {"ts": e.get("ts"), "src": "syscall", "dst_ip": e.get("dst_ip"), "pid": e.get("pid")}
        for e in socket_connects
    ] + [
        {"ts": n.get("ts"), "src": "fakeinternet", "dst_ip": n.get("host"), "pid": None}
        for n in network
    ]

    results: list[dict] = []
    for shell in shell_execs:
        shell_ts = float(shell.get("ts") or 0)
        following = [
            s for s in net_signals
            if s["ts"] is not None
            and 0 <= (float(s["ts"]) - shell_ts) <= CORRELATION_WINDOW_SECS
        ]
        if following:
            results.append({
                "shell_exec":        shell,
                "following_network": following,
            })
    return results


def _subprocess_payloads(telemetry: list[dict]) -> list[dict]:
    """Detect suspicious execs that appear to be spawned by the root installer.

    Pattern: a non-suspicious exec (pip3/npm) runs first, then later a suspicious
    exec (curl, bash, python, etc.) appears with a different PID.  The most recent
    non-suspicious exec before the payload is recorded as the potential parent.
    """
    execs = sorted(
        [e for e in telemetry if e.get("event_type") == "exec"],
        key=lambda x: x.get("ts") or 0,
    )
    suspicious = [e for e in execs if e.get("suspicious")]

    payloads: list[dict] = []
    for susp in suspicious:
        susp_ts = float(susp.get("ts") or 0)
        potential_parents = [
            e for e in execs
            if e["pid"] != susp["pid"]
            and float(e.get("ts") or 0) < susp_ts
            and not e.get("suspicious")
        ]
        parent = (
            max(potential_parents, key=lambda x: x.get("ts") or 0)
            if potential_parents else None
        )
        payloads.append({
            "payload_exec":     susp,
            "potential_parent": parent,
        })
    return payloads


# ── public API ────────────────────────────────────────────────────────────────

def analyze(run_dir: str | Path) -> dict:
    """Cross-correlate telemetry.jsonl and network.jsonl in *run_dir*.

    Returns a dict with correlation findings grouped by query type.
    Also writes ``correlations.json`` into *run_dir* for offline inspection.

    Parameters
    ----------
    run_dir:
        Path to a run directory produced by ``capture.run()``.  Must contain
        ``telemetry.jsonl`` and/or ``network.jsonl``; missing files are silently
        treated as empty (no telemetry / no network events).

    Returns
    -------
    dict with keys:
        connections_attributed  — each connect() event annotated with its process
        network_attributed      — each fakeinternet event annotated with a process
        file_before_exfil       — sensitive file reads that precede network activity
        shell_before_network    — shell spawn events that precede network activity
        subprocess_payloads     — suspicious child execs and their likely parent
        summary                 — aggregate counts
    """
    run_dir    = Path(run_dir)
    telemetry  = _read_jsonl(run_dir / "telemetry.jsonl")
    network    = _read_jsonl(run_dir / "network.jsonl")

    # pid → most recent exec record (last exec by a PID overrides earlier ones)
    pid_last_exec: dict[int, dict] = {}
    for ev in sorted(
        [e for e in telemetry if e.get("event_type") == "exec"],
        key=lambda x: x.get("ts") or 0,
    ):
        pid_last_exec[ev["pid"]] = ev

    connections  = _attribute_connections(telemetry, pid_last_exec)
    net_attr     = _network_attributed(telemetry, network, pid_last_exec)
    file_exfil   = _file_before_exfil(telemetry, network)
    shell_net    = _shell_before_network(telemetry, network)
    sub_payloads = _subprocess_payloads(telemetry)

    result: dict = {
        "connections_attributed": connections,
        "network_attributed":     net_attr,
        "file_before_exfil":      file_exfil,
        "shell_before_network":   shell_net,
        "subprocess_payloads":    sub_payloads,
        "summary": {
            "total_telemetry_events":  len(telemetry),
            "total_network_events":    len(network),
            "attributed_connections":  sum(1 for c in connections if c["initiated_by"]),
            "file_exfil_pairs":        len(file_exfil),
            "shell_before_network":    len(shell_net),
            "subprocess_payloads":     len(sub_payloads),
        },
    }

    (run_dir / "correlations.json").write_text(json.dumps(result, indent=2))
    return result
