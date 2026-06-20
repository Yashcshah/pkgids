#!/usr/bin/env python3
"""
pkgids fake-internet appliance.

Resolves every DNS hostname to itself and catches all TCP connections on
common ports, writing JSONL logs to /logs/<src_ip>.jsonl so each detonation
container gets its own capture file (keyed by its IP on detonet).

No real internet traffic is generated or forwarded.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from pathlib import Path

LOG_DIR = Path(os.environ.get("LOG_DIR", "/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

TCP_PORTS = [21, 25, 80, 443, 8080]

_own_ip_cache: str | None = None


# ── own-IP discovery ─────────────────────────────────────────────────────────

def _own_ip() -> str:
    """Return this container's primary IP without sending any packets."""
    global _own_ip_cache
    if _own_ip_cache:
        return _own_ip_cache
    for target in ("8.8.8.8", "10.0.0.1", "192.168.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip not in ("0.0.0.0", "127.0.0.1"):
                _own_ip_cache = ip
                return ip
        except Exception:
            pass
    fallback = os.environ.get("FAKEINTERNET_IP", "0.0.0.0")
    _own_ip_cache = fallback
    return fallback


# ── logging ──────────────────────────────────────────────────────────────────

def _log(src_ip: str, event: dict) -> None:
    path = LOG_DIR / f"{src_ip}.jsonl"
    with open(path, "a") as fh:
        fh.write(json.dumps(event, default=str) + "\n")


# ── DNS ──────────────────────────────────────────────────────────────────────

def _dns_parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name at *offset*; return (dotted-name, offset-after-name)."""
    labels: list[str] = []
    visited: set[int] = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _dns_parse_name(data, ptr)
            labels.append(sub)
            offset += 2
            break
        labels.append(
            data[offset + 1 : offset + 1 + length].decode("ascii", errors="replace")
        )
        offset += 1 + length
    return ".".join(labels), offset


def _dns_response(query: bytes, answer_ip: str) -> bytes | None:
    """Build a minimal DNS response that resolves everything to *answer_ip*."""
    try:
        txn_id = query[:2]
        flags = b"\x81\x80"           # QR=1 AA=0 TC=0 RD=1 RA=1 RCODE=0
        qdcount_raw = query[4:6]

        name, qend = _dns_parse_name(query, 12)
        if len(query) < qend + 4:
            return None               # malformed

        qtype = struct.unpack("!H", query[qend : qend + 2])[0]
        question = query[12 : qend + 4]  # name + QTYPE + QCLASS

        if qtype == 1:  # A record → resolve to our IP
            ancount = b"\x00\x01"
            answer = (
                b"\xc0\x0c"               # pointer to question name (offset 12)
                + b"\x00\x01"            # TYPE A
                + b"\x00\x01"            # CLASS IN
                + b"\x00\x00\x00\x3c"   # TTL 60 s
                + b"\x00\x04"            # RDLENGTH 4
                + socket.inet_aton(answer_ip)
            )
        else:
            # AAAA, PTR, etc. — NOERROR, 0 answers so clients fall back to A
            ancount = b"\x00\x00"
            answer = b""

        header = txn_id + flags + qdcount_raw + ancount + b"\x00\x00\x00\x00"
        return header + question + answer
    except Exception:
        return None


def _dns_server(our_ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print(f"[dns]  UDP/53  → resolving everything to {our_ip}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
            src_ip = addr[0]
            try:
                name, _ = _dns_parse_name(data, 12)
            except Exception:
                name = "<parse-error>"

            event = {
                "ts": time.time(),
                "type": "dns",
                "src": src_ip,
                "query": name,
                "resolved_to": our_ip,
            }
            _log(src_ip, event)
            print(f"[dns]  {src_ip} → {name!r} → {our_ip}", flush=True)

            resp = _dns_response(data, our_ip)
            if resp:
                sock.sendto(resp, addr)
        except Exception as exc:
            print(f"[dns]  error: {exc}", flush=True)


# ── TLS SNI extraction ────────────────────────────────────────────────────────

def _tls_sni(data: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello, or return None."""
    try:
        # TLS record: type(1) version(2) length(2) | handshake type(1) length(3)
        if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None

        idx = 9               # start of ClientHello body
        idx += 2              # client_version
        idx += 32             # random

        if idx >= len(data):
            return None
        sess_len = data[idx]
        idx += 1 + sess_len

        if idx + 2 > len(data):
            return None
        cipher_len = struct.unpack("!H", data[idx : idx + 2])[0]
        idx += 2 + cipher_len

        if idx >= len(data):
            return None
        comp_len = data[idx]
        idx += 1 + comp_len

        if idx + 2 > len(data):
            return None
        ext_total = struct.unpack("!H", data[idx : idx + 2])[0]
        idx += 2
        ext_end = idx + ext_total

        while idx + 4 <= ext_end and idx + 4 <= len(data):
            ext_type = struct.unpack("!H", data[idx : idx + 2])[0]
            ext_len  = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
            idx += 4
            if ext_type == 0 and idx + 5 <= len(data):  # server_name
                # SNI list: list_len(2) name_type(1) name_len(2) name(...)
                name_len = struct.unpack("!H", data[idx + 3 : idx + 5])[0]
                if idx + 5 + name_len <= len(data):
                    return data[idx + 5 : idx + 5 + name_len].decode(
                        "ascii", errors="replace"
                    )
            idx += ext_len
    except Exception:
        pass
    return None


# ── HTTP header extraction ────────────────────────────────────────────────────

def _http_info(data: bytes) -> tuple[str | None, str | None]:
    """Return (Host header value, request-line) from raw HTTP data."""
    try:
        text = data.decode("latin-1")
        lines = text.split("\r\n")
        req_line = lines[0] if lines else None
        host = next(
            (l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("host:")),
            None,
        )
        return host, req_line
    except Exception:
        return None, None


# ── TCP catch-all ─────────────────────────────────────────────────────────────

def _handle_conn(conn: socket.socket, addr: tuple, port: int) -> None:
    src_ip = addr[0]
    try:
        conn.settimeout(5.0)
        payload = b""
        try:
            payload = conn.recv(4096)
        except (socket.timeout, OSError):
            pass

        event: dict = {
            "ts":            time.time(),
            "type":          "tcp",
            "src":           src_ip,
            "dst_port":      port,
            "payload_bytes": len(payload),
        }

        if port in (80, 8080):
            host, req_line = _http_info(payload)
            event.update(protocol="http", host=host, request_line=req_line)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            label = f"http host={host!r} req={req_line!r}"
        elif port == 443:
            sni = _tls_sni(payload)
            event.update(protocol="tls", sni=sni)
            # Don't attempt a TLS handshake — just log and drop
            label = f"tls sni={sni!r}"
        elif port == 25:
            conn.sendall(b"220 fakeinternet SMTP\r\n")
            event.update(protocol="smtp")
            label = "smtp"
        elif port == 21:
            conn.sendall(b"220 fakeinternet FTP\r\n")
            event.update(protocol="ftp")
            label = "ftp"
        else:
            event.update(protocol="tcp", payload_hex=payload[:64].hex())
            label = f"tcp payload={len(payload)}B"

        _log(src_ip, event)
        print(f"[tcp:{port}]  {src_ip}  {label}", flush=True)

    except Exception as exc:
        print(f"[tcp:{port}]  error from {src_ip}: {exc}", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _tcp_listener(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(128)
    print(f"[tcp]  TCP/{port}  listening", flush=True)
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(
                target=_handle_conn, args=(conn, addr, port), daemon=True
            ).start()
        except Exception as exc:
            print(f"[tcp:{port}]  accept error: {exc}", flush=True)


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    our_ip = _own_ip()
    print(f"[fakeinternet]  starting — own IP {our_ip}", flush=True)
    print(f"[fakeinternet]  logs → {LOG_DIR}", flush=True)

    threads: list[threading.Thread] = [
        threading.Thread(target=_dns_server, args=(our_ip,), daemon=True),
        *(
            threading.Thread(target=_tcp_listener, args=(p,), daemon=True)
            for p in TCP_PORTS
        ),
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("[fakeinternet]  shutting down", flush=True)


if __name__ == "__main__":
    main()
