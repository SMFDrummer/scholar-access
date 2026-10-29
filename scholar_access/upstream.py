"""上游解析：学校 DoH（RFC 8484）与系统 DNS 回退。"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import dnsmsg

DEFAULT_SCHOOL_DOH = "https://doh.scholar.work/dns-query"

# 校园网内这两台最稳；后面的公共 DNS 只作兜底
DEFAULT_SYS_DNS = ["59.49.49.49", "219.149.135.188", "223.5.5.5", "119.29.29.29"]

USER_AGENT = "scholar-access/1.0 (+https://github.com/)"


class _UpstreamError(RuntimeError):
    pass


class SchoolDoH:
    """带连接复用 + 并发上限的学校 DoH 客户端。

    注意：绝对不要手工设置 ``Host`` 头，``http.client`` 会自动补，
    重复的 Host 会被服务端直接拒绝（这是第一版每次静默回落的原因）。
    """

    def __init__(self, url: str = DEFAULT_SCHOOL_DOH, *, timeout: float = 2.5,
                 pool_size: int = 6, idle: float = 25.0, log=None):
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("学校 DoH 地址必须是 https://：%r" % url)
        self.url = url
        self.host = parts.hostname or ""
        self.port = parts.port or 443
        self.path = parts.path or "/dns-query"
        if parts.query:
            self.path += "?" + parts.query
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._pool: list[list] = []          # [[conn, last_used_ts], ...]
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max(1, pool_size))
        self._idle = idle
        self._log = log or (lambda *a, **k: None)
        self.requests = 0
        self.failures = 0

    # --- 连接池 ---------------------------------------------------------
    def _new_conn(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(
            self.host, self.port, timeout=self.timeout, context=self._ctx
        )

    def _borrow(self):
        now = time.time()
        with self._lock:
            while self._pool:
                conn, ts = self._pool.pop()
                if now - ts <= self._idle and conn.sock is not None:
                    return conn, True
                try:
                    conn.close()
                except Exception:
                    pass
        return self._new_conn(), False

    def _give_back(self, conn) -> None:
        with self._lock:
            if len(self._pool) < 8:
                self._pool.append([conn, time.time()])
                return
        try:
            conn.close()
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, []
        for conn, _ts in pool:
            try:
                conn.close()
            except Exception:
                pass

    # --- 查询 -----------------------------------------------------------
    def query(self, packet: bytes) -> bytes | None:
        """POST 原始报文，返回原始响应；失败返回 None（不抛异常）。"""
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "User-Agent": USER_AGENT,
        }
        with self._sem:
            self.requests += 1
            for attempt in range(2):
                conn, reused = self._borrow()
                try:
                    self._log("doh send attempt=%d reused=%s host=%s" %
                              (attempt, reused, self.host))
                    conn.request("POST", self.path, body=packet, headers=headers)
                    resp = conn.getresponse()
                    body = resp.read()
                    if resp.status != 200:
                        raise _UpstreamError("HTTP %d" % resp.status)
                    self._give_back(conn)
                    return body or None
                except Exception as exc:
                    self.failures += 1
                    try:
                        conn.close()
                    except Exception:
                        pass
                    if attempt == 1:
                        self._log("doh failed: %r" % (exc,))
                        return None
                    time.sleep(0.05)
        return None


def udp_query(packet: bytes, server: str, timeout: float = 1.2) -> bytes | None:
    """经典 UDP 查询；被截断时自动改走 TCP。"""
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        while True:
            data, addr = sock.recvfrom(dnsmsg.MAX_PACKET)
            if addr[0] == server and dnsmsg.packet_id(data) == dnsmsg.packet_id(packet):
                break
        if dnsmsg.is_truncated(data):
            tcp = _tcp_query(packet, server, timeout)
            return tcp or data
        return data
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _tcp_query(packet: bytes, server: str, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        head = _recv_exact(sock, 2)
        if not head:
            return None
        length = struct.unpack("!H", head)[0]
        return _recv_exact(sock, length)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class SystemDNS:
    """系统 DNS 列表上的顺序回退查询。"""

    def __init__(self, servers: list[str] | None = None, *, timeout: float = 1.2, log=None):
        self.servers = [s for s in (servers or detect_system_dns()) if s]
        self.timeout = timeout
        self._log = log or (lambda *a, **k: None)
        self.queries = 0

    def query(self, packet: bytes) -> bytes | None:
        self.queries += 1
        for server in self.servers:
            started = time.time()
            response = udp_query(packet, server, self.timeout)
            if response and dnsmsg.rcode_of(response) in (0, 3, 5):
                self._log("udp %s %dms" % (server, int((time.time() - started) * 1000)))
                return response
        return None

    def describe(self) -> str:
        return ", ".join(self.servers) if self.servers else "(未检测到)"


# ------------------------------------------------------------ 系统 DNS 探测 ---

def detect_system_dns(cache_dir: Path | None = None, max_age: float = 3600.0) -> list[str]:
    """探测本机 DNS；结果缓存在 cache_dir，避免每次启动都调用系统命令。"""
    if cache_dir is not None:
        cached = _read_cache(cache_dir, max_age)
        if cached:
            return cached
    servers = _probe_platform()
    if not servers:
        servers = list(DEFAULT_SYS_DNS)
    if cache_dir is not None:
        _write_cache(cache_dir, servers)
    return servers


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / "sysdns.json"


def _read_cache(cache_dir: Path, max_age: float) -> list[str]:
    try:
        data = json.loads(_cache_path(cache_dir).read_text("utf-8"))
        if time.time() - float(data.get("ts", 0)) > max_age:
            return []
        servers = [str(s) for s in data.get("servers", []) if s]
        return servers if servers else []
    except Exception:
        return []


def _write_cache(cache_dir: Path, servers: list[str]) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache_path(cache_dir).write_text(
            json.dumps({"ts": time.time(), "servers": servers}), "utf-8"
        )
    except Exception:
        pass


def _probe_platform() -> list[str]:
    try:
        if os.name == "nt":
            return _probe_windows()
        if os.uname().sysname == "Darwin":  # type: ignore[attr-defined]
            return _probe_macos()
        return _probe_resolvconf()
    except Exception:
        return []


def _probe_windows() -> list[str]:
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-DnsClientServerAddress -AddressFamily IPv4 |"
        " Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notmatch 'Loopback' } |"
        " ForEach-Object { $_.ServerAddresses } | Select-Object -Unique"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=25,
    )
    servers = [line.strip() for line in (out.stdout or "").splitlines() if line.strip()]
    return [s for s in servers if _looks_like_ip(s)]


def _probe_macos() -> list[str]:
    out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=15)
    servers = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("nameserver["):
            value = line.split(":", 1)[-1].strip()
            if _looks_like_ip(value) and value not in servers:
                servers.append(value)
    return servers


def _probe_resolvconf() -> list[str]:
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                value = line.split()[1]
                if _looks_like_ip(value) and value not in servers:
                    servers.append(value)
    except OSError:
        pass
    return servers


def _looks_like_ip(text: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, text)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, text)
            return True
        except OSError:
            return False
