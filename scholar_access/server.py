"""本地 DoH 服务端（RFC 8484）+ 状态接口。

浏览器要求 DoH 模板必须是 **https**（写 http:// 时 Chromium 一个请求都不发，
只会在 netlog 里留一条被拒绝的配置），所以默认走 TLS。
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import dnsmsg

DNS_MEDIA_TYPE = "application/dns-message"
MAX_BODY = 8192


class _QuietServer(ThreadingHTTPServer):
    """浏览器取消请求会产生 ConnectionAborted/Reset，不该刷 traceback。"""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:  # noqa: D102
        exc = sys.exc_info()[1]
        name = type(exc).__name__ if exc else "unknown"
        # 浏览器取消连接是常态（切标签、停止加载），不值得打 traceback
        if name in {"ConnectionAbortedError", "ConnectionResetError",
                    "BrokenPipeError", "TimeoutError"}:
            return
        try:
            self.log("connection error from %s: %s: %s" %
                     (client_address[0], name, exc))
        except Exception:
            pass

    def log(self, message: str) -> None:
        sink = getattr(self, "log_sink", None)
        if sink:
            sink(message)
        else:
            sys.stderr.write(message + "\n")


class DoHRequestHandler(BaseHTTPRequestHandler):
    server_version = "scholar-access/1.0"
    protocol_version = "HTTP/1.1"

    # 由 make_server 注入
    router = None
    stats_provider = None

    def log_message(self, fmt: str, *args) -> None:  # 交给上层统一日志
        if getattr(self.server, "quiet", True):
            return
        self.server.log("http %s" % (fmt % args))

    # --- 路由 -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/dns-query":
            self._handle_dns_get()
        elif path == "/stats":
            self._send_json(self._stats())
        elif path in ("/healthz", "/health"):
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path != "/dns-query":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            self._send_json({"error": "bad length"}, status=HTTPStatus.BAD_REQUEST)
            return
        packet = self.rfile.read(length)
        self._answer(packet)

    # --- DNS ------------------------------------------------------------
    def _handle_dns_get(self) -> None:
        query = parse_qs(urlsplit(self.path).query)
        raw = (query.get("dns") or [""])[0]
        if not raw:
            self._send_json({"error": "missing dns parameter"},
                            status=HTTPStatus.BAD_REQUEST)
            return
        try:
            packet = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception:
            self._send_json({"error": "bad base64url"}, status=HTTPStatus.BAD_REQUEST)
            return
        self._answer(packet)

    def _answer(self, packet: bytes) -> None:
        if len(packet) < 12:
            self._send_json({"error": "short packet"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            response = self.router.resolve(packet)
        except Exception as exc:                      # 兜底：绝不把异常抛给浏览器
            self.server.log("resolve error: %r" % (exc,))
            response = dnsmsg.make_servfail(packet)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", DNS_MEDIA_TYPE)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

    # --- 其它 -----------------------------------------------------------
    def _stats(self) -> dict:
        if self.stats_provider is None:
            return {"ok": False}
        return self.stats_provider()

    def _send_json(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(router, *, host: str = "127.0.0.1", port: int = 5380,
                certfile=None, keyfile=None, stats_provider=None, log=None,
                quiet: bool = True) -> ThreadingHTTPServer:
    handler = type("BoundDoHHandler", (DoHRequestHandler,), {})
    handler.router = router
    handler.stats_provider = stats_provider

    httpd = _QuietServer((host, port), handler)
    httpd.quiet = quiet
    httpd.log_sink = log
    httpd.log = log or (lambda msg: None)

    if certfile and keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        httpd.scheme = "https"
    else:
        httpd.scheme = "http"
    return httpd


def serve_forever(httpd: ThreadingHTTPServer, *, on_start=None) -> None:
    if on_start:
        on_start(httpd)
    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


def serve_in_thread(httpd: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=serve_forever, args=(httpd,), daemon=True)
    thread.start()
    return thread
