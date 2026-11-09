"""Local web interface: ``pqcscan ui``.

A small HTTP server from the standard library. It only listens on 127.0.0.1,
and every request that runs a scan has to carry a random token that is baked
into the page when it is served. That stops other websites open in the same
browser from poking at the local API, and the Host check stops DNS rebinding.
"""

from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, report
from .rules import RULES
from .scanner import ScanOptions, scan_bytes_zip, scan_path

MAX_UPLOAD = 64 * 1024 * 1024
MAX_TLS_TARGETS = 20


def _page(token: str) -> bytes:
    html = resources.files("pqcscan").joinpath("web/index.html").read_text(encoding="utf-8")
    return (html.replace("{{TOKEN}}", token)
                .replace("{{VERSION}}", __version__)).encode("utf-8")


def _bundle(result) -> dict:
    """Everything the page needs: the JSON report plus the other formats as text."""
    return {
        "report": json.loads(report.to_json(result)),
        "files": {
            "pqc-report.json": report.to_json(result),
            "pqc-report.sarif": report.to_sarif(result),
            "cbom.cdx.json": report.to_cbom(result),
            "pqc-report.md": report.to_markdown(result),
        },
    }


def _rules() -> list[dict]:
    return [{"id": r.id, "title": r.title, "algorithm": r.algorithm, "kind": r.kind.value,
             "severity": r.severity.value, "langs": sorted(r.langs)} for r in RULES]


class Handler(BaseHTTPRequestHandler):
    server_version = f"pqcscan/{__version__}"
    token: str = ""
    allowed_hosts: set[str] = set()
    quiet = True

    def log_message(self, fmt, *args):  # keep the terminal clean
        if not self.quiet:
            super().log_message(fmt, *args)

    # helpers

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline' "
                             "https://fonts.googleapis.com; font-src 'self' data: "
                             "https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.allowed_hosts

    def _token_ok(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Pqcscan-Token", ""), self.token)

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_UPLOAD:
            return None
        return self.rfile.read(length)

    # routes

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, b"bad host", "text/plain")
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(200, _page(self.token), "text/html; charset=utf-8")
        if path == "/api/rules":
            return self._json(200, {"rules": _rules(), "version": __version__})
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if not self._host_ok() or not self._token_ok():
            return self._json(403, {"error": "forbidden"})
        path = urlparse(self.path)
        body = self._read_body()
        if body is None:
            return self._json(413, {"error": f"request too large (limit {MAX_UPLOAD // 2**20} MB)"})
        try:
            if path.path == "/api/scan/zip":
                opts = ScanOptions(include_tests="no_tests=1" not in (path.query or ""))
                result = scan_bytes_zip(body, opts)
                result.target = self.headers.get("X-Pqcscan-Filename", "upload.zip")[:200]
                return self._json(200, _bundle(result))
            if path.path == "/api/scan/path":
                req = json.loads(body or b"{}")
                target = Path(str(req.get("path", ""))).expanduser()
                if not target.exists():
                    return self._json(400, {"error": f"path not found: {target}"})
                opts = ScanOptions(include_tests=not req.get("no_tests"))
                return self._json(200, _bundle(scan_path(target, opts)))
            if path.path == "/api/tls":
                from .tls import scan_endpoints
                req = json.loads(body or b"{}")
                targets = [t.strip() for t in req.get("targets", []) if str(t).strip()]
                if not targets:
                    return self._json(400, {"error": "no hosts given"})
                if len(targets) > MAX_TLS_TARGETS:
                    return self._json(400, {"error": f"at most {MAX_TLS_TARGETS} hosts at a time"})
                return self._json(200, _bundle(scan_endpoints(targets, timeout=8.0)))
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad JSON"})
        except Exception as exc:   # report it in the page instead of dropping the connection
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
        return self._json(404, {"error": "unknown endpoint"})


def make_server(port: int = 8765, token: str | None = None) -> ThreadingHTTPServer:
    token = token or secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    real_port = httpd.server_address[1]
    Handler.token = token
    Handler.allowed_hosts = {f"127.0.0.1:{real_port}", f"localhost:{real_port}"}
    return httpd


def run(port: int = 8765, open_browser: bool = True) -> None:
    httpd = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"pqcscan {__version__} is running at {url}")
    print("Only this computer can reach it. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
