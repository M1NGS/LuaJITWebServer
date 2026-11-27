#!/usr/bin/env python3
"""Implicit config table -> FFI: C calls httpd_config.load(cfg) after config.lua.

The user only edits a plain table (`config = {...}; return config`); the injected
bytecode library reads cfg.log and writes g_config.log via FFI.
"""
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, free_port, http_request,
                     start_expect_failure)

NAME = "13_ffi_config"
ERROR_APP = Path(__file__).resolve().parents[1] / "fixtures" / "error_app.lua"


def table_cfg(port, log_lua, app=ERROR_APP):
    return f"""return {{
  server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  log = {log_lua},
  app = "{app}"
}}
"""


def no_return_cfg(port, log_lua):
    return f"""config = {{
  server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  log = {log_lua},
  app = "{ERROR_APP}"
}}
"""


def method_cfg(port, d):
    return f"""local cfg = httpd_config
cfg.log.file{{ access_path = "{d}/method-access.log",
  error_path = "{d}/method-error.log", flush_interval = 0.05 }}
return {{ server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  app = "{ERROR_APP}" }}
"""


class UdpMock:
    def __init__(self):
        self.msgs = []
        self._stop = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.msgs.append(self.sock.recv(8192))
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self._stop = True
        self.thread.join(timeout=1)
        self.sock.close()


class OtlpMock:
    def __init__(self):
        self.requests = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                app.requests.append((self.path, self.rfile.read(n)))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, fmt, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.thread.join(timeout=2)
        self.httpd.server_close()


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-ffi-cfg-") as td:
        d = Path(td)

        # ---- implicit table: file + syslog (access disabled, error only) ----
        port = free_port()
        mock = UdpMock()
        access = d / "ffi-access.log"
        error = d / "ffi-error.log"
        log_lua = f"""{{
    level = "info",
    file = {{ access_path = "{access}", error_path = "{error}", flush_interval = 0.05 }},
    syslog = {{ enabled = true, transport = "udp", host = "127.0.0.1",
                port = {mock.port}, access = false, error = true, level = "warn" }}
  }}"""
        try:
            with Server(table_cfg(port, log_lua), port, name=NAME) as srv:
                st, _, _ = http_request(port, "/")
                http_request(port, "/boom", timeout=5)
                time.sleep(0.5)
                srvlog = srv.log()
        finally:
            mock.close()
        text = access.read_text(errors="replace") if access.exists() else ""
        err = error.read_text(errors="replace") if error.exists() else ""
        msgs = [m.decode("utf-8", "replace") for m in mock.msgs]
        r.case("table: request served", st == 200, f"status={st}")
        r.case("table: file access written",
               '"GET / HTTP/1.1" 200' in text, text.splitlines()[:1])
        r.case("table: file error written", "[info]" in err, err.splitlines()[:1])
        r.case("table: syslog receives only error",
               any("handler error" in m for m in msgs) and
               not any('"GET /' in m for m in msgs),
               str(msgs[:1]))
        r.case("table: ABI check passed", "mismatch" not in srvlog, srvlog[-120:])

        # ---- implicit table: otlp ----
        port = free_port()
        mock = OtlpMock()
        log_lua = f"""{{
    otlp = {{ enabled = true, endpoint = "http://127.0.0.1:{mock.port}",
              batch_max_records = 10, flush_interval = 0.2, timeout = 1 }}
  }}"""
        try:
            with Server(table_cfg(port, log_lua), port, name=NAME):
                for _ in range(10):
                    http_request(port, "/")
                time.sleep(1.0)
        finally:
            mock.close()
        paths = [p for p, _ in mock.requests]
        bodies = [b for _, b in mock.requests]
        r.case("table: otlp POST /v1/logs",
               bool(paths) and all(p == "/v1/logs" for p in paths), str(paths[:3]))
        r.case("table: otlp access scope", any(b"httpd.access" in b for b in bodies))
        r.case("table: otlp resource service.name",
               any(b"service.name" in b for b in bodies))

        # ---- table: global config without return ----
        port = free_port()
        plain = d / "plain-access.log"
        log_lua = f"""{{
    file = {{ access_path = "{plain}", error_path = "{d}/plain-error.log", flush_interval = 0.05 }}
  }}"""
        with Server(no_return_cfg(port, log_lua), port, name=NAME):
            http_request(port, "/")
        r.case("table: global config without return works",
               plain.exists() and '"GET / HTTP/1.1" 200' in plain.read_text(errors="replace"))

        # ---- table: older flat log fields ----
        port = free_port()
        flat = d / "flat-access.log"
        log_lua = f'{{ access = "{flat}", error = "{d}/flat-error.log", flush_interval = 0.05 }}'
        with Server(table_cfg(port, log_lua), port, name=NAME):
            http_request(port, "/")
        r.case("table: legacy flat log fields work",
               flat.exists() and '"GET / HTTP/1.1" 200' in flat.read_text(errors="replace"))

        # ---- method API still works (optional) ----
        port = free_port()
        with Server(method_cfg(port, d), port, name=NAME):
            http_request(port, "/")
        r.case("method API still works",
               (d / "method-access.log").exists() and
               '"GET / HTTP/1.1" 200' in (d / "method-access.log").read_text(errors="replace"))

        # ---- large size fields (LuaJIT << is 32-bit: 1<<40 == 256 regression) ----
        port = free_port()
        big = d / "big-access.log"
        log_lua = f"""{{
    file = {{ access_path = "{big}", error_path = "{d}/big-error.log",
              max_buffer = 4 * 1024 * 1024, rotate_size = 1024 * 1024 }},
    otlp = {{ enabled = false, queue_max_bytes = 32 * 1024 * 1024 }},
    syslog = {{ enabled = false, queue_max_bytes = 8 * 1024 * 1024 }}
  }}"""
        with Server(table_cfg(port, log_lua), port, name=NAME):
            st, _, _ = http_request(port, "/")
        r.case("table: large log size fields accepted", st == 200, f"status={st}")

        # ---- validation errors ----
        cases = [
            ("table: bad syslog transport",
             table_cfg(0, '{ syslog = { enabled = true, transport = "smoke" } }')),
            ("table: otlp endpoint missing (C validate)",
             table_cfg(0, '{ otlp = { enabled = true } }')),
            ("table: file access without path (C validate)",
             table_cfg(0, '{ file = { access = true } }')),
            ("table: overlong access_path",
             table_cfg(0, '{ file = { access_path = "' + "x" * 600 + '" } }')),
        ]
        for name, text in cases:
            rc, log = start_expect_failure(text)
            last = log.strip().splitlines()[-1] if log.strip() else ""
            r.case(name, rc not in (0, -999), f"rc={rc} {last[:120]}")

    r.finish()


if __name__ == "__main__":
    main()
