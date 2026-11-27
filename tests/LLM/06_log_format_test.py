#!/usr/bin/env python3
"""Fixed nginx-style access/error log format and async flush."""
import re
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, free_port, gen_self_signed,
                     http_request, raw_request, read_response, wait_port)

NAME = "06_log_format"


def main():
    r = Runner(NAME)
    http_port = free_port()
    tls_port = free_port()

    with tempfile.TemporaryDirectory(prefix="httpd-log-") as td:
        d = Path(td)
        cert, key = d / "server.crt", d / "server.key"
        gen_self_signed(cert, key, "localhost", "IP:127.0.0.1,DNS:localhost")
        logs = d / "logs"
        logs.mkdir()
        access = logs / "access.log"
        error = logs / "error.log"

        cfg = f"""return {{
  server = {{
    listen = {{
      {{ host = "127.0.0.1", port = {http_port} }},
      {{ host = "127.0.0.1", port = {tls_port}, tls = true }}
    }},
    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2" }},
    limits = {{ idle_timeout = 30 }}
  }},
  log = {{
    access = "{access}", error = "{error}", level = "info",
    flush_interval = 0.1, max_buffer = 4 * 1024 * 1024
  }},
  app = "{APP}"
}}
"""
        with Server(cfg, http_port, name=NAME):
            wait_port(tls_port)

            http_request(http_port, "/")
            http_request(http_port, "/utf8")
            http_request(http_port, "/missing")
            http_request(http_port, "/upload", "POST", b"hello")
            http_request(http_port, "/download", method="HEAD")
            http_request(http_port, "/download")

            s = socket.create_connection(("127.0.0.1", http_port), timeout=5)
            for _ in range(3):
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                read_response(s)
            s.close()

            raw = raw_request(http_port,
                              b"GET / HTTP/1.1\r\nHost: x\r\nBad Header\r\n\r\n",
                              timeout=2)
            bad_status = raw.split(b"\r\n", 1)[0].decode("latin1") if raw else "-"

            raw_tls = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
            raw_tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                raw_tls.recv(1024)
            except Exception:
                pass
            raw_tls.close()

            time.sleep(0.7)
            alines = access.read_text(errors="replace").splitlines() if access.exists() else []
            elines = error.read_text(errors="replace").splitlines() if error.exists() else []

            pat = re.compile(r'^(\S+) - - \[[^\]]+\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$')
            format_ok = bool(alines) and all(pat.match(ln) for ln in alines)
            r.case("access log format", format_ok, f"lines={len(alines)}")

            def has(sub):
                return any(sub in ln for ln in alines)

            checks = [
                ('GET / 200 13', '"GET / HTTP/1.1" 200 13'),
                ('GET /utf8 200 22', '"GET /utf8 HTTP/1.1" 200 22'),
                ('GET /missing 404 10', '"GET /missing HTTP/1.1" 404 10'),
                ('POST /upload 200 16', '"POST /upload HTTP/1.1" 200 16'),
                ('HEAD /download 200 0', '"HEAD /download HTTP/1.1" 200 0'),
                ('GET /download 10MiB', '"GET /download HTTP/1.1" 200 10485760'),
                ('keep-alive 3 GET /', sum(1 for ln in alines if '"GET / HTTP/1.1" 200 13' in ln) >= 4),
                ('malformed 400', "400" in bad_status and any(" 400 " in ln for ln in alines)),
            ]
            for name, ok in checks:
                r.case(name, ok)
                if not ok:
                    print("  access lines:", alines)

            err_info = any("[info]" in ln and "listener" in ln for ln in elines)
            err_tls = any("[warn]" in ln and "tls handshake failed" in ln for ln in elines)
            r.case("error log startup [info]", err_info)
            r.case("error log TLS handshake [warn]", err_tls)

    r.finish()


if __name__ == "__main__":
    main()
