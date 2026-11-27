#!/usr/bin/env python3
"""Multi-worker log pipeline: per-worker rings -> collector -> file/OTLP/syslog."""
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import APP, Runner, Server, free_port, http_request

NAME = "16_log_pipeline"
ERROR_APP = Path(__file__).resolve().parents[1] / "fixtures" / "error_app.lua"


class UdpMock:
    def __init__(self):
        self.msgs = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
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
        self.bodies = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                app.bodies.append(self.rfile.read(n))
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


def cfg(port, access, error, otlp_port, udp_port):
    return f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port} }} }},
    workers = 4,
  }},
  log = {{
    file = {{ access_path = "{access}", error_path = "{error}",
              flush_interval = 0.05, rotate_size = 2048, rotate_keep = 2 }},
    otlp = {{ enabled = true, endpoint = "http://127.0.0.1:{otlp_port}",
              access = true, error = true, flush_interval = 0.2,
              batch_max_records = 10, timeout = 1 }},
    syslog = {{ enabled = true, transport = "udp", host = "127.0.0.1",
                port = {udp_port}, access = true, error = true, level = "info" }},
  }},
  app = "{ERROR_APP}"
}}
"""


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-logp-") as td:
        d = Path(td)
        access = d / "access.log"
        error = d / "error.log"
        port = free_port()
        otlp = OtlpMock()
        udp = UdpMock()
        try:
            with Server(cfg(port, access, error, otlp.port, udp.port), port, name=NAME) as srv:
                ok = 0
                for _ in range(40):
                    st, _, _ = http_request(port, "/")
                    ok += (st == 200)
                http_request(port, "/boom", timeout=5)
                time.sleep(1.0)

                text = access.read_text(errors="replace") if access.exists() else ""
                err = error.read_text(errors="replace") if error.exists() else ""
                total_access = 0
                for p in d.glob("access.log*"):
                    if p.is_file():
                        total_access += p.read_text(errors="replace").count('"GET / HTTP/1.1" 200')
                bodies = b"".join(otlp.bodies)
                r.case("4 workers: requests served", ok == 40, f"ok={ok}/40")
                r.case("4 workers: file access complete", total_access >= 40,
                       f"lines={total_access}")
                r.case("4 workers: file error written", "handler error" in err, err[-120:])
                r.case("4 workers: rotate .1 exists", (d / "access.log.1").exists(),
                       f"files={sorted(p.name for p in d.glob('access.log*'))}")
                r.case("4 workers: otlp access+error",
                       b"httpd.access" in bodies and b"httpd.error" in bodies,
                       f"posts={len(otlp.bodies)}")
                r.case("4 workers: syslog receives events", len(udp.msgs) >= 40,
                       f"msgs={len(udp.msgs)}")

                srv.proc.send_signal(15)  # SIGTERM
                rc = srv.proc.wait(timeout=8)
                r.case("4 workers: graceful exit 0", rc == 0, f"rc={rc}")

                total = 0
                for p in d.glob("access.log*"):
                    if p.is_file():
                        total += len(p.read_text(errors="replace").splitlines())
                r.case("4 workers: rotated files keep all lines", total >= 40,
                       f"lines={total}")
        finally:
            otlp.close()
            udp.close()
    r.finish()


if __name__ == "__main__":
    main()
