#!/usr/bin/env python3
"""TLS 1.2/1.3, ALPN, HTTPS streaming, pipeline, slow reader, abort, concurrency."""
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, free_port, gen_self_signed,
                     read_response, tls_request, tls_socket, wait_port)

NAME = "02_tls_https"


def main():
    r = Runner(NAME)
    http_port = free_port()
    tls_port = free_port()

    with tempfile.TemporaryDirectory(prefix="httpd-cert-") as td:
        d = Path(td)
        cert, key = d / "server.crt", d / "server.key"
        gen_self_signed(cert, key, "localhost", "IP:127.0.0.1,DNS:localhost")

        cfg = f"""return {{
  server = {{
    listen = {{
      {{ host = "127.0.0.1", port = {http_port} }},
      {{ host = "127.0.0.1", port = {tls_port}, tls = true }}
    }},
    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2", check_interval = 1,
             alpn = {{ "http/1.1" }} }},
    limits = {{ max_body = 64 * 1024 * 1024, idle_timeout = 30 }}
  }},
  app = "{APP}"
}}
"""
        with Server(cfg, http_port, name=NAME):
            wait_port(tls_port)

            st, h, b = tls_request(tls_port, "/", tls_version=ssl.TLSVersion.TLSv1_2)
            r.case("TLS1.2 GET /", st == 200 and b == b"Hello, World!",
                   f"status={st}")

            st, h, b = tls_request(tls_port, "/", tls_version=ssl.TLSVersion.TLSv1_3)
            r.case("TLS1.3 GET /", st == 200 and b == b"Hello, World!",
                   f"status={st}")

            s = tls_socket(tls_port, alpn=["http/1.1"])
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(s)
            proto = s.selected_alpn_protocol()
            s.close()
            r.case("ALPN http/1.1", st == 200 and proto == "http/1.1",
                   f"status={st} alpn={proto}")

            st, h, b = tls_request(tls_port, "/upload", "POST", b"u" * (2 * 1024 * 1024))
            r.case("POST /upload 2MiB", st == 200 and b == b"received 2097152 bytes",
                   f"status={st} body={b[:40]!r}")

            st, h, b = tls_request(tls_port, "/echo", "POST", b"e" * (2 * 1024 * 1024))
            r.case("POST /echo 2MiB", st == 200 and len(b) == 2 * 1024 * 1024,
                   f"status={st} len={len(b)}")

            st, h, b = tls_request(tls_port, "/download")
            r.case("GET /download chunked 10MiB", st == 200 and len(b) == 10 * 1024 * 1024,
                   f"status={st} len={len(b)}")

            st, h, b = tls_request(tls_port, "/download-cl")
            r.case("GET /download-cl CL 10MiB", st == 200 and len(b) == 10 * 1024 * 1024,
                   f"status={st} len={len(b)}")

            st, h, b = tls_request(tls_port, "/events")
            r.case("GET /events SSE", st == 200 and len(b) == 291,
                   f"status={st} len={len(b)}")

            st, h, b = tls_request(tls_port, "/download", version="1.0")
            r.case("HTTP/1.0 close-delimited 10MiB",
                   st == 200 and len(b) == 10 * 1024 * 1024, f"status={st} len={len(b)}")

            st, h, b = tls_request(tls_port, "/download", method="HEAD")
            r.case("HEAD /download no body", st == 200 and len(b) == 0, f"status={st}")

            s = tls_socket(tls_port)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                      b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            data = b""
            s.settimeout(5)
            while data.count(b"HTTP/1.1 200") < 2:
                c = s.recv(65536)
                if not c:
                    break
                data += c
            s.close()
            r.case("TLS pipeline 2 requests", data.count(b"HTTP/1.1 200") == 2,
                   f"responses={data.count(b'HTTP/1.1 200')}")

            s = tls_socket(tls_port)
            s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            time.sleep(1.2)
            st, h, b = read_response(s, timeout=30)
            s.close()
            r.case("TLS slow reader 10MiB", st == 200 and len(b) == 10 * 1024 * 1024,
                   f"status={st} len={len(b)}")

            s = tls_socket(tls_port)
            s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\n\r\n")
            s.recv(8192)
            s.close()
            time.sleep(0.3)
            st, h, b = tls_request(tls_port, "/")
            r.case("TLS client abort then GET /", st == 200, f"status={st}")

            raw = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
            raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            raw.settimeout(2)
            data = b""
            try:
                while True:
                    c = raw.recv(4096)
                    if not c:
                        break
                    data += c
            except socket.timeout:
                pass
            raw.close()
            r.case("plain HTTP to TLS port rejected", b"HTTP/1.1" not in data)
            st, h, b = tls_request(tls_port, "/")
            r.case("TLS alive after plain-to-TLS", st == 200, f"status={st}")

            results = []
            lock = threading.Lock()

            def worker():
                try:
                    st, _, _ = tls_request(tls_port, "/")
                    with lock:
                        results.append(st == 200)
                except Exception:
                    with lock:
                        results.append(False)

            threads = [threading.Thread(target=worker) for _ in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            r.case("50 concurrent TLS requests", len(results) == 50 and all(results),
                   f"ok={sum(results)}/50")

    r.finish()


if __name__ == "__main__":
    main()
