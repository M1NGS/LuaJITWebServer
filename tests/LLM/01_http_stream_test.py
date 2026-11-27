#!/usr/bin/env python3
"""HTTP/1.1 streaming, upload/download, keep-alive, pipeline, backpressure."""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (Runner, Server, free_port, http_config, http_request,
                     raw_request, read_response)

NAME = "01_http_stream"


def main():
    r = Runner(NAME)
    port = free_port()
    cfg = http_config(port, "limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 }")

    with Server(cfg, port, name=NAME):
        st, h, b = http_request(port, "/")
        r.case("GET / 200 13", st == 200 and b == b"Hello, World!",
               f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/utf8")
        r.case("GET /utf8 200 22", st == 200 and b == "你好，世界！😀".encode(),
               f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/meta")
        meta = b.decode(errors="replace")
        r.case("GET /meta no body flags",
               st == 200 and "has_body=false" in meta and "body_size=0" in meta
               and "streaming=false" in meta and "buffered=false" in meta, meta.strip())

        st, h, b = http_request(port, "/meta", "POST", b"hello")
        meta = b.decode(errors="replace")
        r.case("POST /meta small flags",
               st == 200 and "has_body=true" in meta and "body_size=5" in meta
               and "streaming=false" in meta and "buffered=true" in meta, meta.strip())

        st, h, b = http_request(port, "/meta", "POST", b"m" * (2 * 1024 * 1024),
                                close=False)
        meta = b.decode(errors="replace")
        r.case("POST /meta 2MiB streaming flags",
               st == 200 and "body_size=2097152" in meta and "streaming=true" in meta
               and "buffered=false" in meta, meta.strip())

        st, h, b = http_request(port, "/echo", "POST", b"hello")
        r.case("POST /echo small echo", st == 200 and b == b"hello", f"status={st}")

        st, h, b = http_request(port, "/echo")
        r.case("GET /echo no body -> 400", st == 400, f"status={st}")

        st, h, b = http_request(port, "/upload", "POST", b"u" * (2 * 1024 * 1024))
        r.case("POST /upload 2MiB streaming", st == 200 and b == b"received 2097152 bytes",
               f"status={st} body={b[:40]!r}")

        st, h, b = http_request(port, "/echo", "POST", b"e" * (2 * 1024 * 1024))
        r.case("POST /echo 2MiB text aggregate",
               st == 200 and len(b) == 2 * 1024 * 1024, f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/download")
        r.case("GET /download chunked 10MiB",
               st == 200 and len(b) == 10 * 1024 * 1024, f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/download-cl")
        r.case("GET /download-cl CL 10MiB",
               st == 200 and len(b) == 10 * 1024 * 1024, f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/events")
        r.case("GET /events SSE", st == 200 and len(b) == 291, f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/download", version="1.0")
        r.case("GET /download HTTP/1.0 close", st == 200 and len(b) == 10 * 1024 * 1024,
               f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/download", method="HEAD")
        r.case("HEAD /download no body", st == 200 and len(b) == 0, f"status={st}")

        st, h, b = http_request(port, "/upload", "POST",
                                headers=["Transfer-Encoding: gzip"])
        r.case("POST /upload unsupported TE -> 400", st == 400, f"status={st}")

        payload = (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
                   b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        data = raw_request(port, payload, timeout=5,
                           stop_cond=lambda d: d.count(b"HTTP/1.1 200") >= 2)
        r.case("pipeline 2 requests", data.count(b"HTTP/1.1 200") == 2,
               f"responses={data.count(b'HTTP/1.1 200')}")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        ok = 0
        for _ in range(3):
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(s)
            ok += 1 if st == 200 and b == b"Hello, World!" else 0
        s.close()
        r.case("keep-alive 3 requests", ok == 3, f"ok={ok}/3")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        time.sleep(1.2)  # slow reader: force write-queue backpressure
        st, h, b = read_response(s, timeout=30)
        s.close()
        r.case("slow reader /download 10MiB",
               st == 200 and len(b) == 10 * 1024 * 1024, f"status={st} len={len(b)}")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\n\r\n")
        s.recv(8192)
        s.close()
        time.sleep(0.3)
        st, h, b = http_request(port, "/")
        r.case("client abort then GET /", st == 200, f"status={st}")

    # max_body applies before the handler
    port2 = free_port()
    cfg2 = http_config(port2, "limits = { max_body = 1024, idle_timeout = 30 }")
    with Server(cfg2, port2, name=NAME + "-limit"):
        st, h, b = http_request(port2, "/upload", "POST", b"x" * 2048)
        r.case("max_body 1KiB rejects 2KiB with 413", st == 413, f"status={st}")

    r.finish()


if __name__ == "__main__":
    main()
