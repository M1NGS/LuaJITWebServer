#!/usr/bin/env python3
"""Raw-socket HTTP robustness: malformed requests, limits, UTF-8, pipeline, concurrency."""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_config, raw_request, read_response

NAME = "08_http_robustness"


def status_of(data: bytes):
    if not data:
        return 0
    first = data.split(b"\r\n", 1)[0]
    parts = first.split()
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return -1
    return -1


def main():
    r = Runner(NAME)
    port = free_port()
    cfg = http_config(port, "limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 }")

    with Server(cfg, port, name=NAME):
        def one(name, payload, expect, timeout=2.0):
            data = raw_request(port, payload, timeout=timeout)
            st = status_of(data)
            r.case(name, st == expect, f"status={st} expect={expect}")

        one("normal GET", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
        one("empty connection", b"", 0, timeout=1.2)
        one("only CRLF", b"\r\n\r\n", 400)
        one("bad method with space", b"G ET / HTTP/1.1\r\nHost: x\r\n\r\n", 400)
        one("bad version 9.9", b"GET / HTTP/9.9\r\nHost: x\r\n\r\n", 400)
        one("bare LF line endings", b"GET / HTTP/1.1\nHost: x\n\n", 200)
        one("leading CRLF", b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
        one("NUL byte in path", b"GET /\x00x HTTP/1.1\r\nHost: x\r\n\r\n", 400)
        one("space in path", b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n", 400)
        one("CRLF in header value", b"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\r\nInjected: b\r\n\r\n", 200)

        one("utf8 path raw", b"GET /\xe4\xb8\xad\xe6\x96\x87 HTTP/1.1\r\nHost: x\r\n\r\n", 404)
        one("utf8 path percent", b"GET /%E4%B8%AD%E6%96%87 HTTP/1.1\r\nHost: x\r\n\r\n", 404)
        one("utf8 query raw", b"GET /s?q=\xe4\xb8\xad HTTP/1.1\r\nHost: x\r\n\r\n", 404)
        one("utf8 header value", b"GET / HTTP/1.1\r\nHost: x\r\nX-N: \xe4\xbd\xa0\xe5\xa5\xbd\r\n\r\n", 200)
        one("utf8 header name", b"GET / HTTP/1.1\r\nHost: x\r\nX-\xe5\x90\x8d: v\r\n\r\n", 400)
        one("emoji path", b"GET /\xf0\x9f\x98\x80 HTTP/1.1\r\nHost: x\r\n\r\n", 404)

        one("URI 8KiB", b"GET /" + b"a" * 8192 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 404, 3)
        one("URI 16KiB", b"GET /" + b"a" * 16384 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 431, 3)
        one("header value 8KiB", b"GET / HTTP/1.1\r\nHost: x\r\nX-Long: " + b"b" * 8192 + b"\r\n\r\n", 200, 3)
        hs = b"".join(b"X-H%d: v\r\n" % i for i in range(1, 41))
        one("40 headers (cap 64)", b"GET / HTTP/1.1\r\nHost: x\r\n" + hs + b"\r\n", 200, 3)
        one("POST with body", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody", 200)

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody")
        st1, _, _ = read_response(s)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        st2, _, _ = read_response(s)
        s.close()
        r.case("POST then GET on same conn", st1 == 200 and st2 == 200, f"{st1},{st2}")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        data3 = b""
        for _ in range(3):
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, _, _ = read_response(s)
            data3 += str(st).encode()
        s.close()
        r.case("keep-alive 3 requests", data3.count(b"200") == 3, f"statuses={data3!r}")

        payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"
        data = raw_request(port, payload, timeout=3,
                           stop_cond=lambda d: d.count(b"HTTP/1.1 200") >= 2)
        r.case("pipeline 2", data.count(b"HTTP/1.1 200") == 2,
               f"responses={data.count(b'HTTP/1.1 200')}")

        payload = (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 3)
        data = raw_request(port, payload, timeout=3,
                           stop_cond=lambda d: d.count(b"HTTP/1.1 200") >= 3)
        r.case("pipeline 3", data.count(b"HTTP/1.1 200") == 3,
               f"responses={data.count(b'HTTP/1.1 200')}")

        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
        s.shutdown(socket.SHUT_WR)
        s.settimeout(2)
        data = b""
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except socket.timeout:
            pass
        s.close()
        r.case("half-close incomplete request", b"HTTP/1.1" not in data,
               f"bytes={len(data)}")

        socks = []
        for _ in range(200):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            socks.append(s)
        ok = 0
        for s in socks:
            try:
                st, _, _ = read_response(s, timeout=3)
                ok += 1 if st == 200 else 0
            except Exception:
                pass
            s.close()
        r.case("200 concurrent connections", ok == 200, f"ok={ok}/200")

        data = raw_request(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", timeout=2)
        r.case("server alive after all tests", status_of(data) == 200)

    # idle keep-alive timeout（触发 on_idle_timeout）
    port2 = free_port()
    with Server(http_config(port2, "limits = { idle_timeout = 1 }"), port2,
                name=NAME + "-idle") as s:
        sock = socket.create_connection(("127.0.0.1", port2), timeout=5)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        st, _, _ = read_response(sock)
        sock.settimeout(3)
        t0 = time.time()
        try:
            closed = sock.recv(64) == b""
        except Exception:
            closed = True
        elapsed = time.time() - t0
        sock.close()
        r.case("idle keep-alive timeout closes connection",
               st == 200 and closed and 0.8 <= elapsed <= 2.5,
               f"status={st} closed={closed} elapsed={elapsed:.2f}s")

    r.finish()


if __name__ == "__main__":
    main()
