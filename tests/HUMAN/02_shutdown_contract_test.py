#!/usr/bin/env python3
"""HUMAN-originated regression: graceful shutdown contract.

The user asked to confirm two behaviors, so they are locked here:
- after shutdown starts, listeners are closed and no new request is accepted;
- active requests have a configurable grace timeout before forced shutdown.
"""
import signal
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_config, http_request, read_response

NAME = "HUMAN_02_shutdown_contract"
TIMEOUT = 2


def main():
    r = Runner(NAME)

    # 1) idle connection: listener closed, idle conn closed, process exits
    port = free_port()
    cfg = http_config(port, f"limits = {{ idle_timeout = 30, shutdown_timeout = {TIMEOUT} }}")
    with Server(cfg, port, name=NAME) as srv:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        st, _, _ = read_response(s)
        before = st == 200

        srv.proc.send_signal(signal.SIGINT)
        time.sleep(0.5)

        s.settimeout(2)
        closed = False
        try:
            closed = s.recv(4096) == b""
        except Exception:
            closed = False
        s.close()

        refused = False
        try:
            n = socket.create_connection(("127.0.0.1", port), timeout=1)
            n.settimeout(1)
            n.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                refused = not n.recv(64).startswith(b"HTTP/1.1 200")
            except socket.timeout:
                refused = True
            n.close()
        except OSError:
            refused = True

        rc = srv.proc.wait(timeout=4)
        r.case("idle conn closed after SIGINT", before and closed, f"closed={closed}")
        r.case("listener closed (new connection refused)", refused, f"refused={refused}")
        r.case("process exit 0", rc == 0, f"rc={rc}")

    # 2) active upload stuck in body read: grace timeout forces shutdown
    port = free_port()
    cfg = http_config(port, f"limits = {{ idle_timeout = 30, shutdown_timeout = {TIMEOUT} }}")
    with Server(cfg, port, name=NAME) as srv:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10485760\r\n\r\n")
        s.sendall(b"x" * 100)
        time.sleep(0.2)
        t0 = time.time()
        srv.proc.send_signal(signal.SIGINT)
        rc = srv.proc.wait(timeout=4)
        elapsed = time.time() - t0
        s.settimeout(1)
        try:
            closed = s.recv(64) == b""
        except Exception:
            closed = True
        s.close()
        r.case("active request obeys shutdown_timeout",
               rc == 0 and 1.8 <= elapsed <= 3.5 and closed,
               f"rc={rc} elapsed={elapsed:.2f}s closed={closed}")

    # 3) 第二次 SIGTERM 立即强制关闭（不等 shutdown_timeout）
    port = free_port()
    cfg = http_config(port, "limits = { idle_timeout = 30, shutdown_timeout = 10 }")
    with Server(cfg, port, name=NAME) as srv:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10485760\r\n\r\n")
        s.sendall(b"x" * 100)
        time.sleep(0.2)
        srv.proc.send_signal(signal.SIGTERM)
        time.sleep(0.2)
        t0 = time.time()
        srv.proc.send_signal(signal.SIGTERM)
        rc = srv.proc.wait(timeout=3)
        elapsed = time.time() - t0
        s.settimeout(1)
        try:
            closed = s.recv(64) == b""
        except Exception:
            closed = True
        s.close()
        r.case("second SIGTERM forces immediate exit",
               rc == 0 and elapsed < 1.5 and closed,
               f"rc={rc} elapsed={elapsed:.2f}s closed={closed}")

    r.finish()


if __name__ == "__main__":
    main()
