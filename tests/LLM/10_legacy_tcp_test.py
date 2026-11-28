#!/usr/bin/env python3
"""Legacy app.lua mode and Linux TCP options (keepalive, buffers, SO_REUSEPORT)."""
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, BIN, LUA_LIB, ROOT, Runner, Server, free_port,
                     have_ss, http_config, http_request, read_response, ss_blocks,
                     ss_lines, wait_port)

NAME = "10_legacy_tcp"


def main():
    r = Runner(NAME)

    # legacy `app.lua port` mode
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="httpd-legacy-") as td:
        log_path = Path(td) / "legacy.log"
        env = os.environ.copy()
        old = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = str(LUA_LIB) + ((":" + old) if old else "")
        with open(log_path, "w") as log:
            p = subprocess.Popen([str(BIN), str(APP), str(port)], cwd=str(ROOT),
                                 env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                wait_port(port, 5, p, log_path)
                st, h, b = http_request(port, "/")
                r.case("legacy app.lua mode GET /", st == 200 and b == b"Hello, World!",
                       f"status={st}")
            finally:
                if p.poll() is None:
                    p.send_signal(signal.SIGTERM)
                    try:
                        p.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait()

    # TCP options
    tcp_port = free_port()
    tcp_extra = """tcp = { nodelay = true, keepalive = true, keepalive_delay = 1,
      keepalive_interval = 10, keepalive_count = 5,
      send_buffer = 65536, recv_buffer = 65536, backlog = 1024 },
    limits = { idle_timeout = 30 }"""
    with Server(http_config(tcp_port, tcp_extra), tcp_port, name=NAME) as srv:
        s = socket.create_connection(("127.0.0.1", tcp_port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        st, _, _ = read_response(s)
        time.sleep(1.2)
        lines = ss_lines(tcp_port, "-tno")
        keepalive = any("timer:(keepalive" in ln for ln in lines)
        r.case("TCP keepalive timer", st == 200 and keepalive,
               f"status={st} keepalive={keepalive} lines={len(lines)}")

        if have_ss():
            mem = "\n".join(ss_blocks(tcp_port, "-tnoime"))
            r.case("TCP SO_SNDBUF/SO_RCVBUF applied",
                   "rb131072" in mem and "tb131072" in mem,
                   mem[:160].replace("\n", " "))
        else:
            r.case("TCP buffer check skipped (no ss)", True, "ss unavailable")
        s.close()

    # SO_REUSEPORT: two independent instances bind the same port
    reuse_port = free_port()
    reuse_cfg = http_config(reuse_port, """tcp = { reuse_port = true },
    limits = { idle_timeout = 30 }""")
    with Server(reuse_cfg, reuse_port, name=NAME + "-a") as a:
        with Server(reuse_cfg, reuse_port, name=NAME + "-b") as b:
            ok = 0
            total = 20
            for _ in range(total):
                st, _, _ = http_request(reuse_port, "/")
                ok += 1 if st == 200 else 0
            both_alive = a.proc.poll() is None and b.proc.poll() is None
            r.case("SO_REUSEPORT two instances", ok == total and both_alive,
                   f"ok={ok}/{total} alive={both_alive}")

    # listen 简写：host:port 字符串、纯端口字符串、数字（parse_listen_string/entry）
    for name, make_listen in [
        ("host:port string", lambda p: f'"127.0.0.1:{p}"'),
        ("port string", lambda p: f'"{p}"'),
        ("number", lambda p: f"{p}"),
    ]:
        port = free_port()
        text = f"""return {{ server = {{ listen = {make_listen(port)} }},
  log = {{ file = {{ enabled = false }} }}, app = "{APP}" }}"""
        with Server(text, port, name=NAME + "-listen") as s:
            st, _, b = http_request(port, "/")
            r.case(f"listen shorthand {name}", st == 200 and b == b"Hello, World!",
                   f"{st} {b!r}")

    r.finish()


if __name__ == "__main__":
    main()
