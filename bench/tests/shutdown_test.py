#!/usr/bin/env python3
"""优雅退出测试：空闲连接、进行中的慢响应、超时强制。

用法（在项目根目录、已设置 LD_LIBRARY_PATH 的 WSL 中）：
  python3 bench/tests/shutdown_test.py <server_bin> <config.lua> <port>
"""
import os
import signal
import socket
import subprocess
import sys
import time

BIN = sys.argv[1]
CONFIG = sys.argv[2]
PORT = int(sys.argv[3])
LOGDIR = "/tmp/httpd-shutdown-tests"
os.makedirs(LOGDIR, exist_ok=True)


def wait_port(timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def start(tag):
    path = os.path.join(LOGDIR, f"{tag}.log")
    log = open(path, "w")
    p = subprocess.Popen([BIN, CONFIG], cwd=os.getcwd(), stdout=log, stderr=log)
    if not wait_port():
        p.kill()
        raise RuntimeError(f"{tag}: server did not start")
    return p, path


def http_get(keep_alive=True):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    h = b"GET / HTTP/1.1\r\nHost: x\r\n"
    if not keep_alive:
        h += b"Connection: close\r\n"
    s.sendall(h + b"\r\n")
    return s


def read_response(s, timeout=5):
    s.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(65536)
        if not c:
            return data
        data += c
    head, sep, body = data.partition(b"\r\n\r\n")
    cl = None
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            cl = int(ln.split(b":", 1)[1])
    if cl is not None:
        while len(body) < cl:
            c = s.recv(65536)
            if not c:
                break
            body += c
    return head + sep + body


def chunked_decode(body):
    out = b""
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        n = int(body[i:j].split(b";")[0], 16)
        i = j + 2
        if n == 0:
            break
        out += body[i:i + n]
        i += n + 2
    return out


def scenario_idle():
    p, log = start("idle")
    s = http_get()
    resp = read_response(s)
    ok_before = resp.startswith(b"HTTP/1.1 200")
    os.kill(p.pid, signal.SIGINT)
    time.sleep(0.5)

    s.settimeout(2)
    closed = False
    try:
        closed = s.recv(4096) == b""
    except socket.timeout:
        closed = False
    s.close()

    refused = False
    try:
        n = socket.create_connection(("127.0.0.1", PORT), timeout=1)
        n.settimeout(1)
        n.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        try:
            d = n.recv(64)
            refused = not d.startswith(b"HTTP/1.1 200")
        except socket.timeout:
            refused = True
        n.close()
    except OSError:
        refused = True

    rc = p.wait(timeout=4)
    ok = ok_before and closed and refused and rc == 0
    print(f"idle: before={ok_before} closed={closed} new_conn_refused={refused} exit={rc} {'PASS' if ok else 'FAIL'}")
    return ok, log


def scenario_active():
    p, log = start("active")
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    time.sleep(0.4)  # 不读，让服务器写队列积压
    os.kill(p.pid, signal.SIGINT)
    data = b""
    s.settimeout(20)
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
    s.close()
    _, _, body = data.partition(b"\r\n\r\n")
    n = len(chunked_decode(body))
    rc = p.wait(timeout=6)
    ok = n == 10485760 and rc == 0
    print(f"active: body={n} exit={rc} {'PASS' if ok else 'FAIL'}")
    return ok, log


def scenario_timeout():
    p, log = start("timeout")
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.sendall(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10485760\r\n\r\n")
    s.sendall(b"x" * 100)
    time.sleep(0.2)
    t0 = time.time()
    os.kill(p.pid, signal.SIGINT)
    rc = p.wait(timeout=4)
    elapsed = time.time() - t0
    s.settimeout(1)
    try:
        closed = s.recv(64) == b""
    except Exception:
        closed = True
    s.close()
    ok = rc == 0 and 1.8 <= elapsed <= 3.5 and closed
    print(f"timeout: exit={rc} elapsed={elapsed:.2f}s closed={closed} {'PASS' if ok else 'FAIL'}")
    return ok, log


def main():
    results = []
    for fn in (scenario_idle, scenario_active, scenario_timeout):
        ok, log = fn()
        results.append(ok)
        with open(log, errors="replace") as f:
            for ln in f.read().splitlines():
                if "shutdown" in ln:
                    print("  log:", ln)
    print("RESULT:", "PASS" if all(results) else "FAIL")


if __name__ == "__main__":
    main()
