#!/usr/bin/env python3
"""固定格式 access/error 日志测试。

用法：python3 log_test.py <http_port> <https_port> <access_log> <error_log>
"""
import http.client
import os
import re
import socket
import sys
import time

HTTP_PORT = int(sys.argv[1])
HTTPS_PORT = int(sys.argv[2])
ACCESS = sys.argv[3]
ERROR = sys.argv[4]


def req(method, path, body=None, headers=None, conn=None):
    own = conn is None
    if own:
        conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    status, length = r.status, len(data)
    if own:
        conn.close()
    return status, length


def main():
    print(f"target: http={HTTP_PORT} https={HTTPS_PORT}")
    print(f"access: {ACCESS}\nerror:  {ERROR}")

    req("GET", "/")
    req("GET", "/utf8")
    req("GET", "/missing")
    req("POST", "/upload", body=b"hello")
    req("HEAD", "/")
    req("GET", "/download")
    conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=10)
    for _ in range(3):
        req("GET", "/", conn=conn)
    conn.close()

    # 畸形请求（解析失败 -> 400，request 字段为 "-"）
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nBad Header\r\n\r\n")
    data = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        data += c
    s.close()
    print("malformed status:", data.split(b"\r\n", 1)[0].decode())

    # 明文打到 TLS 端口 -> error log 里应有 handshake failed
    raw = socket.create_connection(("127.0.0.1", HTTPS_PORT), timeout=5)
    raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    try:
        raw.recv(1024)
    except Exception:
        pass
    raw.close()

    time.sleep(0.7)

    alines = open(ACCESS, "rb").read().decode("utf-8", "replace").splitlines()
    elines = open(ERROR, "rb").read().decode("utf-8", "replace").splitlines()
    print(f"access lines: {len(alines)}, error lines: {len(elines)}")

    pat = re.compile(r'^(\S+) - - \[[^\]]+\] "([^"]*)" (\d{3}) (\d+) "([^"]*)" "([^"]*)"$')
    ok = True
    for ln in alines:
        if not pat.match(ln):
            print("BAD FORMAT:", ln)
            ok = False

    def has(sub):
        return any(sub in ln for ln in alines)

    checks = [
        ('"GET / HTTP/1.1" 200 13', has('"GET / HTTP/1.1" 200 13')),
        ('"GET /utf8 HTTP/1.1" 200 22', has('"GET /utf8 HTTP/1.1" 200 22')),
        ('"GET /missing HTTP/1.1" 404 10', has('"GET /missing HTTP/1.1" 404 10')),
        ('"POST /upload HTTP/1.1" 200 16', has('"POST /upload HTTP/1.1" 200 16')),
        ('"HEAD / HTTP/1.1" 200 0', has('"HEAD / HTTP/1.1" 200 0')),
        ('"GET /download HTTP/1.1" 200 10485760', has('"GET /download HTTP/1.1" 200 10485760')),
        ('keep-alive 3x GET /', sum(1 for ln in alines if '"GET / HTTP/1.1" 200 13' in ln) >= 4),
        ('malformed 400', has("400")),
    ]
    for name, good in checks:
        print(f"{name:48s} {'OK' if good else 'FAIL'}")
        ok = ok and good

    err_ok = any("[info]" in ln and "listener" in ln for ln in elines)
    warn_ok = any("[warn]" in ln and "tls handshake failed" in ln for ln in elines)
    print(f"{'error log startup [info]':48s} {'OK' if err_ok else 'FAIL'}")
    print(f"{'error log tls handshake [warn]':48s} {'OK' if warn_ok else 'FAIL'}")
    ok = ok and err_ok and warn_ok

    print("=== access log (first 8) ===")
    for ln in alines[:8]:
        print(" ", ln)
    print("=== error log (first 4) ===")
    for ln in elines[:4]:
        print(" ", ln)

    print("RESULT:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()
