#!/usr/bin/env python3
"""luajit-httpd HTTPS 功能测试（raw TLS socket）。

用法：python3 bench/tests/tls_test.py [port]
前置：服务器已用 bench/tests/config-https.lua 启动（默认 18443）。
"""
import socket
import ssl
import sys
import time
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18443


def make_ctx(ver=None, alpn=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if ver:
        c.minimum_version = ver
        c.maximum_version = ver
    if alpn:
        c.set_alpn_protocols(alpn)
    return c


def conn(ver=None, alpn=None):
    raw = socket.create_connection((HOST, PORT), timeout=10)
    s = make_ctx(ver, alpn).wrap_socket(raw, server_hostname="localhost")
    s.settimeout(20)
    return s


def read_all(s, stop_cond=None):
    s.settimeout(20)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
            if stop_cond and stop_cond(data):
                break
    except socket.timeout:
        pass
    return data


def parse(data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return (lines[0] if lines else b""), body


def chunked_decode(body):
    out = b""
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            break
        i = j + 2
        if n == 0:
            break
        out += body[i:i + n]
        i += n + 2
    return out


def do(name, path, method="GET", body=None, version="1.1", decode=None, close=True,
       ver=None, alpn=None):
    s = conn(ver, alpn)
    hdrs = [f"{method} {path} HTTP/{version}", "Host: x"]
    if body is not None:
        hdrs.append(f"Content-Length: {len(body)}")
    if close:
        hdrs.append("Connection: close")
    s.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode())
    if body:
        s.sendall(body)
    data = read_all(s)
    s.close()
    st, rbody = parse(data)
    if decode:
        rbody = decode(rbody)
    print(f"{name:46s} {st.decode('latin1'):22s} len={len(rbody):8d}")
    return st, rbody


def t_versions():
    for name, ver in (("TLS1.2", ssl.TLSVersion.TLSv1_2), ("TLS1.3", ssl.TLSVersion.TLSv1_3)):
        s = conn(ver)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = read_all(s)
        s.close()
        st, _ = parse(data)
        print(f"{'negotiated ' + name:46s} {st.decode('latin1'):22s}")


def t_alpn():
    s = conn(alpn=["http/1.1"])
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = read_all(s)
    proto = s.selected_alpn_protocol()
    s.close()
    st, _ = parse(data)
    print(f"{'ALPN http/1.1':46s} {st.decode('latin1'):22s} alpn={proto}")


def t_pipeline():
    s = conn()
    body = b"hello"
    r1 = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    r2 = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n" + body
    s.sendall(r1 + r2)
    data = read_all(s, stop_cond=lambda d: d.count(b"HTTP/1.1 200") >= 2)
    s.close()
    print(f"{'pipeline: GET / + POST /upload':46s} responses={data.count(b'HTTP/1.1 200')}/2")


def t_slow_reader():
    s = conn()
    s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    time.sleep(1.2)
    data = read_all(s)
    s.close()
    st, body = parse(data)
    body = chunked_decode(body)
    print(f"{'slow reader: /download after 1.2s pause':46s} {st.decode('latin1'):22s} len={len(body):8d}")


def t_abort():
    s = conn()
    s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\n\r\n")
    s.recv(8192)
    s.close()
    time.sleep(0.3)
    do("after abort: GET /", "/")


def t_plain_to_tls():
    raw = socket.create_connection((HOST, PORT), timeout=5)
    raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    raw.settimeout(3)
    data = b""
    try:
        while True:
            c = raw.recv(4096)
            if not c:
                break
            data += c
    except Exception:
        pass
    raw.close()
    ok = b"HTTP/1.1" not in data
    print(f"{'plain HTTP sent to TLS port (expect no HTTP resp)':46s} rejected={ok}")
    do("after plain-to-tls: GET /", "/")


def t_concurrency(n=50):
    ok = [0]
    lock = threading.Lock()

    def worker():
        try:
            s = conn()
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            data = read_all(s)
            s.close()
            if data.startswith(b"HTTP/1.1 200"):
                with lock:
                    ok[0] += 1
        except Exception:
            pass

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"{f'{n} concurrent TLS requests':46s} ok={ok[0]}/{n}")


def main():
    print(f"target: {HOST}:{PORT} (TLS)")
    do("legacy table GET /", "/")
    do("GET /utf8", "/utf8")
    do("GET /meta", "/meta")
    do("POST /echo 2 MiB (text aggregate)", "/echo", "POST", b"e" * (2 * 1024 * 1024))
    do("POST /upload 2 MiB streaming", "/upload", "POST", b"u" * (2 * 1024 * 1024))
    do("GET /download chunked 10 MiB", "/download", decode=chunked_decode)
    do("GET /download-cl CL 10 MiB", "/download-cl")
    do("GET /events SSE", "/events", decode=chunked_decode)
    do("GET /download HTTP/1.0 close-delimited", "/download", version="1.0")
    do("HEAD /download (no body)", "/download", method="HEAD")
    t_versions()
    t_alpn()
    t_pipeline()
    t_slow_reader()
    t_abort()
    t_plain_to_tls()
    t_concurrency()


if __name__ == "__main__":
    main()
