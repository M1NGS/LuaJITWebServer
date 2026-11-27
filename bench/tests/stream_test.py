#!/usr/bin/env python3
"""luajit-httpd 流式功能测试（raw socket）。

用法：python3 bench/tests/stream_test.py [port]
前置：服务器已用 src/app.lua 启动。
"""
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def conn():
    return socket.create_connection((HOST, PORT), timeout=5)


def recv_headers(s, timeout=5):
    s.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(65536)
        if not c:
            break
        data += c
    return data


def read_rest(s, timeout=15, stop_cond=None):
    s.settimeout(timeout)
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


def parse_response(data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0] if lines else b""
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


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


def read_complete_response(s, timeout=20):
    """读到完整响应（按 Content-Length / chunked 终止块）即返回，适合 keep-alive 连接。"""
    s.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(65536)
        if not c:
            return data
        data += c
    head, sep, body = data.partition(b"\r\n\r\n")
    headers = {}
    for ln in head.split(b"\r\n")[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    if b"content-length" in headers:
        n = int(headers[b"content-length"])
        while len(body) < n:
            c = s.recv(65536)
            if not c:
                break
            body += c
    else:  # chunked：读到终止块
        while b"0\r\n\r\n" not in body:
            c = s.recv(65536)
            if not c:
                break
            body += c
    return head + sep + body


def do(name, path, method="GET", body=None, extra=None, version="1.1", decode=None,
       close=True, stop_at_body=False):
    s = conn()
    hdrs = [f"{method} {path} HTTP/{version}", "Host: x"]
    if extra:
        hdrs += extra
    if body is not None:
        hdrs.append(f"Content-Length: {len(body)}")
    if close:
        hdrs.append("Connection: close")
    s.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode())
    if body:
        s.sendall(body)
    if stop_at_body:
        data = read_complete_response(s)
    else:
        data = read_rest(s, timeout=20)
    s.close()
    status, headers, rbody = parse_response(data)
    if decode:
        rbody = decode(rbody)
    print(f"{name:46s} {status.decode('latin1'):20s} len={len(rbody):8d} "
          f"cl={headers.get(b'content-length', b'-').decode() if isinstance(headers.get(b'content-length'), bytes) else '-'} "
          f"te={headers.get(b'transfer-encoding', b'-').decode() if isinstance(headers.get(b'transfer-encoding'), bytes) else '-'}")
    return status, headers, rbody


def t_pipeline():
    s = conn()
    body = b"hello"
    r1 = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    r2 = (b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n" + body)
    s.sendall(r1 + r2)
    data = read_rest(s, timeout=5, stop_cond=lambda d: d.count(b"HTTP/1.1 200") >= 2)
    s.close()
    n = data.count(b"HTTP/1.1 200")
    print(f"{'pipeline: GET / + POST /upload':46s} responses={n}/2")


def t_slow_reader():
    s = conn()
    s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    s.settimeout(10)
    time.sleep(1.2)  # 故意不读，让服务器写队列积压（触发 res:drain）
    data = read_rest(s, timeout=30)
    s.close()
    status, headers, body = parse_response(data)
    body = chunked_decode(body)
    print(f"{'slow reader: /download after 1.2s pause':46s} {status.decode('latin1'):20s} len={len(body):8d}")


def t_abort():
    s = conn()
    s.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(3)
    s.recv(8192)  # 读一点就断开
    s.close()
    time.sleep(0.3)
    st, hd, body = do("after abort: GET /", "/")
    return st


def main():
    print(f"target: {HOST}:{PORT}")
    do("legacy table GET /", "/")
    do("GET /utf8", "/utf8")
    do("GET /meta no body", "/meta")
    do("POST /meta small (5B)", "/meta", "POST", b"hello")
    do("POST /meta 2 MiB (streaming flags)", "/meta", "POST", b"m" * (2 * 1024 * 1024),
       close=False, stop_at_body=True)
    do("GET /timeout (res:set_timeout)", "/timeout")
    do("POST /echo small (5B)", "/echo", "POST", b"hello")
    do("GET /echo no body (expect 400)", "/echo")
    do("POST /upload 2 MiB streaming", "/upload", "POST", b"u" * (2 * 1024 * 1024))
    do("POST /echo 2 MiB (text aggregate)", "/echo", "POST", b"e" * (2 * 1024 * 1024))
    do("GET /download chunked 10 MiB", "/download", decode=chunked_decode)
    do("GET /download-cl CL 10 MiB", "/download-cl")
    do("GET /events SSE", "/events", decode=chunked_decode)
    do("GET /download HTTP/1.0 close-delimited", "/download", version="1.0",
       decode=lambda x: x)  # HTTP/1.0 无 chunked，body 原样
    do("HEAD /download (no body)", "/download", method="HEAD")
    do("POST /upload with TE chunked (expect 400)", "/upload", "POST",
       extra=["Transfer-Encoding: chunked"], body=b"0\r\n\r\n")
    t_pipeline()
    t_slow_reader()
    t_abort()


if __name__ == "__main__":
    main()
