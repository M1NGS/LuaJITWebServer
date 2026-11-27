#!/usr/bin/env python3
"""pico 服务器健壮性测试：用 raw socket 发送各类请求，记录响应与连接行为。

用法：python3 tests/pico_robust.py [port]
前置：pico 服务器已在 127.0.0.1:<port> 运行。
"""
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
OK = b"HTTP/1.1 200"
BODY = b"Hello, World!"


def conn(timeout=3):
    return socket.create_connection((HOST, PORT), timeout=timeout)


def read_response(s, timeout=2.0):
    s.settimeout(timeout)
    data = b""
    closed = False
    try:
        while True:
            c = s.recv(4096)
            if not c:
                closed = True
                break
            data += c
            if BODY in data:
                break
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError):
        closed = True
    return data, closed


def status_of(data):
    if data.startswith(OK):
        return "200"
    if not data:
        return "NO-RESP"
    return data.split(b"\r\n", 1)[0].decode("latin1", "replace")[:40]


def one(name, raw, timeout=2.0, half_close=False):
    s = conn()
    try:
        s.sendall(raw)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        data, closed = read_response(s, timeout)
        print(f"{name:42s} resp={status_of(data):14s} bytes={len(data):4d} closed={closed}")
    except Exception as e:
        print(f"{name:42s} EXCEPTION {type(e).__name__}: {e}")
    finally:
        s.close()


def keepalive(name, reqs, timeout=2.0):
    s = conn()
    s.settimeout(timeout)
    total = b""
    try:
        for r in reqs:
            s.sendall(r)
            d, _ = read_response(s, timeout)
            total += d
        print(f"{name:42s} responses={total.count(OK)}/{len(reqs)}")
    except Exception as e:
        print(f"{name:42s} responses={total.count(OK)}/{len(reqs)} (exception {type(e).__name__})")
    finally:
        s.close()


def pipeline(name, reqs, timeout=2.0):
    s = conn()
    s.settimeout(timeout)
    data = b""
    try:
        s.sendall(b"".join(reqs))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            data += c
            if data.count(OK) >= len(reqs):
                break
    except Exception:
        pass
    finally:
        s.close()
    print(f"{name:42s} responses={data.count(OK)}/{len(reqs)}")


def partial(name, part1, part2, delay=0.25):
    s = conn()
    s.settimeout(2.0)
    data = b""
    closed = False
    try:
        s.sendall(part1)
        time.sleep(delay)
        s.sendall(part2)
        data, closed = read_response(s, 2.0)
    except Exception:
        pass
    finally:
        s.close()
    print(f"{name:42s} resp={status_of(data):14s} bytes={len(data):4d} closed={closed}")


def burst(name, n=200):
    socks = []
    ok = 0
    for _ in range(n):
        try:
            s = conn()
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            socks.append(s)
        except Exception:
            pass
    for s in socks:
        try:
            d, _ = read_response(s, 2.0)
            ok += 1 if d.startswith(OK) else 0
        except Exception:
            pass
        s.close()
    print(f"{name:42s} ok={ok}/{n}")


def alive():
    try:
        s = conn(2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        d, _ = read_response(s, 2.0)
        s.close()
        return d.startswith(OK)
    except Exception:
        return False


def main():
    print(f"target: {HOST}:{PORT}")
    print("=== baseline ===")
    one("normal GET", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    keepalive("keep-alive 3 requests", [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"] * 3)
    pipeline("pipeline 2 requests",
             [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
              b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
    pipeline("pipeline 3 requests",
             [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
              b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
              b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"])
    partial("partial request (split)", b"GET / HTTP/1.1\r\nHost: x\r\n", b"\r\n")
    partial("partial in method", b"GE", b"T / HTTP/1.1\r\nHost: x\r\n\r\n")

    print("\n=== malformed ===")
    one("empty connection (no bytes)", b"", timeout=1.5)
    one("only CRLF", b"\r\n\r\n", timeout=1.5)
    one("bad method with space", b"G ET / HTTP/1.1\r\nHost: x\r\n\r\n")
    one("bad version 9.9", b"GET / HTTP/9.9\r\nHost: x\r\n\r\n")
    one("bare LF line endings", b"GET / HTTP/1.1\nHost: x\n\n")
    one("leading CRLF", b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
    one("NUL byte in path", b"GET /\x00x HTTP/1.1\r\nHost: x\r\n\r\n")
    one("space in path", b"GET /a b HTTP/1.1\r\nHost: x\r\n\r\n")
    one("CRLF injection in header", b"GET / HTTP/1.1\r\nHost: x\r\nX-A: a\r\nInjected: b\r\n\r\n")
    one("half-close after headers", b"GET / HTTP/1.1\r\nHost: x\r\n", half_close=True, timeout=1.5)

    print("\n=== UTF-8 ===")
    one("utf8 path raw", b"GET /\xe4\xb8\xad\xe6\x96\x87 HTTP/1.1\r\nHost: x\r\n\r\n")
    one("utf8 path percent-encoded", b"GET /%E4%B8%AD%E6%96%87 HTTP/1.1\r\nHost: x\r\n\r\n")
    one("utf8 query raw", b"GET /s?q=\xe4\xb8\xad HTTP/1.1\r\nHost: x\r\n\r\n")
    one("utf8 header value", b"GET / HTTP/1.1\r\nHost: x\r\nX-Name: \xe4\xbd\xa0\xe5\xa5\xbd\r\n\r\n")
    one("utf8 header name", b"GET / HTTP/1.1\r\nHost: x\r\nX-\xe5\x90\x8d: v\r\n\r\n")
    one("emoji path raw", b"GET /\xf0\x9f\x98\x80 HTTP/1.1\r\nHost: x\r\n\r\n")

    print("\n=== limits / body ===")
    one("URI 8 KiB", b"GET /" + b"a" * 8192 + b" HTTP/1.1\r\nHost: x\r\n\r\n", timeout=3.0)
    one("URI 16 KiB", b"GET /" + b"a" * 16384 + b" HTTP/1.1\r\nHost: x\r\n\r\n", timeout=3.0)
    one("header value 8 KiB", b"GET / HTTP/1.1\r\nHost: x\r\nX-Long: " + b"b" * 8192 + b"\r\n\r\n", timeout=3.0)
    hs = b"".join(b"X-H%d: v\r\n" % i for i in range(1, 41))
    one("40 headers (server cap 32)", b"GET / HTTP/1.1\r\nHost: x\r\n" + hs + b"\r\n", timeout=3.0)
    one("POST with body (len 4)", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody")
    keepalive("POST then GET on same conn", [
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody",
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    ])

    print("\n=== concurrency ===")
    burst("200 concurrent connections", 200)

    print("\n=== health ===")
    print("server alive after all tests:", "YES" if alive() else "NO")


if __name__ == "__main__":
    main()
