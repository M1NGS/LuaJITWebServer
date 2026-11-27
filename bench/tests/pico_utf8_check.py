#!/usr/bin/env python3
"""验证 Connection: close 的大小写处理，以及 UTF-8 响应的字节与 Content-Length。

用法：python3 tests/pico_utf8_check.py [keepalive_port] [utf8_port]
"""
import socket
import sys


def exchange(port, raw, marker, wait=0.6):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(raw)
    s.settimeout(2)
    data = b""
    closed = False
    try:
        while True:
            c = s.recv(4096)
            if not c:
                closed = True
                break
            data += c
            if marker in data:
                s.settimeout(wait)
                try:
                    c2 = s.recv(4096)
                    if not c2:
                        closed = True
                except socket.timeout:
                    pass
                break
    except socket.timeout:
        pass
    s.close()
    return data, closed


def main():
    p1 = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    p2 = int(sys.argv[2]) if len(sys.argv) > 2 else 8081

    print("== Connection header handling (port %d) ==" % p1)
    for name, raw in [
        ("Connection: close", b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        ("no Connection header", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("CONNECTION: CLOSE", b"GET / HTTP/1.1\r\nHost: x\r\nCONNECTION: CLOSE\r\n\r\n"),
    ]:
        d, cl = exchange(p1, raw, b"Hello, World!")
        status = d.split(b"\r\n", 1)[0].decode("latin1") if d else "NO-RESP"
        print("  %-22s status=%s closed_after_response=%s" % (name, status, cl))

    print("== UTF-8 response (port %d) ==" % p2)
    expected = len("你好，世界！😀".encode("utf-8"))
    d, _ = exchange(p2, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"\xf0\x9f\x98\x80")
    head, _, body = d.partition(b"\r\n\r\n")
    clen = ""
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            clen = line.split(b":", 1)[1].strip().decode()
    ok = body == "你好，世界！😀".encode("utf-8")
    status = head.split(b"\r\n", 1)[0].decode("latin1") if head else "NO-RESP"
    print("  status=%s content-length=%s body_bytes=%d expected=%d body_matches=%s"
          % (status, clen, len(body), expected, ok))


if __name__ == "__main__":
    main()
