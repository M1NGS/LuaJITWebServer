#!/usr/bin/env python3
"""Chunked request bodies: streaming decode, trailers, limits, keep-alive."""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import APP, Runner, Server, free_port, http_config

NAME = "17_chunked_request"


def raw(port, data: bytes, read_timeout: float = 1.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(data)
    s.settimeout(read_timeout)
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
            if b"\r\n\r\n" in out and out.startswith(b"HTTP/1.1 200") and b"Content-Length" in out:
                # 简单响应：CL 已给出时按长度判断是否读全
                head, _, body = out.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        cl = int(line.split(b":", 1)[1])
                if len(body) >= cl:
                    break
    except socket.timeout:
        pass
    s.close()
    return out


def status(resp: bytes) -> bytes:
    return resp.split(b"\r\n", 1)[0]


def body(resp: bytes) -> bytes:
    return resp.split(b"\r\n\r\n", 1)[-1]


def chunked(data: bytes, extra_headers: bytes = b"", trailers: bytes = b"") -> bytes:
    out = b"%x\r\n%s\r\n0\r\n" % (len(data), data)
    out += trailers + b"\r\n"
    return (b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
            + extra_headers + b"\r\n" + out)


def main():
    r = Runner(NAME)
    port = free_port()
    with Server(http_config(port, app=APP), port, name=NAME):
        ok = raw(port, chunked(b"hello chunked"))
        r.case("chunked echo", status(ok).startswith(b"HTTP/1.1 200") and body(ok) == b"hello chunked",
               body(ok)[:40])

        with_trailers = raw(port, chunked(b"hello", trailers=b"X-T: y\r\n"))
        r.case("chunked trailers accepted", body(with_trailers) == b"hello", body(with_trailers)[:40])

        # chunk size 跨包
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5")
        time.sleep(0.1)
        s.sendall(b"\r\nhello\r\n0\r\n\r\n")
        time.sleep(0.2)
        resp = s.recv(4096)
        s.close()
        r.case("chunk size split across packets", body(resp) == b"hello", body(resp)[:40])

        # HTTP/1.0 + TE
        bad10 = raw(port, b"POST /echo HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        r.case("HTTP/1.0 chunked rejected", status(bad10).startswith(b"HTTP/1.1 400"), status(bad10))

        # 非 chunked coding
        badte = raw(port, b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\nx")
        r.case("unsupported TE rejected", status(badte).startswith(b"HTTP/1.1 400"), status(badte))

        # TE + CL 同时出现
        badboth = raw(port, b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        r.case("TE with CL rejected", status(badboth).startswith(b"HTTP/1.1 400"), status(badboth))

        # 非法 chunk size
        badsz = raw(port, b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nx\r\n0\r\n\r\n")
        r.case("invalid chunk size rejected", status(badsz).startswith(b"HTTP/1.1 400"), status(badsz))

        # handler 不读 body：丢弃后同一 keep-alive 连接可继续
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"POST /meta HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        time.sleep(0.3)
        first = s.recv(8192)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.3)
        second = s.recv(8192)
        s.close()
        r.case("discarded chunked body keeps connection usable",
               status(first).startswith(b"HTTP/1.1 200") and status(second).startswith(b"HTTP/1.1 200"),
               f"{status(first)} / {status(second)}")

    # chunked 总量超过 limits.max_body：handler 启动后仍应在超限时返回 413
    port = free_port()
    with Server(http_config(port, extra_server="limits = { max_body = 1024 },", app=APP), port, name=NAME):
        big = b"x" * 4096
        over = raw(port, chunked(big))
        r.case("chunked total over max_body -> 413", status(over).startswith(b"HTTP/1.1 413"),
               status(over))

    r.finish()


if __name__ == "__main__":
    main()
