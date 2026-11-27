#!/usr/bin/env python3
"""per-SNI mTLS 测试：不同域名使用不同客户端 CA / 是否要求客户端证书。

用法：python3 mtls_sni_test.py <https_port> <cert_dir>
前置：服务器已用 bench/tests/config-mtls.lua 启动，cert_dir 与 TEST_MTLS_DIR 一致。
"""
import socket
import ssl
import subprocess
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18445
DIR = sys.argv[2] if len(sys.argv) > 2 else "/tmp/httpd-mtls"


def make_ctx(client=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if client:
        ctx.load_cert_chain(f"{DIR}/{client}.crt", f"{DIR}/{client}.key")
    return ctx


def request(server_name, client=None):
    ctx = make_ctx(client)
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname=server_name)
    s.settimeout(10)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        data += c
    s.close()
    return data


def case(name, server_name, client, expect_ok):
    try:
        data = request(server_name, client)
        ok = data.startswith(b"HTTP/1.1 200")
        if expect_ok:
            passed = ok
            detail = "200" if ok else "unexpected response"
        else:
            # 期望握手失败；如果握手成功并返回 200 则是漏洞
            passed = False
            detail = "handshake unexpectedly succeeded"
    except ssl.SSLError as e:
        passed = not expect_ok
        detail = f"handshake rejected: {e.reason or e}"
    except Exception as e:
        passed = not expect_ok
        detail = f"{type(e).__name__}: {e}"
    print(f"{name:48s} {'PASS' if passed else 'FAIL'}  ({detail})")
    return passed


def main():
    print(f"target: 127.0.0.1:{PORT}, certs: {DIR}")
    cases = [
        ("a.example.test + client-a (CA-A)", "a.example.test", "client-a", True),
        ("a.example.test + client-b (CA-B)", "a.example.test", "client-b", False),
        ("a.example.test + no client cert", "a.example.test", None, False),
        ("b.example.test + client-b (CA-B)", "b.example.test", "client-b", True),
        ("b.example.test + client-a (CA-A)", "b.example.test", "client-a", False),
        ("b.example.test + no client cert", "b.example.test", None, False),
        ("public.example.test + no client cert (override false)", "public.example.test", None, True),
        ("inherit.example.test + client-a (global CA)", "inherit.example.test", "client-a", True),
        ("inherit.example.test + client-b", "inherit.example.test", "client-b", False),
        ("inherit.example.test + no client cert", "inherit.example.test", None, False),
        ("no SNI (default) + client-a (global required)", None, "client-a", True),
        ("no SNI (default) + client-b", None, "client-b", False),
        ("no SNI (default) + no client cert", None, None, False),
    ]
    results = [case(*c) for c in cases]
    print("RESULT:", "PASS" if all(results) else "FAIL")


if __name__ == "__main__":
    main()
