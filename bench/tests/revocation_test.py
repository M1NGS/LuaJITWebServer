#!/usr/bin/env python3
"""客户端证书吊销表（mock）定时刷新测试。

用法：python3 revocation_test.py <https_port> <server_pid> <cert_dir> <revoked_file>
前置：config-revocation.lua 的 revocation.interval = 1。
"""
import hashlib
import socket
import ssl
import sys
import time

PORT = int(sys.argv[1])
PID = int(sys.argv[2])          # 保留参数兼容旧调用，测试本身不再发信号
DIR = sys.argv[3]
REVOKED = sys.argv[4]
REFRESH_WAIT = 1.8              # interval=1 的刷新余量

BASE = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
BASE.check_hostname = False
BASE.verify_mode = ssl.CERT_NONE
BASE.minimum_version = ssl.TLSVersion.TLSv1_2


def fingerprint(name):
    pem = open(f"{DIR}/{name}.crt").read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def write_list(lines):
    with open(REVOKED, "w") as f:
        for line in lines:
            f.write(line + "\n")


def reload():
    time.sleep(REFRESH_WAIT)


def request(server_name, client=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if client:
        ctx.load_cert_chain(f"{DIR}/{client}.crt", f"{DIR}/{client}.key")
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


def check(name, server_name, client, expect_ok):
    try:
        data = request(server_name, client)
        ok = data.startswith(b"HTTP/1.1 200")
        passed = ok if expect_ok else False
        detail = "200" if ok else "unexpected response"
    except ssl.SSLError as e:
        passed = not expect_ok
        detail = f"rejected: {e.reason or e}"
    except Exception as e:
        passed = not expect_ok
        detail = f"{type(e).__name__}: {e}"
    print(f"{name:56s} {'PASS' if passed else 'FAIL'}  ({detail})")
    return passed


def main():
    fa = fingerprint("client-a")
    fb = fingerprint("client-b")
    print(f"target: 127.0.0.1:{PORT}, file: {REVOKED}")
    print(f"client-a fp: {fa}")
    print(f"client-b fp: {fb}")

    results = []

    # 1) 空表：正常通过
    write_list([])
    reload()
    results.append(check("empty list: a+client-a", "a.example.test", "client-a", True))

    # 2) 吊销 client-a：a 被拒，public 和 b 不受影响
    write_list([fa])
    reload()
    results.append(check("revoke client-a: a+client-a", "a.example.test", "client-a", False))
    results.append(check("revoke client-a: b+client-b unaffected", "b.example.test", "client-b", True))
    results.append(check("revoke client-a: public unaffected", "public.example.test", None, True))

    # 3) 非法数据：加载失败，保留旧表（a 仍然被拒）
    write_list(["zzzz-not-a-fingerprint"])
    reload()
    results.append(check("invalid data: old table kept (a still revoked)",
                         "a.example.test", "client-a", False))

    # 4) 清空：a 恢复
    write_list([])
    reload()
    results.append(check("clear list: a+client-a restored", "a.example.test", "client-a", True))

    # 5) 只吊销 client-b
    write_list([fb])
    reload()
    results.append(check("revoke client-b: b+client-b", "b.example.test", "client-b", False))
    results.append(check("revoke client-b: a+client-a unaffected",
                         "a.example.test", "client-a", True))

    print("RESULT:", "PASS" if all(results) else "FAIL")


if __name__ == "__main__":
    main()
