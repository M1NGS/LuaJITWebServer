#!/usr/bin/env python3
"""SNI 多证书与定时证书检测测试（不再使用信号）。

前置：服务器已用 bench/tests/config-https.lua 启动，tls.check_interval = 1；
证书目录里应有 a.crt/a.key、wild.crt/wild.key、reloaded.crt/reloaded.key。

用法：
  python3 tls_sni_reload_test.py <https_port> <server_pid> <sni_dir> <default_cert> <default_key>
"""
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import shutil

PORT = int(sys.argv[1])
PID = int(sys.argv[2])          # 保留参数兼容旧调用，测试本身不再发信号
SNI_DIR = sys.argv[3]
DEFAULT_CERT = sys.argv[4]
DEFAULT_KEY = sys.argv[5]
CHECK_WAIT = 2.5                # check_interval=1 的检测 + 构建余量

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def cert_subject(servername=None):
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{PORT}"]
    if servername:
        cmd += ["-servername", servername]
    out = subprocess.run(cmd, input=b"", capture_output=True, timeout=10).stdout
    m = re.search(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not m:
        return None
    p = subprocess.run(["openssl", "x509", "-noout", "-subject"],
                       input=m.group(0), capture_output=True)
    return p.stdout.decode().strip()


def tls_conn():
    s = CTX.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=5),
                        server_hostname="localhost")
    s.settimeout(10)
    return s


def read_response(s):
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


def request_keepalive(s, path="/"):
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    return read_response(s)


def main():
    # 每次测试先从 sni_dir/default.* 恢复默认证书，保证可重复运行
    dflt = os.path.join(SNI_DIR, "default.crt")
    if os.path.exists(dflt):
        shutil.copy(dflt, DEFAULT_CERT)
        shutil.copy(os.path.join(SNI_DIR, "default.key"), DEFAULT_KEY)
        time.sleep(CHECK_WAIT)

    print("== SNI ==")
    cases = [
        (None, "CN=localhost"),
        ("a.example.test", "CN=a.example.test"),
        ("x.wild.test", "CN=*.wild.test"),
        ("a.b.wild.test", "CN=localhost"),   # 通配只匹配一级标签
        ("unknown.test", "CN=localhost"),    # 无匹配回退默认
    ]
    ok = True
    for sni, expect in cases:
        subj = cert_subject(sni)
        norm = subj.replace(" ", "") if subj else ""
        good = bool(norm) and expect in norm
        ok = ok and good
        print(f"  sni={str(sni):16s} {subj} expect~{expect} {'OK' if good else 'FAIL'}")

    print("== existing connection before update ==")
    old_conn = tls_conn()
    resp = request_keepalive(old_conn)
    print("  status:", resp.split(b"\r\n", 1)[0].decode())

    print("== periodic check picks up new cert ==")
    shutil.copy(os.path.join(SNI_DIR, "reloaded.crt"), DEFAULT_CERT)
    shutil.copy(os.path.join(SNI_DIR, "reloaded.key"), DEFAULT_KEY)
    time.sleep(CHECK_WAIT)
    subj = cert_subject()
    print("  default cert after update:", subj)
    new_ok = subj is not None and "CN=reloaded" in subj.replace(" ", "")

    print("== existing connection after update ==")
    resp2 = request_keepalive(old_conn)
    print("  status:", resp2.split(b"\r\n", 1)[0].decode())
    old_ok = resp2.startswith(b"HTTP/1.1 200")
    old_conn.close()

    print("== TCP keepalive timer ==")
    ka_conn = tls_conn()
    request_keepalive(ka_conn)
    time.sleep(1.2)  # 等 keepalive 计时器启动
    ss = subprocess.run(["ss", "-tno"], capture_output=True, text=True).stdout
    lines = [l for l in ss.splitlines() if f"127.0.0.1:{PORT}" in l]
    ka = any("timer:(keepalive" in l for l in lines)
    print("  keepalive timer visible:", ka)
    for l in lines:
        print("   ", l.strip()[:160])
    ka_conn.close()

    print("RESULT:", "PASS" if (ok and new_ok and old_ok and ka) else "FAIL")


if __name__ == "__main__":
    main()
