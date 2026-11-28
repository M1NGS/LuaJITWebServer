#!/usr/bin/env python3
"""tls.ciphers / tls.ciphersuites：mbedTLS 名称映射、TLS1.2/1.3 限制、数组、
非法名称启动失败、多 worker、SIGHUP 更新。"""
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, gen_self_signed, start_expect_failure

NAME = "22_tls_ciphers"

TLS12_AES128 = "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
TLS12_AES256 = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
TLS13_AES128 = "TLS1-3-AES-128-GCM-SHA256"
TLS13_AES256 = "TLS1-3-AES-256-GCM-SHA384"

OSSL_TLS12_AES128 = "ECDHE-RSA-AES128-GCM-SHA256"
OSSL_TLS12_AES256 = "ECDHE-RSA-AES256-GCM-SHA384"
OSSL_TLS13_AES128 = "TLS_AES_128_GCM_SHA256"
OSSL_TLS13_AES256 = "TLS_AES_256_GCM_SHA384"


def cfg(port, app, cert, key, ciphers=None, suites=None, workers=1):
    extra = ""
    if ciphers:
        extra += f"ciphers = {ciphers}, "
    if suites:
        extra += f"ciphersuites = {suites}, "
    return f"""return {{
  server = {{
    workers = {workers},
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2", check_interval = 0,
             {extra}alpn = {{ "http/1.1" }} }},
  }},
  log = {{ file = {{ enabled = false }} }},
  app = "{app}"
}}
"""


def handshake(port, version, cipher):
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}"]
    if version == "1.2":
        cmd += ["-tls1_2", "-cipher", cipher]
    else:
        cmd += ["-tls1_3", "-ciphersuites", cipher]
    p = subprocess.run(cmd, input=b"", capture_output=True, timeout=8)
    text = (p.stdout + p.stderr).decode(errors="replace")
    m = re.search(r"Cipher is (\S+)", text)
    if m and m.group(1) != "(NONE)":
        return m.group(1), text
    return None, text


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-ciphers-") as td:
        d = Path(td)
        app = d / "app.lua"
        app.write_text("return { handle = function(req,res) return {status=200} end }\n")
        cert, key = d / "server.crt", d / "server.key"
        gen_self_signed(cert, key, "localhost", "IP:127.0.0.1,DNS:localhost")
        port = free_port()

        with Server(cfg(port, app, cert, key,
                        ciphers=f'"{TLS12_AES128}"',
                        suites=f'"{TLS13_AES128}"'), port, name=NAME) as srv:
            c, _ = handshake(port, "1.2", OSSL_TLS12_AES128)
            r.case("TLS1.2 allowed cipher", c == OSSL_TLS12_AES128, f"cipher={c}")
            c, txt = handshake(port, "1.2", OSSL_TLS12_AES256)
            r.case("TLS1.2 other cipher rejected", c is None,
                   f"cipher={c} {txt.strip().splitlines()[-1][:80] if txt.strip() else ''}")
            c, _ = handshake(port, "1.3", OSSL_TLS13_AES128)
            r.case("TLS1.3 allowed ciphersuite", c == OSSL_TLS13_AES128, f"cipher={c}")
            c, _ = handshake(port, "1.3", OSSL_TLS13_AES256)
            r.case("TLS1.3 other ciphersuite rejected", c is None, f"cipher={c}")

            # SIGHUP 只改 ciphers：新连接用新限制
            srv.config_path.write_text(cfg(port, app, cert, key,
                                           ciphers=f'"{TLS12_AES256}"',
                                           suites=f'"{TLS13_AES128}"'))
            srv.proc.send_signal(1)
            time.sleep(0.8)
            c, _ = handshake(port, "1.2", OSSL_TLS12_AES256)
            r.case("reload: new allowed cipher", c == OSSL_TLS12_AES256, f"cipher={c}")
            c, _ = handshake(port, "1.2", OSSL_TLS12_AES128)
            r.case("reload: old cipher rejected", c is None, f"cipher={c}")

            srv.proc.send_signal(15)
            r.case("graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 默认（不配置）两种 cipher 都能协商
        port = free_port()
        with Server(cfg(port, app, cert, key), port, name=NAME) as srv:
            c1, _ = handshake(port, "1.2", OSSL_TLS12_AES256)
            c2, _ = handshake(port, "1.3", OSSL_TLS13_AES256)
            r.case("defaults allow both ciphers", c1 == OSSL_TLS12_AES256
                   and c2 == OSSL_TLS13_AES256, f"{c1} {c2}")
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # 数组写法：只允许 AES256（TLS1.2）
        port = free_port()
        arr = f'{{ "{TLS12_AES256}" }}'
        with Server(cfg(port, app, cert, key, ciphers=arr), port, name=NAME) as srv:
            c, _ = handshake(port, "1.2", OSSL_TLS12_AES256)
            r.case("ciphers array accepted", c == OSSL_TLS12_AES256, f"cipher={c}")
            c, _ = handshake(port, "1.2", OSSL_TLS12_AES128)
            r.case("ciphers array rejects others", c is None, f"cipher={c}")
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # 4 worker：限制在每 worker 的 conf 副本上生效
        port = free_port()
        with Server(cfg(port, app, cert, key, ciphers=f'"{TLS12_AES128}"',
                        suites=f'"{TLS13_AES128}"', workers=4), port, name=NAME) as srv:
            ok = 0
            for _ in range(16):
                c, _ = handshake(port, "1.3", OSSL_TLS13_AES128)
                ok += 1 if c == OSSL_TLS13_AES128 else 0
            r.case("4 workers: allowed ciphersuite", ok == 16, f"ok={ok}/16")
            c, _ = handshake(port, "1.3", OSSL_TLS13_AES256)
            r.case("4 workers: other ciphersuite rejected", c is None, f"cipher={c}")
            srv.proc.send_signal(15)
            r.case("4 workers: graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 非法名称启动失败
        rc, log = start_expect_failure(
            cfg(port, app, cert, key, ciphers='"TLS-NOT-A-CIPHER"').replace(
                f"port = {port}", "port = 0"))
        r.case("unknown cipher rejected at startup", rc not in (0, -999)
               and "unknown ciphersuite" in log,
               f"rc={rc} {log.strip().splitlines()[-1][:90] if log.strip() else ''}")

    r.finish()


if __name__ == "__main__":
    main()
