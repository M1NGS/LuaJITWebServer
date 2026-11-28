#!/usr/bin/env python3
"""4 worker 共享证书材料并发验证：x509/CA 共享只读，pk/conf/DRBG 每 worker 独立。

背景：2026-11-29 把整个 ssl_config/cert/pk 做成进程级共享、每 worker 只用线程局部
DRBG 时，4 worker/200 并发握手只有 31 成功并报 BAD_SIGNATURE。改为共享只读
x509_crt/CA、私钥与 conf/DRBG 每 worker 独立后，本套件用于守住该并发正确性：
TLS1.2/TLS1.3 混合握手、SIGHUP 证书换代后的并发握手都不能失败或回落到旧证书。
"""
import hashlib
import ssl
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (Runner, Server, cert_subject, free_port, gen_ca,
                     gen_self_signed, gen_signed, tls_request, tls_socket)

NAME = "19_tls_shared_material"
WORKERS = 4
CLIENTS = 200


def cfg(port, cert, key, log, app, ca=None, client_auth=False):
    tls_extra = ""
    if ca:
        tls_extra += f', ca = "{ca}"'
    if client_auth:
        tls_extra += ", client_auth = true"
    return f"""return {{
  server = {{
    workers = {WORKERS},
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2", check_interval = 0{tls_extra} }},
  }},
  log = {{ file = {{ access_path = "{log}", error_path = "{log}.err" }} }},
  app = "{app}"
}}
"""


def pem_hash(cert: Path) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()


def one_handshake(port, version, client_cert=None, client_key=None):
    """一次 TLS 握手 + GET /；返回 (ok, 证书 DER SHA256 或异常文本)。"""
    try:
        s = tls_socket(port, "localhost", version, None, client_cert, client_key)
        der = s.getpeercert(binary_form=True)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
        s.close()
        return data.startswith(b"HTTP/1.1 200"), hashlib.sha256(der).hexdigest()
    except Exception as e:
        return False, f"ERR {type(e).__name__}: {e}"


def err_log_tail(d, n=300):
    p = Path(str(d / "access.log") + ".err")
    time.sleep(0.2)
    try:
        return p.read_text(errors="replace")[-n:].replace("\n", " | ")
    except Exception:
        return ""


def run_batch(port, versions, clients=CLIENTS, client_cert=None, client_key=None):
    results = []
    lock = threading.Lock()

    def worker(idx):
        ok, h = one_handshake(port, versions[idx % len(versions)],
                              client_cert, client_key)
        with lock:
            results.append((ok, h))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = sum(1 for o, _ in results if o)
    return ok, results


def main():
    r = Runner(NAME)
    with __import__("tempfile").TemporaryDirectory(prefix="httpd-tls-shared-") as td:
        d = Path(td)
        app = d / "app.lua"
        app.write_text(
            'return { handle = function(req,res) return {status=200, body="ok"} end }\n')
        cert1, key1 = d / "one.crt", d / "one.key"
        cert2, key2 = d / "two.crt", d / "two.key"
        gen_self_signed(cert1, key1, "shared", "IP:127.0.0.1,DNS:localhost")
        gen_self_signed(cert2, key2, "reloaded", "IP:127.0.0.1,DNS:localhost")
        h1, h2 = pem_hash(cert1), pem_hash(cert2)
        log = d / "access.log"
        log_dir = d

        port = free_port()
        with Server(cfg(port, cert1, key1, log, app), port, name=NAME) as srv:
            ok, res = run_batch(port, [ssl.TLSVersion.TLSv1_3])
            same = sum(1 for o, h in res if o and h == h1)
            errs = [h for o, h in res if not o][:3]
            r.case("200 concurrent TLS1.3 handshakes", ok == CLIENTS and same == CLIENTS,
                   f"ok={ok}/{CLIENTS} cert={same}/{CLIENTS} errs={errs}" +
                   (f" log={err_log_tail(log_dir)}" if ok != CLIENTS or same != CLIENTS else ""))

            ok, res = run_batch(
                port, [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
            same = sum(1 for o, h in res if o and h == h1)
            errs = [h for o, h in res if not o][:3]
            r.case("200 concurrent mixed TLS1.2/1.3", ok == CLIENTS and same == CLIENTS,
                   f"ok={ok}/{CLIENTS} cert={same}/{CLIENTS} errs={errs}" +
                   (f" log={err_log_tail(log_dir)}" if ok != CLIENTS or same != CLIENTS else ""))

            # SIGHUP 换成第二张证书：control 构建新共享材料，4 个 worker 换新代
            srv.config_path.write_text(cfg(port, cert2, key2, log, app))
            srv.proc.send_signal(1)
            deadline = time.time() + 3.0
            subj = ""
            while time.time() < deadline:
                subj = cert_subject(port, "localhost")
                if "CN = reloaded" in subj:
                    break
                time.sleep(0.1)
            r.case("reload: new shared material served", "CN = reloaded" in subj, subj)

            ok, res = run_batch(port, [ssl.TLSVersion.TLSv1_3])
            same = sum(1 for o, h in res if o and h == h2)
            errs = [h for o, h in res if not o][:3]
            r.case("200 concurrent handshakes after reload", ok == CLIENTS and same == CLIENTS,
                   f"ok={ok}/{CLIENTS} cert={same}/{CLIENTS} errs={errs}" +
                   (f" log={err_log_tail(log_dir)}" if ok != CLIENTS or same != CLIENTS else ""))

            # 坏证书 reload：control 构建失败，旧共享材料/旧代必须保留
            bad = d / "bad.crt"
            bad.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            srv.config_path.write_text(cfg(port, bad, key2, log, app))
            srv.proc.send_signal(1)
            time.sleep(0.8)
            subj = cert_subject(port, "localhost")
            st, _, _ = tls_request(port, "/")
            r.case("reload: bad cert rejected, old material kept",
                   "CN = reloaded" in subj and st == 200, f"{subj} status={st}")

            st, _, _ = tls_request(port, "/")
            r.case("server alive after concurrent handshakes", st == 200, f"status={st}")

            srv.proc.send_signal(15)
            rc = srv.proc.wait(timeout=8)
            r.case("graceful exit 0", rc == 0, f"rc={rc}")

        # 共享客户端 CA 的并发验证（mTLS，4 worker）
        ca_cert, ca_key = d / "ca.crt", d / "ca.key"
        cli_cert, cli_key = d / "cli.crt", d / "cli.key"
        mtls_cert, mtls_key = d / "mtls.crt", d / "mtls.key"
        gen_ca(ca_cert, ca_key, "client-ca")
        gen_signed(cli_cert, cli_key, ca_cert, ca_key, "client")
        gen_signed(mtls_cert, mtls_key, ca_cert, ca_key, "localhost")
        port = free_port()
        mtls_cfg = cfg(port, mtls_cert, mtls_key, d / "mtls.log", app,
                       ca=ca_cert, client_auth=True)
        with Server(mtls_cfg, port, name=NAME) as srv:
            ok, res = run_batch(port, [ssl.TLSVersion.TLSv1_3], clients=50,
                                client_cert=cli_cert, client_key=cli_key)
            r.case("50 concurrent mTLS handshakes (shared CA)", ok == 50,
                   f"ok={ok}/50")
            rejected = 0
            for _ in range(5):
                try:
                    st, _, _ = tls_request(port, "/", tls_version=ssl.TLSVersion.TLSv1_3)
                    if st != 200:
                        rejected += 1
                except Exception:
                    rejected += 1
            r.case("mTLS rejects clients without cert", rejected == 5,
                   f"rejected={rejected}/5")
            srv.proc.send_signal(15)
            r.case("mTLS graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

    r.finish()


if __name__ == "__main__":
    main()
