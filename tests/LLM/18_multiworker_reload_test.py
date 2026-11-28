#!/usr/bin/env python3
"""Multi-worker SIGHUP reload: app/TLS/log path changes, restart-only rejects."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (Runner, Server, cert_subject, free_port, gen_self_signed,
                     http_request)

NAME = "18_multiworker_reload"


def cfg(port, app, access, error, workers=4, tls=False, cert="", key="", port_tls=None):
    tls_line = ""
    if tls:
        tls_line = f"""    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2", check_interval = 0 }},
"""
    listen = f'{{ host = "127.0.0.1", port = {port}' + (", tls = true" if tls else "") + " }"
    return f"""return {{
  server = {{
    listen = {{ {listen} }},
    workers = {workers},
{tls_line}  }},
  log = {{ file = {{ access_path = "{access}", error_path = "{error}", flush_interval = 0.05 }} }},
  app = "{app}"
}}
"""


def main():
    r = Runner(NAME)
    with __import__("tempfile").TemporaryDirectory(prefix="httpd-mwrel-") as td:
        d = Path(td)
        app_old = d / "app_old.lua"
        app_new = d / "app_new.lua"
        app_bad = d / "app_bad.lua"
        app_old.write_text('return { handle = function(req,res) return {status=200, body="OLD"} end }\n')
        app_new.write_text('return { handle = function(req,res) return {status=200, body="NEW"} end }\n')
        app_bad.write_text("return { handle = function( end }\n")
        log_a = d / "a.log"
        log_b = d / "b.log"
        err = d / "err.log"

        port = free_port()
        base = cfg(port, app_old, log_a, err)
        with Server(base, port, name=NAME) as srv:
            st, _, b = http_request(port, "/")
            r.case("before reload: old app", st == 200 and b == b"OLD", f"{st} {b!r}")

            # app + 日志路径变化：都允许
            srv.config_path.write_text(cfg(port, app_new, log_b, err))
            srv.proc.send_signal(1)  # SIGHUP
            time.sleep(0.8)
            done = 0
            for _ in range(4):
                st, _, b = http_request(port, "/")
                done += 1 if (st == 200 and b == b"NEW") else 0
            r.case("reload: app replaced on all workers", done == 4, f"new={done}/4")
            time.sleep(0.4)
            r.case("reload: file writer switched path", log_b.exists() and log_b.stat().st_size > 0,
                   f"a={log_a.exists()} b={log_b.exists()}")
            err_text = err.read_text(errors="replace") if err.exists() else ""
            r.case("reload: workers applied", "worker 3 applied" in err_text,
                   err_text[-160:])

            # listen 变化：拒绝，服务继续
            srv.config_path.write_text(cfg(port + 1, app_new, log_b, err))
            srv.proc.send_signal(1)
            time.sleep(0.6)
            st, _, b = http_request(port, "/")
            r.case("reload: listen change rejected, old serving",
                   st == 200 and b == b"NEW" and "listen changes require restart" in srv.log(),
                   f"{st} {b!r}")

            # 日志通道开关变化：拒绝
            srv.config_path.write_text(
                cfg(port, app_new, log_b, err).replace(
                    f'access_path = "{log_b}"',
                    f'access_path = "{log_b}", access = false'))
            srv.proc.send_signal(1)
            time.sleep(0.6)
            st, _, b = http_request(port, "/")
            r.case("reload: log switch change rejected",
                   st == 200 and b == b"NEW" and "log channel enable/disable" in srv.log(),
                   f"{st} {b!r}")

            # 坏 app：校验阶段拒绝
            srv.config_path.write_text(cfg(port, app_bad, log_b, err))
            srv.proc.send_signal(1)
            time.sleep(0.6)
            st, _, b = http_request(port, "/")
            r.case("reload: bad app rejected", st == 200 and b == b"NEW" and "app load" in srv.log(),
                   f"{st} {b!r}")

            srv.proc.send_signal(15)
            rc = srv.proc.wait(timeout=8)
            r.case("reload: graceful exit 0", rc == 0, f"rc={rc}")

        # TLS 证书热重载（workers=2）
        cert = d / "server.crt"
        key = d / "server.key"
        gen_self_signed(cert, key, "old", "IP:127.0.0.1,DNS:localhost")
        port = free_port()
        tls_cfg = cfg(port, app_old, d / "tls.log", d / "tls-err.log", workers=2,
                      tls=True, cert=str(cert), key=str(key))
        with Server(tls_cfg, port, name=NAME) as srv:
            subj = cert_subject(port, "localhost")
            r.case("tls reload: initial cert", "CN = old" in subj, subj)
            gen_self_signed(cert, key, "reloaded", "IP:127.0.0.1,DNS:localhost")
            srv.proc.send_signal(1)
            time.sleep(0.8)
            subj = cert_subject(port, "localhost")
            r.case("tls reload: new cert served", "CN = reloaded" in subj, subj)
            r.case("tls reload: workers applied",
                   "worker 1 applied" in srv.log() or "worker 1 applied" in
                   (d / "tls-err.log").read_text(errors="replace"), srv.log()[-120:])
        r.case("tls reload: graceful exit 0", srv.proc.returncode == 0, f"rc={srv.proc.returncode}")

    r.finish()


if __name__ == "__main__":
    main()
