#!/usr/bin/env python3
"""nginx-style config check (--check) and SIGHUP reload."""
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, BIN, LUA_LIB, ROOT, Runner, Server, cert_subject,
                     free_port, gen_self_signed, http_request, read_log)

NAME = "14_reload"


def cfg_http(port, access, error, log_extra="", app=APP):
    return f"""return {{
  server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  log = {{ file = {{ access_path = "{access}", error_path = "{error}", flush_interval = 0.05 }}, {log_extra} }},
  app = "{app}"
}}
"""


def cfg_https(port, cert, key, access, error):
    return f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{ cert = "{cert}", key = "{key}", check_interval = 0 }}
  }},
  log = {{ file = {{ access_path = "{access}", error_path = "{error}", flush_interval = 0.05 }} }},
  app = "{APP}"
}}
"""


def run_check(text, d, name="check.lua"):
    path = d / name
    path.write_text(text)
    env = os.environ.copy()
    old = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = str(LUA_LIB) + ((":" + old) if old else "")
    p = subprocess.run([str(BIN), "--check", str(path)], cwd=str(ROOT), env=env,
                       capture_output=True, text=True, timeout=15)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-reload-") as td:
        d = Path(td)

        # ---- --check: valid / invalid ----
        port = free_port()
        valid = cfg_http(port, d / "check-access.log", d / "check-error.log")
        rc, out = run_check(valid, d)
        r.case("check: valid config", rc == 0 and "test is successful" in out,
               f"rc={rc} {out.strip()[-120:]}")

        rc, out = run_check("return {\n", d, "syntax.lua")
        r.case("check: syntax error", rc != 0, f"rc={rc} {out.strip()[-120:]}")

        bad = cfg_http(port, d / "x.log", d / "y.log",
                       log_extra='otlp = { enabled = true },')
        rc, out = run_check(bad, d, "bad-otlp.lua")
        r.case("check: missing otlp endpoint", rc != 0 and "endpoint" in out,
               f"rc={rc} {out.strip()[-120:]}")

        bad = cfg_https(port, "/no/such.crt", "/no/such.key", d / "x.log", d / "y.log")
        rc, out = run_check(bad, d, "bad-cert.lua")
        r.case("check: missing cert", rc != 0, f"rc={rc} {out.strip()[-120:]}")

        bad = cfg_http(port, "/no/such/dir/access.log", d / "y.log")
        rc, out = run_check(bad, d, "bad-logpath.lua")
        r.case("check: log path not writable", rc != 0 and "log file" in out,
               f"rc={rc} {out.strip()[-120:]}")

        bad = cfg_http(port, d / "x.log", d / "y.log", app="/no/such/app.lua")
        rc, out = run_check(bad, d, "bad-app.lua")
        r.case("check: missing app file", rc != 0 and "app file" in out,
               f"rc={rc} {out.strip()[-120:]}")

        # ---- --check does not bind (same port as a running server) ----
        port = free_port()
        a, e = d / "run-a.log", d / "run-e.log"
        with Server(cfg_http(port, a, e), port, name=NAME):
            rc, out = run_check(cfg_http(port, d / "check2.log", d / "check2e.log"), d, "live.lua")
            r.case("check: does not bind running port", rc == 0 and "test is successful" in out,
                   f"rc={rc} {out.strip()[-120:]}")

        # ---- reload success: log path switches ----
        port = free_port()
        a, e, b = d / "reload-a.log", d / "reload-e.log", d / "reload-b.log"
        with Server(cfg_http(port, a, e), port, name=NAME) as srv:
            st, _, _ = http_request(port, "/")
            time.sleep(0.3)
            srv.config_path.write_text(cfg_http(port, b, e))
            os.kill(srv.proc.pid, signal.SIGHUP)
            time.sleep(0.6)
            st2, _, _ = http_request(port, "/")
            time.sleep(0.4)
            elog = read_log(e, 40)
        r.case("reload: request before/after", st == 200 and st2 == 200,
               f"{st}/{st2}")
        r.case("reload: new access path receives logs",
               b.exists() and '"GET / HTTP/1.1" 200' in b.read_text(errors="replace"),
               str(b))
        r.case("reload: applied message in error log",
               "reload: configuration applied" in elog, elog[-150:])

        # ---- reload failure: keep old config ----
        port = free_port()
        a, e = d / "fail-a.log", d / "fail-e.log"
        with Server(cfg_http(port, a, e), port, name=NAME) as srv:
            http_request(port, "/")
            srv.config_path.write_text(f"""return {{
  server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  log = {{ otlp = {{ enabled = true }} }},
  app = "{APP}"
}}
""")
            os.kill(srv.proc.pid, signal.SIGHUP)
            time.sleep(0.6)
            st2, _, _ = http_request(port, "/")
            time.sleep(0.3)
            elog = read_log(e, 40)
        r.case("reload failure: old config still serves", st2 == 200, f"status={st2}")
        r.case("reload failure: error logged",
               "reload failed" in elog and "endpoint" in elog, elog[-150:])

        # ---- reload rejects listen changes ----
        port = free_port()
        a, e = d / "listen-a.log", d / "listen-e.log"
        with Server(cfg_http(port, a, e), port, name=NAME) as srv:
            srv.config_path.write_text(cfg_http(port + 1, a, e))
            os.kill(srv.proc.pid, signal.SIGHUP)
            time.sleep(0.6)
            st2, _, _ = http_request(port, "/")
            time.sleep(0.3)
            elog = read_log(e, 40)
        r.case("reload: listen change rejected", st2 == 200, f"status={st2}")
        r.case("reload: listen change error logged",
               "listen changes require restart" in elog, elog[-150:])

        # ---- reload TLS cert ----
        cert_a, key_a = d / "reload-a.crt", d / "reload-a.key"
        cert_b, key_b = d / "reload-b.crt", d / "reload-b.key"
        gen_self_signed(cert_a, key_a, "reload-a", "IP:127.0.0.1,DNS:localhost")
        gen_self_signed(cert_b, key_b, "reload-b", "IP:127.0.0.1,DNS:localhost")
        port = free_port()
        a, e = d / "tls-a.log", d / "tls-e.log"
        with Server(cfg_https(port, cert_a, key_a, a, e), port, name=NAME) as srv:
            subj1 = cert_subject(port)
            srv.config_path.write_text(cfg_https(port, cert_b, key_b, a, e))
            os.kill(srv.proc.pid, signal.SIGHUP)
            time.sleep(0.8)
            subj2 = cert_subject(port)
        r.case("reload: initial cert", "CN=reload-a" in subj1.replace(" ", ""), subj1)
        r.case("reload: new cert active",
               "CN=reload-b" in subj2.replace(" ", ""), subj2)

    r.finish()


if __name__ == "__main__":
    main()
