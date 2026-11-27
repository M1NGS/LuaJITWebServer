#!/usr/bin/env python3
"""SNI certificate selection and periodic st_mtime certificate refresh (no signal)."""
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, cert_subject, free_port,
                     gen_self_signed, read_response, tls_socket, wait_port)

NAME = "03_sni_cert_refresh"


def main():
    r = Runner(NAME)
    port = free_port()

    with tempfile.TemporaryDirectory(prefix="httpd-sni-") as td:
        d = Path(td)
        cert, key = d / "default.crt", d / "default.key"
        a_cert, a_key = d / "a.crt", d / "a.key"
        wild_cert, wild_key = d / "wild.crt", d / "wild.key"
        new_cert, new_key = d / "reloaded.crt", d / "reloaded.key"
        signal_cert, signal_key = d / "signal.crt", d / "signal.key"
        gen_self_signed(cert, key, "localhost", "IP:127.0.0.1,DNS:localhost")
        gen_self_signed(a_cert, a_key, "a.example.test", "DNS:a.example.test")
        gen_self_signed(wild_cert, wild_key, "*.wild.test", "DNS:*.wild.test")
        gen_self_signed(new_cert, new_key, "reloaded", "DNS:reloaded")
        gen_self_signed(signal_cert, signal_key, "signal", "DNS:signal")

        cfg = f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{
      cert = "{cert}", key = "{key}", check_interval = 1,
      sni = {{
        {{ server_name = "a.example.test", cert = "{a_cert}", key = "{a_key}" }},
        {{ server_name = "*.wild.test", cert = "{wild_cert}", key = "{wild_key}" }}
      }}
    }},
    limits = {{ idle_timeout = 30 }}
  }},
  app = "{APP}"
}}
"""
        with Server(cfg, port, name=NAME) as srv:
            wait_port(port)

            cases = [
                (None, "CN=localhost"),
                ("a.example.test", "CN=a.example.test"),
                ("x.wild.test", "CN=*.wild.test"),
                ("a.b.wild.test", "CN=localhost"),  # wildcard is one label only
                ("unknown.test", "CN=localhost"),
            ]
            ok = True
            for sni, expect in cases:
                subj = cert_subject(port, sni)
                good = expect in subj.replace(" ", "")
                ok = ok and good
                r.case(f"SNI {sni or '(default)'}", good, f"subject={subj} expect~{expect}")

            old = tls_socket(port, server_name="localhost")
            old.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(old)
            r.case("existing connection before cert update", st == 200, f"status={st}")

            shutil.copyfile(new_cert, cert)
            shutil.copyfile(new_key, key)
            time.sleep(2.5)

            subj = cert_subject(port)
            r.case("periodic check picks up new cert",
                   "CN=reloaded" in subj.replace(" ", ""), f"subject={subj}")

            old.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(old)
            old.close()
            r.case("existing connection keeps old generation", st == 200, f"status={st}")

            # Invalid replacement must keep the previous good generation.
            cert.write_text("this is not a certificate\n")
            time.sleep(2.5)
            subj = cert_subject(port)
            r.case("invalid update keeps old cert",
                   "CN=reloaded" in subj.replace(" ", ""), f"subject={subj}")

            s = tls_socket(port)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(s)
            s.close()
            r.case("server alive after invalid cert update", st == 200, f"status={st}")

            # SIGHUP triggers an immediate reload (rebuild cert generation).
            shutil.copyfile(signal_cert, cert)
            shutil.copyfile(signal_key, key)
            os.kill(srv.proc.pid, signal.SIGHUP)
            time.sleep(0.5)
            subj = cert_subject(port)
            r.case("SIGHUP reloads cert immediately",
                   "CN=signal" in subj.replace(" ", ""), f"subject={subj}")

            s = tls_socket(port)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            st, h, b = read_response(s)
            s.close()
            r.case("server serves after reload", st == 200, f"status={st}")

    r.finish()


if __name__ == "__main__":
    main()
