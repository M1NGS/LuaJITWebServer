#!/usr/bin/env python3
"""Client certificate revocation table: periodic refresh, keep-old, preload, reject_all."""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, fingerprint, free_port, mtls_fixture,
                     tls_request, wait_port)

NAME = "05_revocation_refresh"


def config_text(port: int, f: dict, revoked: Path, on_error="keep") -> str:
    return f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{
      cert = "{f['default.crt']}", key = "{f['default.key']}",
      ca = "{f['ca-a.crt']}", client_auth = true,
      check_interval = 10,
      sni = {{
        {{ server_name = "a.example.test", cert = "{f['a-server.crt']}",
           key = "{f['a-server.key']}", ca = "{f['ca-a.crt']}", client_auth = true }},
        {{ server_name = "b.example.test", cert = "{f['b-server.crt']}",
           key = "{f['b-server.key']}", ca = "{f['ca-b.crt']}", client_auth = true }},
        {{ server_name = "public.example.test", cert = "{f['public-server.crt']}",
           key = "{f['public-server.key']}", client_auth = false }}
      }}
    }},
    limits = {{ idle_timeout = 30 }}
  }},
  revocation = {{
    enabled = true,
    key = "sha256",
    interval = 1,
    load_on_start = true,
    max_bytes = 64 * 1024 * 1024,
    max_entries = 500000,
    on_error = "{on_error}",
    provider = {{
      type = "pgsql",
      dsn = "postgresql://mock/revoked",
      sql = "SELECT fingerprint_sha256 FROM revoked_client_certs",
      mock_file = "{revoked}"
    }}
  }},
  app = "{APP}"
}}
"""


def write_list(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def make_try(port: int, f: dict):
    def try_req(server_name, client):
        cc = f[f"{client}.crt"] if client else None
        ck = f[f"{client}.key"] if client else None
        try:
            st, _, _ = tls_request(port, server_name=server_name,
                                   client_cert=cc, client_key=ck)
            return st == 200
        except Exception:
            return False
    return try_req


def main():
    r = Runner(NAME)

    with tempfile.TemporaryDirectory(prefix="httpd-rev-") as td:
        d = Path(td)
        f = mtls_fixture(d)
        revoked = d / "revoked.txt"
        fa = fingerprint(f["client-a.crt"])
        fb = fingerprint(f["client-b.crt"])

        # 1) empty table, periodic updates
        write_list(revoked, [])
        p = free_port()
        with Server(config_text(p, f, revoked), p, name=NAME):
            wait_port(p)
            try_req = make_try(p, f)

            r.case("empty list: a+client-a", try_req("a.example.test", "client-a"))

            write_list(revoked, [fa])
            time.sleep(1.8)
            r.case("revoke a: a+client-a", not try_req("a.example.test", "client-a"))
            r.case("revoke a: b+client-b unaffected", try_req("b.example.test", "client-b"))
            r.case("revoke a: public unaffected", try_req("public.example.test", None))

            write_list(revoked, ["zzzz-not-a-fingerprint"])
            time.sleep(1.8)
            r.case("invalid data keeps old table", not try_req("a.example.test", "client-a"))

            write_list(revoked, [])
            time.sleep(1.8)
            r.case("clear list restores a", try_req("a.example.test", "client-a"))

            write_list(revoked, [fb])
            time.sleep(1.8)
            r.case("revoke b: b+client-b", not try_req("b.example.test", "client-b"))
            r.case("revoke b: a+client-a unaffected", try_req("a.example.test", "client-a"))

        # 2) startup preload
        write_list(revoked, [fa])
        p2 = free_port()
        with Server(config_text(p2, f, revoked), p2, name=NAME):
            wait_port(p2)
            try_req2 = make_try(p2, f)
            r.case("startup preload: a+client-a", not try_req2("a.example.test", "client-a"))
            r.case("startup preload: b+client-b", try_req2("b.example.test", "client-b"))

        # 3) reject_all when the first load never succeeds
        missing = d / "missing.txt"
        p3 = free_port()
        with Server(config_text(p3, f, missing, on_error="reject_all"), p3, name=NAME):
            wait_port(p3)
            try_req3 = make_try(p3, f)
            r.case("reject_all missing file: a+client-a",
                   not try_req3("a.example.test", "client-a"))
            r.case("reject_all missing file: public unaffected",
                   try_req3("public.example.test", None))

        # 4) hash table growth: 3000 > initial capacity (1024)
        big = d / "big.txt"
        write_list(big, [f"{i:064x}" for i in range(3000)])
        p4 = free_port()
        with Server(config_text(p4, f, big), p4, name=NAME):
            wait_port(p4)
            try_req4 = make_try(p4, f)
            r.case("large revocation table loads and serves",
                   try_req4("b.example.test", "client-b"))

    r.finish()


if __name__ == "__main__":
    main()
