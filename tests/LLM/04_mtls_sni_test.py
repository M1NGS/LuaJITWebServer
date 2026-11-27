#!/usr/bin/env python3
"""per-SNI mTLS: different client CAs, override and inherit client_auth."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, free_port, mtls_fixture, tls_request,
                     wait_port)

NAME = "04_mtls_sni"


def main():
    r = Runner(NAME)
    port = free_port()

    with tempfile.TemporaryDirectory(prefix="httpd-mtls-") as td:
        f = mtls_fixture(Path(td))
        cfg = f"""return {{
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
           key = "{f['public-server.key']}", client_auth = false }},
        {{ server_name = "inherit.example.test", cert = "{f['a-server.crt']}",
           key = "{f['a-server.key']}", client_auth = true }}
      }}
    }},
    limits = {{ idle_timeout = 30 }}
  }},
  app = "{APP}"
}}
"""
        with Server(cfg, port, name=NAME):
            wait_port(port)

            def try_request(server_name, client):
                cc = f[f"{client}.crt"] if client else None
                ck = f[f"{client}.key"] if client else None
                try:
                    st, _, _ = tls_request(port, server_name=server_name,
                                           client_cert=cc, client_key=ck)
                    return st == 200
                except Exception:
                    return False

            cases = [
                ("a + client-a (CA-A)", "a.example.test", "client-a", True),
                ("a + client-b (CA-B)", "a.example.test", "client-b", False),
                ("a + no client cert", "a.example.test", None, False),
                ("b + client-b (CA-B)", "b.example.test", "client-b", True),
                ("b + client-a (CA-A)", "b.example.test", "client-a", False),
                ("b + no client cert", "b.example.test", None, False),
                ("public + no client cert (override false)", "public.example.test", None, True),
                ("inherit + client-a (global ca)", "inherit.example.test", "client-a", True),
                ("inherit + client-b", "inherit.example.test", "client-b", False),
                ("inherit + no client cert", "inherit.example.test", None, False),
                ("default no SNI + client-a", None, "client-a", True),
                ("default no SNI + client-b", None, "client-b", False),
                ("default no SNI + no client cert", None, None, False),
            ]
            for name, sni, client, expect in cases:
                result = try_request(sni, client)
                r.case(name, result == expect, f"expected={'accept' if expect else 'reject'} got={'accept' if result else 'reject'}")

    r.finish()


if __name__ == "__main__":
    main()
