#!/usr/bin/env python3
"""Lua API semantics: query, headers, text(max), header map, 204/304, status/body."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_config, http_request, low_headers

NAME = "11_lua_api"
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "api_app.lua"


def main():
    r = Runner(NAME)
    port = free_port()
    cfg = http_config(port, "limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 }",
                      app=FIXTURE)

    with Server(cfg, port, name=NAME):
        st, h, b = http_request(port, "/query?x=1&y=2")
        r.case("req.query raw", st == 200 and b == b"x=1&y=2", f"status={st} body={b!r}")

        st, h, b = http_request(port, "/header", headers=["X-Test: abc"])
        r.case("req.headers lookup", st == 200 and b == b"abc", f"status={st} body={b!r}")

        st, h, b = http_request(port, "/text", "POST", b"t" * (2 * 1024 * 1024))
        r.case("req:text(max) aggregates", st == 200 and b == b"len=2097152",
               f"status={st} body={b!r}")

        st, h, b = http_request(port, "/timeout0")
        r.case("res:set_timeout(0)", st == 200 and b == b"ok", f"status={st}")

        st, h, b = http_request(port, "/header-map")
        r.case("res header map", st == 200 and low_headers(h, b"x-map") == b"yes" and b == b"ok",
               f"status={st} x-map={low_headers(h, b'x-map')!r}")

        st, h, b = http_request(port, "/queue")
        q = low_headers(h, b"x-queue")
        r.case("res:queue_size header", st == 200 and q.isdigit(), f"status={st} queue={q!r}")

        st, h, b = http_request(port, "/header-sent")
        r.case("res:header_sent false before / true after",
               st == 200 and low_headers(h, b"x-before") == b"false" and b == b"after=true",
               f"status={st} x-before={low_headers(h, b'x-before')!r} body={b!r}")

        st, h, b = http_request(port, "/204")
        r.case("204 no body / CL 0",
               st == 204 and b == b"" and low_headers(h, b"content-length") in (b"0", b"-"),
               f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/304")
        r.case("304 no body", st == 304 and b == b"", f"status={st} len={len(b)}")

        st, h, b = http_request(port, "/method")
        r.case("req.method/path", st == 200 and b == b"GET /method", f"status={st} body={b!r}")

    r.finish()


if __name__ == "__main__":
    main()
