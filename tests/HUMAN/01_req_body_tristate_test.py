#!/usr/bin/env python3
"""HUMAN-originated regression: request body tristate semantics.

The user questioned how Lua distinguishes "no body" from "large streaming body"
when req.body is nil. This locks the explicit has_body/body_size/streaming
fields and the no-body 400 behavior.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_config, http_request

NAME = "HUMAN_01_req_body_tristate"


def main():
    r = Runner(NAME)
    port = free_port()
    cfg = http_config(port, "limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 }")
    with Server(cfg, port, name=NAME):
        st, h, b = http_request(port, "/meta")
        text = b.decode(errors="replace")
        r.case("no body: has_body=false body_size=0 streaming=false buffered=false",
               st == 200 and "has_body=false" in text and "body_size=0" in text
               and "streaming=false" in text and "buffered=false" in text, text.strip())

        st, h, b = http_request(port, "/meta", "POST", b"hello")
        text = b.decode(errors="replace")
        r.case("small body: has_body=true body_size=5 streaming=false buffered=true",
               st == 200 and "has_body=true" in text and "body_size=5" in text
               and "streaming=false" in text and "buffered=true" in text, text.strip())

        st, h, b = http_request(port, "/meta", "POST", b"x" * (2 * 1024 * 1024),
                                close=False)
        text = b.decode(errors="replace")
        r.case("large body: body_size=2097152 streaming=true buffered=false",
               st == 200 and "body_size=2097152" in text and "streaming=true" in text
               and "buffered=false" in text, text.strip())

        st, h, b = http_request(port, "/echo")
        r.case("GET /echo without body -> 400 (not silent 200)", st == 400,
               f"status={st}")

    r.finish()


if __name__ == "__main__":
    main()
