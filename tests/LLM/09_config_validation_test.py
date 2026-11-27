#!/usr/bin/env python3
"""Config validation: invalid configuration must fail fast, not hang."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import APP, Runner, start_expect_failure

NAME = "09_config_validation"


def cfg(server: str, app: str | None = None, top: str = "") -> str:
    parts = [f"server = {{ {server} }}"]
    if top:
        parts.append(top)
    if app:
        parts.append(f'app = "{app}"')
    return "return { " + ", ".join(parts) + " }"


def main():
    r = Runner(NAME)
    cases = [
        ("missing app/handle",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }')),
        ("TLS listener without cert/key",
         cfg('listen = { { host = "127.0.0.1", port = 0, tls = true } }, tls = { min_version = "1.2" }', str(APP))),
        ("bad min_version",
         cfg('listen = { { host = "127.0.0.1", port = 0, tls = true } }, tls = { cert = "x", key = "x", min_version = "1.1" }', str(APP))),
        ("missing cert file",
         cfg('listen = { { host = "127.0.0.1", port = 0, tls = true } }, tls = { cert = "/no/such.crt", key = "/no/such.key" }', str(APP))),
        ("buffer low > high",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }, buffers = { write_high_water = 1024, write_low_water = 2048 }', str(APP))),
        ("buffer high > hard",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }, buffers = { write_high_water = 4 * 1024 * 1024, write_hard_limit = 1024 }', str(APP))),
        ("tcp keepalive_delay 0",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }, tcp = { keepalive = true, keepalive_delay = 0 }', str(APP))),
        ("bad log level",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { access = "/tmp/x", level = "verbose" }')),
        ("bad revocation key",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'revocation = { enabled = true, key = "md5" }')),
        ("revocation without provider",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'revocation = { enabled = true, interval = 1 }')),
        ("listen port out of range",
         cfg('listen = { { host = "127.0.0.1", port = 70000 } }', str(APP))),
        ("missing app file",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', "/no/such/app.lua")),
        ("log.file access without path",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { file = { access = true } }')),
        ("log.otlp without endpoint",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { otlp = { enabled = true } }')),
        ("log.otlp bad endpoint scheme",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { otlp = { enabled = true, endpoint = "ftp://127.0.0.1:4318" } }')),
        ("log.otlp batch too small",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { otlp = { enabled = true, endpoint = "http://127.0.0.1:4318", batch_max_bytes = 512 } }')),
        ("log.otlp queue below batch",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { otlp = { enabled = true, endpoint = "http://127.0.0.1:4318", batch_max_bytes = 1048576, queue_max_bytes = 1024 } }')),
        ("log.syslog without host",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { syslog = { enabled = true, transport = "udp" } }')),
        ("log.syslog unix without path",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { syslog = { enabled = true, transport = "unix" } }')),
        ("log.syslog bad transport",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { syslog = { enabled = true, host = "127.0.0.1", transport = "smoke" } }')),
        ("log.syslog bad format",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { syslog = { enabled = true, host = "127.0.0.1", format = "xml" } }')),
        ("log.syslog tls ca missing",
         cfg('listen = { { host = "127.0.0.1", port = 0 } }', str(APP),
             'log = { syslog = { enabled = true, transport = "tls", host = "127.0.0.1", ca = "/no/such/ca.crt" } }')),
    ]
    for name, text in cases:
        rc, log = start_expect_failure(text)
        last = log.strip().splitlines()[-1] if log.strip() else ""
        r.case(name, rc not in (0, -999), f"rc={rc} {last[:100]}")

    r.finish()


if __name__ == "__main__":
    main()
