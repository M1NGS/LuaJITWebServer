#!/usr/bin/env python3
"""Periodic log rotation and truncate in the libuv thread pool."""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_config, http_request

NAME = "07_log_rotate"


def main():
    r = Runner(NAME)

    # rotate mode: keep 2
    with tempfile.TemporaryDirectory(prefix="httpd-rot-") as td:
        d = Path(td)
        logs = d / "logs"
        logs.mkdir()
        access = logs / "access.log"
        error = logs / "error.log"
        port = free_port()
        cfg = http_config(
            port,
            "limits = { idle_timeout = 30 }",
            extra_top=f'log = {{ access = "{access}", error = "{error}", level = "info", '
                      f'flush_interval = 0.1, rotate_interval = 1, rotate_keep = 2 }}',
        )
        with Server(cfg, port, name=NAME):
            for _ in range(3):
                http_request(port, "/")
                time.sleep(0.05)
            time.sleep(1.2)
            http_request(port, "/")
            time.sleep(1.2)

            files = [access, Path(str(access) + ".1"), Path(str(access) + ".2")]
            counts = {p.name: len(p.read_text().splitlines()) if p.exists() else 0
                      for p in files}
            total = sum(counts.values())
            r.case("rotate keep=2: total lines", total == 4, str(counts))
            r.case("rotate keep=2: .1 has 1", counts.get("access.log.1", 0) == 1, str(counts))
            r.case("rotate keep=2: .2 has 3", counts.get("access.log.2", 0) == 3, str(counts))

    # truncate mode: keep 0
    with tempfile.TemporaryDirectory(prefix="httpd-trunc-") as td:
        d = Path(td)
        logs = d / "logs"
        logs.mkdir()
        access = logs / "access.log"
        error = logs / "error.log"
        port = free_port()
        cfg = http_config(
            port,
            "limits = { idle_timeout = 30 }",
            extra_top=f'log = {{ access = "{access}", error = "{error}", level = "info", '
                      f'flush_interval = 0.1, rotate_interval = 1, rotate_keep = 0 }}',
        )
        with Server(cfg, port, name=NAME):
            http_request(port, "/")
            time.sleep(1.2)
            size = access.stat().st_size if access.exists() else -1
            r.case("truncate keep=0 empties file", size == 0, f"size={size}")

            http_request(port, "/")
            time.sleep(0.3)
            lines = access.read_text().splitlines() if access.exists() else []
            r.case("write after truncate", len(lines) == 1, f"lines={len(lines)}")

    r.finish()


if __name__ == "__main__":
    main()
