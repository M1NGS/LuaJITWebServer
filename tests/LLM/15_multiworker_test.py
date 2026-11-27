#!/usr/bin/env python3
"""Multi-worker (SO_REUSEPORT, per-thread loop + LuaJIT VM) smoke tests.

P0 scope: workers=N starts N threads each with its own libuv loop / Lua state /
listener; file logging is per-worker (same paths, O_APPEND); SIGHUP reload is
rejected while workers > 1; SIGTERM drains all workers and exits 0.
"""
import os
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (APP, Runner, Server, free_port, http_request,
                     start_expect_failure)

NAME = "15_multiworker"


def cfg(port, workers, access, error):
    return f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port} }} }},
    workers = {workers},
  }},
  log = {{ file = {{ access_path = "{access}", error_path = "{error}",
                      flush_interval = 0.05 }} }},
  app = "{APP}"
}}
"""


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-mw-") as td:
        d = Path(td)
        access = d / "access.log"
        error = d / "error.log"
        port = free_port()

        with Server(cfg(port, 4, access, error), port, name=NAME) as srv:
            st, _, _ = http_request(port, "/")
            r.case("4 workers: request served", st == 200, f"status={st}")

            results = []
            lock = threading.Lock()

            def one():
                try:
                    s, _, _ = http_request(port, "/")
                except Exception as e:  # noqa: BLE001
                    s = repr(e)
                with lock:
                    results.append(s)

            threads = [threading.Thread(target=one) for _ in range(64)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            ok = sum(1 for s in results if s == 200)
            r.case("4 workers: 64 concurrent requests", ok == 64, f"ok={ok}/64")
            time.sleep(0.4)

            text = access.read_text(errors="replace") if access.exists() else ""
            err = error.read_text(errors="replace") if error.exists() else ""
            r.case("4 workers: access log complete",
                   text.count('"GET / HTTP/1.1" 200') >= 65,
                   f"lines={len(text.splitlines())}")
            r.case("4 workers: startup log", "workers=4" in err, err.splitlines()[:1])
            r.case("4 workers: reuse_port forced",
                   "reuse_port=1" in err, err[-120:])

            tids = len(os.listdir(f"/proc/{srv.proc.pid}/task"))
            r.case("4 workers: thread count >= 5", tids >= 5, f"threads={tids}")

            srv.proc.send_signal(signal.SIGHUP)
            time.sleep(0.3)
            st2, _, _ = http_request(port, "/")
            r.case("SIGHUP rejected while workers > 1", st2 == 200, f"status={st2}")
            r.case("SIGHUP rejection logged", "not supported with workers" in srv.log(),
                   srv.log()[-100:])

            srv.proc.send_signal(signal.SIGTERM)
            try:
                rc = srv.proc.wait(timeout=6)
            except Exception:  # noqa: BLE001
                srv.proc.kill()
                rc = -1
            r.case("SIGTERM drains workers and exits 0", rc == 0, f"rc={rc}")

        # workers > 1 与端口 0 组合必须拒绝（每个 worker 会拿到不同端口）
        rc, log = start_expect_failure(cfg(0, 2, d / "a.log", d / "e.log"))
        r.case("port 0 rejected with workers > 1", rc not in (0, -999),
               log.strip().splitlines()[-1][:100] if log.strip() else "no output")

    r.finish()


if __name__ == "__main__":
    main()
