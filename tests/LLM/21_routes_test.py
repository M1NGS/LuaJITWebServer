#!/usr/bin/env python3
"""routes 配置：启动时编译的精确/前缀/method 路由、kind=upload 415、fallback、
多 worker 与 SIGHUP 限制（routes 变化需 restart）。"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, http_request, start_expect_failure

NAME = "21_routes"

ROUTES_LUA = """  routes = {
    { path = "/api", method = "GET", handler = function(req, res)
        return { status = 200, body = "api:" .. req.path }
      end },
    { path = "/any", handler = function(req, res)
        return { status = 200, body = "any" }
      end },
    { path = "/static/", prefix = true, handler = function(req, res)
        return { status = 200, body = "static:" .. req.path }
      end },
    { path = "/upload", method = "POST", kind = "upload",
      handler = function(req, res)
        return { status = 200,
                 body = "up:" .. tostring(req.multipart) .. ":"
                        .. tostring(req.fields and req.fields.x) }
      end },
  },"""


def cfg(port, app, routes=ROUTES_LUA, workers=1):
    return f"""return {{
  server = {{
    workers = {workers},
    listen = {{ {{ host = "127.0.0.1", port = {port} }} }},
  }},
  log = {{ file = {{ enabled = false }} }},
{routes}
  app = "{app}"
}}
"""


def app_lua(tag):
    return (f"return {{ handle = function(req, res) "
            f"return {{ status = 200, body = \"{tag}:\" .. req.path }} end }}\n")


def mp_body(boundary, fields):
    out = []
    for name, value in fields:
        out.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out)


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-routes-") as td:
        d = Path(td)
        app = d / "app.lua"
        app.write_text(app_lua("fallback"))
        port = free_port()

        with Server(cfg(port, app), port, name=NAME) as srv:
            st, _, b = http_request(port, "/api")
            r.case("exact path + method", st == 200 and b == b"api:/api",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/api", method="POST", body=b"x")
            r.case("method mismatch falls back", st == 200 and b == b"fallback:/api",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/api/x")
            r.case("exact path does not prefix-match", st == 200 and b == b"fallback:/api/x",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/any")
            r.case("method omitted matches any", st == 200 and b == b"any",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/any", method="POST", body=b"x")
            r.case("method omitted matches POST", st == 200 and b == b"any",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/static/a/b.txt")
            r.case("prefix route", st == 200 and b == b"static:/static/a/b.txt",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/static")
            r.case("prefix needs full prefix", st == 200 and b == b"fallback:/static",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/staticx")
            r.case("prefix boundary", st == 200 and b == b"fallback:/staticx",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/upload")
            r.case("GET /upload falls back (method mismatch)",
                   st == 200 and b == b"fallback:/upload", f"{st} {b!r}")
            st, _, b = http_request(port, "/upload", method="POST", body=b"x")
            r.case("upload route with CL body -> 415", st == 415,
                   f"{st} {b!r}")
            boundary = "bnd-route"
            body = mp_body(boundary, [("x", b"value")])
            st, _, b = http_request(port, "/upload", method="POST", body=body,
                                    headers=[f"Content-Type: multipart/form-data; boundary={boundary}"])
            r.case("upload route with multipart", st == 200 and b == b"up:true:value",
                   f"{st} {b!r}")
            st, _, b = http_request(port, "/nope")
            r.case("unmatched falls back", st == 200 and b == b"fallback:/nope",
                   f"{st} {b!r}")

            # 单 worker reload 不重载 app（既有文档限制），routes 也不变
            app.write_text(app_lua("newfallback"))
            srv.proc.send_signal(1)
            time.sleep(0.8)
            st, _, b = http_request(port, "/nope")
            r.case("single-worker reload keeps old app",
                   st == 200 and b == b"fallback:/nope", f"{st} {b!r}")
            st, _, b = http_request(port, "/api")
            r.case("reload does not rebuild routes", st == 200 and b == b"api:/api",
                   f"{st} {b!r}")

            # 改 routes：reload 拒绝，旧路由继续
            srv.config_path.write_text(
                cfg(port, app, ROUTES_LUA.replace('path = "/any"', 'path = "/renamed"')))
            srv.proc.send_signal(1)
            time.sleep(0.8)
            st, _, b = http_request(port, "/any")
            log = srv.log()
            r.case("routes change requires restart", st == 200 and b == b"any"
                   and "routes changes require restart" in log, f"{st} {b!r}")

            srv.proc.send_signal(15)
            r.case("graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 多 worker：每个 worker 独立 refs，同一路由全部命中
        app.write_text(app_lua("mw"))
        port = free_port()
        with Server(cfg(port, app, workers=4), port, name=NAME) as srv:
            hits = 0
            for _ in range(8):
                st, _, b = http_request(port, "/api")
                hits += 1 if (st == 200 and b == b"api:/api") else 0
            r.case("4 workers: route handlers work", hits == 8, f"{hits}/8")
            st, _, b = http_request(port, "/unknown")
            r.case("4 workers: fallback", st == 200 and b == b"mw:/unknown",
                   f"{st} {b!r}")

            # 多 worker reload app：fallback 更新，路由 handler 保持
            app.write_text(app_lua("mw2"))
            srv.proc.send_signal(1)
            deadline = time.time() + 3.0
            new_hits = 0
            while time.time() < deadline and new_hits < 8:
                st, _, b = http_request(port, "/unknown")
                if st == 200 and b == b"mw2:/unknown":
                    new_hits += 1
                time.sleep(0.05)
            r.case("4 workers: reload app updates fallback", new_hits == 8,
                   f"new={new_hits}/8 log={srv.log()[-300:]}")
            st, _, b = http_request(port, "/api")
            r.case("4 workers: routes survive app reload",
                   st == 200 and b == b"api:/api", f"{st} {b!r}")
            srv.proc.send_signal(15)
            r.case("4 workers: graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 启动校验：routes 结构错误
        bad_cases = [
            ("routes not array", '  routes = "x",'),
            ("handler not function", '  routes = { { path = "/x", handler = 1 } },'),
            ("bad kind", '  routes = { { path = "/x", kind = "static", '
                         'handler = function(req,res) return {status=200} end } },'),
            ("path without slash", '  routes = { { path = "x", '
                                   'handler = function(req,res) return {status=200} end } },'),
        ]
        for name, routes in bad_cases:
            text = cfg(port, app, routes)
            text = text.replace(f'port = {port}', 'port = 0')
            rc, log = start_expect_failure(text)
            r.case(f"startup rejects {name}", rc not in (0, -999),
                   f"rc={rc} {log.strip().splitlines()[-1][:80] if log.strip() else ''}")

    r.finish()


if __name__ == "__main__":
    main()
