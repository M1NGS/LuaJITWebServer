#!/usr/bin/env python3
"""SNI IDN：配置可写 Unicode，服务端转 A-label（RFC 3492）匹配；新增 **.suffix
多级通配（*.suffix 仍只匹配一级）。"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import (Runner, Server, cert_subject, free_port, gen_self_signed,
                     start_expect_failure)

NAME = "23_sni_idn"

IDN_CN = "例子.example".encode("idna").decode()
IDN_WILD_CN = "*." + IDN_CN


def cfg(port, app, cert, key, sni_lua, workers=1):
    return f"""return {{
  server = {{
    workers = {workers},
    listen = {{ {{ host = "127.0.0.1", port = {port}, tls = true }} }},
    tls = {{ cert = "{cert}", key = "{key}", min_version = "1.2",
             check_interval = 0,
             sni = {{ {sni_lua} }} }},
  }},
  log = {{ file = {{ enabled = false }} }},
  app = "{app}"
}}
"""


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-idn-") as td:
        d = Path(td)
        app = d / "app.lua"
        app.write_text("return { handle = function(req,res) return {status=200} end }\n")

        def cert_for(name, cn):
            c = d / f"{name}.crt"
            k = d / f"{name}.key"
            gen_self_signed(c, k, cn, f"DNS:{cn.replace('*.', '')}")
            return c, k

        dcert, dkey = cert_for("default", "localhost")
        icert, ikey = cert_for("idn", IDN_CN)
        wcert, wkey = cert_for("idnwild", IDN_WILD_CN)
        onecert, onekey = cert_for("wildone", "wild-one")
        multicert, multikey = cert_for("wildmulti", "wild-multi")

        sni = (f'{{ server_name = "例子.example", cert = "{icert}", key = "{ikey}" }}, '
               f'{{ server_name = "*.例子.example", cert = "{wcert}", key = "{wkey}" }}, '
               f'{{ server_name = "*.wild.example", cert = "{onecert}", key = "{onekey}" }}, '
               f'{{ server_name = "**.wild.example", cert = "{multicert}", key = "{multikey}" }}')
        port = free_port()

        with Server(cfg(port, app, dcert, dkey, sni), port, name=NAME) as srv:
            subj = cert_subject(port, IDN_CN)
            r.case("IDN exact (config Unicode)", IDN_CN in subj, subj)
            subj = cert_subject(port, "a." + IDN_CN)
            r.case("IDN wildcard one level", IDN_CN in subj and "CN = *" in subj, subj)
            subj = cert_subject(port, "XN--FSQU00A.Example")
            r.case("IDN uppercase A-label", IDN_CN in subj, subj)

            subj = cert_subject(port, "a.wild.example")
            r.case("*. matches one label", "wild-one" in subj, subj)
            subj = cert_subject(port, "a.b.wild.example")
            r.case("**. matches multiple labels", "wild-multi" in subj, subj)
            subj = cert_subject(port, "a.b.c.wild.example")
            r.case("**. matches deep labels", "wild-multi" in subj, subj)
            subj = cert_subject(port, "wild.example")
            r.case("wildcard needs a label", "CN = localhost" in subj, subj)
            subj = cert_subject(port, "notwild.example")
            r.case("suffix boundary", "CN = localhost" in subj, subj)

            srv.proc.send_signal(15)
            r.case("graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 4 worker：每 worker 的 SNI 材料都做同样的归一化
        port = free_port()
        with Server(cfg(port, app, dcert, dkey, sni, workers=4), port, name=NAME) as srv:
            hits = 0
            for _ in range(4):
                subj = cert_subject(port, IDN_CN)
                hits += 1 if IDN_CN in subj else 0
            r.case("4 workers: IDN exact", hits == 4, f"{hits}/4")
            subj = cert_subject(port, "a.b.wild.example")
            r.case("4 workers: multi-level wildcard", "wild-multi" in subj, subj)
            srv.proc.send_signal(15)
            r.case("4 workers: graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # 非法 SNI 域名 / 通配符启动失败
        bad_cases = [
            ("empty IDN label", 'server_name = "例子..example"'),
            ("bad wildcard", 'server_name = "*example"'),
            ("double wildcard only", 'server_name = "**"'),
            ("invalid utf8", 'server_name = "a\\255b"'),
        ]
        for name, bad_name in bad_cases:
            text = cfg(0, app, dcert, dkey,
                       f'{{ {bad_name}, cert = "{icert}", key = "{ikey}" }}')
            rc, log = start_expect_failure(text)
            r.case(f"startup rejects {name}", rc not in (0, -999),
                   f"rc={rc} {log.strip().splitlines()[-1][:90] if log.strip() else ''}")

    r.finish()


if __name__ == "__main__":
    main()
