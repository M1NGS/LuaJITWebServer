#!/usr/bin/env python3
"""C 层流式 multipart/form-data：字段/文件、软限制、错误、清理、keep-alive、多 worker。

覆盖 TODO 第 1 节 P1：单遍解析落盘、req.fields/req.files、临时文件清理、
chunked 与 Content-Length 双模式、文件数/大小/字段总量软限制、畸形请求 400、
超 max_body 413。文件内容通过 app 把临时文件 rename 到 keep 目录后由测试校验。
"""
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import Runner, Server, free_port, read_response

NAME = "20_multipart_upload"

APP_LUA = r"""
return { handle = function(req, res)
  if not req.multipart then
    return { status = 200, body = "plain" }
  end
  if req.fields.reject then
    return { status = 403, body = "denied" }
  end
  local keep = config.uploader.keep_dir
  local out = {}
  for k, v in pairs(req.fields) do
    out[#out + 1] = "F\t" .. k .. "\t" .. v
  end
  for i, f in ipairs(req.files) do
    local ok = false
    if keep and keep ~= "" then
      ok = os.rename(f.path, keep .. "/" .. f.filename)
    end
    out[#out + 1] = table.concat(
      { "P", f.field, f.filename, f.content_type, tostring(f.size), tostring(ok) }, "\t")
  end
  out[#out + 1] = "READ\t" .. tostring(req:read())
  out[#out + 1] = "TEXT\t" .. tostring(req:text())
  return { status = 200, body = table.concat(out, "\n") }
end }
"""


def cfg(port, app, keep, workers=1):
    return f"""return {{
  server = {{
    workers = {workers},
    listen = {{ {{ host = "127.0.0.1", port = {port} }} }},
  }},
  log = {{ file = {{ enabled = false }} }},
  app = "{app}",
  uploader = {{ keep_dir = "{keep}" }}
}}
"""


def build_body(boundary, fields, files, end=True):
    out = []
    for name, value in fields:
        out.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value + b"\r\n")
    for name, filename, ctype, data in files:
        h = (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
             f'filename="{filename}"\r\n')
        if ctype:
            h += f"Content-Type: {ctype}\r\n"
        h += "\r\n"
        out.append(h.encode() + data + b"\r\n")
    if end:
        out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out)


def post_mp(port, boundary, body, chunked=False, close=True, ctype=None, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    ct = ctype if ctype is not None else f"multipart/form-data; boundary={boundary}"
    hdr = ["POST / HTTP/1.1", "Host: x", f"Content-Type: {ct}"]
    if chunked:
        hdr.append("Transfer-Encoding: chunked")
    else:
        hdr.append(f"Content-Length: {len(body)}")
    hdr.append("Connection: " + ("close" if close else "keep-alive"))
    s.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode())
    if chunked:
        pos = 0
        while pos < len(body):
            part = body[pos:pos + 700]   # 让 boundary 跨块
            s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            pos += 700
        s.sendall(b"0\r\n\r\n")
    else:
        s.sendall(body)
    st, hdrs, rb = read_response(s, "POST", timeout)
    return s, st, hdrs, rb


def parse_meta(body):
    fields = {}
    files = []
    read = text = None
    for line in body.decode("utf-8", "replace").splitlines():
        p = line.split("\t")
        if p[0] == "F" and len(p) >= 3:
            fields[p[1]] = p[2]
        elif p[0] == "P" and len(p) >= 6:
            files.append({"field": p[1], "filename": p[2], "content_type": p[3],
                          "size": int(p[4]), "moved": p[5]})
        elif p[0] == "READ":
            read = p[1]
        elif p[0] == "TEXT":
            text = p[1]
    return fields, files, read, text


def upload_dir_files(upload_dir):
    return list(upload_dir.iterdir()) if upload_dir.exists() else []


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-mp-") as td:
        d = Path(td)
        keep = d / "keep"
        keep.mkdir()
        app = d / "app.lua"
        app.write_text(APP_LUA)
        up = d / "up"

        # ---------- 基本字段/文件、Lua API、清理 ----------
        port = free_port()
        with Server(cfg(port, app, keep), port,
                    env={"HTTPD_UPLOAD_DIR": str(up)}, name=NAME) as srv:
            b = "bnd-basic"
            body = build_body(
                b,
                [("alpha", b"hello"), ("name", "张三".encode()), ("empty", b""),
                 ("dup", b"one"), ("dup", b"two")],
                [("upload", "a.txt", "text/plain", b"file-a"),
                 ("blob", "b.bin", "application/octet-stream", b"\x00\x01\xffxyz")])
            _, st, _, rb = post_mp(port, b, body)
            fields, files, read, text = parse_meta(rb)
            r.case("multipart fields", st == 200 and fields.get("alpha") == "hello"
                   and fields.get("name") == "张三" and fields.get("empty") == ""
                   and fields.get("dup") == "two",
                   f"status={st} fields={fields}")
            r.case("multipart files metadata",
                   len(files) == 2
                   and files[0]["field"] == "upload" and files[0]["filename"] == "a.txt"
                   and files[0]["content_type"] == "text/plain" and files[0]["size"] == 6
                   and files[1]["field"] == "blob" and files[1]["filename"] == "b.bin"
                   and files[1]["size"] == 6 and files[1]["moved"] == "true",
                   f"files={files}")
            r.case("multipart file contents",
                   (keep / "a.txt").read_bytes() == b"file-a"
                   and (keep / "b.bin").read_bytes() == b"\x00\x01\xffxyz",
                   "")
            r.case("req:read()/text() return nil for multipart",
                   read == "nil" and text == "nil", f"read={read} text={text}")
            r.case("upload dir empty after request", upload_dir_files(up) == [],
                   str(upload_dir_files(up)))

            # quoted boundary + 额外参数
            b = "quoted-bnd"
            body = build_body(b, [("q", b"v")], [("f", "q.txt", "text/plain", b"qq")])
            ct = f'multipart/form-data; boundary="{b}"; charset=utf-8'
            _, st, _, rb = post_mp(port, b, body, ctype=ct)
            fields, files, _, _ = parse_meta(rb)
            r.case("quoted boundary", st == 200 and fields.get("q") == "v"
                   and len(files) == 1 and files[0]["size"] == 2,
                   f"status={st} fields={fields} files={files}")

            # chunked multipart（boundary 跨块）
            b = "bnd-chunk"
            body = build_body(b, [("c", b"chunked-value")],
                              [("file", "c.bin", "application/octet-stream", b"\x00" * 1500)])
            _, st, _, rb = post_mp(port, b, body, chunked=True)
            fields, files, _, _ = parse_meta(rb)
            r.case("chunked multipart", st == 200 and fields.get("c") == "chunked-value"
                   and len(files) == 1 and files[0]["size"] == 1500
                   and (keep / "c.bin").read_bytes() == b"\x00" * 1500,
                   f"status={st} fields={fields} files={files}")

            # 畸形：缺 boundary
            _, st, _, rb = post_mp(port, "x", b"", ctype="multipart/form-data")
            r.case("missing boundary -> 400", st == 400, f"status={st} {rb[:80]}")
            # boundary 过长（71 字节）
            longb = "x" * 71
            body = build_body(longb, [("a", b"b")], [])
            ct = f"multipart/form-data; boundary={longb}"
            _, st, _, rb = post_mp(port, longb, body, ctype=ct)
            r.case("boundary too long -> 400", st == 400, f"status={st}")
            # 缺 Content-Disposition
            body = (b"--bnd-bad\r\nContent-Type: text/plain\r\n\r\nx\r\n"
                    b"--bnd-bad--\r\n")
            _, st, _, rb = post_mp(port, "bnd-bad", body)
            r.case("part without Content-Disposition -> 400", st == 400, f"status={st}")
            # 缺 name
            body = b"--bnd-bad\r\nContent-Disposition: form-data\r\n\r\nx\r\n--bnd-bad--\r\n"
            _, st, _, rb = post_mp(port, "bnd-bad", body)
            r.case("part without name -> 400", st == 400, f"status={st} {rb[:80]}")

            # handler 403：临时文件由 C 清理
            b = "bnd-reject"
            body = build_body(b, [("reject", b"1")],
                              [("f", "reject.bin", "application/octet-stream", b"rrr")])
            _, st, _, rb = post_mp(port, b, body)
            r.case("handler 403 and temp files cleaned",
                   st == 403 and upload_dir_files(up) == [],
                   f"status={st} left={upload_dir_files(up)}")

            # keep-alive：同一连接上传后 GET
            b = "bnd-ka"
            body = build_body(b, [("ka", b"1")], [("f", "ka.txt", "text/plain", b"ka")])
            s, st, _, rb = post_mp(port, b, body, close=False)
            fields, files, _, _ = parse_meta(rb)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            st2, _, rb2 = read_response(s, "GET")
            s.close()
            r.case("keep-alive after multipart", st == 200 and fields.get("ka") == "1"
                   and st2 == 200 and rb2 == b"plain",
                   f"first={st} second={st2} body={rb2!r}")

            # 普通 POST（非 multipart）不受影响
            _, st, _, rb = post_mp(port, "x", b"a=1&b=2",
                                   ctype="application/x-www-form-urlencoded")
            r.case("plain POST unaffected", st == 200 and rb == b"plain",
                   f"status={st} body={rb!r}")

            srv.proc.send_signal(15)
            r.case("graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

        # ---------- 文件软限：超限省略、继续解析 ----------
        up2 = d / "up2"
        keep2 = d / "keep2"
        keep2.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep2), port,
                    env={"HTTPD_UPLOAD_DIR": str(up2),
                         "HTTPD_UPLOAD_MAX_FILE": "100"}, name=NAME) as srv:
            b = "bnd-limit"
            body = build_body(b, [("note", b"still-parsed")],
                              [("small", "small.txt", "text/plain", b"s" * 50),
                               ("big", "big.bin", "application/octet-stream", b"B" * 200)])
            _, st, _, rb = post_mp(port, b, body)
            fields, files, _, _ = parse_meta(rb)
            r.case("file size soft limit omits large file",
                   st == 200 and fields.get("note") == "still-parsed" and len(files) == 1
                   and files[0]["filename"] == "small.txt" and files[0]["size"] == 50,
                   f"status={st} fields={fields} files={files}")
            r.case("omitted file leaves no temp file", upload_dir_files(up2) == [],
                   str(upload_dir_files(up2)))
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # ---------- 文件数上限 ----------
        up3 = d / "up3"
        keep3 = d / "keep3"
        keep3.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep3), port,
                    env={"HTTPD_UPLOAD_DIR": str(up3),
                         "HTTPD_UPLOAD_MAX_FILES": "2"}, name=NAME) as srv:
            b = "bnd-count"
            body = build_body(b, [], [
                ("f", "one.txt", "text/plain", b"1"),
                ("f", "two.txt", "text/plain", b"2"),
                ("f", "three.txt", "text/plain", b"3")])
            _, st, _, rb = post_mp(port, b, body)
            fields, files, _, _ = parse_meta(rb)
            r.case("file count limit keeps first two",
                   st == 200 and len(files) == 2
                   and [f["filename"] for f in files] == ["one.txt", "two.txt"],
                   f"status={st} files={files}")
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # ---------- 字段总量上限 ----------
        up4 = d / "up4"
        keep4 = d / "keep4"
        keep4.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep4), port,
                    env={"HTTPD_UPLOAD_DIR": str(up4),
                         "HTTPD_UPLOAD_MAX_FIELD_BYTES": "100"}, name=NAME) as srv:
            b = "bnd-fields"
            body = build_body(b, [("a", b"A" * 80), ("b", b"B" * 80)], [])
            _, st, _, rb = post_mp(port, b, body)
            fields, files, _, _ = parse_meta(rb)
            r.case("field bytes limit omits overflowing field",
                   st == 200 and fields.get("a") == "A" * 80 and "b" not in fields,
                   f"status={st} keys={list(fields)}")
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # ---------- 总 body 超限 413（CL 与 chunked） ----------
        up5 = d / "up5"
        keep5 = d / "keep5"
        keep5.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep5), port,
                    env={"HTTPD_UPLOAD_DIR": str(up5), "HTTPD_MAX_BODY": "500"},
                    name=NAME) as srv:
            b = "bnd-413"
            body = build_body(b, [("big", b"x" * 1000)], [])
            _, st, _, rb = post_mp(port, b, body)
            r.case("multipart body over max_body -> 413 (CL)", st == 413,
                   f"status={st} {rb[:60]}")
            body = build_body(b, [("big", b"x" * 1000)], [])
            _, st, _, rb = post_mp(port, b, body, chunked=True)
            r.case("multipart body over max_body -> 413 (chunked)", st == 413,
                   f"status={st} {rb[:60]}")
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # ---------- 客户端中途断开：临时文件清理 ----------
        up6 = d / "up6"
        keep6 = d / "keep6"
        keep6.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep6), port,
                    env={"HTTPD_UPLOAD_DIR": str(up6)}, name=NAME) as srv:
            b = "bnd-abort"
            prefix = (f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; "
                      f"filename=\"abort.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                      ).encode() + b"Z" * 200
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall((f"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; "
                       f"boundary={b}\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n"
                       ).encode() + prefix)
            time.sleep(0.2)
            s.close()
            time.sleep(0.4)
            r.case("client abort cleans temp files", upload_dir_files(up6) == [],
                   str(upload_dir_files(up6)))
            srv.proc.send_signal(15)
            srv.proc.wait(timeout=8)

        # ---------- 多 worker 并发上传 ----------
        up7 = d / "up7"
        keep7 = d / "keep7"
        keep7.mkdir()
        port = free_port()
        with Server(cfg(port, app, keep7, workers=4), port,
                    env={"HTTPD_UPLOAD_DIR": str(up7)}, name=NAME) as srv:
            results = []
            lock = threading.Lock()

            def one(i):
                b = f"bnd-mw-{i}"
                body = build_body(b, [("idx", str(i).encode())],
                                  [("f", f"f{i}.bin", "application/octet-stream",
                                    bytes([i]) * (100 + i))])
                try:
                    _, st, _, rb = post_mp(port, b, body)
                    fields, files, read, _ = parse_meta(rb)
                    ok = (st == 200 and fields.get("idx") == str(i)
                          and len(files) == 1 and files[0]["size"] == 100 + i)
                except Exception:
                    ok = False
                with lock:
                    results.append(ok)

            threads = [threading.Thread(target=one, args=(i,)) for i in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            r.case("4 workers: 16 concurrent multipart uploads",
                   len(results) == 16 and all(results), f"ok={sum(results)}/16")
            r.case("4 workers: upload dir empty after uploads", upload_dir_files(up7) == [],
                   str(upload_dir_files(up7)))
            srv.proc.send_signal(15)
            r.case("4 workers: graceful exit 0", srv.proc.wait(timeout=8) == 0, "")

    r.finish()


if __name__ == "__main__":
    main()
