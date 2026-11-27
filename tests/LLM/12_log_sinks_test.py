#!/usr/bin/env python3
"""Log channels regression: file / OTLP / syslog switches, filters, batching, retry.

OTLP is decoded with a minimal protobuf wire-format reader (no protobuf package).
"""
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from testkit import APP, Runner, Server, free_port, gen_self_signed, http_request

NAME = "12_log_sinks"
ERROR_APP = Path(__file__).resolve().parents[1] / "fixtures" / "error_app.lua"


# ---------- minimal protobuf decoding (OTLP ExportLogsServiceRequest) ----------

def pb_varint(buf, i):
    v = 0
    shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        v |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            return v, i
    raise ValueError("truncated varint")


def pb_fields(buf):
    out = []
    i = 0
    while i < len(buf):
        tag, i = pb_varint(buf, i)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            v, i = pb_varint(buf, i)
            out.append((field, v))
        elif wire == 1:
            out.append((field, bytes(buf[i:i + 8])))
            i += 8
        elif wire == 2:
            n, i = pb_varint(buf, i)
            out.append((field, bytes(buf[i:i + n])))
            i += n
        elif wire == 5:
            i += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return out


def any_value(buf):
    for f, v in pb_fields(buf):
        if f == 1:
            return v.decode("utf-8", "replace")
        if f == 3:
            return v
    return None


def kv(buf):
    key = None
    val = None
    for f, v in pb_fields(buf):
        if f == 1:
            key = v.decode("utf-8", "replace")
        elif f == 2:
            val = any_value(v)
    return key, val


def otlp_resource(body):
    attrs = {}
    for f, rl in pb_fields(body):
        if f != 1:
            continue
        for f2, v2 in pb_fields(rl):
            if f2 == 1:
                for f3, v3 in pb_fields(v2):
                    if f3 == 1:
                        k, v = kv(v3)
                        if k:
                            attrs[k] = v
    return attrs


def otlp_scopes(body):
    """Return [(scope_name, [record dict...])] for every ScopeLogs."""
    result = []
    for f, rl in pb_fields(body):
        if f != 1:
            continue
        for f2, v2 in pb_fields(rl):
            if f2 != 2:
                continue
            scope = ""
            for f3, v3 in pb_fields(v2):
                if f3 == 1:
                    for f4, v4 in pb_fields(v3):
                        if f4 == 1:
                            scope = v4.decode("utf-8", "replace")
            recs = []
            for f3, v3 in pb_fields(v2):
                if f3 != 2:
                    continue
                rec = {"severity": 0, "severity_text": "", "body": "", "attrs": {}}
                for f5, v5 in pb_fields(v3):
                    if f5 == 2:
                        rec["severity"] = v5
                    elif f5 == 3:
                        rec["severity_text"] = v5.decode("utf-8", "replace")
                    elif f5 == 5:
                        rec["body"] = any_value(v5)
                    elif f5 == 6:
                        k, v = kv(v5)
                        if k:
                            rec["attrs"][k] = v
                recs.append(rec)
            result.append((scope, recs))
    return result


# ---------- mock receivers ----------

class OtlpMock:
    def __init__(self, fail_left=0):
        self.requests = []
        self.fail_left = fail_left
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n)
                app.requests.append({"path": self.path, "headers": dict(self.headers),
                                     "body": body, "time": time.time()})
                if app.fail_left > 0:
                    app.fail_left -= 1
                    self.send_response(500)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, fmt, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.thread.join(timeout=2)
        self.httpd.server_close()


class UdpMock:
    def __init__(self):
        self.msgs = []
        self._stop = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.msgs.append(self.sock.recv(8192))
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self._stop = True
        self.thread.join(timeout=1)
        self.sock.close()


def _drain_frames(buf, frames):
    """Decode complete RFC 6587 octet-counted frames; return the remainder."""
    while True:
        sp = buf.find(b" ")
        if sp < 0:
            break
        try:
            n = int(buf[:sp])
        except ValueError:
            break
        if len(buf) < sp + 1 + n:
            break
        frames.append(buf[sp + 1:sp + 1 + n])
        buf = buf[sp + 1 + n:]
    return buf


class TcpMock:
    """Accepts one connection and decodes RFC 6587 octet-counted frames."""

    def __init__(self):
        self.frames = []
        self._stop = False
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        buf = b""
        conn = None
        while not self._stop:
            if conn is None:
                try:
                    conn, _ = self.listener.accept()
                    conn.settimeout(0.2)
                    buf = b""
                except socket.timeout:
                    continue
            try:
                data = conn.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                data = b""
            if not data:
                conn.close()
                conn = None
                continue
            buf = _drain_frames(buf + data, self.frames)
        if conn is not None:
            conn.close()

    def close(self):
        self._stop = True
        self.thread.join(timeout=1)
        self.listener.close()


class TlsTcpMock(TcpMock):
    """TLS variant of TcpMock, trusted via a self-signed cert."""

    def __init__(self, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        super().__init__()

    def _run(self):
        buf = b""
        conn = None
        while not self._stop:
            if conn is None:
                try:
                    raw, _ = self.listener.accept()
                except socket.timeout:
                    continue
                try:
                    conn = self.ctx.wrap_socket(raw, server_side=True)
                except (ssl.SSLError, OSError):
                    raw.close()
                    conn = None
                    continue
                conn.settimeout(0.2)
                buf = b""
            try:
                data = conn.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                data = b""
            if not data:
                conn.close()
                conn = None
                continue
            buf = _drain_frames(buf + data, self.frames)
        if conn is not None:
            conn.close()


class UnixDgramMock:
    def __init__(self, path):
        self.msgs = []
        self._stop = False
        self.path = Path(path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.path))
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop:
            try:
                self.msgs.append(self.sock.recv(8192))
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self._stop = True
        self.thread.join(timeout=1)
        self.sock.close()
        self.path.unlink(missing_ok=True)


# ---------- config ----------

def cfg(port, log_lua, app=APP):
    return f"""return {{
  server = {{ listen = {{ {{ host = "127.0.0.1", port = {port} }} }} }},
  log = {log_lua},
  app = "{app}"
}}
"""


def main():
    r = Runner(NAME)
    with tempfile.TemporaryDirectory(prefix="httpd-log-sinks-") as td:
        d = Path(td)

        # ---- file channel: new subtable ----
        port = free_port()
        access = d / "access.log"
        error = d / "error.log"
        log = f"""{{
    file = {{ access_path = "{access}", error_path = "{error}", flush_interval = 0.05 }}
  }}"""
        with Server(cfg(port, log), port, name=NAME) as srv:
            st, _, _ = http_request(port, "/")
        text = access.read_text(errors="replace") if access.exists() else ""
        err = error.read_text(errors="replace") if error.exists() else ""
        r.case("file: request served", st == 200, f"status={st}")
        r.case("file: access line written", '"GET / HTTP/1.1" 200' in text, text.splitlines()[:1])
        r.case("file: error line written", "[info]" in err, err.splitlines()[:1])

        # ---- file channel: access switch off ----
        port = free_port()
        no_access = d / "no-access.log"
        only_error = d / "only-error.log"
        log = f"""{{
    file = {{ access = false, error_path = "{only_error}", flush_interval = 0.05 }}
  }}"""
        with Server(cfg(port, log), port, name=NAME):
            http_request(port, "/")
        r.case("file: access=false creates no access file", not no_access.exists(), str(no_access))
        r.case("file: error file still written",
               only_error.exists() and "[info]" in only_error.read_text(errors="replace"))

        # ---- file channel: legacy flat config ----
        port = free_port()
        legacy = d / "legacy-access.log"
        log = f'{{ access = "{legacy}", error = "{d}/legacy-error.log", flush_interval = 0.05 }}'
        with Server(cfg(port, log), port, name=NAME):
            http_request(port, "/")
        r.case("file: legacy flat config works",
               legacy.exists() and '"GET / HTTP/1.1" 200' in legacy.read_text(errors="replace"))

        # ---- otlp: batch + access records + local retention ----
        port = free_port()
        mock = OtlpMock()
        otlp_access = d / "otlp-access.log"
        log = f"""{{
    file = {{ access_path = "{otlp_access}", error_path = "{d}/otlp-e.log", flush_interval = 0.05 }},
    otlp = {{
      enabled = true, endpoint = "http://127.0.0.1:{mock.port}",
      batch_max_records = 10, flush_interval = 0.2, timeout = 1
    }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME) as srv:
                for _ in range(10):
                    http_request(port, "/")
                time.sleep(1.0)
                alive = srv.proc.poll() is None
        finally:
            mock.close()
        paths = [q["path"] for q in mock.requests]
        ctypes = [q["headers"].get("Content-Type", "") for q in mock.requests]
        scopes = [s for q in mock.requests for s in otlp_scopes(q["body"])]
        access_recs = [rec for scope, recs in scopes if scope == "httpd.access" for rec in recs]
        resource = otlp_resource(mock.requests[0]["body"]) if mock.requests else {}
        r.case("otlp: POST /v1/logs", bool(mock.requests) and all(p == "/v1/logs" for p in paths), str(paths[:3]))
        r.case("otlp: protobuf content-type",
               bool(ctypes) and all("application/x-protobuf" in c for c in ctypes), str(ctypes[:1]))
        r.case("otlp: access records batched", len(access_recs) >= 10, f"records={len(access_recs)}")
        r.case("otlp: resource service.name", resource.get("service.name") == "luajit-httpd", str(resource))
        r.case("otlp: structured access attributes",
               any(rec["attrs"].get("http.response.status_code") == 200 and
                   rec["attrs"].get("http.request.method") == "GET" for rec in access_recs),
               str(access_recs[:1]))
        r.case("otlp: local file retained with sending",
               otlp_access.exists() and '"GET / HTTP/1.1" 200' in otlp_access.read_text(errors="replace"))
        r.case("otlp: server alive after sending", alive)

        # ---- otlp: flush interval (time threshold) ----
        port = free_port()
        mock = OtlpMock()
        log = f"""{{
    otlp = {{ enabled = true, endpoint = "http://127.0.0.1:{mock.port}",
              access = true, error = false, batch_max_records = 100,
              flush_interval = 0.2, timeout = 1 }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME):
                http_request(port, "/")
                time.sleep(0.8)
        finally:
            mock.close()
        r.case("otlp: flush_interval sends small batch", bool(mock.requests), f"requests={len(mock.requests)}")

        # ---- otlp: error records only ----
        port = free_port()
        mock = OtlpMock()
        log = f"""{{
    otlp = {{ enabled = true, endpoint = "http://127.0.0.1:{mock.port}",
              access = false, error = true, level = "info",
              batch_max_records = 100, flush_interval = 0.2, timeout = 1 }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME):
                http_request(port, "/")
                time.sleep(0.8)
        finally:
            mock.close()
        scopes = [s for q in mock.requests for s in otlp_scopes(q["body"])]
        r.case("otlp: error scope present", any(scope == "httpd.error" for scope, _ in scopes))
        r.case("otlp: access=false suppresses access scope",
               not any(scope == "httpd.access" for scope, _ in scopes))

        # ---- otlp: retry after 500 ----
        port = free_port()
        mock = OtlpMock(fail_left=2)
        log = f"""{{
    otlp = {{ enabled = true, endpoint = "http://127.0.0.1:{mock.port}",
              access = true, error = false, batch_max_records = 1,
              flush_interval = 0.2, timeout = 1, max_retries = 3 }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME) as srv:
                http_request(port, "/")
                time.sleep(5.0)
                alive = srv.proc.poll() is None
        finally:
            mock.close()
        t0 = mock.requests[0]["time"] if mock.requests else 0
        times = [round(q["time"] - t0, 2) for q in mock.requests]
        r.case("otlp: 500 is retried", len(mock.requests) >= 3,
               f"requests={len(mock.requests)} times={times}")
        r.case("otlp: server alive after retries", alive)

        # ---- syslog: UDP rfc5424 ----
        port = free_port()
        mock = UdpMock()
        log = f"""{{
    syslog = {{ enabled = true, transport = "udp", host = "127.0.0.1",
                port = {mock.port}, format = "rfc5424",
                facility = "local0", tag = "luajit-httpd" }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME) as srv:
                http_request(port, "/")
                time.sleep(0.5)
                alive = srv.proc.poll() is None
        finally:
            mock.close()
        msgs = [m.decode("utf-8", "replace") for m in mock.msgs]
        r.case("syslog: rfc5424 access message",
               any(m.startswith("<134>1 ") and '"GET / HTTP/1.1" 200' in m for m in msgs),
               str(msgs[:1]))
        r.case("syslog: server alive after udp", alive)

        # ---- syslog: error only ----
        port = free_port()
        mock = UdpMock()
        log = f"""{{
    syslog = {{ enabled = true, transport = "udp", host = "127.0.0.1",
                port = {mock.port}, format = "rfc5424",
                facility = "local0", tag = "luajit-httpd",
                access = false, error = true, level = "warn" }}
  }}"""
        try:
            with Server(cfg(port, log, app=ERROR_APP), port, name=NAME):
                http_request(port, "/boom", timeout=5)
                time.sleep(0.5)
        finally:
            mock.close()
        msgs = [m.decode("utf-8", "replace") for m in mock.msgs]
        r.case("syslog: error message sent",
               any(m.startswith("<131>1 ") and "handler error" in m for m in msgs), str(msgs[:1]))
        r.case("syslog: access=false suppresses access messages",
               not any('"GET /boom' in m for m in msgs))

        # ---- syslog: TCP octet-counting ----
        port = free_port()
        mock = TcpMock()
        log = f"""{{
    syslog = {{ enabled = true, transport = "tcp", host = "127.0.0.1",
                port = {mock.port}, format = "rfc3164",
                facility = "local0", tag = "luajit-httpd" }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME):
                http_request(port, "/")
                time.sleep(0.5)
        finally:
            mock.close()
        frames = [f.decode("utf-8", "replace") for f in mock.frames]
        r.case("syslog: tcp octet-counted frame",
               any(f.startswith("<134>") and '"GET / HTTP/1.1" 200' in f for f in frames),
               str(frames[:1]))
        r.case("syslog: rfc3164 timestamp format",
               any(f.startswith("<134>") and "luajit-httpd[" in f for f in frames))

        # ---- syslog: unix dgram ----
        port = free_port()
        sockpath = d / "syslog.sock"
        mock = UnixDgramMock(sockpath)
        log = f"""{{
    syslog = {{ enabled = true, transport = "unix", path = "{sockpath}",
                format = "rfc5424", facility = "local0", tag = "luajit-httpd" }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME):
                http_request(port, "/")
                time.sleep(0.5)
        finally:
            mock.close()
        msgs = [m.decode("utf-8", "replace") for m in mock.msgs]
        r.case("syslog: unix dgram access message",
               any(m.startswith("<134>1 ") and '"GET / HTTP/1.1" 200' in m for m in msgs),
               str(msgs[:1]))

        # ---- syslog: TLS ----
        cert = d / "syslog-tls.crt"
        key = d / "syslog-tls.key"
        gen_self_signed(cert, key, "syslog", "IP:127.0.0.1")
        port = free_port()
        mock = TlsTcpMock(cert, key)
        log = f"""{{
    syslog = {{ enabled = true, transport = "tls", host = "127.0.0.1",
                port = {mock.port}, ca = "{cert}",
                format = "rfc5424", facility = "local0", tag = "luajit-httpd" }}
  }}"""
        try:
            with Server(cfg(port, log), port, name=NAME):
                http_request(port, "/")
                time.sleep(0.6)
        finally:
            mock.close()
        frames = [f.decode("utf-8", "replace") for f in mock.frames]
        r.case("syslog: tls access message",
               any(f.startswith("<134>1 ") and '"GET / HTTP/1.1" 200' in f for f in frames),
               str(frames[:1]))

    r.finish()


if __name__ == "__main__":
    main()
