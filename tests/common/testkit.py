"""Shared helpers for the regression suite.

Every test script is standalone: it starts its own server on a free port in a
temporary directory, runs cases, prints the unified output, and exits 0/1.

Output format:

    TEST: <script>
    CASE <name>: PASS|FAIL (detail)
    RESULT: PASS|FAIL (passed/total)
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("HTTPD_BIN") or (ROOT / "prefix/c-httpd/bin/luajit-httpd"))
LUA_LIB = ROOT / "prefix/luajit/lib"
APP = ROOT / "src/app.lua"


# ---------- unified output ----------

class Runner:
    def __init__(self, name: str):
        self.name = name
        self.total = 0
        self.failed = 0
        print(f"TEST: {name}")

    def case(self, name: str, ok: bool, detail: str = ""):
        self.total += 1
        if not ok:
            self.failed += 1
        line = f"CASE {name}: {'PASS' if ok else 'FAIL'}"
        if detail:
            line += f" ({detail})"
        print(line)

    def finish(self):
        passed = self.total - self.failed
        print(f"RESULT: {'PASS' if self.failed == 0 else 'FAIL'} ({passed}/{self.total})")
        sys.exit(0 if self.failed == 0 else 1)


def low_headers(headers: dict[bytes, bytes], name: bytes) -> bytes:
    return headers.get(name.lower(), b"-")


def http_config(port: int, extra_server: str = "", app: Path | str = APP,
                extra_top: str = "") -> str:
    """Minimal HTTP-only config text. extra_top is inserted inside the top table."""
    top = (extra_top + ",\n  ") if extra_top else ""
    return f"""return {{
  server = {{
    listen = {{ {{ host = "127.0.0.1", port = {port} }} }},
    {extra_server}
  }},
  {top}app = "{app}"
}}
"""


def mtls_fixture(d: Path) -> dict:
    """Generate default/a/b/public server certs, CA-A/B and client-a/b under d."""
    d.mkdir(parents=True, exist_ok=True)
    p = lambda n: d / n
    gen_self_signed(p("default.crt"), p("default.key"), "localhost",
                    "IP:127.0.0.1,DNS:localhost")
    gen_self_signed(p("a-server.crt"), p("a-server.key"), "a.example.test",
                    "DNS:a.example.test")
    gen_self_signed(p("b-server.crt"), p("b-server.key"), "b.example.test",
                    "DNS:b.example.test")
    gen_self_signed(p("public-server.crt"), p("public-server.key"),
                    "public.example.test", "DNS:public.example.test")
    gen_ca(p("ca-a.crt"), p("ca-a.key"), "CA-A")
    gen_ca(p("ca-b.crt"), p("ca-b.key"), "CA-B")
    gen_signed(p("client-a.crt"), p("client-a.key"), p("ca-a.crt"), p("ca-a.key"), "client-a")
    gen_signed(p("client-b.crt"), p("client-b.key"), p("ca-b.crt"), p("ca-b.key"), "client-b")
    return {name: p(name) for name in (
        "default.crt", "default.key", "a-server.crt", "a-server.key",
        "b-server.crt", "b-server.key", "public-server.crt", "public-server.key",
        "ca-a.crt", "ca-b.crt", "client-a.crt", "client-a.key",
        "client-b.crt", "client-b.key",
    )}


# ---------- ports / server lifecycle ----------

def free_port(host: str = "127.0.0.1") -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_ports(n: int, host: str = "127.0.0.1") -> list[int]:
    ports = []
    while len(ports) < n:
        p = free_port(host)
        if p not in ports:
            ports.append(p)
    return ports


def read_log(path: Path, tail: int = 60) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-tail:])
    except OSError:
        return ""


def wait_port(port: int, timeout: float = 5.0, proc: subprocess.Popen | None = None,
              log_path: Path | None = None, host: str = "127.0.0.1") -> None:
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            detail = read_log(log_path) if log_path else ""
            raise RuntimeError(f"server exited rc={proc.returncode}\n{detail}")
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    detail = read_log(log_path) if log_path else ""
    raise RuntimeError(f"server did not listen on {host}:{port}\n{detail}")


class Server:
    """Own a server process + temp config/log dir."""

    def __init__(self, config_text: str, port: int, env: dict[str, str] | None = None,
                 name: str = "server"):
        self.port = port
        self.name = name
        self.tmp = tempfile.TemporaryDirectory(prefix="httpd-test-")
        self.dir = Path(self.tmp.name)
        self.config_path = self.dir / "config.lua"
        self.log_path = self.dir / "server.log"
        self.config_path.write_text(config_text)
        self.env = os.environ.copy()
        old_ld = self.env.get("LD_LIBRARY_PATH", "")
        self.env["LD_LIBRARY_PATH"] = str(LUA_LIB) + ((":" + old_ld) if old_ld else "")
        if env:
            self.env.update(env)
        self.proc: subprocess.Popen | None = None
        self._log = None

    def start(self):
        if not BIN.exists():
            raise RuntimeError(f"server binary not found: {BIN}")
        self._log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [str(BIN), str(self.config_path)],
            cwd=str(ROOT), env=self.env,
            stdout=self._log, stderr=subprocess.STDOUT,
        )
        try:
            wait_port(self.port, 5.0, self.proc, self.log_path)
        except Exception:
            self.stop()
            raise
        return self

    def log(self) -> str:
        return read_log(self.log_path)

    def stop(self, timeout: float = 5.0):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=1.0)
        if self._log is not None:
            self._log.close()
            self._log = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        self.tmp.cleanup()


def start_expect_failure(config_text: str, env: dict[str, str] | None = None,
                         timeout: float = 4.0) -> tuple[int, str]:
    """Start a server expected to fail config validation; return (rc, log)."""
    tmp = tempfile.TemporaryDirectory(prefix="httpd-test-fail-")
    d = Path(tmp.name)
    cfg = d / "config.lua"
    log = d / "server.log"
    cfg.write_text(config_text)
    e = os.environ.copy()
    old_ld = e.get("LD_LIBRARY_PATH", "")
    e["LD_LIBRARY_PATH"] = str(LUA_LIB) + ((":" + old_ld) if old_ld else "")
    if env:
        e.update(env)
    with open(log, "w") as f:
        p = subprocess.Popen([str(BIN), str(cfg)], cwd=str(ROOT), env=e,
                             stdout=f, stderr=subprocess.STDOUT)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=1.0)
            rc = -999
    text = read_log(log)
    tmp.cleanup()
    return rc, text


# ---------- HTTP (plaintext) ----------

def chunked_decode(body: bytes) -> bytes:
    out = b""
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            break
        i = j + 2
        if n == 0:
            break
        out += body[i:i + n]
        i += n + 2
    return out


def read_response(sock: socket.socket, method: str = "GET", timeout: float = 10.0):
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        c = sock.recv(65536)
        if not c:
            break
        data += c
    if not data:
        return 0, {}, b""
    head, sep, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[bytes, bytes] = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    if method == "HEAD" or status in (204, 304):
        return status, headers, b""

    if b"content-length" in headers:
        n = int(headers[b"content-length"])
        while len(body) < n:
            c = sock.recv(65536)
            if not c:
                break
            body += c
        return status, headers, body[:n]

    te = headers.get(b"transfer-encoding", b"").lower()
    if b"chunked" in te:
        while b"0\r\n\r\n" not in body:
            c = sock.recv(65536)
            if not c:
                break
            body += c
        return status, headers, chunked_decode(body)

    # close-delimited
    while True:
        c = sock.recv(65536)
        if not c:
            break
        body += c
    return status, headers, body


def http_request(port: int, path: str = "/", method: str = "GET", body: bytes | None = None,
                 headers: list[str] | None = None, version: str = "1.1",
                 close: bool = True, timeout: float = 10.0, host: str = "127.0.0.1"):
    s = socket.create_connection((host, port), timeout=5)
    lines = [f"{method} {path} HTTP/{version}", "Host: x"]
    if headers:
        lines.extend(headers)
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    if close:
        lines.append("Connection: close")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    if body:
        s.sendall(body)
    status, hdrs, rbody = read_response(s, method, timeout)
    s.close()
    return status, hdrs, rbody


def raw_request(port: int, payload: bytes, timeout: float = 2.0,
                stop_cond=None, host: str = "127.0.0.1") -> bytes:
    s = socket.create_connection((host, port), timeout=3)
    s.sendall(payload)
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
            if stop_cond and stop_cond(data):
                break
    except socket.timeout:
        pass
    s.close()
    return data


# ---------- TLS ----------

def tls_context(version=None, alpn: list[str] | None = None,
                client_cert: Path | str | None = None,
                client_key: Path | str | None = None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version:
        ctx.minimum_version = version
        ctx.maximum_version = version
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if client_cert:
        ctx.load_cert_chain(str(client_cert), str(client_key))
    return ctx


def tls_socket(port: int, server_name: str | None = "localhost", version=None,
               alpn: list[str] | None = None, client_cert=None, client_key=None,
               host: str = "127.0.0.1") -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=5)
    ctx = tls_context(version, alpn, client_cert, client_key)
    return ctx.wrap_socket(raw, server_hostname=server_name)


def tls_request(port: int, path: str = "/", method: str = "GET", body: bytes | None = None,
                headers: list[str] | None = None, version: str = "1.1",
                close: bool = True, timeout: float = 10.0,
                server_name: str | None = "localhost", tls_version=None,
                alpn: list[str] | None = None, client_cert=None, client_key=None):
    s = tls_socket(port, server_name, tls_version, alpn, client_cert, client_key)
    lines = [f"{method} {path} HTTP/{version}", "Host: x"]
    if headers:
        lines.extend(headers)
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    if close:
        lines.append("Connection: close")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    if body:
        s.sendall(body)
    status, hdrs, rbody = read_response(s, method, timeout)
    s.close()
    return status, hdrs, rbody


def cert_subject(port: int, servername: str | None = None, host: str = "127.0.0.1") -> str:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}"]
    if servername:
        cmd += ["-servername", servername]
    out = subprocess.run(cmd, input=b"", capture_output=True, timeout=10).stdout
    m = re.search(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not m:
        return ""
    p = subprocess.run(["openssl", "x509", "-noout", "-subject"],
                       input=m.group(0), capture_output=True)
    return p.stdout.decode().strip()


# ---------- certificates ----------

def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def gen_self_signed(cert: Path, key: Path, cn: str, san: str | None = None) -> None:
    args = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={cn}"]
    if san:
        args += ["-addext", f"subjectAltName={san}"]
    _openssl(*args)


def gen_ca(cert: Path, key: Path, cn: str) -> None:
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={cn}",
             "-addext", "basicConstraints=critical,CA:true")


def gen_signed(cert: Path, key: Path, ca_cert: Path, ca_key: Path, cn: str) -> None:
    csr = cert.with_suffix(".csr")
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(csr), "-subj", f"/CN={cn}")
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
             "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert),
             "-days", "2")
    csr.unlink(missing_ok=True)


def fingerprint(cert: Path) -> str:
    import hashlib
    pem = cert.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


# ---------- misc ----------

def have_ss() -> bool:
    return shutil.which("ss") is not None


def ss_lines(port: int, opts: str = "-tno") -> list[str]:
    out = subprocess.run(["ss", opts], capture_output=True, text=True).stdout
    return [ln for ln in out.splitlines() if f":{port}" in ln]


def ss_blocks(port: int, opts: str = "-tnoime") -> list[str]:
    """Return per-socket blocks; skmem detail is on continuation lines."""
    out = subprocess.run(["ss", opts], capture_output=True, text=True).stdout
    blocks = []
    cur = None
    for line in out.splitlines():
        if f":{port}" in line:
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur is not None and line.startswith((" ", "\t")):
            cur.append(line)
        elif cur is not None:
            blocks.append("\n".join(cur))
            cur = None
    if cur:
        blocks.append("\n".join(cur))
    return blocks
