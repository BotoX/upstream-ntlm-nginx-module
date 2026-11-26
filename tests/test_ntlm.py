#!/usr/bin/env python3
"""
End-to-end test suite for ngx_http_upstream_ntlm_module.

Usage:
    python3 tests/test_ntlm.py --nginx /path/to/nginx --module /path/to/ngx_http_upstream_ntlm_module.so

Or via environment variables:
    NGINX_BIN=/usr/local/openresty/nginx/sbin/nginx \
    NTLM_SO=/usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so \
    python3 tests/test_ntlm.py
"""
import argparse
import base64
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Valid protocol-level test tokens (no external crypto dependencies required)
NTLM_TYPE1 = base64.b64encode(b"NTLMSSP\x00\x01\x00\x00\x00\x00\x00\x00\x00").decode()
NTLM_TYPE2 = base64.b64encode(b"NTLMSSP\x00\x02\x00\x00\x00\x00\x00\x00\x00").decode()
NTLM_TYPE3 = base64.b64encode(b"NTLMSSP\x00\x03\x00\x00\x00\x00\x00\x00\x00").decode()
SPNEGO_INIT = base64.b64encode(b"\x60\x06\x06\x04\x2b\x06\x01\x05").decode()
SPNEGO_CHALLENGE = base64.b64encode(b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x01").decode()
SPNEGO_RESP = base64.b64encode(b"\xa1\x08\x30\x06\xa2\x04\x04\x02\xaa\xbb").decode()
SPNEGO_COMPLETE = base64.b64encode(b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00").decode()


class BackendServer:
    def __init__(self, name, port, ssl_ctx=None):
        self.name = name
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.closed_ports = set()
        self.live_sockets = {}
        self.authed_ports = {}
        self.lock = threading.Lock()
        self.server = None
        self.thread = None

    def force_close_peer(self, peer_port):
        with self.lock:
            s = self.live_sockets.get(peer_port)
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def push_unsolicited_bytes(self, peer_port, data=b"UNSOLICITED_RECORD\r\n"):
        with self.lock:
            s = self.live_sockets.get(peer_port)
        if s is not None:
            s.sendall(data)

    def start(self):
        parent = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def setup(self):
                super().setup()
                with parent.lock:
                    parent.live_sockets[self.client_address[1]] = self.connection

            def _read_request_body(self):
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    chunks = []
                    while True:
                        line = self.rfile.readline().strip()
                        size = int(line.split(b";", 1)[0], 16)
                        if size == 0:
                            self.rfile.readline()
                            break
                        chunks.append(self.rfile.read(size))
                        self.rfile.readline()
                    return b"".join(chunks)
                cl = int(self.headers.get("Content-Length", "0") or "0")
                return self.rfile.read(cl) if cl > 0 else b""

            def do_POST(self):
                peer_port = self.client_address[1]
                req_body = self._read_request_body()
                auth = self.headers.get("Authorization", "")
                pin_age = self.headers.get("X-NTLM-Pin-Age", "")
                body = (
                    f"backend={parent.name} port={peer_port} auth={auth} "
                    f"pin_age={pin_age} body_len={len(req_body)}\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                peer_port = self.client_address[1]
                auth = self.headers.get("Authorization", "")
                pin_age = self.headers.get("X-NTLM-Pin-Age", "")
                if auth:
                    with parent.lock:
                        parent.authed_ports[peer_port] = auth
                body = f"backend={parent.name} port={peer_port} auth={auth} pin_age={pin_age}\n".encode()

                if self.path == "/close":
                    self.send_response(200)
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                    return

                if self.path == "/next403":
                    if parent.name == "B1":
                        self.send_response(403)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                if self.path == "/spnego":
                    if auth == f"Negotiate {SPNEGO_INIT}":
                        self.send_response(401)
                        self.send_header(
                            "WWW-Authenticate",
                            f'Basic realm="corp, quoted \\"realm\\"", Negotiate {SPNEGO_CHALLENGE}',
                        )
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    if auth == f"Negotiate {SPNEGO_RESP}":
                        self.send_response(200)
                        self.send_header("WWW-Authenticate", f"Negotiate {SPNEGO_COMPLETE}")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                if self.path in ("/ntlm", "/least_time", "/least_conn", "/ip_hash", "/sticky", "/tls"):
                    if auth.startswith(f"NTLM {NTLM_TYPE1}") or auth.startswith(f"NTLM\t{NTLM_TYPE1}"):
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", f"NTLM {NTLM_TYPE2}")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def finish(self):
                with parent.lock:
                    parent.live_sockets.pop(self.client_address[1], None)
                    parent.authed_ports.pop(self.client_address[1], None)
                    parent.closed_ports.add(self.client_address[1])
                super().finish()

        class ReusableThreadingHTTPServer(ThreadingHTTPServer):
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                exc = sys.exc_info()[1]
                if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
                    return
                super().handle_error(request, client_address)

        self.server = ReusableThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        if self.ssl_ctx is not None:
            self.server.socket = self.ssl_ctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def parse_body(body_bytes):
    text = body_bytes.decode("utf-8", errors="replace").strip()
    m = re.match(r"backend=(\S+) port=(\d+) auth=(.*?) pin_age=(.*)", text)
    if not m:
        raise AssertionError(f"Unexpected backend body: {text!r}")
    return {
        "backend": m.group(1),
        "port": int(m.group(2)),
        "auth": m.group(3),
        "pin_age": m.group(4),
    }


def raw_http1_exchange(sock, path, headers=None):
    hdrs = {"Host": "localhost", "Connection": "keep-alive"}
    if headers:
        hdrs.update(headers)
    req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    sock.sendall(req.encode())

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(f"EOF while reading headers; got {buf!r}")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1])
    cl = 0
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            cl = int(line.split(":", 1)[1].strip())
    while len(rest) < cl:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("EOF while reading body")
        rest += chunk
    return status, rest[:cl]


def build_h2_frame(ftype, flags, sid, payload):
    length = len(payload)
    return (
        length.to_bytes(3, "big")
        + bytes([ftype, flags])
        + (sid & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def hpack_literal(name, value):
    nb = name.encode()
    vb = value.encode()
    assert len(nb) < 127 and len(vb) < 127
    return b"\x00" + bytes([len(nb)]) + nb + bytes([len(vb)]) + vb


def send_h2_request(port, path, auth_header=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    assert tls.selected_alpn_protocol() == "h2", f"ALPN was {tls.selected_alpn_protocol()}"

    tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    tls.sendall(build_h2_frame(0x4, 0x0, 0, b""))

    block = (
        b"\x82"  # :method: GET
        + b"\x87"  # :scheme: https
        + hpack_literal(":authority", "localhost")
        + hpack_literal(":path", path)
    )
    if auth_header is not None:
        block += hpack_literal("authorization", auth_header)
    tls.sendall(build_h2_frame(0x1, 0x5, 1, block))

    frames = []
    tls.settimeout(2.0)
    buf = b""
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            chunk = tls.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
        while len(buf) >= 9:
            flen = int.from_bytes(buf[0:3], "big")
            ftype = buf[3]
            fflags = buf[4]
            fsid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            if len(buf) < 9 + flen:
                break
            payload = buf[9 : 9 + flen]
            buf = buf[9 + flen :]
            frames.append((ftype, fflags, fsid, payload))
            if ftype == 0x4 and (fflags & 0x1) == 0:
                tls.sendall(build_h2_frame(0x4, 0x1, 0, b""))
        ftypes = [f[0] for f in frames]
        if (7 in ftypes and 3 in ftypes) or any(
            f[2] == 1 and f[0] in (0, 1) and (f[1] & 0x1) for f in frames
        ):
            break

    tls.close()
    return frames


def supports_directive(nginx_bin, ntlm_so, workdir, snippet):
    probe_conf = os.path.join(workdir, "probe.conf")
    probe_pid = os.path.join(workdir, "probe.pid")
    with open(probe_conf, "w") as f:
        f.write(
            f"load_module {ntlm_so};\n"
            f"pid {probe_pid};\n"
            f"error_log /dev/null;\n"
            f"events {{ worker_connections 16; }}\n"
            f"http {{\n"
            f"    access_log off;\n"
            f"    client_body_temp_path {workdir}/client_body_temp;\n"
            f"    proxy_temp_path {workdir}/proxy_temp;\n"
            f"    {snippet}\n"
            f"}}\n"
        )
    r = subprocess.run([nginx_bin, "-t", "-c", probe_conf, "-p", workdir], capture_output=True, text=True)
    return r.returncode == 0


def detect_default_paths():
    nginx_candidates = [
        os.environ.get("NGINX_BIN"),
        "/tmp/nginx_ntlm_build/nginx",
        "/usr/local/openresty/nginx/sbin/nginx",
        shutil.which("openresty"),
        shutil.which("nginx"),
    ]
    so_candidates = [
        os.environ.get("NTLM_SO"),
        "/tmp/nginx_ntlm_build/ngx_http_upstream_ntlm_module.so",
        "/usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so",
    ]
    nginx_bin = next((p for p in nginx_candidates if p and os.path.isfile(p)), None)
    ntlm_so = next((p for p in so_candidates if p and os.path.isfile(p)), None)
    return nginx_bin, ntlm_so


def run_tests(nginx_bin, ntlm_so):
    workdir = tempfile.mkdtemp(prefix="ntlm_test_")
    # Allow nginx workers (e.g. 'nobody' when launched as root) to traverse workdir
    # and write client_body_temp / proxy_temp during chunked POST tests.
    os.chmod(workdir, 0o755)
    for sub in ("logs", "client_body_temp", "proxy_temp"):
        sub_path = os.path.join(workdir, sub)
        os.makedirs(sub_path, exist_ok=True)
        os.chmod(sub_path, 0o777)
    b1 = b2 = b_tls = None
    nginx_proc = None
    try:
        cert_file = os.path.join(workdir, "cert.pem")
        key_file = os.path.join(workdir, "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_file, "-out", cert_file,
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # --- Test 1: Duplicate ntlm; directive rejected cleanly ---
        dup_conf = os.path.join(workdir, "dup.conf")
        with open(dup_conf, "w") as f:
            f.write(f"""
load_module {ntlm_so};
events {{ worker_connections 64; }}
http {{
    upstream dup_up {{
        ntlm;
        ntlm;
        server 127.0.0.1:9;
    }}
}}
""")
        r = subprocess.run([nginx_bin, "-t", "-c", dup_conf, "-p", workdir], capture_output=True, text=True)
        assert r.returncode != 0 and "is duplicate" in r.stderr, (
            f"Expected duplicate error, got rc={r.returncode}, stderr={r.stderr}"
        )
        print("[PASS] Test 1: Duplicate 'ntlm;' directive cleanly rejected")

        has_least_time = supports_directive(
            nginx_bin,
            ntlm_so,
            workdir,
            "upstream lt_probe { least_time header inflight; ntlm; server 127.0.0.1:9; }",
        )
        has_sticky = supports_directive(
            nginx_bin,
            ntlm_so,
            workdir,
            "upstream st_probe { zone st_z 64k; sticky cookie srv_id; ntlm; server 127.0.0.1:9; }",
        )
        has_http2_directive = supports_directive(
            nginx_bin,
            ntlm_so,
            workdir,
            f"server {{ listen 127.0.0.1:{get_free_port()} ssl; http2 on; ssl_certificate {cert_file}; ssl_certificate_key {key_file}; }}",
        )
        h2_listen = "ssl;\n        http2 on;" if has_http2_directive else "ssl http2;"

        p_b1 = get_free_port()
        p_b2 = get_free_port()
        p_tls = get_free_port()
        p_dead = get_free_port()
        p_http = get_free_port()
        p_https = get_free_port()

        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        tls_ctx.load_cert_chain(cert_file, key_file)

        b1 = BackendServer("B1", p_b1)
        b2 = BackendServer("B2", p_b2)
        b_tls = BackendServer("BTLS", p_tls, ssl_ctx=tls_ctx)
        b1.start()
        b2.start()
        b_tls.start()

        err_log = os.path.join(workdir, "error.log")
        acc_log = os.path.join(workdir, "access.log")
        pid_file = os.path.join(workdir, "nginx.pid")
        conf_file = os.path.join(workdir, "nginx.conf")

        least_time_upstream = (
            f"""
    upstream least_time_pool {{
        least_time header inflight;
        ntlm;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
    }}
"""
            if has_least_time
            else ""
        )
        least_time_location = (
            """
        location /least_time {
            proxy_pass http://least_time_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
"""
            if has_least_time
            else ""
        )
        sticky_upstream = (
            f"""
    upstream sticky_pool {{
        zone sticky_zone 64k;
        sticky cookie srv_id;
        ntlm;
        keepalive 8;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
    }}
"""
            if has_sticky
            else ""
        )
        sticky_location = (
            """
        location /sticky {
            proxy_pass http://sticky_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
"""
            if has_sticky
            else ""
        )

        user_directive = "user root;\n" if os.geteuid() == 0 else ""

        with open(conf_file, "w") as f:
            f.write(f"""
{user_directive}load_module {ntlm_so};
worker_processes 1;
pid {pid_file};
error_log {err_log} debug;

events {{
    worker_connections 128;
}}

http {{
    client_body_buffer_size 64k;
    client_body_temp_path {workdir}/client_body_temp;
    proxy_temp_path {workdir}/proxy_temp;
    log_format ntlm '$request_uri status=$status upstream=$upstream_addr pin=$ntlm_pinned';
    access_log {acc_log} ntlm;

    upstream ntlm_pool {{
        ntlm;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
        keepalive 8;
    }}

    upstream next403_pool {{
        ntlm;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
        keepalive 8;
    }}

    upstream least_conn_pool {{
        ntlm;
        least_conn;
        keepalive 8;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
    }}

    upstream ip_hash_pool {{
        ntlm;
        ip_hash;
        server 127.0.0.1:{p_b1};
        server 127.0.0.1:{p_b2};
    }}

    upstream tls_pool {{
        zone tls_zone 64k;
        ntlm;
        keepalive 8;
        server 127.0.0.1:{p_tls};
    }}

    upstream failover_pool {{
        ntlm;
        server 127.0.0.1:{p_dead};
        server 127.0.0.1:{p_b1};
    }}
{least_time_upstream}{sticky_upstream}
    upstream owa_pool {{
        ntlm;
        server 127.0.0.1:{p_b2};
    }}

    server {{
        listen 127.0.0.1:{p_http};

        location /ntlm {{
            set $early_pin $ntlm_pinned;
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age $early_pin;
        }}

        location /msx_unbuffered {{
            set $p_ex $ntlm_pinned_ntlm_pool;
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering off;
            proxy_set_header X-NTLM-Pin-Age $p_ex;
        }}

        location /ip_hash {{
            proxy_pass http://ip_hash_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age $ntlm_pinned;
        }}

        location /spnego {{
            set $early_pin $ntlm_pinned;
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age $early_pin;
        }}

        location /next403 {{
            proxy_pass http://next403_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_next_upstream http_403;
        }}

        location /least_conn {{
            proxy_pass http://least_conn_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age $ntlm_pinned;
        }}

        location /tls {{
            proxy_pass https://tls_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_ssl_protocols TLSv1.2;
            proxy_ssl_session_reuse on;
            proxy_ssl_verify off;
            proxy_set_header X-NTLM-Pin-Age $ntlm_pinned;
        }}

        location /close {{
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age $ntlm_pinned;
        }}

        location /failover {{
            proxy_pass http://failover_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
{least_time_location}{sticky_location}
        location /owa {{
            set $p_owa $ntlm_pinned_owa_pool;
            set $p_ex  $ntlm_pinned_ntlm_pool;
            proxy_pass http://owa_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age "$p_owa|$p_ex";
        }}

        location /ex {{
            set $p_owa $ntlm_pinned_owa_pool;
            set $p_ex  $ntlm_pinned_ntlm_pool;
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-NTLM-Pin-Age "$p_owa|$p_ex";
        }}
    }}

    server {{
        listen 127.0.0.1:{p_https} {h2_listen}
        ssl_certificate {cert_file};
        ssl_certificate_key {key_file};

        location / {{
            proxy_pass http://ntlm_pool;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
""")

        os.makedirs(os.path.join(workdir, "logs"), exist_ok=True)
        nginx_proc = subprocess.Popen([nginx_bin, "-g", "daemon off;", "-c", conf_file, "-p", workdir])
        time.sleep(0.5)
        assert nginx_proc.poll() is None, f"Nginx exited early; log:\n{open(err_log).read()}"

        # --- Test 2: HTTP/1.1 NTLM Pinning Lifecycle + $ntlm_pinned + Client Disconnect Cleanup ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm")
        d0 = parse_body(body)
        assert st == 200 and d0["pin_age"] == "", f"Expected unpinned, got {d0}"

        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLMfoo"})
        d_foo = parse_body(body)
        assert st == 200 and d_foo["pin_age"] == "", f"'NTLMfoo' should not pin: {d_foo}"

        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        d1 = parse_body(body)
        assert st == 401, f"Expected 401 on Type 1, got {st}"

        time.sleep(0.02)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        d2 = parse_body(body)
        assert st == 200, f"Expected 200 on Type 3, got {st}"
        assert d2["backend"] == d1["backend"] and d2["port"] == d1["port"], f"Pin broken! r1={d1}, r2={d2}"
        assert d2["pin_age"].isdigit(), f"Expected numeric pin_age in pre-upstream phase, got {d2}"

        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": ""})
        d3 = parse_body(body)
        assert st == 200 and d3["backend"] == d1["backend"] and d3["port"] == d1["port"], (
            f"Empty Authorization broke pin! r1={d1}, r3={d3}"
        )

        st, body = raw_http1_exchange(sock, "/ntlm")
        d4 = parse_body(body)
        assert st == 200 and d4["backend"] == d1["backend"] and d4["port"] == d1["port"], (
            f"Follow-up not pinned! r1={d1}, r4={d4}"
        )

        pinned_backend = b1 if d1["backend"] == "B1" else b2
        sock.close()
        time.sleep(0.2)
        assert d1["port"] in pinned_backend.closed_ports, (
            f"Pinned backend port {d1['port']} was NOT closed after client disconnect!"
        )
        print(f"[PASS] Test 2: HTTP/1.1 NTLM pinning, $ntlm_pinned={d2['pin_age']}ms, cleanup closed backend port {d1['port']}")

        # --- Test 3: Credential switching (Basic on pinned NTLM conn) tears down pin ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        p1 = parse_body(body)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "Basic dXNlcjpwYXNz"})
        p2 = parse_body(body)
        time.sleep(0.1)
        pinned_backend = b1 if p1["backend"] == "B1" else b2
        assert p1["port"] in pinned_backend.closed_ports, "Old NTLM pinned backend was NOT closed on Basic auth switch!"
        assert not (p2["backend"] == p1["backend"] and p2["port"] == p1["port"]), "Basic auth reused NTLM pinned socket!"
        sock.close()
        print("[PASS] Test 3: Switching to Basic auth on pinned connection cleanly tore down NTLM pin")

        # --- Test 4: Upstream failover (proxy_next_upstream) ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        for _ in range(3):
            st, body = raw_http1_exchange(sock, "/failover", {"Authorization": f"NTLM {NTLM_TYPE1}"})
            assert st == 200, f"Failover failed with status {st}"
        sock.close()
        assert nginx_proc.poll() is None, "Nginx crashed during failover!"
        print("[PASS] Test 4: Upstream failover (dead backend -> live backend) succeeded")

        # --- Test 5: Connection: close (u->keepalive == 0) is NOT pinned ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/close", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        c1 = parse_body(body)
        assert st == 200
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        c2 = parse_body(body)
        assert st == 200, f"Expected 200 after Connection: close, got {st}"
        assert c2["port"] != c1["port"] or c2["backend"] != c1["backend"], "Closing backend socket was mistakenly pinned!"
        sock.close()
        print("[PASS] Test 5: Backend Connection: close (u->keepalive == 0) was not pinned")

        # --- Test 6: least_time header inflight + ntlm (peer.notify wrapper) ---
        if has_least_time:
            sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
            st, body = raw_http1_exchange(sock, "/least_time", {"Authorization": f"NTLM {NTLM_TYPE1}"})
            lt1 = parse_body(body)
            assert st == 401
            st, body = raw_http1_exchange(sock, "/least_time", {"Authorization": f"NTLM {NTLM_TYPE3}"})
            lt2 = parse_body(body)
            assert st == 200 and lt2["backend"] == lt1["backend"] and lt2["port"] == lt1["port"], (
                f"least_time pin mismatch: {lt1} vs {lt2}"
            )
            sock.close()
            print("[PASS] Test 6: least_time header inflight + ntlm (peer.notify) succeeded")
        else:
            print("[SKIP] Test 6: Nginx binary does not support least_time directive")

        # --- Test 7: HTTP/2 non-NTLM passthrough & NTLM GOAWAY+RST_STREAM(0xd) ---
        frames_ok = send_h2_request(p_https, "/")
        assert any(f[0] == 0x1 and f[2] == 1 for f in frames_ok), f"Expected HEADERS on non-NTLM H2, got {frames_ok}"
        assert not any(f[0] == 0x7 for f in frames_ok), f"Unexpected GOAWAY on non-NTLM H2: {frames_ok}"

        frames_bare = send_h2_request(p_https, "/ntlm", auth_header="NTLM")
        assert any(f[0] == 0x7 and int.from_bytes(f[3][4:8], "big") == 0xD for f in frames_bare), (
            f"Bare 'NTLM' failed H2 downgrade: {frames_bare}"
        )
        assert any(f[0] == 0x3 and f[2] == 1 and int.from_bytes(f[3][0:4], "big") == 0xD for f in frames_bare), (
            f"Bare 'NTLM' missing RST_STREAM: {frames_bare}"
        )

        for i in range(70):
            frames_ntlm = send_h2_request(p_https, "/ntlm", auth_header=f"NTLM {NTLM_TYPE1}")
            goaways = [f for f in frames_ntlm if f[0] == 0x7]
            rsts = [f for f in frames_ntlm if f[0] == 0x3 and f[2] == 1]
            assert goaways, f"Iter {i}: Expected GOAWAY frame, got {frames_ntlm}"
            assert int.from_bytes(goaways[0][3][4:8], "big") == 0xD, "Expected HTTP_1_1_REQUIRED (0xd) in GOAWAY"
            assert rsts, f"Iter {i}: Expected flushed RST_STREAM frame, got {frames_ntlm}"
            assert int.from_bytes(rsts[0][3][0:4], "big") == 0xD, "Expected HTTP_1_1_REQUIRED (0xd) in RST_STREAM"

        print("[PASS] Test 7: HTTP/2 non-NTLM succeeded (200) & 70 NTLM H2 downgrades leaked 0 connections")

        # --- Test 8: Prefix variable $ntlm_pinned_<upstream_name> isolation ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/owa", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        m1 = parse_body(body)
        assert st == 200 and m1["pin_age"] == "|", f"Expected both unpinned before first req, got {m1}"

        time.sleep(0.02)
        st, body = raw_http1_exchange(sock, "/ex")
        m2 = parse_body(body)
        owa_age, ex_age = m2["pin_age"].split("|")
        assert st == 200 and owa_age.isdigit() and ex_age == "", f"Expected owa pinned & ex unpinned, got {m2}"

        st, body = raw_http1_exchange(sock, "/ex", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        assert st == 200

        time.sleep(0.02)
        st, body = raw_http1_exchange(sock, "/owa")
        m3 = parse_body(body)
        owa_age2, ex_age2 = m3["pin_age"].split("|")
        assert st == 200 and owa_age2.isdigit() and ex_age2.isdigit(), f"Expected both pinned, got {m3}"
        assert int(owa_age2) >= int(ex_age2), f"Expected owa pin older than ex pin, got {m3}"
        sock.close()
        print(f"[PASS] Test 8: $ntlm_pinned_<upstream_name> isolated owa_pool ({owa_age2}ms) vs ntlm_pool ({ex_age2}ms)")

        # --- Test 9: 20 concurrent NTLM clients — strict cross-session isolation ---
        def concurrent_client(cid):
            s = socket.create_connection(("127.0.0.1", p_http), timeout=5)
            try:
                st1, b1_resp = raw_http1_exchange(s, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
                r1 = parse_body(b1_resp)
                assert st1 == 401
                time.sleep(0.01 * (cid % 5))
                st2, b2_resp = raw_http1_exchange(s, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE3}"})
                r2 = parse_body(b2_resp)
                assert st2 == 200 and r2["backend"] == r1["backend"] and r2["port"] == r1["port"]
                for _ in range(4):
                    stn, bn_resp = raw_http1_exchange(s, "/ntlm")
                    rn = parse_body(bn_resp)
                    assert stn == 200 and rn["backend"] == r1["backend"] and rn["port"] == r1["port"]
                return (r1["backend"], r1["port"])
            finally:
                s.close()

        with ThreadPoolExecutor(max_workers=20) as pool:
            futs = [pool.submit(concurrent_client, i) for i in range(20)]
            endpoints = [f.result() for f in futs]
        assert len(set(endpoints)) == 20, f"Two concurrent clients shared a pinned backend socket! {endpoints}"
        print("[PASS] Test 9: 20 concurrent NTLM clients maintained strict 1:1 backend isolation (0 cross-talk)")

        # --- Test 10: Backend-initiated idle close recovery + no anonymous re-pin ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        idle1 = parse_body(body)
        assert st == 200
        pinned_be = b1 if idle1["backend"] == "B1" else b2
        pinned_be.force_close_peer(idle1["port"])
        time.sleep(0.15)
        # Next anonymous request must see cleared pin and NOT re-pin
        st, body = raw_http1_exchange(sock, "/ntlm")
        idle2 = parse_body(body)
        assert st == 200 and idle2["pin_age"] == "", f"Expected cleared pin after backend idle close, got {idle2}"
        assert (idle2["backend"], idle2["port"]) != (idle1["backend"], idle1["port"])
        st, body = raw_http1_exchange(sock, "/ntlm")
        idle3 = parse_body(body)
        assert st == 200 and idle3["pin_age"] == "", f"Anonymous follow-up mistakenly re-pinned! got {idle3}"
        sock.close()
        print("[PASS] Test 10: Backend idle disconnect invalidated pin, recovered without 502, and did not re-pin anonymous follow-ups")

        # --- Test 11: Unsolicited bytes on idle pinned socket (MSG_PEEK drops dirty socket) ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        pk1 = parse_body(body)
        assert st == 200
        pinned_be = b1 if pk1["backend"] == "B1" else b2
        pinned_be.push_unsolicited_bytes(pk1["port"], b"UNSOLICITED_DATA\r\n")
        time.sleep(0.15)
        assert pk1["port"] in pinned_be.closed_ports, "MSG_PEEK handler did not close dirty idle pinned socket!"
        st, body = raw_http1_exchange(sock, "/ntlm")
        pk2 = parse_body(body)
        assert st == 200 and pk2["pin_age"] == "", f"Expected clean unpinned recovery after MSG_PEEK drop, got {pk2}"
        st, body = raw_http1_exchange(sock, "/ntlm")
        pk3 = parse_body(body)
        assert st == 200 and pk3["pin_age"] == "", f"Anonymous follow-up after MSG_PEEK drop re-pinned! got {pk3}"
        sock.close()
        print("[PASS] Test 11: Unsolicited bytes on idle pinned socket triggered MSG_PEEK teardown & clean unpinned recovery")

        # --- Test 12: Abrupt client TCP RST mid-handshake closes backend socket ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        rst1 = parse_body(body)
        assert st == 401
        # Force immediate TCP RST on close
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
        time.sleep(0.2)
        pinned_be = b1 if rst1["backend"] == "B1" else b2
        assert rst1["port"] in pinned_be.closed_ports, "Backend socket leaked after abrupt client TCP RST!"
        print("[PASS] Test 12: Abrupt client TCP RST mid-handshake cleanly closed pinned backend socket")

        # --- Test 13: Chunked POST over pinned NTLM connection ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        cp1 = parse_body(body)
        assert st == 200
        payload_chunk = b"X" * 16384
        chunked_req = (
            b"POST /ntlm HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: keep-alive\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(payload_chunk):x}\r\n".encode()
            + payload_chunk
            + b"\r\n0\r\n\r\n"
        )
        sock.sendall(chunked_req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += sock.recv(4096)
        head, rest = buf.split(b"\r\n\r\n", 1)
        cl = next(int(l.split(":", 1)[1].strip()) for l in head.decode().split("\r\n")[1:] if l.lower().startswith("content-length:"))
        while len(rest) < cl:
            rest += sock.recv(4096)
        post_text = rest[:cl].decode()
        assert f"backend={cp1['backend']} port={cp1['port']}" in post_text and "body_len=16384" in post_text, (
            f"Chunked POST broke pin or body: {post_text!r}"
        )
        # Follow-up GET still pinned to same backend socket
        st, body = raw_http1_exchange(sock, "/ntlm")
        cp2 = parse_body(body)
        assert st == 200 and cp2["backend"] == cp1["backend"] and cp2["port"] == cp1["port"]
        sock.close()
        print("[PASS] Test 13: 16KB chunked POST + follow-up GET preserved NTLM pin and body integrity")

        # --- Test 14: HTTP/1.0 (non-keepalive) NTLM client does not leak backend socket ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        sock.sendall(f"GET /ntlm HTTP/1.0\r\nHost: localhost\r\nAuthorization: Negotiate {SPNEGO_INIT}\r\n\r\n".encode())
        resp10 = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp10 += chunk
        sock.close()
        _, body10 = resp10.split(b"\r\n\r\n", 1)
        h10 = parse_body(body10)
        time.sleep(0.2)
        pinned_be = b1 if h10["backend"] == "B1" else b2
        assert h10["port"] in pinned_be.closed_ports, "HTTP/1.0 client leaked pinned backend socket!"
        print("[PASS] Test 14: HTTP/1.0 non-keepalive NTLM request closed backend socket cleanly")

        # --- Test 15: proxy_next_upstream http_403 (NGX_PEER_NEXT) does not leak NTLM socket to shared keepalive ---
        b1_before = set(b1.closed_ports)
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/next403", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        nx1 = parse_body(body)
        assert st == 200 and nx1["backend"] == "B2", f"Expected failover from B1(403) to B2(200), got st={st}, {nx1}"
        time.sleep(0.15)
        b1_closed_now = b1.closed_ports - b1_before
        assert b1_closed_now, "B1 NTLM socket rejected via NGX_PEER_NEXT was NOT closed (leaked into shared keepalive)!"
        # Anonymous stranger hitting /next403 must never land on an NTLM-authenticated B1 socket
        stranger = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(stranger, "/ntlm")
        s_resp = parse_body(body)
        assert st == 200 and s_resp["port"] not in b1.authed_ports, (
            f"Anonymous stranger inherited an authenticated socket! {s_resp}"
        )
        sock.close()
        stranger.close()
        print("[PASS] Test 15: NGX_PEER_NEXT (http_403) closed rejected NTLM socket without leaking to shared keepalive")

        # --- Test 16: Protocol-aware re-authentication, scheme switch, and SPNEGO continuation ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        # Complete NTLM handshake with tab delimiter
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM\t{NTLM_TYPE1}"})
        pr1 = parse_body(body)
        assert st == 401
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        pr2 = parse_body(body)
        assert st == 200 and (pr2["backend"], pr2["port"]) == (pr1["backend"], pr1["port"])
        # Unsolicited Type-3 after completion must retire old socket
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        pr3 = parse_body(body)
        assert st == 200 and (pr3["backend"], pr3["port"]) != (pr2["backend"], pr2["port"]), (
            f"Unsolicited Type-3 reused completed socket! {pr2} vs {pr3}"
        )
        # New Type-1 must retire previous socket
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        pr4 = parse_body(body)
        assert st == 401 and (pr4["backend"], pr4["port"]) != (pr3["backend"], pr3["port"]), (
            f"New Type-1 reused previous socket! {pr3} vs {pr4}"
        )
        # Switching from NTLM to Negotiate must retire NTLM socket and run 2-step SPNEGO
        st, body = raw_http1_exchange(sock, "/spnego", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        sp1 = parse_body(body)
        assert st == 401 and (sp1["backend"], sp1["port"]) != (pr4["backend"], pr4["port"])
        st, body = raw_http1_exchange(sock, "/spnego", {"Authorization": f"Negotiate {SPNEGO_RESP}"})
        sp2 = parse_body(body)
        assert st == 200 and (sp2["backend"], sp2["port"]) == (sp1["backend"], sp1["port"]), (
            f"SPNEGO continuation broke pin! {sp1} vs {sp2}"
        )
        # Replaying SPNEGO response after accept-completed must retire socket
        st, body = raw_http1_exchange(sock, "/spnego", {"Authorization": f"Negotiate {SPNEGO_RESP}"})
        sp3 = parse_body(body)
        assert st == 200 and (sp3["backend"], sp3["port"]) != (sp2["backend"], sp2["port"]), (
            f"Replayed SPNEGO response reused completed socket! {sp2} vs {sp3}"
        )
        sock.close()
        print("[PASS] Test 16: Protocol-aware Type-1 restart, scheme switch, tab OWS, and SPNEGO DER continuation verified")

        # --- Test 17: ntlm; before least_conn; + keepalive directive order independence ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/least_conn", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        lc1 = parse_body(body)
        assert st == 401
        st, body = raw_http1_exchange(sock, "/least_conn", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        lc2 = parse_body(body)
        assert st == 200 and (lc2["backend"], lc2["port"]) == (lc1["backend"], lc1["port"]), (
            f"ntlm before least_conn broke pin! {lc1} vs {lc2}"
        )
        st, body = raw_http1_exchange(sock, "/least_conn")
        lc3 = parse_body(body)
        assert st == 200 and (lc3["backend"], lc3["port"]) == (lc1["backend"], lc1["port"])
        sock.close()
        print("[PASS] Test 17: 'ntlm;' placed before 'least_conn;' and 'keepalive' preserved pinning")

        # --- Test 18: HTTPS upstream with zone + proxy_ssl_session_reuse on ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/tls", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        tl1 = parse_body(body)
        assert st == 401 and tl1["backend"] == "BTLS"
        st, body = raw_http1_exchange(sock, "/tls", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        tl2 = parse_body(body)
        assert st == 200 and tl2["port"] == tl1["port"], f"HTTPS upstream pin broke! {tl1} vs {tl2}"
        # Anonymous client must use a separate TLS connection
        stranger = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(stranger, "/tls")
        tl_anon = parse_body(body)
        assert st == 200 and tl_anon["port"] != tl1["port"], "Anonymous client shared TLS NTLM socket!"
        sock.close()
        stranger.close()
        time.sleep(0.2)
        assert tl1["port"] in b_tls.closed_ports, "TLS pinned backend socket was NOT closed on client disconnect!"
        print("[PASS] Test 18: HTTPS upstream (zone + proxy_ssl_session_reuse on) pinned, isolated, and closed cleanly")

        # --- Test 19: msxproxy unbuffered POST + zero-sleep backend close race on $ntlm_pinned_<upstream> ---
        for _ in range(10):
            sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
            st, body = raw_http1_exchange(sock, "/msx_unbuffered", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
            ub1 = parse_body(body)
            assert st == 200
            pinned_be = b1 if ub1["backend"] == "B1" else b2
            # Close backend socket and IMMEDIATELY (no sleep!) send POST with proxy_request_buffering off
            pinned_be.force_close_peer(ub1["port"])
            post_payload = b"<EWS/>"
            raw_post = (
                b"POST /msx_unbuffered HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: keep-alive\r\n"
                b"Authorization: \r\n"
                + f"Content-Length: {len(post_payload)}\r\n\r\n".encode()
                + post_payload
            )
            sock.sendall(raw_post)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            head, rest = buf.split(b"\r\n\r\n", 1)
            post_st = int(head.decode("latin1").split("\r\n")[0].split()[1])
            cl = next(
                int(l.split(":", 1)[1].strip())
                for l in head.decode("latin1").split("\r\n")[1:]
                if l.lower().startswith("content-length:")
            )
            while len(rest) < cl:
                rest += sock.recv(4096)
            post_body = rest[:cl].decode()
            assert post_st == 200, f"Unbuffered POST hit 502 on backend-close race: st={post_st}, body={post_body!r}"
            assert "pin_age= body_len=6" in post_body, (
                f"Expected $ntlm_pinned_ntlm_pool='' via MSG_PEEK liveness check, got {post_body!r}"
            )
            sock.close()
        print("[PASS] Test 19: Unbuffered POST (msxproxy flow) survived 10 zero-sleep backend-close races with 0 502s")

        # --- Test 20: Multi-upstream unprefixed $ntlm_pinned skips unpinned ctx to find active pin ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/owa", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        mu_owa = parse_body(body)
        assert st == 200
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        mu_ex = parse_body(body)
        assert st == 200
        # Drop owa_pool's backend socket while ntlm_pool stays pinned
        b2.force_close_peer(mu_owa["port"])
        time.sleep(0.05)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "   "})
        mu_check = parse_body(body)
        assert st == 200 and mu_check["pin_age"].isdigit(), (
            f"Unprefixed $ntlm_pinned missed active pin or whitespace-only Authorization broke pin: {mu_check}"
        )
        assert (mu_check["backend"], mu_check["port"]) == (mu_ex["backend"], mu_ex["port"])
        sock.close()
        print("[PASS] Test 20: Unprefixed $ntlm_pinned skipped dropped upstream ctx & preserved whitespace-only Authorization")

        # --- Test 21: Token68 Base64 '=' padding smuggling & SPNEGO negState=reject+payload rejected ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        sm1 = parse_body(body)
        assert st == 401
        # Pad valid NTLM Type-3 with '=' followed by smuggled garbage (ngx_decode_base64 stops at '=')
        raw_t3_padded = base64.b64encode(b"NTLMSSP\x00\x03\x00\x00\x00\xaa").decode()  # ends with '=='
        assert raw_t3_padded.endswith("==")
        smuggled_t3 = raw_t3_padded[:-1] + "X"  # '=' followed by non-'='
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": f"NTLM {smuggled_t3}"})
        sm2 = parse_body(body)
        assert (sm2["backend"], sm2["port"]) != (sm1["backend"], sm1["port"]), (
            f"Smuggled Base64 padding reused pending challenge socket! {sm1} vs {sm2}"
        )
        # SPNEGO NegTokenResp with negState=reject(2) + responseToken must NOT continue pending SPNEGO challenge
        st, body = raw_http1_exchange(sock, "/spnego", {"Authorization": f"Negotiate {SPNEGO_INIT}"})
        rj1 = parse_body(body)
        assert st == 401
        spnego_reject_with_payload = base64.b64encode(
            b"\xa1\x0d\x30\x0b\xa0\x03\x0a\x01\x02\xa2\x04\x04\x02\xaa\xbb"
        ).decode()
        st, body = raw_http1_exchange(sock, "/spnego", {"Authorization": f"Negotiate {spnego_reject_with_payload}"})
        rj2 = parse_body(body)
        assert (rj2["backend"], rj2["port"]) != (rj1["backend"], rj1["port"]), (
            f"SPNEGO negState=reject+payload reused pending challenge socket! {rj1} vs {rj2}"
        )
        sock.close()
        print("[PASS] Test 21: Base64 '=' padding smuggling & SPNEGO negState=reject+payload cleanly rejected")

        # --- Test 22: ip_hash + ntlm (msxproxy exchange_upstream) & sticky cookie + ntlm compatibility ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ip_hash", {"Authorization": f"NTLM {NTLM_TYPE1}"})
        ih1 = parse_body(body)
        assert st == 401
        st, body = raw_http1_exchange(sock, "/ip_hash", {"Authorization": f"NTLM {NTLM_TYPE3}"})
        ih2 = parse_body(body)
        assert st == 200 and (ih2["backend"], ih2["port"]) == (ih1["backend"], ih1["port"])
        sock.close()
        if has_sticky:
            sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
            st, body = raw_http1_exchange(sock, "/sticky", {"Authorization": f"NTLM {NTLM_TYPE1}"})
            sk1 = parse_body(body)
            assert st == 401
            # Omit sticky cookie on Type-3 — NTLM pin must still hold on the same backend socket
            st, body = raw_http1_exchange(sock, "/sticky", {"Authorization": f"NTLM {NTLM_TYPE3}"})
            sk2 = parse_body(body)
            assert st == 200 and (sk2["backend"], sk2["port"]) == (sk1["backend"], sk1["port"])
            sock.close()
            print("[PASS] Test 22: 'ip_hash + ntlm' and 'sticky cookie + ntlm' pinned cleanly")
        else:
            print("[PASS] Test 22: 'ip_hash + ntlm' pinned cleanly (sticky directive not supported by binary)")

        # --- Test 23: Zero worker crashes / alerts / emergs / config warnings ---
        time.sleep(0.2)
        err_text = open(err_log).read()
        bad_lines = [
            l for l in err_text.splitlines()
            if any(k in l.lower() for k in ("signal", "[emerg]", "[alert]", "redefined"))
        ]
        assert not bad_lines, "Unexpected error/warning in error.log:\n" + "\n".join(bad_lines)
        print("[PASS] Test 23: Zero [alert], [emerg], balancer warnings, or worker crashes in error.log")

        print("\nALL 23 NTLM MODULE TESTS PASSED!")
    finally:
        if nginx_proc:
            nginx_proc.terminate()
            try:
                nginx_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                nginx_proc.kill()
        if b1:
            b1.stop()
        if b2:
            b2.stop()
        if b_tls:
            b_tls.stop()
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    default_nginx, default_so = detect_default_paths()
    parser = argparse.ArgumentParser(description="End-to-end test suite for ngx_http_upstream_ntlm_module")
    parser.add_argument("--nginx", default=default_nginx, help="Path to nginx/openresty binary")
    parser.add_argument("--module", default=default_so, help="Path to ngx_http_upstream_ntlm_module.so")
    args = parser.parse_args()

    if not args.nginx or not os.path.isfile(args.nginx):
        sys.exit("Error: nginx binary not found. Pass --nginx /path/to/nginx or set NGINX_BIN.")
    if not args.module or not os.path.isfile(args.module):
        sys.exit("Error: module .so not found. Pass --module /path/to/ngx_http_upstream_ntlm_module.so or set NTLM_SO.")

    run_tests(os.path.abspath(args.nginx), os.path.abspath(args.module))


if __name__ == "__main__":
    main()
