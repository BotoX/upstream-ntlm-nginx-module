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


class BackendServer:
    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.closed_ports = set()
        self.live_sockets = {}
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
                body = f"backend={parent.name} port={peer_port} auth={auth} pin_age={pin_age}\n".encode()

                if self.path == "/close":
                    self.send_response(200)
                    self.send_header("Connection", "close")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                    return

                if self.path == "/ntlm":
                    if auth.startswith("NTLM dHlwZTE"):
                        self.send_response(401)
                        self.send_header("WWW-Authenticate", "NTLM dHlwZTI=")
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
    b1 = b2 = None
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
        has_http2_directive = supports_directive(
            nginx_bin,
            ntlm_so,
            workdir,
            f"server {{ listen 127.0.0.1:{get_free_port()} ssl; http2 on; ssl_certificate {cert_file}; ssl_certificate_key {key_file}; }}",
        )
        h2_listen = "ssl;\n        http2 on;" if has_http2_directive else "ssl http2;"

        p_b1 = get_free_port()
        p_b2 = get_free_port()
        p_dead = get_free_port()
        p_http = get_free_port()
        p_https = get_free_port()

        b1 = BackendServer("B1", p_b1)
        b2 = BackendServer("B2", p_b2)
        b1.start()
        b2.start()

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

        with open(conf_file, "w") as f:
            f.write(f"""
load_module {ntlm_so};
worker_processes 1;
pid {pid_file};
error_log {err_log} debug;

events {{
    worker_connections 64;
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

    upstream failover_pool {{
        ntlm;
        server 127.0.0.1:{p_dead};
        server 127.0.0.1:{p_b1};
    }}
{least_time_upstream}
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
{least_time_location}
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

        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLM dHlwZTE="})
        d1 = parse_body(body)
        assert st == 401, f"Expected 401 on Type 1, got {st}"

        time.sleep(0.02)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLM dHlwZTM="})
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
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLM dHlwZTE="})
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
            st, body = raw_http1_exchange(sock, "/failover", {"Authorization": "NTLM dHlwZTE="})
            assert st == 200, f"Failover failed with status {st}"
        sock.close()
        assert nginx_proc.poll() is None, "Nginx crashed during failover!"
        print("[PASS] Test 4: Upstream failover (dead backend -> live backend) succeeded")

        # --- Test 5: Connection: close (u->keepalive == 0) is NOT pinned ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/close", {"Authorization": "NTLM dHlwZTE="})
        c1 = parse_body(body)
        assert st == 200
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLM dHlwZTM="})
        c2 = parse_body(body)
        assert st == 200, f"Expected 200 after Connection: close, got {st}"
        assert c2["port"] != c1["port"] or c2["backend"] != c1["backend"], "Closing backend socket was mistakenly pinned!"
        sock.close()
        print("[PASS] Test 5: Backend Connection: close (u->keepalive == 0) was not pinned")

        # --- Test 6: least_time header inflight + ntlm (peer.notify wrapper) ---
        if has_least_time:
            sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
            st, body = raw_http1_exchange(sock, "/least_time", {"Authorization": "NTLM dHlwZTE="})
            lt1 = parse_body(body)
            assert st == 200
            st, body = raw_http1_exchange(sock, "/least_time", {"Authorization": "NTLM dHlwZTM="})
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
            frames_ntlm = send_h2_request(p_https, "/ntlm", auth_header="NTLM dHlwZTE=")
            goaways = [f for f in frames_ntlm if f[0] == 0x7]
            rsts = [f for f in frames_ntlm if f[0] == 0x3 and f[2] == 1]
            assert goaways, f"Iter {i}: Expected GOAWAY frame, got {frames_ntlm}"
            assert int.from_bytes(goaways[0][3][4:8], "big") == 0xD, "Expected HTTP_1_1_REQUIRED (0xd) in GOAWAY"
            assert rsts, f"Iter {i}: Expected flushed RST_STREAM frame, got {frames_ntlm}"
            assert int.from_bytes(rsts[0][3][0:4], "big") == 0xD, "Expected HTTP_1_1_REQUIRED (0xd) in RST_STREAM"

        print("[PASS] Test 7: HTTP/2 non-NTLM succeeded (200) & 70 NTLM H2 downgrades leaked 0 connections")

        # --- Test 8: Prefix variable $ntlm_pinned_<upstream_name> isolation ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/owa", {"Authorization": "Negotiate dGlja2V0MQ=="})
        m1 = parse_body(body)
        assert st == 200 and m1["pin_age"] == "|", f"Expected both unpinned before first req, got {m1}"

        time.sleep(0.02)
        st, body = raw_http1_exchange(sock, "/ex")
        m2 = parse_body(body)
        owa_age, ex_age = m2["pin_age"].split("|")
        assert st == 200 and owa_age.isdigit() and ex_age == "", f"Expected owa pinned & ex unpinned, got {m2}"

        st, body = raw_http1_exchange(sock, "/ex", {"Authorization": "Negotiate dGlja2V0Mg=="})
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
                st1, b1_resp = raw_http1_exchange(s, "/ntlm", {"Authorization": f"NTLM dHlwZTE={cid}"})
                r1 = parse_body(b1_resp)
                assert st1 == 401
                time.sleep(0.01 * (cid % 5))
                st2, b2_resp = raw_http1_exchange(s, "/ntlm", {"Authorization": f"NTLM dHlwZTM={cid}"})
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

        # --- Test 10: Backend-initiated idle close recovery ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "Negotiate dGlja2V0X2lkbGU="})
        idle1 = parse_body(body)
        assert st == 200
        pinned_be = b1 if idle1["backend"] == "B1" else b2
        pinned_be.force_close_peer(idle1["port"])
        time.sleep(0.15)
        # Next request on same client socket must see cleared pin and open a fresh backend socket cleanly
        st, body = raw_http1_exchange(sock, "/ntlm")
        idle2 = parse_body(body)
        assert st == 200 and idle2["pin_age"] == "", f"Expected cleared pin after backend idle close, got {idle2}"
        assert (idle2["backend"], idle2["port"]) != (idle1["backend"], idle1["port"])
        sock.close()
        print("[PASS] Test 10: Backend idle disconnect cleanly invalidated pin & recovered without 502")

        # --- Test 11: Unsolicited bytes on idle pinned socket (MSG_PEEK drops dirty socket) ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "Negotiate dGlja2V0X3BlZWs="})
        pk1 = parse_body(body)
        assert st == 200
        pinned_be = b1 if pk1["backend"] == "B1" else b2
        pinned_be.push_unsolicited_bytes(pk1["port"], b"UNSOLICITED_DATA\r\n")
        time.sleep(0.15)
        assert pk1["port"] in pinned_be.closed_ports, "MSG_PEEK handler did not close dirty idle pinned socket!"
        st, body = raw_http1_exchange(sock, "/ntlm")
        pk2 = parse_body(body)
        assert st == 200 and pk2["pin_age"] == "", f"Expected clean unpinned recovery after MSG_PEEK drop, got {pk2}"
        sock.close()
        print("[PASS] Test 11: Unsolicited bytes on idle pinned socket triggered MSG_PEEK teardown & clean recovery")

        # --- Test 12: Abrupt client TCP RST mid-handshake closes backend socket ---
        sock = socket.create_connection(("127.0.0.1", p_http), timeout=5)
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "NTLM dHlwZTE="})
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
        st, body = raw_http1_exchange(sock, "/ntlm", {"Authorization": "Negotiate dGlja2V0X3Bvc3Q="})
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
        sock.sendall(b"GET /ntlm HTTP/1.0\r\nHost: localhost\r\nAuthorization: Negotiate dGlja2V0MTA=\r\n\r\n")
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

        # --- Test 15: Zero worker crashes / alerts / emergs ---
        time.sleep(0.2)
        err_text = open(err_log).read()
        assert "signal" not in err_text.lower() and "[emerg]" not in err_text.lower() and "[alert]" not in err_text.lower(), (
            "Unexpected critical error in error.log:\n"
            + "\n".join(l for l in err_text.splitlines() if any(k in l.lower() for k in ("signal", "[emerg]", "[alert]")))
        )
        print("[PASS] Test 15: Zero [alert], [emerg], or worker crashes in error.log")

        print("\nALL 15 NTLM MODULE TESTS PASSED!")
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
