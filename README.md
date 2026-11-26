# ngx_http_upstream_ntlm_module

An Nginx / OpenResty dynamic module that implements **NTLM and Negotiate (Kerberos) upstream connection pinning**.

---

## Overview

NTLM (and Negotiate/Kerberos) is a **connection-oriented, multi-round-trip authentication protocol**. A backend such as Microsoft Exchange, IIS, or SharePoint binds the authenticated user identity to a specific upstream TCP connection. Standard Nginx upstream load balancing and shared `keepalive` pools break NTLM by dispatching requests across different backend connections or sharing authenticated sockets between clients.

This module pins an upstream TCP connection to the client's TCP connection when an `Authorization: NTLM <token>` or `Authorization: Negotiate <token>` header is detected:

- **Per-client connection pinning** scoped to each `upstream {}` block, bypassing the shared `keepalive` pool so authenticated backend sockets are never shared across users.
- **Automatic teardown** when the client disconnects, the backend closes the socket, `Connection: close` is received, an upstream error occurs, or the client switches to a different `Authorization` scheme (e.g., `Basic` or `Bearer`).
- **HTTP/2 → HTTP/1.1 downgrade**: Non-NTLM and initial unauthenticated HTTP/2 requests pass through normally (so the backend can reply with `401 WWW-Authenticate: NTLM`). Once the client sends `Authorization: NTLM ` or `Negotiate ` over HTTP/2, the module sends `GOAWAY` + `RST_STREAM` with `HTTP_1_1_REQUIRED` (`0xd`) and cleanly closes the stream so the client retries over HTTP/1.1.
- **OpenResty / Lua compatible**: Inspects `Authorization` headers in both `PREACCESS` (client headers) and `PRECONTENT` (headers injected via Lua).
- **Nginx 1.11.5 – 1.31.x compatible**: Works with modern Nginx upstreams including default `keepalive`, `least_conn`, `least_time`, `sticky`, and TLS upstreams.
- **`$ntlm_pinned` variable**: Exposes pin age in milliseconds for logging and upstream headers.

---

## Requirements

- **Nginx** ≥ 1.11.5 (tested up to Nginx 1.31.10) **or OpenResty**
- Build tools (`gcc`, `make`) and development libraries matching your installation (`pcre2`/`pcre`, `openssl`, `zlib`)
- `--with-http_ssl_module` (required for `--with-compat` dynamic modules and TLS upstreams)
- Optional: `--with-http_v2_module` for HTTP/2 → HTTP/1.1 downgrade support

> [!IMPORTANT]
> Dynamic modules must be compiled against the **exact same Nginx / OpenResty version** (and compatible configure flags) as the running binary. Check your installed version with `nginx -V` or `openresty -V`.

---

## Pre-built Releases

Pre-built `--with-compat` dynamic modules (`.so`) for **Linux (`amd64` and `arm64`, glibc ≥ 2.35)** are built, tested, and published automatically via GitHub Actions on every tagged release (`v*`) for:

- **Nginx** `1.30.8` (`ngx_http_upstream_ntlm_module-nginx-1.30.8-linux-{amd64,arm64}.so`)
- **OpenResty** `1.31.9.1` (`ngx_http_upstream_ntlm_module-openresty-1.31.9.1-linux-{amd64,arm64}.so`)

Download the matching `.so` and `SHA256SUMS.txt` from [GitHub Releases](https://github.com/BotoX/upstream-ntlm-nginx-module/releases), verify the checksum, and copy it into `/etc/nginx/modules/ngx_http_upstream_ntlm_module.so` (or `/usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so`).

---

## Building & Installing

### Option A: Standard Nginx

1. **Check your running Nginx version** and download the matching source tarball:

```bash
nginx -v
NGINX_VERSION=1.31.10   # replace with your exact Nginx version
wget "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf "nginx-${NGINX_VERSION}.tar.gz"
```

2. **Clone this repository** alongside the Nginx source directory:

```bash
git clone https://github.com/your-org/ngx_http_upstream_ntlm_module.git
```

3. **Configure and compile the dynamic module:**

```bash
cd "nginx-${NGINX_VERSION}"

./configure \
    --with-compat \
    --with-http_ssl_module \
    --with-http_v2_module \
    --add-dynamic-module=../ngx_http_upstream_ntlm_module

make modules
```

4. **Install the compiled module:**

```bash
sudo cp objs/ngx_http_upstream_ntlm_module.so /etc/nginx/modules/
```

---

### Option B: OpenResty

1. **Check your installed OpenResty version** (`openresty -V`) and download/extract the matching OpenResty source tarball:

```bash
tar -xvf openresty-VERSION.tar.gz
cd openresty-VERSION/
```

2. **Configure** using flags compatible with the official OpenResty package (adjust `--add-dynamic-module` to your clone path if different):

```bash
./configure \
    --prefix=/usr/local/openresty/nginx \
    --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/zlib/include -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' \
    --with-ld-opt='-Wl,-rpath,/usr/local/openresty/luajit/lib -L/usr/local/openresty/zlib/lib -L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/zlib/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' \
    --with-pcre-jit \
    --with-stream \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --with-threads \
    --with-compat \
    --with-http_v2_module \
    --with-http_ssl_module \
    --add-dynamic-module=../ngx_http_upstream_ntlm_module \
    -j8
```

3. **Compile and install the module:**

```bash
make -j

sudo mkdir -p /usr/local/openresty/modules
sudo cp ./build/nginx-*/objs/ngx_http_upstream_ntlm_module.so /usr/local/openresty/modules/
```

---

## Configuration

### 1. Load the module

Add `load_module` at the top level of `nginx.conf`, **before** the `http {}` block:

```nginx
# Standard Nginx
load_module modules/ngx_http_upstream_ntlm_module.so;

# OpenResty
# load_module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so;
```

### 2. Enable pinning in `upstream {}`

Add the `ntlm;` directive inside any `upstream {}` block that fronts an NTLM/Negotiate backend (Exchange, IIS, SharePoint, etc.):

```nginx
upstream exchange_backend {
    ntlm;

    server 10.0.0.10:443;
    server 10.0.0.11:443;

    # Optional: shared keepalive pool for non-NTLM requests only.
    # Pinned NTLM connections bypass this pool.
    keepalive 32;
}
```

### 3. Complete Example (Exchange / IIS over HTTPS)

```nginx
load_module modules/ngx_http_upstream_ntlm_module.so;

events {
    worker_connections 4096;
}

http {
    log_format ntlm_log '$remote_addr [$time_local] "$request" $status '
                        'upstream=$upstream_addr pin_age=${ntlm_pinned}ms';

    upstream exchange_backend {
        ntlm;

        server 10.0.0.10:443;
        server 10.0.0.11:443;
    }

    server {
        listen 443 ssl;
        http2 on;
        server_name mail.example.com;

        ssl_certificate     /etc/ssl/certs/mail.crt;
        ssl_certificate_key /etc/ssl/private/mail.key;

        access_log /var/log/nginx/exchange_access.log ntlm_log;

        location / {
            proxy_pass          https://exchange_backend;
            proxy_http_version  1.1;
            proxy_set_header    Connection "";
            proxy_set_header    Host $host;

            # Recommended for HTTPS backends (see TLS 1.3 note below)
            proxy_ssl_protocols TLSv1.2;

            # Optional: pass pin age (in ms, or empty if unpinned) to backend
            proxy_set_header    X-NTLM-Pin-Age $ntlm_pinned;
        }
    }
}
```

> [!TIP]
> Always set `proxy_http_version 1.1;` and `proxy_set_header Connection "";` in the `location {}` block so upstream connections stay persistent across the NTLM handshake.

---

## Directive & Variable Reference

### Directive

| Directive | Context | Arguments | Description |
| :--- | :--- | :--- | :--- |
| `ntlm` | `upstream {}` | none | Enables NTLM / Negotiate connection pinning on this upstream group. Must only be specified once per `upstream {}` block. |

### Variables: `$ntlm_pinned` and `$ntlm_pinned_<upstream_name>`

| Variable | Value when pinned | Value when not pinned |
| :--- | :--- | :--- |
| `$ntlm_pinned` | Elapsed milliseconds since the upstream pin was established (e.g. `"4231"`) for the current request's upstream (or any pinned upstream on the client connection if evaluated before `proxy_pass`, e.g., in `access_by_lua_*`) | `""` (empty string) |
| `$ntlm_pinned_<upstream_name>` | Elapsed milliseconds since the named `upstream {}` block was pinned on this client connection (case-insensitive) | `""` (empty string) |

Both variables work in `log_format`, `proxy_set_header`, `map`, `if`, and OpenResty/Lua (`ngx.var.ntlm_pinned`, `ngx.var.ntlm_pinned_my_upstream`).

> [!TIP]
> **Multi-upstream setups (e.g., OpenResty `access_by_lua_*`):** When a single `server {}` block routes to multiple `ntlm` upstreams (such as `owa_upstream` and `exchange_upstream`), prefer `$ntlm_pinned_<upstream_name>` in access-phase Lua handlers so a pin on one upstream is never mistaken for a pin on another:
> ```lua
> local is_pinned = ((ngx.var.ntlm_pinned_exchange_upstream or "") ~= "")
> ```

---

## Important Operational & Security Notes

> [!WARNING]
> **Do NOT place a connection-multiplexing Layer 7 proxy in front of Nginx.**
> NTLM binds authentication to the **client TCP connection**. If an L7 proxy, CDN, WAF, or load balancer (e.g., Cloudflare, AWS ALB, HAProxy/Envoy/Nginx in HTTP mode with upstream keepalive) multiplexes requests from multiple end-users onto shared TCP connections to this Nginx instance, **User B can inherit User A's authenticated NTLM session**. Terminate client TLS/TCP directly at Nginx, or use pure Layer 4 TCP passthrough (with or without PROXY protocol).

- **Pinned connections bypass `keepalive` limits:** Nginx's `keepalive <N>`, `keepalive_timeout`, `keepalive_time`, and `keepalive_requests` directives only apply to non-NTLM pooled connections. A pinned NTLM connection stays open for the lifetime of the client TCP connection (governed by client `keepalive_timeout` and your backend's idle timeout). Use `keepalive_timeout` and `limit_conn` to prevent clients from exhausting backend connection limits.
- **HTTPS upstreams and TLS 1.3:** When proxying to Exchange/IIS over HTTPS (`proxy_pass https://...`), TLS 1.3 servers may send post-handshake `NewSessionTicket` records while the upstream socket is idle. Because idle sockets are monitored with `MSG_PEEK`, any unexpected data from an idle backend closes the pinned connection. Use `proxy_ssl_protocols TLSv1.2;` on HTTPS NTLM locations (or disable TLS 1.3 session tickets on the backend) for stable pinning.
- **HTTP/2 & HTTP/3:**
  - HTTP/2 downgrade (`GOAWAY` + `RST_STREAM` with `HTTP_1_1_REQUIRED`) is registered globally when compiled with `--with-http_v2_module`, and triggers whenever an HTTP/2 request carries `Authorization: NTLM` or `Authorization: Negotiate`.
  - HTTP/3 (QUIC) uses ephemeral per-stream connections and cannot sustain NTLM pinning. Do not enable `listen ... quic;` or advertise `Alt-Svc: h3` on NTLM-authenticated virtual hosts.
- **Per-worker state:** Nginx worker processes do not share pin state; each client TCP connection is handled by a single worker for its entire lifetime.
- **Verify configuration before reloading:** Always run `nginx -t` (or `openresty -t`) after installing or upgrading the module.

---

## Testing

An end-to-end test suite is included in [tests/test_ntlm.py](tests/test_ntlm.py) (uses only Python stdlib + `openssl`). Run it after compiling against a new Nginx or OpenResty release:

```bash
python3 tests/test_ntlm.py \
  --nginx /usr/local/openresty/nginx/sbin/nginx \
  --module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so
```

It verifies duplicate `ntlm;` rejection, HTTP/1.1 pinning lifecycle & client disconnect cleanup, protocol-aware NTLM/SPNEGO continuation & re-authentication teardown, RFC 9110 `token68` Base64 padding & SPNEGO `negState` validation, credential switching teardown, upstream failover, `NGX_PEER_NEXT` (`http_403`) shared-keepalive isolation, unbuffered `POST` idle-socket liveness checks, `Connection: close`, `least_conn` / `ip_hash` / `sticky` / `least_time` compatibility, HTTPS upstreams (`proxy_ssl_session_reuse on`), HTTP/2 `GOAWAY`+`RST_STREAM` downgrade with zero connection leaks, `$ntlm_pinned` / `$ntlm_pinned_<upstream_name>` isolation, and clean error logs.
