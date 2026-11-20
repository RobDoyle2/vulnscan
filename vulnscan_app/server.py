"""Web server for the app's screens.

Desktop mode: listens on 127.0.0.1 only, so nothing on the network can reach it.
If phone access is switched on in Settings, a second listener opens on the home
network and every request from it must carry a private access key (QR code).

Server mode (run.py --server, used by the container): serves a team behind a
sign-in gateway (oauth2-proxy with Entra ID). The gateway signs people in and
passes their e-mail and groups in X-Forwarded-* headers; requests without them
are refused. Admins (VULNSCAN_ADMINS / VULNSCAN_ADMIN_GROUPS) can scan and change
sources; everyone else can view and export. Scans run on a schedule.
"""
import json
import logging
import mimetypes
import os
import secrets as pysecrets
import socket
import threading
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, exporter, secrets_store, settings, store
from .paths import data_dir, static_dir
from .scanner import Scanner

DEFAULT_PORT = 8765
LAN_PORT_OFFSET = 1
log = logging.getLogger("vulnscan")

# Admin-only actions in server mode; viewers can read and export.
ADMIN_PATHS = {"/api/scan", "/api/scan/stop", "/api/settings", "/api/settings/reset",
               "/api/sources/test", "/api/sources/clear"}
# Desktop-only actions, never available in server mode.
DESKTOP_ONLY_PATHS = {"/api/secrets", "/api/phone/new-key", "/api/quit"}
USER_HEADERS = ("X-Forwarded-Email", "X-Auth-Request-Email", "X-Forwarded-Preferred-Username",
                "X-Auth-Request-Preferred-Username", "X-Forwarded-User", "X-Auth-Request-User")
GROUP_HEADERS = ("X-Forwarded-Groups", "X-Auth-Request-Groups")


def _csv_env(name):
    return {x.strip().lower() for x in os.environ.get(name, "").split(",") if x.strip()}


class App:
    def __init__(self, port=DEFAULT_PORT, server_mode=False):
        self.port = port
        self.server_mode = server_mode
        self.scan_every_hours = float(os.environ.get("VULNSCAN_SCAN_EVERY_HOURS") or 6)
        self.next_scan = None
        self.scanner = Scanner(store.connect())
        self.last_ping = None
        self.quit_event = threading.Event()
        self.lan_server = None
        self.lan_lock = threading.Lock()
        self._local = threading.local()

    def db(self):
        """One SQLite connection per server thread (the scan has its own)."""
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._local.con = store.connect()
        return con

    # --------------------------------------------------------- phone access ----
    def phone_token(self):
        p = data_dir() / "phone_key.txt"
        try:
            tok = p.read_text().strip()
            if len(tok) >= 16:
                return tok
        except OSError:
            pass
        tok = pysecrets.token_urlsafe(18)
        p.write_text(tok)
        return tok

    def new_phone_token(self):
        (data_dir() / "phone_key.txt").write_text(pysecrets.token_urlsafe(18))

    @staticmethod
    def lan_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))  # no packet is sent; picks the LAN interface
            return s.getsockname()[0]
        except OSError:
            return ""
        finally:
            s.close()

    def phone_info(self):
        cfg = settings.load()
        ip = self.lan_ip()
        running = self.lan_server is not None
        url = f"http://{ip}:{self.port + LAN_PORT_OFFSET}/?k={self.phone_token()}" if ip and running else ""
        svg = ""
        if url:
            try:
                import segno
                import io
                buf = io.BytesIO()
                segno.make(url, error="m").save(buf, kind="svg", scale=5, border=2, dark="#111", light="#fff")
                svg = buf.getvalue().decode("utf-8")
            except Exception:
                svg = ""
        return {"enabled": cfg["phone_access"], "running": running, "url": url, "qr_svg": svg,
                "ip": ip, "error": getattr(self, "lan_error", "")}

    # ------------------------------------------------------------ schedule ----
    def start_scheduler(self):
        """Server mode: scan shortly after start, then every N hours."""
        def loop():
            self.next_scan = time.time() + 15
            while True:
                if time.time() >= self.next_scan:
                    if self.scanner.start():
                        log.info("scheduled scan started")
                    self.next_scan = time.time() + self.scan_every_hours * 3600
                time.sleep(10)
        threading.Thread(target=loop, daemon=True, name="scheduler").start()

    def apply_phone_access(self):
        if self.server_mode:
            return
        with self.lan_lock:
            want = settings.load()["phone_access"]
            self.lan_error = ""
            if want and not self.lan_server:
                try:
                    srv = ThreadingHTTPServer(("0.0.0.0", self.port + LAN_PORT_OFFSET), make_handler(self, lan=True))
                    srv.daemon_threads = True
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    self.lan_server = srv
                except OSError as e:
                    self.lan_error = f"Could not open the phone connection: {e}"
            elif not want and self.lan_server:
                self.lan_server.shutdown()
                self.lan_server.server_close()
                self.lan_server = None


def _filters(qs):
    g = lambda k, d="": (qs.get(k) or [d])[0]  # noqa: E731
    days = g("days", "7")
    return {
        "q": g("q")[:200], "days": int(days) if days.isdigit() and 1 <= int(days) <= 3650 else 7,
        "severity": g("severity", "high") if g("severity", "high") in ("critical", "high", "all") else "high",
        "exploited_only": g("exploited_only") in ("1", "true", "on"),
        "source": g("source")[:40],
    }


def make_handler(app, lan=False, server=False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VulnScan/" + __version__
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        # ------------------------------------------------------------ utils ----
        def send(self, code, body=b"", ctype="application/json", headers=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def body_json(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise ValueError("request too large")
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def identity(self):
            """Who is asking. Desktop: the local user (admin). Server: from the
            sign-in gateway's headers; None if they are missing."""
            if not server:
                return {"user": None, "admin": True}
            if os.environ.get("VULNSCAN_AUTH", "header").lower() == "none":
                return {"user": "anonymous (sign-in switched off)", "admin": True}
            user = next((self.headers.get(h) for h in USER_HEADERS if self.headers.get(h)), "")
            if not user:
                return None
            groups = set()
            for h in GROUP_HEADERS:
                groups |= {g.strip().lower() for g in (self.headers.get(h) or "").split(",") if g.strip()}
            admin = user.strip().lower() in _csv_env("VULNSCAN_ADMINS") or bool(groups & _csv_env("VULNSCAN_ADMIN_GROUPS"))
            return {"user": user.strip()[:200], "admin": admin}

        def allowed(self):
            if server:
                return self.identity() is not None
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            if not lan:
                # Blocks DNS-rebinding: only accept our own loopback names.
                return host in ("127.0.0.1", "localhost")
            tok = app.phone_token()
            c = cookies.SimpleCookie(self.headers.get("Cookie") or "")
            if "vs_k" in c and pysecrets.compare_digest(c["vs_k"].value, tok):
                return True
            qs = parse_qs(urlparse(self.path).query)
            return pysecrets.compare_digest((qs.get("k") or [""])[0], tok)

        def write_ok(self):
            # Browsers cannot add this header to a cross-site request without
            # our permission (which we never give), so other web pages can't
            # trigger scans or change settings behind your back.
            return self.headers.get("X-VulnScan") == "1"

        # ------------------------------------------------------------ routes ----
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if server and urlparse(self.path).path == "/healthz":
                st = app.scanner.state
                return self.send(200, {"ok": True, "version": __version__, "scan_running": st["running"],
                                       "last_scan_finished": st["finished"]})
            if server and not self.allowed():
                return self.send(401, "Sign-in required. Open VulnScan through the company sign-in address.",
                                 "text/plain; charset=utf-8")
            if not self.allowed():
                return self.send(403, "Access denied. On a phone, open the link from the QR code in Settings.",
                                 "text/plain; charset=utf-8")
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            path = u.path
            if lan and "k" in qs:
                c = f"vs_k={app.phone_token()}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000"
                return self.send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": c})
            try:
                if path == "/api/ping":
                    return self.send(200, {"app": "VulnScan", "version": __version__})
                if path == "/api/info":
                    return self.send(200, self.info())
                if path == "/api/results":
                    return self.send(200, self.results(qs))
                if path == "/api/scan":
                    return self.send(200, app.scanner.state)
                if path == "/api/settings":
                    return self.send(200, self.settings_view())
                if path == "/api/phone":
                    if lan or server:
                        return self.send(403, {"error": "not available from a phone"})
                    return self.send(200, app.phone_info())
                if path in ("/api/export.xlsx", "/api/export.pdf"):
                    return self.export(path.endswith("pdf"), qs)
                return self.static(path)
            except Exception as e:  # noqa: BLE001
                return self.send(500, {"error": f"{e.__class__.__name__}: {e}"})

        def do_POST(self):
            self.do_write()

        def do_PUT(self):
            self.do_write()

        def do_write(self):
            if not self.allowed() or not self.write_ok():
                return self.send(401 if server and not self.allowed() else 403, {"error": "forbidden"})
            path = urlparse(self.path).path
            if server:
                who = self.identity()
                if path in DESKTOP_ONLY_PATHS:
                    return self.send(403, {"error": "Not available on the server. Keys are set by the server administrator."})
                if path in ADMIN_PATHS and not who["admin"]:
                    return self.send(403, {"error": "Only VulnScan administrators can do this."})
                if path in ADMIN_PATHS and path != "/api/sources/test":
                    log.info("%s by %s", path, who["user"])
            try:
                data = self.body_json()
            except (ValueError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})
            try:
                if path == "/api/heartbeat":
                    if not lan:
                        app.last_ping = time.time()
                    return self.send(200, {"ok": True})
                if path == "/api/scan":
                    started = app.scanner.start(only=data.get("only"))
                    return self.send(200 if started else 409, {"started": started, **app.scanner.state})
                if path == "/api/scan/stop":
                    app.scanner.stop()
                    return self.send(200, {"ok": True})
                if path == "/api/settings":
                    return self.send(200, self.save_settings(data))
                if path == "/api/settings/reset":
                    settings.reset()
                    app.apply_phone_access()
                    return self.send(200, self.settings_view())
                if path == "/api/sources/test":
                    src = settings.validate({"sources": [data.get("source") or {}]})["sources"]
                    if not src:
                        return self.send(400, {"error": "no source"})
                    return self.send(200, app.scanner.test_source(src[0], settings.load()["first_scan_days"], con=app.db()))
                if path == "/api/sources/clear":
                    store.clear_source(app.db(), str(data.get("id") or ""))
                    return self.send(200, {"ok": True})
                if lan:
                    return self.send(403, {"error": "not available from a phone"})
                if path == "/api/secrets":
                    name = data.get("name")
                    if name not in secrets_store.NAMES:
                        return self.send(400, {"error": "unknown key"})
                    secrets_store.set(name, data.get("value") or "")
                    return self.send(200, self.settings_view())
                if path == "/api/phone/new-key":
                    app.new_phone_token()
                    return self.send(200, app.phone_info())
                if path == "/api/quit":
                    self.send(200, {"ok": True})
                    threading.Timer(0.3, app.quit_event.set).start()
                    return None
                return self.send(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001
                return self.send(500, {"error": f"{e.__class__.__name__}: {e}"})

        # ------------------------------------------------------------ views ----
        def info(self):
            cfg = settings.load()
            con = app.db()
            total, by_source = store.totals(con)
            return {
                "title": cfg["app_title"], "tagline": cfg["tagline"], "version": __version__,
                "phone": lan, "mode": "server" if server else "desktop",
                "user": (self.identity() or {}).get("user"), "admin": (self.identity() or {}).get("admin", False),
                "scan_every_hours": app.scan_every_hours if server else None,
                "next_scan": datetime.fromtimestamp(app.next_scan).isoformat(timespec="minutes")
                if server and app.next_scan else None,
                "sources": [{"id": s["id"], "name": s["name"], "enabled": s["enabled"],
                             "count": by_source.get(s["id"], 0)} for s in cfg["sources"]],
                "other_sources": sorted(set(by_source) - {s["id"] for s in cfg["sources"]}),
                "total": total, "last_runs": store.last_runs(con),
            }

        def results(self, qs):
            f = _filters(qs)
            con = app.db()
            limit = min(int((qs.get("limit") or ["500"])[0] or 500), 5000)
            rows = store.query(con, f, limit=limit)
            matching, exploited = store.count(con, f)
            total, _ = store.totals(con)
            return {"rows": rows, "matching": matching, "exploited": exploited, "total": total,
                    "limit": limit, "filters": f, "summary": store.summary(con, f["days"])}

        def settings_view(self):
            cfg = settings.load()
            cfg["secrets"] = {} if lan else {n: secrets_store.masked(n) for n in secrets_store.NAMES}
            cfg["last_runs"] = store.last_runs(app.db())
            return cfg

        def save_settings(self, data):
            cur = settings.load()
            for k in ("app_title", "tagline", "first_scan_days", "sources"):
                if k in data:
                    cur[k] = data[k]
            if "phone_access" in data and not lan and not server:
                cur["phone_access"] = bool(data["phone_access"])
            settings.save(cur)
            app.apply_phone_access()
            return self.settings_view()

        def export(self, pdf, qs):
            f = _filters(qs)
            con = app.db()
            rows = store.query(con, f)
            summ = store.summary(con, f["days"])
            title = settings.load()["app_title"]
            stamp = datetime.now().strftime("%Y-%m-%d")
            if pdf:
                body = exporter.to_pdf(rows, summ, f, title)
                name, ctype = f"vulnerabilities-{stamp}.pdf", "application/pdf"
            else:
                body = exporter.to_xlsx(rows, summ, f, title)
                name = f"vulnerabilities-{stamp}.xlsx"
                ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            return self.send(200, body, ctype, {"Content-Disposition": f'attachment; filename="{name}"'})

        def static(self, path):
            if path in ("", "/"):
                path = "/index.html"
            root = static_dir().resolve()
            target = (root / path.lstrip("/")).resolve()
            if root not in target.parents or not target.is_file():
                return self.send(404, "Not found", "text/plain")
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            return self.send(200, target.read_bytes(), ctype)

    return Handler


def find_port(preferred):
    for port in [preferred] + list(range(preferred + 2, preferred + 40, 2)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise OSError("no free port")


def serve(port=None):
    """Start the loopback server in a thread. Returns (app, httpd)."""
    port = port or find_port(int(os.environ.get("VULNSCAN_PORT") or DEFAULT_PORT))
    app = App(port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    app.apply_phone_access()
    return app, httpd


def serve_server(host="0.0.0.0", port=8080):
    """Server mode (container): listen on the network, scan on a schedule."""
    app = App(port, server_mode=True)
    httpd = ThreadingHTTPServer((host, port), make_handler(app, server=True))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    app.start_scheduler()
    auth = os.environ.get("VULNSCAN_AUTH", "header").lower()
    log.info("VulnScan %s server listening on %s:%s (sign-in: %s, scan every %sh)",
             __version__, host, port, "from gateway headers" if auth != "none" else "SWITCHED OFF", app.scan_every_hours)
    if auth == "none":
        log.warning("VULNSCAN_AUTH=none: anyone who can reach this port is an admin. Use for testing only.")
    if not (_csv_env("VULNSCAN_ADMINS") or _csv_env("VULNSCAN_ADMIN_GROUPS")):
        log.warning("No VULNSCAN_ADMINS or VULNSCAN_ADMIN_GROUPS set: nobody can change sources or start scans by hand.")
    return app, httpd
