"""
app.py
Web Honeypot Service - fake phpMyAdmin

Binds on port 8080 (localhost only via Docker port mapping).
Serves a convincing phpMyAdmin login portal. Accepts any credentials,
exposes deliberately "vulnerable" post-auth features (SQL query box,
file import, server variables), and serves tempting honey files for
common scanner paths (.env, config.inc.php.bak, setup/, phpinfo).

Logging here is intentionally minimal - a separate project member is
wiring up the shared JSONL + SQLite store that the ssh-honeypot uses.
"""

import logging
import secrets

from flask import Flask, request, make_response, redirect

from fake_content import (
    LOGIN_HTML, MAIN_HTML, SQL_HTML, IMPORT_HTML, STATUS_HTML,
    VARIABLES_HTML, USERS_HTML, THEME_CSS, HONEY_FILES,
    PMA_VERSION, MYSQL_VERSION, fake_sql_result,
)

HOST = "0.0.0.0"
PORT = 8080

SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"
POWERED_BY    = f"PHP/7.4.3 phpMyAdmin/{PMA_VERSION}"

# phpMyAdmin uses a "phpMyAdmin" cookie plus pmaAuth-1 for auth state;
# mimic both so the facade holds up if an attacker inspects cookies.
SESSION_COOKIE = "phpMyAdmin"
AUTH_COOKIE    = "pmaAuth-1"

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [WEB] %(levelname)s %(message)s",
)
log = logging.getLogger("honeyshell.web")

app = Flask(__name__)


def _session_id() -> str:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid or len(sid) < 16:
        sid = secrets.token_hex(16)
    return sid


def _source_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.after_request
def _after(resp):
    resp.headers["Server"] = SERVER_HEADER
    resp.headers["X-Powered-By"] = POWERED_BY
    resp.set_cookie(SESSION_COOKIE, _session_id(), httponly=True, samesite="Lax")
    return resp


# Login portal

@app.route("/", methods=["GET"])
@app.route("/index.php", methods=["GET"])
def index():
    if request.cookies.get(AUTH_COOKIE):
        user = request.cookies.get("pma_user", "root")
        return _authenticated(request.args.get("route", "/"), user)
    return LOGIN_HTML.format(error="", token=secrets.token_hex(16), pma_version=PMA_VERSION)


@app.route("/index.php", methods=["POST"])
def index_post():
    """phpMyAdmin posts every form to /index.php; dispatch by ?route= param."""
    route = request.args.get("route", "")
    if route.startswith("/sql"):
        return _sql_query()
    if route.startswith("/server/import"):
        return _handle_import()
    return _login()


def _login():
    sid  = _session_id()
    user = request.form.get("pma_username", "")
    pw   = request.form.get("pma_password", "")
    log.info(f"[{sid[:8]}] AUTH ip={_source_ip()} user={user!r} pass={pw!r}")

    resp = redirect("/index.php?route=/", code=302)
    resp.set_cookie(AUTH_COOKIE, secrets.token_hex(24), httponly=True, samesite="Lax")
    resp.set_cookie("pma_user", user or "root", samesite="Lax")
    return resp


def _authenticated(route: str, user: str):
    if route in ("/", "", "/index"):
        return MAIN_HTML.format(user=user, pma_version=PMA_VERSION, mysql_version=MYSQL_VERSION)
    if route.startswith("/sql"):
        return SQL_HTML.format(query="", result="", token=secrets.token_hex(16))
    if route.startswith("/server/status"):
        return STATUS_HTML
    if route.startswith("/server/user-accounts"):
        return USERS_HTML
    if route.startswith("/server/variables"):
        return VARIABLES_HTML.format(mysql_version=MYSQL_VERSION)
    if route.startswith("/server/import"):
        return IMPORT_HTML.format(msg="", token=secrets.token_hex(16))
    if route.startswith("/server/export"):
        return "<pre>-- mysqldump 8.0.35\n-- Host: localhost\nSET NAMES utf8mb4;\n</pre>"
    if route.startswith("/database/structure"):
        db = request.args.get("db", "acme_portal")
        return f"<h2>Database: {db}</h2><ul><li>users</li><li>sessions</li><li>invoices</li></ul>"
    if route == "/logout":
        resp = make_response(redirect("/index.php", code=302))
        resp.delete_cookie(AUTH_COOKIE)
        return resp
    return MAIN_HTML.format(user=user, pma_version=PMA_VERSION, mysql_version=MYSQL_VERSION)


def _sql_query():
    sid = _session_id()
    query = (request.form.get("sql_query") or request.args.get("sql_query") or "").strip()
    if query:
        log.info(f"[{sid[:8]}] SQL: {query[:200]!r}")
    result = fake_sql_result(query) if query else ""
    return SQL_HTML.format(query=query, result=result, token=secrets.token_hex(16))


def _handle_import():
    sid = _session_id()
    f = request.files.get("import_file")
    if f:
        content = f.read()
        log.info(f"[{sid[:8]}] IMPORT name={f.filename!r} size={len(content)}")
    msg = '<div class="error">Import has been successfully finished, 0 queries executed.</div>'
    return IMPORT_HTML.format(msg=msg, token=secrets.token_hex(16))


# Also expose /sql directly - real phpMyAdmin accepts bare paths too.
@app.route("/sql", methods=["GET", "POST"])
def sql_bare():
    return _sql_query()


# Static-ish content

@app.route("/themes/pmahomme/css/theme.css")
def theme_css():
    resp = make_response(THEME_CSS)
    resp.headers["Content-Type"] = "text/css"
    return resp


@app.route("/favicon.ico")
def favicon():
    return (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
        b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
        200,
        {"Content-Type": "image/gif"},
    )


# Honey files + catch-all

@app.route("/<path:any_path>", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"])
def catch_all(any_path: str):
    sid = _session_id()
    full = "/" + any_path
    if full in HONEY_FILES:
        ctype, body = HONEY_FILES[full]
        log.info(f"[{sid[:8]}] HONEY {full}")
        resp = make_response(body)
        resp.headers["Content-Type"] = ctype
        return resp
    log.info(f"[{sid[:8]}] 404 {request.method} {full}")
    return make_response(("<h1>404 Not Found</h1>", 404, {"Content-Type": "text/html"}))


def main():
    log.info(f"HoneyShell web honeypot starting on {HOST}:{PORT}")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
