"""
app.py
Web Honeypot Service - fake phpMyAdmin

Binds on port 8080 (localhost only via Docker port mapping).
Serves a convincing phpMyAdmin login portal. Accepts any credentials,
exposes deliberately "vulnerable" post-auth features (SQL query box,
file import, server variables), and serves tempting honey files for
common scanner paths (.env, config.inc.php.bak, setup/, phpinfo).

Every session, login attempt, page visit, SQL query, file upload,
honey-file hit, and path probe is written to the shared JSONL file
and SQLite database that the SSH honeypot also uses.
"""

import json
import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, make_response, redirect

from fake_content import (
    LOGIN_HTML, MAIN_HTML, SQL_HTML, IMPORT_HTML, STATUS_HTML,
    VARIABLES_HTML, USERS_HTML, THEME_CSS, HONEY_FILES,
    PMA_VERSION, MYSQL_VERSION, fake_sql_result,
)

HOST = "0.0.0.0"
PORT = 8080

LOG_DIR    = Path("/app/logs")
JSONL_FILE = LOG_DIR / "events.jsonl"
DB_FILE    = LOG_DIR / "honeyshell.db"

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


# Storage helpers

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_db():
    """Create DB tables if they don't exist yet (SSH honeypot may have already done this)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            started_at   TEXT NOT NULL,
            ended_at     TEXT,
            source_ip    TEXT,
            username     TEXT,
            password     TEXT,
            client_ver   TEXT,
            total_cmds   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            timestamp    TEXT NOT NULL,
            service      TEXT DEFAULT 'ssh',
            event_type   TEXT NOT NULL,
            data         TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
    """)
    conn.commit()
    conn.close()


def write_event(session_id: str, event_type: str, data: dict):
    """Append one event to both the JSONL file and SQLite database."""
    now = _now()
    record = {
        "session_id": session_id,
        "service":    "web",
        "timestamp":  now,
        "event_type": event_type,
        "data":       data,
    }
    try:
        with open(JSONL_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        log.warning(f"JSONL write failed: {e}")
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO events (session_id, timestamp, service, event_type, data) VALUES (?,?,?,?,?)",
            (session_id, now, "web", event_type, json.dumps(data)),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"DB write failed: {e}")


def _upsert_session(session_id: str, source_ip: str, username: str = "", password: str = ""):
    """Insert or replace a web session row (client_ver='web' so the dashboard can distinguish it)."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            """INSERT OR REPLACE INTO sessions
            (session_id, started_at, source_ip, username, password, client_ver)
            VALUES (?,?,?,?,?,?)""",
            (session_id, _now(), source_ip, username, password, "web"),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Session upsert failed: {e}")


def _end_session(session_id: str):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "UPDATE sessions SET ended_at=? WHERE session_id=?",
            (_now(), session_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Session end failed: {e}")


# Flask helpers

def _session_id() -> str:
    """Return the session ID for this request, generating one if needed.

    A generated ID is stored in request.environ so every call within the
    same request returns the same value (before the cookie is set by
    _after()).
    """
    cached = request.environ.get("_web_sid")
    if cached:
        return cached
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid or len(sid) < 16:
        sid = secrets.token_hex(16)
    request.environ["_web_sid"] = sid
    return sid


def _source_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _user_agent() -> str:
    return request.headers.get("User-Agent", "")[:200]


@app.before_request
def _track_new_session():
    """On first visit (no session cookie), create the session row and log a connection event.

    _upsert_session is called here so every web visitor counts as a web session on
    the dashboard, not just those who submit the login form. _login() will call
    _upsert_session again with the actual credentials, which updates the row via
    INSERT OR REPLACE on the primary key.
    """
    existing = request.cookies.get(SESSION_COOKIE)
    if not existing or len(existing) < 16:
        sid = _session_id()
        ip  = _source_ip()
        _upsert_session(sid, ip)
        write_event(sid, "connection", {
            "source_ip":  ip,
            "user_agent": _user_agent(),
            "path":       request.path,
        })
        log.info(f"[{sid[:8]}] NEW SESSION ip={ip} path={request.path!r}")


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
    ip   = _source_ip()
    user = request.form.get("pma_username", "")
    pw   = request.form.get("pma_password", "")

    log.info(f"[{sid[:8]}] LOGIN ip={ip} user={user!r} pass={pw!r}")

    _upsert_session(sid, ip, user, pw)
    write_event(sid, "login_attempt", {
        "source_ip": ip,
        "username":  user,
        "password":  pw,
    })

    resp = redirect("/index.php?route=/", code=302)
    resp.set_cookie(AUTH_COOKIE, secrets.token_hex(24), httponly=True, samesite="Lax")
    resp.set_cookie("pma_user", user or "root", samesite="Lax")
    return resp


def _authenticated(route: str, user: str):
    sid = _session_id()
    ip  = _source_ip()

    if route == "/logout":
        log.info(f"[{sid[:8]}] LOGOUT ip={ip} user={user!r}")
        write_event(sid, "session_end", {"source_ip": ip, "username": user})
        _end_session(sid)
        resp = make_response(redirect("/index.php", code=302))
        resp.delete_cookie(AUTH_COOKIE)
        return resp

    log.info(f"[{sid[:8]}] PAGE ip={ip} user={user!r} route={route!r}")
    write_event(sid, "page_visit", {
        "source_ip": ip,
        "path":      route or "/",
        "user":      user,
    })

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
    return MAIN_HTML.format(user=user, pma_version=PMA_VERSION, mysql_version=MYSQL_VERSION)


def _sql_query():
    sid   = _session_id()
    ip    = _source_ip()
    query = (request.form.get("sql_query") or request.args.get("sql_query") or "").strip()
    if query:
        log.info(f"[{sid[:8]}] SQL ip={ip} query={query[:200]!r}")
        write_event(sid, "sql_query", {
            "source_ip": ip,
            "query":     query,
        })
    result = fake_sql_result(query) if query else ""
    return SQL_HTML.format(query=query, result=result, token=secrets.token_hex(16))


def _handle_import():
    sid = _session_id()
    ip  = _source_ip()
    f = request.files.get("import_file")
    if f:
        content = f.read()
        log.info(f"[{sid[:8]}] UPLOAD ip={ip} name={f.filename!r} size={len(content)}")
        write_event(sid, "file_upload", {
            "source_ip": ip,
            "filename":  f.filename,
            "size":      len(content),
        })
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
    sid  = _session_id()
    ip   = _source_ip()
    ua   = _user_agent()
    full = "/" + any_path
    if full in HONEY_FILES:
        ctype, body = HONEY_FILES[full]
        log.info(f"[{sid[:8]}] HONEY ip={ip} path={full!r}")
        write_event(sid, "honey_file", {
            "source_ip":  ip,
            "path":       full,
            "user_agent": ua,
        })
        resp = make_response(body)
        resp.headers["Content-Type"] = ctype
        return resp
    log.info(f"[{sid[:8]}] PROBE ip={ip} {request.method} {full}")
    write_event(sid, "path_probe", {
        "source_ip":  ip,
        "path":       full,
        "method":     request.method,
        "user_agent": ua,
    })
    return make_response(("<h1>404 Not Found</h1>", 404, {"Content-Type": "text/html"}))


def main():
    _ensure_db()
    log.info(f"HoneyShell web honeypot starting on {HOST}:{PORT}")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
