"""
app.py
Web Honeypot Service

Serves a fake corporate login portal on port 8080.
Logs all interactions to the shared JSONL + SQLite log files,
and detects common web attack patterns.
"""

from flask import Flask, request, render_template_string
import json
import sqlite3
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

app = Flask(__name__)

# Config
LOG_DIR = Path("/app/logs")
JSONL_FILE = LOG_DIR / "events.jsonl"
DB_FILE = LOG_DIR / "honeyshell.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WEB] %(levelname)s %(message)s",
)
log = logging.getLogger("honeyshell.web")

# Attack detection patterns

SQL_PATTERNS = [
    "'", '"', "--", "/*", "*/", ";",
    "or 1=1", "union", "select", "drop", "insert",
    "update", "delete", "xp_", "exec(", "char(",
]

TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e", "etc/passwd", "etc/shadow",
    "windows/system32", "boot.ini", "/proc/",
]

SCANNER_AGENTS = [
    "nikto", "sqlmap", "nmap", "masscan", "burp", "zaproxy",
    "w3af", "acunetix", "nessus", "metasploit", "havij",
    "dirbuster", "gobuster", "hydra", "medusa", "wfuzz",
]

# Storage helpers — same schema as ssh-honeypot so dashboard reads both

def init_db():
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
            service      TEXT DEFAULT 'web',
            event_type   TEXT NOT NULL,
            data         TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );
    """)
    conn.commit()
    conn.close()


def write_event(session_id: str, event_type: str, data: dict):
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "session_id": session_id,
        "service":    "web",
        "timestamp":  now,
        "event_type": event_type,
        "data":       data,
    }
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(JSONL_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO events (session_id, timestamp, service, event_type, data) "
            "VALUES (?,?,?,?,?)",
            (session_id, now, "web", event_type, json.dumps(data)),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"DB write failed: {e}")


def upsert_session(session_id: str, source_ip: str, username: str = None, password: str = None):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            """INSERT OR IGNORE INTO sessions
               (session_id, started_at, source_ip, username, password, client_ver)
               VALUES (?,?,?,?,?,?)""",
            (session_id, datetime.now(timezone.utc).isoformat(),
             source_ip, username, password, "web"),
        )
        if username:
            conn.execute(
                "UPDATE sessions SET username=?, password=? WHERE session_id=?",
                (username, password, session_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Session upsert failed: {e}")

# Detection helpers

def get_source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def detect_sql_injection(value: str) -> bool:
    lower = value.lower()
    return any(p in lower for p in SQL_PATTERNS)


def detect_traversal(value: str) -> bool:
    lower = value.lower()
    return any(p in lower for p in TRAVERSAL_PATTERNS)


def detect_scanner(user_agent: str) -> bool:
    ua = user_agent.lower()
    return any(s in ua for s in SCANNER_AGENTS)

# HTML — fake corporate login portal

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CorpNet — Employee Portal</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #1a1a2e;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .container {
      background: #fff; border-radius: 8px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.4);
      padding: 40px 48px; width: 380px;
    }
    .logo { text-align: center; margin-bottom: 24px; }
    .logo h1 { font-size: 22px; color: #1a1a2e; letter-spacing: 2px; }
    .logo p  { font-size: 12px; color: #888; margin-top: 4px; }
    label { display: block; font-size: 13px; color: #444; margin-bottom: 4px; margin-top: 16px; }
    input[type=text], input[type=password] {
      width: 100%; padding: 10px 14px;
      border: 1px solid #ddd; border-radius: 4px;
      font-size: 14px; outline: none; transition: border 0.2s;
    }
    input:focus { border-color: #1a1a2e; }
    button {
      width: 100%; margin-top: 24px; padding: 11px;
      background: #1a1a2e; color: #fff; border: none;
      border-radius: 4px; font-size: 15px; cursor: pointer; letter-spacing: 1px;
    }
    button:hover { background: #16213e; }
    .error {
      background: #ffeaea; border: 1px solid #f5c6cb;
      color: #842029; border-radius: 4px;
      padding: 10px 14px; margin-top: 16px; font-size: 13px;
    }
    .footer { text-align: center; margin-top: 24px; font-size: 11px; color: #aaa; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <h1>CORPNET</h1>
      <p>Employee Portal &mdash; Authorized Access Only</p>
    </div>
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username"
             autocomplete="off" placeholder="Enter your username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password"
             placeholder="Enter your password">
      <button type="submit">SIGN IN</button>
      {% if error %}
      <div class="error">{{ error }}</div>
      {% endif %}
    </form>
    <div class="footer">
      &copy; 2024 CorpNet Inc. &nbsp;&middot;&nbsp; IT Support: helpdesk@corpnet.internal
    </div>
  </div>
</body>
</html>"""

# Routes

@app.route("/", methods=["GET"])
def index():
    source_ip = get_source_ip()
    ua = request.headers.get("User-Agent", "")
    session_id = str(uuid.uuid4())

    log.info(f"GET / from {source_ip}")
    upsert_session(session_id, source_ip)
    write_event(session_id, "page_visit", {
        "source_ip":  source_ip,
        "user_agent": ua,
        "path":       "/",
    })

    if detect_scanner(ua):
        log.info(f"Scanner probe on / from {source_ip} ua={ua!r}")
        write_event(session_id, "scanner_probe", {
            "source_ip":  source_ip,
            "user_agent": ua,
            "path":       "/",
        })

    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/login", methods=["POST"])
def login():
    source_ip = get_source_ip()
    ua        = request.headers.get("User-Agent", "")
    username  = request.form.get("username", "")
    password  = request.form.get("password", "")
    session_id = str(uuid.uuid4())

    log.info(f"POST /login from {source_ip} user={username!r}")
    upsert_session(session_id, source_ip, username, password)

    write_event(session_id, "login_attempt", {
        "source_ip":  source_ip,
        "username":   username,
        "password":   password,
        "user_agent": ua,
    })

    combined = f"{username} {password}"

    if detect_sql_injection(combined):
        log.info(f"SQL injection from {source_ip}: {combined!r}")
        write_event(session_id, "sql_injection", {
            "source_ip": source_ip,
            "username":  username,
            "password":  password,
            "user_agent": ua,
        })

    if detect_traversal(combined):
        log.info(f"Directory traversal from {source_ip}: {combined!r}")
        write_event(session_id, "directory_traversal", {
            "source_ip":  source_ip,
            "input":      combined,
            "user_agent": ua,
        })

    if detect_scanner(ua):
        write_event(session_id, "scanner_probe", {
            "source_ip":  source_ip,
            "user_agent": ua,
            "path":       "/login",
        })

    # Always deny — keep the attacker engaged and logging
    return render_template_string(LOGIN_PAGE,
                                  error="Invalid username or password. Please try again.")


@app.route("/admin",         methods=["GET", "POST"])
@app.route("/wp-admin",      methods=["GET", "POST"])
@app.route("/wp-login.php",  methods=["GET", "POST"])
@app.route("/phpmyadmin",    methods=["GET", "POST"])
@app.route("/administrator", methods=["GET", "POST"])
@app.route("/.env",          methods=["GET"])
@app.route("/config.php",    methods=["GET"])
def path_probe():
    """Catch common admin / config path probes and log them."""
    source_ip  = get_source_ip()
    ua         = request.headers.get("User-Agent", "")
    session_id = str(uuid.uuid4())
    path       = request.path

    log.info(f"Path probe {path} from {source_ip}")
    upsert_session(session_id, source_ip)
    write_event(session_id, "path_probe", {
        "source_ip":  source_ip,
        "path":       path,
        "method":     request.method,
        "user_agent": ua,
    })

    return "Not Found", 404


if __name__ == "__main__":
    init_db()
    log.info("HoneyShell Web Honeypot starting on port 8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
