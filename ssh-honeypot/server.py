"""
server.py
SSH Honeypot Service
 
Binds on port 2222 (localhost only via Docker port mapping).
Accepts all login attempts, presents a fake interactive shell,
and logs every credential, command, and timing gap to a shared
JSON lines file and SQLite database.
"""
 
import asyncio
import asyncssh
import json
import time
import uuid
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path
 
from fake_fs import resolve_command, HOSTNAME, USERNAME
 
# Config
 
HOST = "0.0.0.0"  # Docker binds 2222 -> 127.0.0.1:2222 on the host
PORT = 2222
LOG_DIR = Path("/app/logs")
JSONL_FILE = LOG_DIR / "events.jsonl"
DB_FILE = LOG_DIR / "honeyshell.db"
 
# Fake SSH server banner, looks like a real Ubuntu production box
SERVER_VERSION = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
 
# Artificial login delay (seconds), slows down automated bruteforcers
DELAY = 1.5

# Logging setup
 
logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [SSH] %(levelname)s %(message)s",
)
log = logging.getLogger("honeyshell.ssh")
 
 
# Storage helpers
 
def init_db():
    LOG_DIR.mkdir(parents = True, exist_ok = True)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.executescript("""
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
    """Append one event to both the JSON lines file and SQLite."""
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "session_id": session_id,
        "service": "ssh",
        "timestamp": now,
        "event_type": event_type,
        "data": data,
    }
 
    # JSON lines
    with open(JSONL_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
 
    # SQLite
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO events (session_id, timestamp, service, event_type, data) VALUES (?,?,?,?,?)",
            (session_id, now, "ssh", event_type, json.dumps(data)),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"DB write failed: {e}")
 
 
def update_session(session_id: str, **kwargs):
    try:
        conn = sqlite3.connect(DB_FILE)
        cols = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [session_id]
        conn.execute(f"UPDATE sessions SET {cols} WHERE session_id=?", vals)
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Session update failed: {e}")
 
# SSH server implementation

class HoneyShellSession(asyncssh.SSHServerSession):
    """
    One instance per authenticated SSH session.
    Manages the fake interactive shell loop.
    """
 
    def __init__(self, session_id: str, source_ip: str):
        self._session_id  = session_id
        self._source_ip = source_ip
        self._cwd = f"/home/{USERNAME}"
        self._input_buf = ""
        self._cmd_count = 0
        self._last_cmd_ts = time.monotonic()
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        self._chan.write(
            b"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1034-aws x86_64)\r\n\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n"
            b" * Management:     https://landscape.canonical.com\r\n\r\n"
            b"Last login: Fri Jan 12 08:44:01 2024 from 10.0.2.1\r\n"
        )
        self._send_prompt()
        return True 
 
    def _send_prompt(self):
        prompt = f"{USERNAME}@{HOSTNAME}:{self._cwd_display()}$ "
        self._chan.write(prompt.encode())
 
    def _cwd_display(self):
        home = f"/home/{USERNAME}"
        if self._cwd == home:
            return "~"
        if self._cwd.startswith(home + "/"):
            return "~" + self._cwd[len(home):]
        return self._cwd
 
    def data_received(self, data, datatype):
        # data arrives as bytes when encoding=None
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors = "replace")
        
        self._input_buf += data
        self._chan.write(data.encode())

        if "\n" in self._input_buf or "\r" in self._input_buf:
            lines = self._input_buf.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            self._input_buf = lines[-1]
            for line in lines[:-1]:
                self._handle_command(line)
 
    def _handle_command(self, cmd: str):
        cmd = cmd.strip()
        now_ts = time.monotonic()
        gap_ms = round((now_ts - self._last_cmd_ts) * 1000)
        self._last_cmd_ts = now_ts
        self._cmd_count += 1

        log.info(f"[{self._session_id[:8]}] CMD: {cmd!r}  gap={gap_ms}ms")

        write_event(self._session_id, "command", {
            "command":       cmd,
            "cwd":           self._cwd,
            "gap_ms":        gap_ms,
            "cmd_index":     self._cmd_count,
            "is_bot_likely": gap_ms < 200,
        })

        output, new_cwd = resolve_command(cmd, self._cwd)
        self._cwd = new_cwd

        if output == "__EXIT__":
            self._chan.write(b"\r\nlogout\r\n")   # <-- bytes
            self._chan.close()
            return

        if output:
            self._chan.write(("\r\n" + output.replace("\n", "\r\n") + "\r\n").encode())  # <-- bytes

        self._send_prompt()
 
    def eof_received(self):
        update_session(
            self._session_id,
            ended_at=datetime.now(timezone.utc).isoformat(),
            total_cmds=self._cmd_count,
        )
        write_event(self._session_id, "session_end", {
            "total_cmds": self._cmd_count,
        })
 
    def connection_lost(self, exc):
        update_session(
            self._session_id,
            ended_at=datetime.now(timezone.utc).isoformat(),
            total_cmds=self._cmd_count,
        )
 
 
class HoneyShellServer(asyncssh.SSHServer):
    """
    Handles new SSH connections.
    Accepts ALL credentials.
    """
 
    def __init__(self):
        self._session_id = str(uuid.uuid4())
        self._source_ip  = "unknown"

    def connection_made(self, conn):
        self._conn = conn
        try:
            peer = conn.get_extra_info("peername")
            self._source_ip = peer[0] if peer else "unknown"
        except Exception:
            self._source_ip = "unknown"
        
        log.info(f"[{self._session_id[:8]}] Connection from {self._source_ip}")

        write_event(self._session_id, "connection", {
            "source_ip":  self._source_ip,
            "client_ver": str(conn.get_extra_info("client_version", "unknown")),
        })
 
    def connection_lost(self, exc):
        log.info(f"[{self._session_id[:8]}] Connection closed from {self._source_ip}")
 
    def begin_auth(self, username: str) -> bool:
        """Called before password check, log the username attempt."""
        self._attempted_username = username
        return True  # True = continue with password auth
 
    def password_auth_supported(self) -> bool:
        return True
 
    async def validate_password(self, username: str, password: str) -> bool:
        await asyncio.sleep(DELAY)

        log.info(f"[{self._session_id[:8]}] AUTH username={username!r} password={password!r}")

        write_event(self._session_id, "auth_attempt", {
            "source_ip": self._source_ip,
            "username":  username,
            "password":  password,
            "success":   True,
        })

        try:
            client_ver = str(self._conn.get_extra_info("client_version", "unknown"))
        except Exception:
            client_ver = "unknown"

        try:
            conn = sqlite3.connect(DB_FILE)
            conn.execute(
                """INSERT OR REPLACE INTO sessions
                (session_id, started_at, source_ip, username, password, client_ver)
                VALUES (?,?,?,?,?,?)""",
                (
                    self._session_id,
                    datetime.now(timezone.utc).isoformat(),
                    self._source_ip,
                    username,
                    password,
                    client_ver,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"Session insert failed: {e}")

        return True
 
    def session_requested(self):
        return HoneyShellSession(self._session_id, self._source_ip)

    def shell_requested(self):
        return True   # explicitly accept shell requests

    def pty_requested(self, term_type, term_size, term_modes):
        return True   # accept PTY requests, needed for interactive shell
 
# Host key generation
 
def get_or_create_host_key() -> asyncssh.SSHKey:
    """
    Load or generate a persistent RSA host key.
    Stored in the log volume so it survives container restarts
    (a changing host key would look suspicious to repeat visitors).
    """
    key_path = LOG_DIR / "ssh_host_key"
    if key_path.exists():
        log.info("Loading existing host key")
        return asyncssh.read_private_key(str(key_path))
    log.info("Generating new RSA host key")
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(str(key_path))
    return key
 
# Entry point
 
async def main():
    init_db()
    host_key = get_or_create_host_key()
 
    log.info(f"HoneyShell SSH honeypot starting on {HOST}:{PORT}")
 
    await asyncssh.create_server(
        HoneyShellServer,
        HOST,
        PORT,
        server_host_keys = [host_key],
        server_version = SERVER_VERSION,
        line_editor = False,
        encoding = None,
        allow_pty = True,
    )
 
    log.info(f"Listening - accepting all connections on port {PORT}")
    await asyncio.Future()  # run forever
 
 
if __name__ == "__main__":
    asyncio.run(main())