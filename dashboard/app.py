"""
app.py
Dashboard Service

Reads from the shared SQLite DB and JSONL log files written by the SSH
and web honeypots, and presents a live-updating summary at port 3000.
Auto-refreshes every 15 seconds via a JSON API polled by the frontend.
"""

import json
import sqlite3
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

LOG_DIR   = Path("/app/logs")
DB_FILE   = LOG_DIR / "honeyshell.db"
JSONL_FILE = LOG_DIR / "events.jsonl"


# Data helpers

def _db_available() -> bool:
    return DB_FILE.exists()


def _read_jsonl() -> list[dict]:
    if not JSONL_FILE.exists():
        return []
    records = []
    with open(JSONL_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def _query(sql: str, params: tuple = ()) -> list[dict]:
    if not _db_available():
        return []
    try:
        conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def get_stats() -> dict:
    # Sessions
    sessions      = _query("SELECT * FROM sessions ORDER BY started_at DESC")
    ssh_sessions  = [s for s in sessions if s.get("client_ver") != "web"]
    web_sessions  = [s for s in sessions if s.get("client_ver") == "web"]

    # Events
    events = _query("SELECT * FROM events ORDER BY timestamp DESC")
    if not events:
        events = _read_jsonl()

    event_types   = Counter(e.get("event_type", "unknown") for e in events)
    service_counts = Counter(e.get("service", "unknown") for e in events)

    # Top credentials
    auth_events = [
        e for e in events
        if e.get("event_type") in ("auth_attempt", "login_attempt")
    ]
    cred_counter: Counter = Counter()
    for e in auth_events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        u = data.get("username", "")
        p = data.get("password", "")
        if u or p:
            cred_counter[f"{u} / {p}"] += 1
    top_creds = [{"cred": k, "count": v} for k, v in cred_counter.most_common(10)]

    # Top source IPs
    ip_counter: Counter = Counter()
    for e in events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        ip = data.get("source_ip") or data.get("ip", "")
        if ip:
            ip_counter[ip] += 1
    top_ips = [{"ip": k, "count": v} for k, v in ip_counter.most_common(10)]

    # Commands run in SSH sessions
    cmd_events = [e for e in events if e.get("event_type") == "command"]
    cmd_counter: Counter = Counter()
    for e in cmd_events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        cmd = data.get("command", "").split()[0] if data.get("command") else ""
        if cmd:
            cmd_counter[cmd] += 1
    top_cmds = [{"cmd": k, "count": v} for k, v in cmd_counter.most_common(10)]

    # Top SQL queries submitted via the web honeypot
    sql_events = [e for e in events if e.get("event_type") == "sql_query"]
    sql_counter: Counter = Counter()
    for e in sql_events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        q = (data.get("query") or "").strip()[:80]
        if q:
            sql_counter[q] += 1
    top_web_queries = [{"query": k, "count": v} for k, v in sql_counter.most_common(10)]

    # Top honey files accessed
    honey_events = [e for e in events if e.get("event_type") == "honey_file"]
    honey_counter: Counter = Counter()
    for e in honey_events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        path = data.get("path", "")
        if path:
            honey_counter[path] += 1
    top_honey = [{"path": k, "count": v} for k, v in honey_counter.most_common(10)]

    # Top probed paths (404s)
    probe_events = [e for e in events if e.get("event_type") == "path_probe"]
    probe_counter: Counter = Counter()
    for e in probe_events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        path = data.get("path", "")
        if path:
            probe_counter[path] += 1
    top_probes = [{"path": k, "count": v} for k, v in probe_counter.most_common(10)]

    # Bot likelihood (SSH commands with gap_ms < 200)
    bot_cmds  = sum(1 for e in cmd_events if _is_bot(e))
    human_cmds = len(cmd_events) - bot_cmds

    # Recent events for the feed (last 50)
    recent = []
    for e in events[:50]:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        recent.append({
            "timestamp":  e.get("timestamp", "")[:19].replace("T", " "),
            "service":    e.get("service", ""),
            "event_type": e.get("event_type", ""),
            "source_ip":  data.get("source_ip") or data.get("ip", "—"),
            "detail":     _event_detail(e.get("event_type", ""), data),
        })

    # Hourly timeline (last 24 buckets)
    timeline = _build_timeline(events)

    iocs = _scan_iocs(events)
    critical_iocs = sum(1 for i in iocs if i["severity"] == "Critical")
    high_iocs     = sum(1 for i in iocs if i["severity"] == "High")

    return {
        "summary": {
            "total_events":    len(events),
            "total_sessions":  len(sessions),
            "ssh_sessions":    len(ssh_sessions),
            "web_sessions":    len(web_sessions),
            "unique_ips":      len(ip_counter),
            "bot_cmds":        bot_cmds,
            "human_cmds":      human_cmds,
            "critical_iocs":   critical_iocs,
            "high_iocs":       high_iocs,
        },
        "event_types":  [{"type": k, "count": v} for k, v in event_types.most_common()],
        "service_counts": [{"service": k, "count": v} for k, v in service_counts.most_common()],
        "top_creds":       top_creds,
        "top_ips":         top_ips,
        "top_cmds":        top_cmds,
        "top_web_queries": top_web_queries,
        "top_honey":       top_honey,
        "top_probes":      top_probes,
        "recent":          recent,
        "timeline":        timeline,
        "iocs":            iocs,
    }


def _is_bot(event: dict) -> bool:
    data = event.get("data") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return False
    return data.get("is_bot_likely", False)


def _event_detail(event_type: str, data: dict) -> str:
    if event_type in ("auth_attempt", "login_attempt"):
        return f"{data.get('username','')} / {data.get('password','')}"
    if event_type == "command":
        return data.get("command", "")
    if event_type in ("sql_query", "sql_injection"):
        return data.get("query", "") or data.get("username", "") or data.get("input", "")
    if event_type == "file_upload":
        name = data.get("filename", "")
        size = data.get("size", "")
        return f"{name} ({size} bytes)" if size != "" else name
    if event_type in ("path_probe", "page_visit", "honey_file"):
        return data.get("path", "")
    if event_type == "connection":
        ua = data.get("user_agent", "")
        return (ua[:60] + ("…" if len(ua) > 60 else "")) or data.get("path", "")
    if event_type == "scanner_probe":
        ua = data.get("user_agent", "")
        return ua[:60] + ("…" if len(ua) > 60 else "")
    return ""


def _build_timeline(events: list[dict]) -> list[dict]:
    """Count events per hour for the last 24 hours."""
    buckets: Counter = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if len(ts) >= 13:
            hour = ts[:13]  # "2024-01-12T09"
            buckets[hour] += 1
    if not buckets:
        return []
    sorted_hours = sorted(buckets.keys())[-24:]
    return [{"hour": h.replace("T", " ") + ":00", "count": buckets[h]}
            for h in sorted_hours]


# IOC detection

_SSH_IOC_RULES = [
    (["wget ", "curl "],                                    "Critical", "Download Attempt",     "Attempted to download an external file"),
    (["sudo su", "sudo bash", "sudo -s ", "sudo sh"],       "Critical", "Privilege Escalation", "Attempted to escalate privileges to root"),
    (["/etc/shadow"],                                       "Critical", "Shadow File Access",   "Accessed the shadow password file"),
    (["nc ", "netcat ", "ncat ", "bash -i ", "/dev/tcp/"],  "Critical", "Reverse Shell",        "Attempted to establish a reverse shell"),
    (["python -c", "python3 -c", "perl -e", "ruby -e"],    "High",     "Code Execution",       "Executed inline code in the shell"),
    (["chmod +x", "bash ./", "sh ./"],                     "High",     "Script Execution",     "Attempted to execute a local script"),
    (["crontab", "/etc/cron"],                             "High",     "Persistence",          "Attempted to establish persistence via cron"),
    (["find / -perm", "find / -user root"],                "High",     "SUID Hunting",         "Searched for SUID privilege escalation vectors"),
    (["/etc/passwd"],                                      "Medium",   "User Enumeration",     "Read the system user account list"),
    (["uname", "/etc/os-release"],                         "Low",      "OS Fingerprinting",    "Gathered OS and kernel version information"),
]

_WEB_SQL_IOC_RULES = [
    (["into outfile", "into dumpfile"],        "Critical", "SQL File Write",      "Attempted to write files via SQL INTO OUTFILE"),
    (["load_file("],                           "High",     "SQL File Read",       "Attempted to read files via SQL LOAD_FILE"),
    (["union select", "union all select"],     "High",     "SQL Data Extraction", "Used UNION SELECT to extract database contents"),
    (["information_schema"],                   "Medium",   "Schema Enumeration",  "Enumerated the database schema structure"),
]

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _scan_iocs(events: list[dict]) -> list[dict]:
    iocs = []

    for e in events:
        data = e.get("data") or {}
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}

        event_type = e.get("event_type", "")
        service    = e.get("service", "ssh")
        ts         = e.get("timestamp", "")[:19].replace("T", " ")
        source_ip  = data.get("source_ip") or data.get("ip", "—")

        def _add(severity, ioc_type, desc, detail=""):
            iocs.append({
                "severity":    severity,
                "type":        ioc_type,
                "description": desc,
                "timestamp":   ts,
                "source_ip":   source_ip,
                "service":     service,
                "detail":      str(detail)[:100],
            })

        if event_type == "command":
            cmd = data.get("command", "").lower()
            for patterns, sev, ioc_type, desc in _SSH_IOC_RULES:
                if any(p.lower() in cmd for p in patterns):
                    _add(sev, ioc_type, desc, data.get("command", ""))
                    break

        elif event_type == "sql_query":
            query = data.get("query", "").lower()
            for patterns, sev, ioc_type, desc in _WEB_SQL_IOC_RULES:
                if any(p in query for p in patterns):
                    _add(sev, ioc_type, desc, data.get("query", "")[:80])
                    break

        elif event_type == "sql_injection":
            detail = data.get("username", "") or data.get("input", "")
            _add("High", "SQL Injection", "SQL injection payload detected in login form", detail)

        elif event_type == "directory_traversal":
            _add("High", "Directory Traversal", "Directory traversal attempt on web honeypot", data.get("input", ""))

        elif event_type == "scanner_probe":
            ua = data.get("user_agent", "")
            _add("Medium", "Automated Scanner", "Known attack scanner or automated tool detected", ua[:80])

    iocs.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 99))
    return iocs[:50]


# Routes

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


# Dashboard HTML — single-page, polls /api/stats every 15 s

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HoneyShell Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body   { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; }
    header { background: #1a1d27; border-bottom: 1px solid #2a2d3a;
             padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }
    header h1  { font-size: 18px; letter-spacing: 1px; color: #fff; }
    header span { font-size: 12px; color: #888; }
    .badge-live { display:inline-block; width:8px; height:8px; border-radius:50%;
                  background:#22c55e; margin-right:6px; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

    .page { padding: 20px 24px; }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 14px; margin-bottom: 22px; }
    .card  { background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 8px; padding: 16px; }
    .card .val  { font-size: 32px; font-weight: 700; color: #fff; }
    .card .label{ font-size: 11px; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }
    .card.red   .val { color: #f87171; }
    .card.green .val { color: #4ade80; }
    .card.blue  .val { color: #60a5fa; }
    .card.yellow.val { color: #facc15; }

    /* Grid layout */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    @media (max-width: 900px) { .grid-2,.grid-3 { grid-template-columns: 1fr; } }

    .panel { background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 8px; padding: 16px; }
    .panel h2 { font-size: 13px; color: #aaa; text-transform: uppercase; letter-spacing: .5px;
                margin-bottom: 14px; border-bottom: 1px solid #2a2d3a; padding-bottom: 8px; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th    { color: #888; font-weight: 600; text-align: left; padding: 6px 8px;
            border-bottom: 1px solid #2a2d3a; font-size: 11px; text-transform: uppercase; }
    td    { padding: 6px 8px; border-bottom: 1px solid #1e2130; color: #ccc; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #1e2130; }

    /* Service badges */
    .badge { display:inline-block; padding:2px 7px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge.ssh { background:#1e3a5f; color:#60a5fa; }
    .badge.web { background:#3a1e1e; color:#f87171; }

    /* Event type colours */
    .et-auth_attempt    { color:#60a5fa; }
    .et-login_attempt   { color:#f87171; }
    .et-command         { color:#4ade80; }
    .et-sql_query       { color:#fb923c; }
    .et-sql_injection   { color:#fb923c; }
    .et-file_upload     { color:#c084fc; }
    .et-directory_traversal { color:#c084fc; }
    .et-path_probe      { color:#facc15; }
    .et-honey_file      { color:#facc15; }
    .et-scanner_probe   { color:#f472b6; }
    .et-connection      { color:#94a3b8; }
    .et-session_end     { color:#94a3b8; }
    .et-page_visit      { color:#94a3b8; }

    .empty { color:#555; font-style:italic; text-align:center; padding:20px 0; }
    canvas { max-height: 220px; }

    /* IOC severity badges */
    .sev { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; letter-spacing:.3px; }
    .sev-Critical { background:#4a1212; color:#f87171; }
    .sev-High     { background:#4a2a0a; color:#fb923c; }
    .sev-Medium   { background:#3a3000; color:#facc15; }
    .sev-Low      { background:#0a2040; color:#60a5fa; }
  </style>
</head>
<body>
<header>
  <h1><span class="badge-live"></span>HoneyShell &mdash; Attack Dashboard</h1>
  <span id="last-updated">Loading…</span>
</header>

<div class="page">

  <!-- Summary cards -->
  <div class="cards" id="cards">
    <div class="card"><div class="val" id="c-events">—</div><div class="label">Total Events</div></div>
    <div class="card"><div class="val" id="c-sessions">—</div><div class="label">Sessions</div></div>
    <div class="card blue"><div class="val" id="c-ssh">—</div><div class="label">SSH Sessions</div></div>
    <div class="card red"><div class="val" id="c-web">—</div><div class="label">Web Sessions</div></div>
    <div class="card"><div class="val" id="c-ips">—</div><div class="label">Unique IPs</div></div>
    <div class="card green"><div class="val" id="c-human">—</div><div class="label">Human Cmds</div></div>
    <div class="card red"><div class="val" id="c-bot">—</div><div class="label">Bot Cmds</div></div>
    <div class="card red"><div class="val" id="c-critical-iocs">—</div><div class="label">Critical IOCs</div></div>
    <div class="card" style="border-color:#fb923c44"><div class="val" style="color:#fb923c" id="c-high-iocs">—</div><div class="label">High IOCs</div></div>
  </div>

  <!-- Timeline -->
  <div class="panel" style="margin-bottom:16px">
    <h2>Event Timeline (hourly)</h2>
    <canvas id="chart-timeline"></canvas>
  </div>

  <!-- Charts row -->
  <div class="grid-2" style="margin-bottom:16px">
    <div class="panel">
      <h2>Event Types</h2>
      <canvas id="chart-types"></canvas>
    </div>
    <div class="panel">
      <h2>Service Breakdown</h2>
      <canvas id="chart-services"></canvas>
    </div>
  </div>

  <!-- Tables row -->
  <div class="grid-3">
    <div class="panel">
      <h2>Top Credentials Tried</h2>
      <table>
        <thead><tr><th>Username / Password</th><th>#</th></tr></thead>
        <tbody id="tbl-creds"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Top Source IPs</h2>
      <table>
        <thead><tr><th>IP</th><th>#</th></tr></thead>
        <tbody id="tbl-ips"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Top SSH Commands</h2>
      <table>
        <thead><tr><th>Command</th><th>#</th></tr></thead>
        <tbody id="tbl-cmds"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Web honeypot tables row -->
  <div class="grid-3" style="margin-top:0">
    <div class="panel">
      <h2>Top Web SQL Queries</h2>
      <table>
        <thead><tr><th>Query</th><th>#</th></tr></thead>
        <tbody id="tbl-queries"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Top Honey Files Hit</h2>
      <table>
        <thead><tr><th>Path</th><th>#</th></tr></thead>
        <tbody id="tbl-honey"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Top Probed Paths</h2>
      <table>
        <thead><tr><th>Path</th><th>#</th></tr></thead>
        <tbody id="tbl-probes"><tr><td colspan="2" class="empty">No data yet</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- IOC Panel -->
  <div class="panel" style="margin-top:16px; border-color:#3a1a1a">
    <h2 style="color:#f87171">Indicators of Compromise (IOC)</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Type</th><th>Description</th>
          <th>Source IP</th><th>Service</th><th>Time</th><th>Detail</th>
        </tr>
      </thead>
      <tbody id="tbl-iocs"><tr><td colspan="7" class="empty">No IOCs detected</td></tr></tbody>
    </table>
  </div>

  <!-- Recent events feed -->
  <div class="panel" style="margin-top:16px">
    <h2>Recent Events</h2>
    <table>
      <thead><tr><th>Time</th><th>Service</th><th>Event</th><th>Source IP</th><th>Detail</th></tr></thead>
      <tbody id="tbl-recent"><tr><td colspan="5" class="empty">No events yet</td></tr></tbody>
    </table>
  </div>

</div><!-- /page -->

<script>
const COLORS = [
  '#60a5fa','#f87171','#4ade80','#fb923c','#c084fc',
  '#facc15','#f472b6','#34d399','#a78bfa','#94a3b8'
];

let timelineChart = null;
let typesChart    = null;
let servicesChart = null;

function mkChart(id, type, labels, data, colors) {
  const ctx = document.getElementById(id).getContext('2d');
  return new Chart(ctx, {
    type,
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors || COLORS,
        borderColor: type === 'bar' ? COLORS[0] : undefined,
        borderWidth: type === 'bar' ? 1 : 0,
        fill: false,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: type !== 'bar', labels: { color: '#ccc', boxWidth: 12 } } },
      scales: type === 'bar' ? {
        x: { ticks: { color:'#888', font:{size:10} }, grid:{color:'#2a2d3a'} },
        y: { ticks: { color:'#888' }, grid:{color:'#2a2d3a'}, beginAtZero: true }
      } : {}
    }
  });
}

function updateChart(chart, labels, data) {
  chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  chart.update('none');
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function buildRows(tbodyId, rows) {
  const tb = document.getElementById(tbodyId);
  if (!tb) return;
  if (!rows || !rows.length) {
    tb.innerHTML = '<tr><td colspan="10" class="empty">No data yet</td></tr>';
    return;
  }
  tb.innerHTML = rows.join('');
}

async function refresh() {
  let stats;
  try {
    const r = await fetch('/api/stats');
    stats = await r.json();
  } catch(e) { return; }

  const s = stats.summary;
  setText('c-events',  s.total_events);
  setText('c-sessions', s.total_sessions);
  setText('c-ssh',     s.ssh_sessions);
  setText('c-web',     s.web_sessions);
  setText('c-ips',     s.unique_ips);
  setText('c-human',        s.human_cmds);
  setText('c-bot',          s.bot_cmds);
  setText('c-critical-iocs', s.critical_iocs);
  setText('c-high-iocs',     s.high_iocs);
  setText('last-updated', 'Updated ' + new Date().toLocaleTimeString());

  // Timeline
  const tl = stats.timeline || [];
  const tlLabels = tl.map(r => r.hour.slice(11,16)); // HH:MM
  const tlData   = tl.map(r => r.count);
  if (!timelineChart) {
    timelineChart = mkChart('chart-timeline', 'bar', tlLabels, tlData);
    timelineChart.data.datasets[0].backgroundColor = '#60a5fa44';
    timelineChart.data.datasets[0].borderColor = '#60a5fa';
    timelineChart.update();
  } else {
    updateChart(timelineChart, tlLabels, tlData);
  }

  // Event types doughnut
  const et = stats.event_types || [];
  if (!typesChart) {
    typesChart = mkChart('chart-types', 'doughnut', et.map(r=>r.type), et.map(r=>r.count));
  } else {
    updateChart(typesChart, et.map(r=>r.type), et.map(r=>r.count));
  }

  // Services doughnut
  const sv = stats.service_counts || [];
  if (!servicesChart) {
    servicesChart = mkChart('chart-services', 'doughnut', sv.map(r=>r.service), sv.map(r=>r.count), ['#60a5fa','#f87171','#4ade80']);
  } else {
    updateChart(servicesChart, sv.map(r=>r.service), sv.map(r=>r.count));
  }

  // Top credentials table
  buildRows('tbl-creds', (stats.top_creds||[]).map(r =>
    `<tr><td style="font-family:monospace">${esc(r.cred)}</td><td>${r.count}</td></tr>`
  ));

  // Top IPs table
  buildRows('tbl-ips', (stats.top_ips||[]).map(r =>
    `<tr><td style="font-family:monospace">${esc(r.ip)}</td><td>${r.count}</td></tr>`
  ));

  // Top commands table
  buildRows('tbl-cmds', (stats.top_cmds||[]).map(r =>
    `<tr><td style="font-family:monospace">${esc(r.cmd)}</td><td>${r.count}</td></tr>`
  ));

  // Top web SQL queries table
  buildRows('tbl-queries', (stats.top_web_queries||[]).map(r =>
    `<tr><td style="font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.query)}</td><td>${r.count}</td></tr>`
  ));

  // Top honey files table
  buildRows('tbl-honey', (stats.top_honey||[]).map(r =>
    `<tr><td style="font-family:monospace">${esc(r.path)}</td><td>${r.count}</td></tr>`
  ));

  // Top probed paths table
  buildRows('tbl-probes', (stats.top_probes||[]).map(r =>
    `<tr><td style="font-family:monospace">${esc(r.path)}</td><td>${r.count}</td></tr>`
  ));

  // IOC table
  buildRows('tbl-iocs', (stats.iocs||[]).map(r => {
    const svc = r.service === 'ssh'
      ? '<span class="badge ssh">SSH</span>'
      : '<span class="badge web">WEB</span>';
    return `<tr>
      <td><span class="sev sev-${esc(r.severity)}">${esc(r.severity)}</span></td>
      <td style="font-weight:600;color:#e0e0e0">${esc(r.type)}</td>
      <td style="color:#aaa">${esc(r.description)}</td>
      <td style="font-family:monospace;font-size:12px">${esc(r.source_ip)}</td>
      <td>${svc}</td>
      <td style="white-space:nowrap;font-size:11px;color:#666">${esc(r.timestamp)}</td>
      <td style="font-family:monospace;font-size:11px;color:#888;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.detail)}</td>
    </tr>`;
  }));

  // Recent events feed
  buildRows('tbl-recent', (stats.recent||[]).map(r => {
    const svc = r.service === 'ssh'
      ? '<span class="badge ssh">SSH</span>'
      : '<span class="badge web">WEB</span>';
    const et = `<span class="et-${r.event_type}">${esc(r.event_type)}</span>`;
    return `<tr>
      <td style="white-space:nowrap;font-size:11px;color:#666">${esc(r.timestamp)}</td>
      <td>${svc}</td>
      <td>${et}</td>
      <td style="font-family:monospace;font-size:12px">${esc(r.source_ip)}</td>
      <td style="font-family:monospace;font-size:12px;color:#aaa;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.detail)}</td>
    </tr>`;
  }));
}

function esc(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [DASH] %(levelname)s %(message)s")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.info("HoneyShell Dashboard starting on port 3000")
    app.run(host="0.0.0.0", port=3000, debug=False, use_reloader=False, threaded=True)
