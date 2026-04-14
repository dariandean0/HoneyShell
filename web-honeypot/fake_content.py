"""
fake_content.py
Templates + canned responses that make the honeypot look like a real
phpMyAdmin instance sitting on an Ubuntu LAMP box. Attackers brute-force
phpMyAdmin constantly, so this is a high-signal facade.
"""

HOSTNAME  = "web-prod-03"
PMA_VERSION = "5.1.1deb5ubuntu1"
MYSQL_VERSION = "8.0.35-0ubuntu0.20.04.1"

# phpMyAdmin login page. Matches the real layout closely (logo block, server
# choice, language dropdown, version footer) so scanners fingerprint it as real.
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>phpMyAdmin</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css">
<link rel="icon" href="/favicon.ico">
<meta name="robots" content="noindex,nofollow">
</head>
<body class="loginform">
<div class="container">
  <a href="https://www.phpmyadmin.net/" target="_blank" class="logo">
    <img src="/themes/pmahomme/img/logo_right.png" alt="phpMyAdmin" border="0">
  </a>
  <h1>Welcome to <bdo dir="ltr">phpMyAdmin</bdo></h1>
  {error}
  <form method="POST" action="/index.php" name="login_form" class="login hide js-show">
    <fieldset>
      <legend>Log in <a href="https://docs.phpmyadmin.net/" target="_blank">(?)</a></legend>
      <div class="item">
        <label for="input_username">Username:</label>
        <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" autocomplete="username">
      </div>
      <div class="item">
        <label for="input_password">Password:</label>
        <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" autocomplete="current-password">
      </div>
      <div class="item">
        <label for="select_server">Server Choice:</label>
        <select name="server" id="select_server">
          <option value="1" selected>localhost</option>
        </select>
      </div>
    </fieldset>
    <fieldset class="tblFooters">
      <input type="hidden" name="set_session" value="">
      <input type="hidden" name="token" value="{token}">
      <input value="Go" type="submit" id="input_go">
    </fieldset>
  </form>
</div>
<div class="footer">
  <div>phpMyAdmin {pma_version}</div>
</div>
</body>
</html>
"""

# Main post-login landing. Fake "Server: localhost" page with tabs: Databases /
# SQL / Status / User accounts / Export / Import / Settings / Variables.
MAIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>localhost | phpMyAdmin {pma_version}</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css">
</head>
<body>
<div id="page_nav_icons">
  <span>Server: <b>localhost:3306</b></span>
  <span>User: <b>{user}@localhost</b></span>
  <a href="/index.php?route=/logout">Log out</a>
</div>
<ul id="topmenu">
  <li><a href="/index.php?route=/">Databases</a></li>
  <li><a href="/index.php?route=/sql">SQL</a></li>
  <li><a href="/index.php?route=/server/status">Status</a></li>
  <li><a href="/index.php?route=/server/user-accounts">User accounts</a></li>
  <li><a href="/index.php?route=/server/export">Export</a></li>
  <li><a href="/index.php?route=/server/import">Import</a></li>
  <li><a href="/index.php?route=/server/variables">Variables</a></li>
</ul>
<div id="page_content">
<h2>Server: <i>localhost:3306</i> via TCP/IP</h2>
<div class="col-6">
  <h3>General settings</h3>
  <ul>
    <li>Server charset: utf8mb4_unicode_ci</li>
    <li>Server version: {mysql_version}</li>
    <li>Protocol version: 10</li>
    <li>User: <b>{user}@localhost</b></li>
  </ul>
</div>
<div class="col-6">
  <h3>Database server</h3>
  <ul>
    <li>Server: localhost via TCP/IP</li>
    <li>Server type: MySQL</li>
    <li>Server connection: SSL is not being used</li>
    <li>phpMyAdmin: {pma_version}</li>
  </ul>
</div>
<h3>Databases</h3>
<table class="data">
<thead><tr><th>Database</th><th>Collation</th><th>Action</th></tr></thead>
<tbody>
  <tr><td><a href="/index.php?route=/database/structure&db=information_schema">information_schema</a></td><td>utf8_general_ci</td><td>—</td></tr>
  <tr><td><a href="/index.php?route=/database/structure&db=acme_portal">acme_portal</a></td><td>utf8mb4_unicode_ci</td><td><a href="/index.php?route=/sql&db=acme_portal">Query</a></td></tr>
  <tr><td><a href="/index.php?route=/database/structure&db=acme_billing">acme_billing</a></td><td>utf8mb4_unicode_ci</td><td><a href="/index.php?route=/sql&db=acme_billing">Query</a></td></tr>
  <tr><td><a href="/index.php?route=/database/structure&db=mysql">mysql</a></td><td>utf8mb4_0900_ai_ci</td><td>—</td></tr>
  <tr><td><a href="/index.php?route=/database/structure&db=performance_schema">performance_schema</a></td><td>utf8_general_ci</td><td>—</td></tr>
  <tr><td><a href="/index.php?route=/database/structure&db=sys">sys</a></td><td>utf8mb4_0900_ai_ci</td><td>—</td></tr>
</tbody>
</table>
</div>
</body>
</html>
"""

# SQL query tab. Mimics phpMyAdmin's textarea + Go button. Whatever attackers
# paste here (webshell, INTO OUTFILE, LOAD_FILE, UNION SELECT) we log verbatim.
SQL_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Run SQL query — phpMyAdmin</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body>
<div id="page_nav_icons"><a href="/index.php?route=/">&laquo; Server</a> · <a href="/index.php?route=/logout">Log out</a></div>
<h2>Run SQL query/queries on server <i>localhost</i></h2>
<form method="POST" action="/index.php?route=/sql">
  <textarea name="sql_query" rows="10" cols="80">{query}</textarea><br>
  <label><input type="checkbox" name="show_query" value="1" checked> Show this query here again</label><br>
  <input type="hidden" name="token" value="{token}">
  <button type="submit">Go</button>
</form>
<div class="result">{result}</div>
</body></html>
"""

# Import tab with file upload. phpMyAdmin accepts .sql / .gz / .zip.
IMPORT_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Import — phpMyAdmin</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body>
<div id="page_nav_icons"><a href="/index.php?route=/">&laquo; Server</a></div>
<h2>Importing into the server</h2>
{msg}
<form method="POST" action="/index.php?route=/server/import" enctype="multipart/form-data">
  <fieldset>
    <legend>File to import:</legend>
    <input type="file" name="import_file">
    <p>Character set of the file: <select name="charset"><option>utf-8</option></select></p>
    <p>Format: <select name="format"><option>SQL</option><option>CSV</option></select></p>
  </fieldset>
  <input type="hidden" name="token" value="{token}">
  <button type="submit">Go</button>
</form>
</body></html>
"""

STATUS_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Server status</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body>
<h2>Runtime Information</h2>
<table class="data">
<tr><th>Start</th><td>Jan 10, 2024 at 06:32 PM</td></tr>
<tr><th>Uptime</th><td>1 day, 14 hours, 42 minutes, 17 seconds</td></tr>
<tr><th>Traffic</th><td>148.2 MiB</td></tr>
<tr><th>Connections</th><td>4,812 (ø 2.1/s)</td></tr>
<tr><th>Failed attempts</th><td>0</td></tr>
<tr><th>Aborted</th><td>3</td></tr>
</table>
</body></html>
"""

VARIABLES_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Server variables</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body>
<h2>Server variables and settings</h2>
<table class="data">
<tr><th>datadir</th><td>/var/lib/mysql/</td></tr>
<tr><th>basedir</th><td>/usr/</td></tr>
<tr><th>tmpdir</th><td>/tmp</td></tr>
<tr><th>secure_file_priv</th><td>/var/lib/mysql-files/</td></tr>
<tr><th>log_bin</th><td>ON</td></tr>
<tr><th>general_log_file</th><td>/var/log/mysql/mysql.log</td></tr>
<tr><th>socket</th><td>/var/run/mysqld/mysqld.sock</td></tr>
<tr><th>bind_address</th><td>127.0.0.1</td></tr>
<tr><th>version</th><td>{mysql_version}</td></tr>
<tr><th>version_compile_os</th><td>Linux</td></tr>
</table>
</body></html>
"""

USERS_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>User accounts</title>
<link rel="stylesheet" href="/themes/pmahomme/css/theme.css"></head>
<body>
<h2>User accounts overview</h2>
<table class="data">
<thead><tr><th>User</th><th>Host</th><th>Password</th><th>Global privileges</th></tr></thead>
<tbody>
<tr><td>root</td><td>localhost</td><td>Yes</td><td>ALL PRIVILEGES</td></tr>
<tr><td>acme_app</td><td>localhost</td><td>Yes</td><td>SELECT, INSERT, UPDATE, DELETE</td></tr>
<tr><td>acme_readonly</td><td>%</td><td>Yes</td><td>SELECT</td></tr>
<tr><td>svc_backup</td><td>127.0.0.1</td><td>Yes</td><td>SELECT, LOCK TABLES, SHOW VIEW</td></tr>
<tr><td>debian-sys-maint</td><td>localhost</td><td>Yes</td><td>ALL PRIVILEGES</td></tr>
</tbody></table>
</body></html>
"""

# Minimal CSS so the pages render readably without shipping real phpMyAdmin assets.
THEME_CSS = """
body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#f5f5f5;color:#222;margin:0}
.container{max-width:520px;margin:4em auto;padding:2em;background:#fff;border:1px solid #d0d0d0;border-radius:4px}
.loginform h1{font-size:1.4em;margin:0 0 1em}
.loginform fieldset{border:1px solid #ccc;padding:1em;margin:0 0 1em}
.loginform .item{margin:0.5em 0}
.loginform label{display:inline-block;width:8em}
.loginform input.textfield, .loginform select{padding:0.3em;width:14em}
.loginform input[type=submit]{padding:0.4em 1.2em;background:#235a81;color:#fff;border:0;border-radius:3px;cursor:pointer}
.footer{text-align:center;color:#666;font-size:0.9em;margin-top:2em}
.error{background:#ffe0e0;border:1px solid #c00;color:#800;padding:0.6em;margin:0 0 1em}
#page_nav_icons{background:#235a81;color:#fff;padding:0.5em 1em;display:flex;justify-content:space-between}
#page_nav_icons a{color:#cfe;margin-left:1em}
#topmenu{background:#eaeaea;padding:0;margin:0;list-style:none;display:flex;border-bottom:1px solid #bbb}
#topmenu li{padding:0.6em 1em;border-right:1px solid #ccc}
#topmenu a{text-decoration:none;color:#235a81}
#page_content{padding:1em 2em}
table.data{border-collapse:collapse;width:100%;background:#fff;margin:0.5em 0}
table.data th, table.data td{border:1px solid #ccc;padding:0.4em 0.7em;text-align:left}
table.data th{background:#dfe8ef}
.col-6{display:inline-block;vertical-align:top;width:48%;margin-right:1%}
textarea{font-family:monospace;width:100%;box-sizing:border-box}
.result{margin-top:1em;padding:0.8em;background:#f0f0f0;border:1px solid #ccc;white-space:pre-wrap;font-family:monospace}
"""

ROBOTS_TXT = "User-agent: *\nDisallow: /\n"

# README.md that lives at phpMyAdmin's repo root — scanners grep it for version.
README_TXT = f"""phpMyAdmin - Readme
=====================
Version {PMA_VERSION}
A web interface for MySQL and MariaDB.
"""

CHANGELOG = f"""phpMyAdmin - ChangeLog
====================
{PMA_VERSION} (2024-01-08)
  - bugfix #17234 Fix session handling on login
  - bugfix #17188 Export: correct column ordering
"""

# Honey-file responses for paths scanners commonly hit against phpMyAdmin/LAMP.
HONEY_FILES = {
    "/robots.txt":          ("text/plain", ROBOTS_TXT),
    "/README":              ("text/plain", README_TXT),
    "/ChangeLog":           ("text/plain", CHANGELOG),
    "/CHANGELOG":           ("text/plain", CHANGELOG),
    "/LICENSE":             ("text/plain", "GNU GENERAL PUBLIC LICENSE Version 2\n"),
    "/config.inc.php":      ("text/plain", ""),  # real pma returns empty
    "/config.inc.php.bak":  ("text/plain",
        "<?php\n"
        "$cfg['Servers'][$i]['host']     = 'localhost';\n"
        "$cfg['Servers'][$i]['user']     = 'root';\n"
        "$cfg['Servers'][$i]['password'] = 'R00t-MySQL-2022!';\n"
        "$cfg['Servers'][$i]['auth_type']= 'config';\n"
        "$cfg['blowfish_secret'] = 'a8b2c4e6f8g0h2j4k6m8n0p2q4r6s8t0';\n"
    ),
    "/.env": ("text/plain",
        "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASS=R00t-MySQL-2022!\n"
        "PMA_CONTROLUSER=pma\nPMA_CONTROLPASS=controlpass-dev\n"
    ),
    "/phpinfo.php": ("text/html",
        "<h1>PHP Version 7.4.3-4ubuntu2.19</h1>"
        "<p>System: Linux web-prod-03 5.15.0-1034-aws x86_64</p>"
        "<p>DOCUMENT_ROOT: /var/www/html</p>"
        "<p>mysqli, pdo_mysql, mbstring, curl, openssl</p>"
    ),
    "/server-status": ("text/plain",
        "Apache Server Status for web-prod-03\n"
        "Server Version: Apache/2.4.41 (Ubuntu)\n"
        "Current Time: Fri, 12 Jan 2024 09:14:32 GMT\n"
    ),
    # Historic phpMyAdmin setup endpoints scanners always probe (CVE territory).
    "/setup/index.php":    ("text/html", "<h1>phpMyAdmin setup</h1><p>Create new server</p>"),
    "/scripts/setup.php":  ("text/html", "<h1>phpMyAdmin setup</h1>"),
}


def fake_sql_result(query: str) -> str:
    """
    Return a plausible-looking result for whatever SQL was submitted.
    Never actually executes anything — we just pattern-match on keywords
    so attackers see output consistent with a real MySQL server.
    """
    q = query.strip().lower()
    if not q:
        return ""
    if q.startswith("select") and "information_schema" in q:
        return (
            "+--------------------+\n| TABLE_NAME         |\n+--------------------+\n"
            "| users              |\n| sessions           |\n| invoices           |\n"
            "| payments           |\n| audit_log          |\n+--------------------+\n"
            "5 rows in set (0.00 sec)"
        )
    if q.startswith("select") and "user()" in q:
        return "+----------------+\n| user()         |\n+----------------+\n| root@localhost |\n+----------------+"
    if q.startswith("select") and "version()" in q:
        return f"+-----------+\n| version() |\n+-----------+\n| {MYSQL_VERSION} |\n+-----------+"
    if q.startswith("show databases"):
        return (
            "+--------------------+\n| Database           |\n+--------------------+\n"
            "| information_schema |\n| acme_billing       |\n| acme_portal        |\n"
            "| mysql              |\n| performance_schema |\n| sys                |\n+--------------------+"
        )
    if q.startswith("show tables"):
        return (
            "+----------------------+\n| Tables_in_acme_portal|\n+----------------------+\n"
            "| users                |\n| sessions             |\n| invoices             |\n+----------------------+"
        )
    if q.startswith("select") and "users" in q:
        return (
            "+----+----------+--------------------+-------+\n"
            "| id | username | email              | role  |\n"
            "+----+----------+--------------------+-------+\n"
            "|  1 | admin    | admin@acme.local   | admin |\n"
            "|  2 | jdoe     | jdoe@acme.local    | user  |\n"
            "|  3 | svc_bkp  | ops@acme.local     | svc   |\n"
            "+----+----------+--------------------+-------+\n"
            "3 rows in set (0.00 sec)"
        )
    if "into outfile" in q or "into dumpfile" in q:
        return "ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement"
    if "load_file" in q:
        return "+--------------------+\n| load_file(...)     |\n+--------------------+\n| NULL               |\n+--------------------+"
    if q.startswith(("insert", "update", "delete", "drop", "create", "alter", "grant")):
        return "Query OK, 0 rows affected (0.01 sec)"
    return "Empty set (0.00 sec)"
