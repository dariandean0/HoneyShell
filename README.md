# HoneyShell

> This system runs entirely on localhost inside Docker and never binds to any external network interface. It is designed for studying attacker behavior patterns in a safe, controlled environment.

---

## What is this?

HoneyShell is a localhost-only honeypot system built for educational purposes. It emulates two common attack targets, an SSH server and a web application login portal, and logs all interaction for analysis. No real services are exposed. No real data is at risk. All traffic is simulated by the team running controlled test scripts.

The system has three components:

- **SSH Honeypot**  a fake SSH server (port 2222) that accepts all login attempts, presents a simulated shell, and logs every credential and command
- **Web Honeypot**  a fake phpMyAdmin login portal (port 8080) that logs credential stuffing, SQL injection probes, scanner fingerprints, and honey-file scans (`/.env`, `/config.inc.php.bak`, `/phpinfo.php`, `/setup/`)
- **Dashboard**  a local web UI (port 3000) that visualizes captured sessions, credential frequency, attack timelines, and behavioral patterns

---

## Prerequisites

Make sure the following are installed before building:

| Tool | Minimum version | Check |
|------|----------------|-------|
| Docker | 20.x | `docker --version` |
| Docker Compose | v2 | `docker compose version` |
| Git | any | `git --version` |

---

## Build and Run

### 1. Clone the repository

```bash
git clone https://github.com/dariandean0/HoneyShell.git
cd honeyshell
```

### 2. Build all containers

```bash
docker compose build
```

### 3. Start the system

```bash
docker compose up
```

All three services will start. You should see output from each container in your terminal.

## Stopping and Resetting

```bash
# Stop all containers (keeps log data)
docker compose down

# Stop and wipe all log data (full reset)
docker compose down -v
```

## Testing SSH Honeypot Service

```bash
docker compose build
docker compose up --build ssh-honeypot

# In another terminal
ssh -p 2222 -o StrictHostKeyChecking=no root@127.0.0.1

# enter anything for the password, it will accept anything
```

## Testing Web Honeypot Service

```bash
docker compose build
docker compose up --build web-honeypot

# Open in a browser
http://127.0.0.1:8080/

# Or from another terminal — any credentials are accepted
curl -c cookies.txt -d 'pma_username=root&pma_password=anything' \
     http://127.0.0.1:8080/index.php

# Post-auth SQL query box (logged verbatim)
curl -b cookies.txt --data-urlencode "sql_query=SELECT * FROM users" \
     'http://127.0.0.1:8080/index.php?route=/sql'

# Honey files scanners commonly probe
curl http://127.0.0.1:8080/.env
curl http://127.0.0.1:8080/config.inc.php.bak
curl http://127.0.0.1:8080/phpinfo.php
```

---

## Services at a Glance

| Service | Local URL | What it does |
|---------|-----------|-------------|
| SSH honeypot | `localhost:2222` | Fake SSH server, logs creds + shell commands |
| Web honeypot | `localhost:8080` | Fake login portal, logs HTTP attack patterns |
| Dashboard | `localhost:3000` | Visualizes all captured session data |

---
