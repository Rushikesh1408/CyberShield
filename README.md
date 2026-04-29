# CyberShield — Ransomware Defense System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![React](https://img.shields.io/badge/react-18%2B-61dafb)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)

CyberShield is a production-grade ransomware defense platform. It autonomously monitors protected system directories, detects ransomware-like behavior in real time using behavioral fingerprinting and entropy analysis, neutralizes suspicious processes, and restores files from versioned snapshots — all surfaced through a live React dashboard.

> **Built for:** Security hackathons, local enterprise demos, and production-ready distributed deployments.

---

## Core Engines

| Engine | Description |
|--------|-------------|
| 🔍 **Early Threat Detection** | File system event monitoring with entropy scoring and behavioral heuristics |
| 🧬 **DNA Fingerprinting** | Structural attack signature generation and cross-run correlation |
| 🛡️ **Active Threat Neutralization** | Safe process intervention, network isolation, and honeypot traps |
| 📸 **Versioned Snapshot System** | Chunked SHA-256 file hashing with timestamped, thread-safe snapshots |
| ♻️ **Automatic System Recovery** | Guaranteed directory unlock via `try/finally`; full file restoration |
| 🌐 **Distributed Sync** | Peer-to-peer event broadcasting via ThreadPoolExecutor with dead-letter queue |
| 📊 **Forensic Reporting** | Wallet tracking, process trees, attack timelines, and incident evidence bundles |

---

## What's Included

- **Flask + SocketIO backend** — real-time detection pipeline, process killing, backup, recovery, and fingerprint storage
- **React + Vite dashboard** — Tailwind UI, live activity graph (Recharts), alerts, logs, and intervention controls
- **SQLite / PostgreSQL** — logs, alerts, metrics, fingerprint history; WAL journal mode for concurrent access
- **Emergency email alerting** — one alert per attack cycle via SMTP (Gmail App Password supported)
- **Distributed cluster sync** — broadcast attack events to peer nodes with exponential backoff retry and API key auth
- **Docker + Nginx** — single public URL proxying `/api/*` to the backend container
- **Security hardened** — `secrets.compare_digest` auth, path-traversal guards, PII masking in logs, no hardcoded secrets

---

## Project Structure

```text
CyberShield/
├── backend/
│   ├── _flask_api.py          # Main Flask + SocketIO app (routes, auth, SMTP, simulation)
│   ├── app.py                 # Application entry point
│   ├── main.py                # Alternate standalone runner
│   ├── database.py            # SQLite/Postgres ORM layer
│   ├── backup.py              # Backup service
│   ├── detection.py           # Legacy detection engine
│   ├── fingerprint.py         # Fingerprint manager
│   ├── distributed_sync.py    # Cluster peer sync with dead-letter queue
│   ├── email_alert.py         # SMTP alerting (no hardcoded credentials)
│   ├── logger.py              # JSON-capable rotating file logger + DB handler
│   ├── seed_db.py             # Database seeder (hashed API keys)
│   ├── config.py              # AppConfig from environment
│   ├── core/
│   │   ├── pipeline.py        # Central detection + assessment pipeline
│   │   ├── monitor.py         # Watchdog file system monitor (thread-safe)
│   │   ├── detector.py        # Rule engine (entropy, rename log, extension checks)
│   │   ├── dna.py             # DNA signature generation + similarity scoring
│   │   ├── snapshot.py        # Chunked SHA-256 snapshots (timezone-aware)
│   │   ├── recovery.py        # File recovery with guaranteed directory unlock
│   │   ├── process_manager.py # Safe process termination (SYSTEM-guarded)
│   │   ├── sync.py            # Core peer sync (ThreadPoolExecutor)
│   │   ├── scoring.py         # Threat confidence scoring
│   │   ├── entropy.py         # File entropy calculation
│   │   ├── baseline.py        # System baseline profiling
│   │   ├── explainer.py       # Detection explanation + input sanitization
│   │   └── network_isolation.py # Network isolation helpers
│   ├── modules/
│   │   ├── correlation_engine.py  # Cross-signature correlation (OverflowError-safe)
│   │   ├── honeypot.py            # Honeypot file trap
│   │   ├── wallet_tracker.py      # Ransom note Bitcoin/Monero wallet extraction
│   │   ├── persistence_detector.py # Registry/startup persistence detection
│   │   ├── report_generator.py    # Evidence bundle generator (path-traversal safe)
│   │   ├── timeline_engine.py     # Attack timeline reconstruction
│   │   ├── signature_engine.py    # Attack signature management
│   │   ├── network_tracker.py     # Network connection monitoring
│   │   └── process_tree.py        # Process tree builder
│   ├── db/
│   │   ├── database.py        # SQLAlchemy engine (Postgres/SQLite, fail-fast)
│   │   ├── models.py          # ORM models (Node.api_key_hash — never plaintext)
│   │   └── sqlite_fallback.py # SQLite WAL mode + busy timeout
│   └── services/              # Service layer (Backup, Detection, Forensic, Recovery…)
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   └── DashboardPage.jsx  # Main dashboard (API key auth, live polling)
│   │   ├── components/            # StatusCard, ActivityChart, AlertsPanel, etc.
│   │   └── App.jsx
│   ├── nginx.conf             # Reverse proxy: /api/* → backend
│   └── Dockerfile
├── tests/
│   └── test_recovery.py       # Unit tests for RecoveryEngine (mock-based)
├── docker-compose.yml         # Hardened: healthchecks, no DB port exposure
├── .env.example               # Placeholder-only secrets (safe to commit)
├── requirements.txt           # Pinned dependencies
└── HARDENING_CHECKLIST.md     # Security audit checklist
```

---

## Quick Start (Local Development)

### Prerequisites

- Python 3.10+
- Node.js 18+
- (Optional) Docker + Docker Compose

### 1. Clone and configure environment

```powershell
git clone https://github.com/Rushikesh1408/CyberShield.git
cd CyberShield
Copy-Item .env.example .env
# Edit .env — fill in all CHANGE_ME / REPLACE_WITH placeholders before starting
```

### 2. Backend

```powershell
cd backend
pip install -r ..\requirements.txt
python app.py
```

Backend runs at `http://127.0.0.1:5000` (Flask + SocketIO).

### 3. Frontend

```powershell
cd frontend
npm install
npm run dev
```

Dashboard runs at `http://127.0.0.1:5173`.

### 4. Environment variables (key ones)

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | x-api-key for all authenticated endpoints | **Yes** |
| `JWT_SECRET` | JWT signing secret (256-bit random) | **Yes** |
| `POSTGRES_PASSWORD` | Database password | Yes (Docker) |
| `CYBERSHIELD_SOCKET_API_KEY` | WebSocket connection auth key | Recommended |
| `CYBERSHIELD_MONITOR_PATHS` | Comma-separated directories to watch | No (auto) |
| `OFFLINE_MODE` | Set to `1` to force SQLite even with Postgres env | No |
| `SMTP_SERVER` / `SMTP_PORT` | SMTP server for alert emails | No |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP credentials | No |
| `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | Email sender/recipient | No |
| `SYNC_NODES` | Comma-separated peer node URLs for cluster sync | No |
| `CLUSTER_NODE_PROTOCOL` | `https` or `http` for peer sync (default: `https`) | No |

> ⚠️ **Never commit real secrets.** All values in `.env.example` are explicit placeholders that will not work in production.

---

## Docker Deployment

```powershell
# Copy and fill in secrets
Copy-Item .env.example .env
# Edit .env with real values

# Build and run
docker compose up --build -d

# View logs
docker compose logs -f backend
```

Access:

- **Dashboard:** `http://127.0.0.1:5173`
- **Backend API:** `http://127.0.0.1:5000`

The Nginx frontend proxies all `/api/*` and `/socket.io/*` requests to the backend container — only one public URL is needed.

### Optional: public tunnel (Cloudflare)

```powershell
docker compose --profile tunnel up -d tunnel
docker logs -f cybershield-tunnel
```

### Optional: public tunnel (ngrok)

```powershell
# Set in .env: NGROK_AUTHTOKEN=your_token
docker compose --profile ngrok up -d ngrok
docker logs -f cybershield-ngrok
```

### Stop all services

```powershell
docker compose down
```

---

## API Reference

All state-changing endpoints require the `x-api-key` header matching the `API_KEY` environment variable.

### Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Full system snapshot |
| `GET` | `/api/metrics` | File activity metrics |
| `GET` | `/api/alerts` | Active alert list |
| `GET` | `/api/logs` | Recent event logs |
| `GET` | `/api/fingerprints` | Stored attack fingerprints |
| `GET` | `/api/network` | Network activity snapshot |
| `GET` | `/api/signature` | DNA signature intelligence |
| `GET` | `/api/config` | Runtime monitor configuration |
| `GET` | `/api/ping` | Health check |
| `POST` | `/api/start` | Start file monitoring |
| `POST` | `/api/stop` | Stop file monitoring |

### Backup & Recovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/backup/status` | Backup status |
| `POST` | `/api/backup/run` | Run backup now |
| `POST` | `/api/backup/recover` | Restore file from snapshot (path-traversal safe) |
| `POST` | `/api/backup/restore` | Alias for `/api/backup/recover` |
| `POST` | `/api/restore` | Restore multiple paths |

### Simulation & Intervention

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/simulate/attack` | Run controlled attack simulation (`low`/`medium`/`high`) |
| `GET` | `/api/simulate/status` | Simulation progress |
| `POST` | `/api/intervention/handle` | Safe process intervention (clamped thresholds) |

### Reports & Forensics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/report` | View attack report (text or JSON with `?format=json`) |
| `GET` | `/api/report/download` | Download `attack_report.txt` |

### Emergency & Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/emergency/contact` | Get emergency contact |
| `POST` | `/api/emergency/contact` | Save emergency contact (email/phone) |
| `GET` | `/api/settings/contact` | Alias for emergency contact GET |
| `POST` | `/api/settings/contact` | Alias for emergency contact POST |
| `POST` | `/api/logs/clear` | Clear all logs (**requires** `x-api-key`) |

### Cluster Sync

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/sync/<event_type>` | Receive sync event from peer node |

---

## Emergency Alert Email

CyberShield sends exactly **one** email per attack cycle. It re-arms when the system returns to `SAFE`.

### Configure SMTP (PowerShell)

```powershell
$env:SMTP_SERVER       = 'smtp.gmail.com'
$env:SMTP_PORT         = '587'
$env:SMTP_USER         = 'your_gmail@gmail.com'
$env:SMTP_PASSWORD     = 'your_google_app_password'   # App Password, not account password
$env:ALERT_EMAIL_FROM  = 'your_gmail@gmail.com'
$env:ALERT_EMAIL_TO    = 'security-team@example.com'
```

Or set equivalent `CYBERSHIELD_SMTP_*` / `MAIL_*` env vars — both name schemes are supported.

### Save contact via API

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:5000/api/emergency/contact' `
    -Headers @{'x-api-key' = $env:API_KEY} `
    -ContentType 'application/json' `
    -Body '{"email":"security-team@example.com"}'
```

> Email addresses are **masked in logs** (`adm***@example.com`) — PII never appears in plaintext in DB or log files.

---

## Controlled Ransomware Simulation (Safe Demo)

The simulator only touches files in the target folder — it does **not** execute malware code.

### Setup demo files

```powershell
$env:CYBERSHIELD_MONITOR_PATHS = 'E:\CyberAttack'
python -m backend.app
# In another terminal:
python demo_attack_simulator.py setup --target E:\CyberAttack
```

### Run attack levels

```powershell
# Low — early warning only
python demo_attack_simulator.py low --target E:\CyberAttack

# Medium — partial rename to .enc + recovery
python demo_attack_simulator.py medium --target E:\CyberAttack

# High — full rename + recovery
python demo_attack_simulator.py high --target E:\CyberAttack

# Rollback renamed files
python demo_attack_simulator.py rollback --target E:\CyberAttack
```

---

## Command Center Integration

Forward detected attack events to a teammate's Command Center backend.

```powershell
$env:CYBERSHIELD_COMMAND_CENTER_BASE_URL  = 'https://command-center.example.com'
$env:CYBERSHIELD_COMMAND_CENTER_API_KEY   = 'your_command_center_key'
$env:CYBERSHIELD_COMMAND_CENTER_SOURCE    = 'cybershield-engine'
$env:CYBERSHIELD_COMMAND_CENTER_LOCATION  = 'local-endpoint'
$env:CYBERSHIELD_COMMAND_CENTER_SYSTEM    = 'CyberShield Protected Filesystem'
```

Target endpoint: `POST /integrations/cybershield/events` with `x-api-key` header.

One forward per attack cycle; re-armed on `SAFE`.

---

## Security Architecture

| Layer | Hardening Applied |
|-------|-------------------|
| **Secrets** | All `.env.example` values are non-functional placeholders; Docker uses `:?` fail-fast |
| **Authentication** | `secrets.compare_digest` for timing-safe comparison; `x-api-key` required on sensitive endpoints |
| **Path Traversal** | `Path.is_relative_to()` guards on `backup/recover` and `report_generator` |
| **Input Validation** | Thresholds clamped to `[min, max]`; SMTP port `int()` wrapped in `try/except` |
| **PII Protection** | Email addresses masked (`loc***@domain`) before DB/log writes |
| **Thread Safety** | `threading.Lock` for monitor state; `is_running` guard on `FileMonitor.start()` |
| **Memory Safety** | `rename_log` pruned on every event; file entropy computed outside the lock |
| **DB Safety** | All sessions closed in `finally` blocks; WAL journal mode on SQLite |
| **Process Safety** | `SYSTEM`/`NT AUTHORITY\SYSTEM` guarded; SIGKILL verified with second `wait()` |
| **SMTP Safety** | `starttls()` only called when `use_tls AND NOT use_ssl` |

---

## Running Tests

```powershell
pip install pytest
pytest tests/ -v
```

Tests use `unittest.mock` — no real filesystem or network access required.

---

## Demo Flow

1. Start backend → dashboard shows **Monitoring: Protected System Directories (Auto-configured)**
2. Run `demo_attack_simulator.py low` — watch early anomaly detection on the Activity Chart
3. Run `demo_attack_simulator.py high` — observe full attack: detection → process kill → recovery
4. Review stored fingerprints and correlation alerts on the Fingerprints panel
5. Download `attack_report.txt` from the SOS panel for forensic evidence

---

## License

MIT — see [LICENSE](./LICENSE)
