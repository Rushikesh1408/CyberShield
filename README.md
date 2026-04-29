# CyberShield - Ransomware Defense System

CyberShield is a lightweight ransomware defense tool for hackathon demos and local use. It automatically monitors protected system directories (Documents, Downloads, Desktop) or falls back to a local protected_folder, detects ransomware-like behavior in real time, neutralizes suspicious processes, restores data using versioned snapshots, and stores attack fingerprints in SQLite.

Core engines include:

- Early Threat Detection
- Active Threat Neutralization
- Versioned Snapshot System
- Automatic System Recovery

## What is included

- Flask backend with real-time detection, process killing, backup, recovery, and fingerprint storage
- React + Vite dashboard with Tailwind UI and Recharts-based activity graph
- SQLite logs, alerts, metrics, and fingerprint history
- Emergency email contact with one alert email per attack cycle (SMTP-backed)

## Project structure

```text
backend/
	app.py
	backup.py
	database.py
	detection.py
	fingerprint.py
	process_killer.py
frontend/
	src/
		components/
		pages/
		App.jsx
```

## Run locally

1. Backend

```bash
cd backend
python app.py
```

2. Frontend

```bash
cd frontend
npm install
npm run dev
```

## Docker deployment and tunneling

This repo now includes:

- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/nginx.conf`
- `docker-compose.yml`
- `.env.docker.example`

The frontend is served by nginx and proxies `/api/*` to backend container, so one public URL is enough.

### 1) Prepare docker env file

PowerShell:

```powershell
Copy-Item .env.docker.example .env
```

Edit `.env` if needed (Command Center, SMTP email, ngrok, and `CYBERSHIELD_FRONTEND_PORT` if port `5173` is already in use).

### 2) Build and run stack

```powershell
docker compose up --build -d
```

Access:

- Frontend: `http://127.0.0.1:${CYBERSHIELD_FRONTEND_PORT}` (defaults to `5173`)
- Backend API: `http://127.0.0.1:5000`

### 3) Start temporary public tunnel (optional)

```powershell
docker compose --profile tunnel up -d tunnel
docker logs -f cybershield-tunnel
```

`cloudflared` will print a temporary public URL. Open that URL to access your frontend and backend-proxied API.

### 4) Start temporary public tunnel with ngrok (alternative)

Set your ngrok auth token in `.env`:

```env
NGROK_AUTHTOKEN=your_ngrok_auth_token
```

Run:

```powershell
docker compose --profile ngrok up -d ngrok
docker logs -f cybershield-ngrok
```

The logs will show the public forwarding URL.

### 5) Stop services

```powershell
docker compose down
```

## API endpoints

- `GET /api/status`
- `GET /api/metrics`
- `GET /api/alerts`
- `GET /api/logs`
- `GET /api/fingerprints`
- `GET /api/emergency/contact`
- `POST /api/emergency/contact`
- `GET /api/report`
- `GET /api/report/download`
- `POST /api/start`
- `POST /api/stop`

## Emergency alert email setup

CyberShield can send an emergency alert email to the saved contact address when the system enters `UNDER_ATTACK`.

Behavior:

- Exactly one email delivery attempt is made per attack cycle.
- Additional detections during the same `UNDER_ATTACK` window do not send duplicates.
- Email sending is re-armed only after the system returns to `SAFE` and a new attack begins.

### 1) Configure SMTP credentials (backend terminal)

PowerShell:

```powershell
$env:MAIL_SERVER='smtp.gmail.com'
$env:MAIL_PORT='587'
$env:MAIL_USERNAME='your_gmail_address@gmail.com'
$env:MAIL_PASSWORD='your_google_app_password'
$env:MAIL_DEFAULT_SENDER='your_gmail_address@gmail.com'
$env:MAIL_USE_TLS='true'
$env:MAIL_USE_SSL='false'
```

### 2) Save emergency contact email

Use the dashboard "SOS Contact & Attack Report" panel, or call API directly:

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:5000/api/emergency/contact' `
	-ContentType 'application/json' `
	-Body '{"email":"security-team@example.com"}'
```

### 3) Start backend and trigger a demo attack

```powershell
$env:CYBERSHIELD_MONITOR_PATHS='E:\mandd\CyberAttack'
python -m backend.app
```

In another terminal:

```powershell
python test_folder\demo_attack_simulator.py high --target E:\mandd\CyberAttack
```

Notes:

- Email addresses are normalized before saving.
- For Gmail, use a Google App Password instead of your normal account password.
- If SMTP credentials are missing/invalid, CyberShield logs emergency alert failure events and no email is delivered.

## Command Center app integration

If your teammate is running CyberShield Command Center, this backend can forward detected attack events directly to that app backend.

Target endpoint used:

- `POST /integrations/cybershield/events`
- Header: `x-api-key: <command-center-api-key>`

### 1) Configure command-center forwarding (backend terminal)

PowerShell:

```powershell
$env:CYBERSHIELD_COMMAND_CENTER_BASE_URL='http://127.0.0.1:8000'
$env:CYBERSHIELD_COMMAND_CENTER_API_KEY='change-me'
$env:CYBERSHIELD_COMMAND_CENTER_SOURCE='cybershield-engine'
$env:CYBERSHIELD_COMMAND_CENTER_LOCATION='local-endpoint'
$env:CYBERSHIELD_COMMAND_CENTER_SYSTEM='CyberShield Protected Filesystem'
```

### 2) Start CyberShield backend normally

```powershell
$env:CYBERSHIELD_MONITOR_PATHS='E:\mandd\CyberAttack'
python -m backend.app
```

### 3) Trigger an attack simulation

```powershell
python test_folder\demo_attack_simulator.py high --target E:\mandd\CyberAttack
```

Behavior:

- On attack detection, CyberShield forwards an integration event to Command Center.
- Event includes threat score, severity, source, timeline, impact, and metadata.
- One forward attempt is made per attack cycle, then re-armed when system returns to SAFE.

## Demo flow

1. Start the backend and dashboard.
2. Verify the dashboard shows: Monitoring: Protected System Directories (Auto-configured).
3. Run a rapid file-modification simulation in one monitored location.
4. Watch early anomaly detection, full attack detection, process kill, and recovery.
5. Review stored fingerprints and similar-attack alerts on subsequent runs.

## Controlled ransomware simulation (safe demo)

Use the included safe simulator in `test_folder/demo_attack_simulator.py`.
It does not execute malware code. It only touches files and renames them with `.enc` suffix.

### 1) Configure monitor path for demo folder

PowerShell:

```powershell
$env:CYBERSHIELD_MONITOR_PATHS='E:\mandd\CyberAttack'
python -m backend.app
```

Frontend in another terminal:

```powershell
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

### 2) Create demo files

```powershell
python test_folder\demo_attack_simulator.py setup --target E:\mandd\CyberAttack
```

This creates these files if missing:

- `report.pdf`
- `image.jpg`
- `notes.txt`
- `project.docx`

### 3) Run attack levels in order

Low level (early warning activity, minimal changes):

```powershell
python test_folder\demo_attack_simulator.py low --target E:\mandd\CyberAttack
```

Medium level (partial rename to `.enc` + backup-based recovery wait):

```powershell
python test_folder\demo_attack_simulator.py medium --target E:\mandd\CyberAttack
```

High level (full rename to `.enc` + recovery wait):

```powershell
python test_folder\demo_attack_simulator.py high --target E:\mandd\CyberAttack
```

### 4) Optional manual rollback

If you need immediate cleanup of renamed files:

```powershell
python test_folder\demo_attack_simulator.py rollback --target E:\mandd\CyberAttack
```

