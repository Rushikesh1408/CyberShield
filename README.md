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

## API endpoints

- `GET /api/status`
- `GET /api/metrics`
- `GET /api/alerts`
- `GET /api/logs`
- `GET /api/fingerprints`
- `POST /api/start`
- `POST /api/stop`

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

