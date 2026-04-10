# CyberShield AI - Real-Time Ransomware Defense & Zero Data Loss System

CyberShield AI is a lightweight ransomware defense tool for hackathon demos and local use. It automatically monitors protected system directories (Documents, Downloads, Desktop) or falls back to a local protected_folder, detects ransomware-like file bursts, kills suspicious processes, restores files from versioned backups, and stores attack fingerprints in SQLite.

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

