"""
CyberShield REST API — production-grade endpoints.
All routes require x-api-key authentication except /health.
Standardised response shape: {"status": "success"|"error", "data": {...}, "error": null|"message"}
"""
import os
import logging
from datetime import datetime
from typing import Any, Dict, Optional

import psutil
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db.database import SessionLocal
from backend.db import models

logger = logging.getLogger("cybershield.api")

router = APIRouter()

# ---------------------------------------------------------------------------
# Database dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# API Key security
# ---------------------------------------------------------------------------

def _get_master_key() -> str:
    key = os.environ.get("API_KEY", "")
    if not key:
        raise RuntimeError(
            "API_KEY environment variable is not set. "
            "Set it in backend/.env before starting the server."
        )
    return key


def verify_api_key(x_api_key: str = Header(...)):
    """
    Validate the x-api-key header.
    Checks against master key first, then per-node keys in DB.
    """
    master_key = _get_master_key()
    if x_api_key == master_key:
        return "master"
    # Per-node key check (only if DB is available)
    try:
        db = SessionLocal()
        try:
            node = db.query(models.Node).filter(models.Node.api_key == x_api_key).first()
            if node:
                return f"node:{node.node_id}"
        finally:
            db.close()
    except Exception:
        pass  # DB unavailable — still reject unknown keys
    raise HTTPException(status_code=403, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# Pipeline singleton
# ---------------------------------------------------------------------------

from backend.core.pipeline import CyberShieldPipeline  # noqa: E402

_pipeline: Optional[CyberShieldPipeline] = None


def get_pipeline() -> CyberShieldPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = CyberShieldPipeline()
    return _pipeline


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def ok(data: Any = None) -> Dict:
    return {"status": "success", "data": data if data is not None else {}, "error": None}


def err(message: str, code: int = 500) -> None:
    raise HTTPException(status_code=code, detail=message)


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class SyncPayload(BaseModel):
    event_type: Optional[str] = None
    data: Optional[Dict] = None

    class Config:
        extra = "allow"  # accept any extra fields


class RecoverPayload(BaseModel):
    file_path: str


class EmergencyContactPayload(BaseModel):
    phone: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/health")
async def health_check():
    """Public health check — no API key required."""
    return ok({"healthy": True, "timestamp": datetime.utcnow().isoformat()})


@router.get("/status")
async def get_status(_auth: str = Depends(verify_api_key)):
    """System status including monitoring state and pipeline metrics."""
    try:
        pipeline = get_pipeline()
        pipeline_status = pipeline.status()
        return ok({
            **pipeline_status,
            "timestamp": datetime.utcnow().isoformat(),
            "monitor_paths": ["./protected_folder"],
            "monitoring_message": "Monitoring: Protected System Directories (Auto-configured)",
        })
    except Exception as exc:
        logger.error(f"Status endpoint error: {exc}")
        err(f"Internal error: {exc}")


@router.get("/metrics")
async def get_metrics(_auth: str = Depends(verify_api_key)):
    """Real-time CPU, memory and pipeline metrics."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        pipeline = get_pipeline()
        pipeline_status = pipeline.status()
        return ok({
            "metrics": {
                "files_per_second": pipeline_status.get("files_per_second", 0),
                "modifications": pipeline_status.get("modifications", 0),
                "accesses": pipeline_status.get("accesses", 0),
                "cpu_percent": cpu,
                "cpu_percent_raw": cpu,
                "cpu_percent_sampled": cpu,
                "memory_percent": mem,
                "status": pipeline_status.get("status", "SAFE"),
            },
            "history": [],
        })
    except Exception as exc:
        logger.error(f"Metrics endpoint error: {exc}")
        err("Internal error fetching metrics")


@router.get("/alerts")
async def get_alerts(db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Return the latest 100 alerts ordered by most recent first."""
    try:
        alerts = (
            db.query(models.Alert)
            .order_by(models.Alert.timestamp.desc())
            .limit(100)
            .all()
        )
        return ok({
            "alerts": [
                {
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                    "severity": a.severity,
                    "reason": a.reason,
                    "file_path": a.file_path,
                    "process_id": a.process_id,
                }
                for a in alerts
            ]
        })
    except Exception as exc:
        logger.error(f"Alerts endpoint error: {exc}")
        err("Internal error fetching alerts")


@router.get("/logs")
async def get_logs(db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Return the latest 100 log entries."""
    try:
        logs = (
            db.query(models.Log)
            .order_by(models.Log.timestamp.desc())
            .limit(100)
            .all()
        )
        return ok({
            "logs": [
                {
                    "id": l.id,
                    "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                    "level": l.level,
                    "message": l.message,
                }
                for l in logs
            ]
        })
    except Exception as exc:
        logger.error(f"Logs endpoint error: {exc}")
        err("Internal error fetching logs")


@router.post("/logs/clear")
async def clear_logs(db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Clear all log entries from the database."""
    try:
        deleted = db.query(models.Log).delete()
        db.commit()
        logger.info(f"Cleared {deleted} log entries.")
        return ok({"cleared": True, "deleted": deleted})
    except Exception as exc:
        logger.error(f"Clear logs error: {exc}")
        err("Internal error clearing logs")


@router.get("/fingerprints")
async def get_fingerprints(db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Return DNA fingerprints (threat signatures)."""
    try:
        dna = (
            db.query(models.Fingerprint)
            .order_by(models.Fingerprint.timestamp.desc())
            .limit(100)
            .all()
        )
        return ok({
            "fingerprints": [
                {
                    "id": f.id,
                    "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                    "signature": f.signature,
                    "source_node": f.source_node,
                }
                for f in dna
            ]
        })
    except Exception as exc:
        logger.error(f"Fingerprints endpoint error: {exc}")
        err("Internal error fetching fingerprints")


@router.get("/dna")
async def get_dna(db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Alias for /fingerprints."""
    return await get_fingerprints(db=db, _auth=_auth)


@router.post("/start")
async def start_monitoring(_auth: str = Depends(verify_api_key)):
    """Start the file-system monitor."""
    try:
        pipeline = get_pipeline()
        started = pipeline.start()
        pipeline_status = pipeline.status()
        logger.info("Monitoring started via API.")
        return ok({"started": started, **pipeline_status})
    except Exception as exc:
        logger.error(f"Start monitoring error: {exc}")
        err(f"Failed to start monitoring: {exc}")


@router.post("/stop")
async def stop_monitoring(_auth: str = Depends(verify_api_key)):
    """Stop the file-system monitor."""
    try:
        pipeline = get_pipeline()
        stopped = pipeline.stop()
        pipeline_status = pipeline.status()
        logger.info("Monitoring stopped via API.")
        return ok({"stopped": stopped, **pipeline_status})
    except Exception as exc:
        logger.error(f"Stop monitoring error: {exc}")
        err(f"Failed to stop monitoring: {exc}")


@router.post("/recover")
async def recover_file(
    payload: Optional[RecoverPayload] = None,
    file_path: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: str = Depends(verify_api_key),
):
    """
    Recover a file from its latest snapshot.
    Accepts file_path either as JSON body {"file_path": "..."} or query param ?file_path=...
    """
    resolved_path = (payload.file_path if payload else None) or file_path or ""
    if not resolved_path:
        raise HTTPException(status_code=422, detail="file_path is required (body or query param)")

    try:
        from backend.core.recovery import RecoveryEngine
        result = RecoveryEngine().recover(resolved_path)

        db_event = models.RecoveryEvent(
            file_path=resolved_path,
            restored=result.get("restored", False),
            process_id=result.get("process_id"),
            details=str(result.get("kill_msg", "")),
        )
        db.add(db_event)
        db.commit()
        logger.info(f"Recovery completed for {resolved_path}: restored={result.get('restored')}")
        return ok({"recovered": resolved_path, "details": result})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Recovery failed for {resolved_path}: {exc}")
        err(f"Recovery failed: {exc}")


@router.get("/backup/status")
async def get_backup_status(_auth: str = Depends(verify_api_key)):
    """Return snapshot/backup statistics."""
    try:
        pipeline = get_pipeline()
        sm = pipeline.snapshot_manager
        root = getattr(sm, "snapshot_root", "./backup_snapshots")

        files = 0
        versions = 0
        last_ts = None
        recent: list = []

        if os.path.exists(root):
            for fname in os.listdir(root):
                fdir = os.path.join(root, fname)
                if not os.path.isdir(fdir):
                    continue
                files += 1
                snaps = os.listdir(fdir)
                versions += len(snaps)
                for snap in snaps:
                    snap_path = os.path.join(fdir, snap)
                    mtime = os.path.getmtime(snap_path)
                    recent.append((mtime, fname))
                    if last_ts is None or mtime > last_ts:
                        last_ts = mtime

        recent.sort(reverse=True)
        recent_files = [label for _, label in recent[:10]]
        last_backup_time = (
            datetime.utcfromtimestamp(last_ts).isoformat() if last_ts else None
        )

        return ok({
            "status": "Active" if files > 0 else "No backups yet",
            "files_secured": files,
            "backup_versions": versions,
            "last_backup_time": last_backup_time,
            "recent_files": recent_files,
            "backup_root": root,
        })
    except Exception as exc:
        logger.error(f"Backup status error: {exc}")
        err(f"Internal error: {exc}")


@router.post("/backup/run")
async def run_backup(_auth: str = Depends(verify_api_key)):
    """Trigger an immediate snapshot of all monitored paths."""
    try:
        pipeline = get_pipeline()
        sm = pipeline.snapshot_manager
        root = getattr(sm, "snapshot_root", "./backup_snapshots")

        watch_paths = []
        if pipeline.is_running and pipeline.monitor:
            watch_paths = list(pipeline.monitor.paths)
        if not watch_paths:
            watch_paths = ["./protected_folder"]

        created = skipped = errors = 0
        backed_files = []

        for watch_path in watch_paths:
            if not os.path.exists(watch_path):
                continue
            for dirpath, _, filenames in os.walk(watch_path):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        ok_flag, detail = sm.create_snapshot(fpath)
                        if ok_flag:
                            created += 1
                            backed_files.append(fpath)
                        else:
                            skipped += 1
                    except Exception:
                        errors += 1

        logger.info(f"Backup run: created={created} skipped={skipped} errors={errors}")
        return ok({
            "created": created,
            "skipped": skipped,
            "errors": errors,
            "backup_root": root,
            "paths_scanned": watch_paths,
        })
    except Exception as exc:
        logger.error(f"Backup run failed: {exc}")
        err(f"Backup failed: {exc}")


@router.get("/emergency/contact")
async def get_emergency_contact(
    db: Session = Depends(get_db),
    _auth: str = Depends(verify_api_key),
):
    """Return the saved emergency contact."""
    try:
        cfg = db.query(models.Config).filter(models.Config.key == "emergency_contact").first()
        return ok({"contact": cfg.value if cfg else ""})
    except Exception as exc:
        logger.error(f"Get emergency contact error: {exc}")
        err("Internal error")


@router.post("/emergency/contact")
async def set_emergency_contact(
    payload: EmergencyContactPayload,
    db: Session = Depends(get_db),
    _auth: str = Depends(verify_api_key),
):
    """Save an emergency contact phone number."""
    try:
        phone = payload.phone.strip()
        if not phone:
            raise HTTPException(status_code=422, detail="phone must not be empty")
        cfg = db.query(models.Config).filter(models.Config.key == "emergency_contact").first()
        if cfg:
            cfg.value = phone
        else:
            db.add(models.Config(key="emergency_contact", value=phone))
        db.commit()
        logger.info(f"Emergency contact saved: {phone}")
        return ok({"contact": phone})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Set emergency contact error: {exc}")
        err("Internal error")


@router.get("/report/download")
async def download_report(_auth: str = Depends(verify_api_key)):
    """Generate and download a plain-text security report."""
    try:
        pipeline = get_pipeline()
        pipeline_status = pipeline.status()
        report_lines = [
            "CyberShield Security Report",
            f"Generated: {datetime.utcnow().isoformat()}",
            f"Status: {pipeline_status.get('status', 'SAFE')}",
            f"Is Monitoring: {pipeline_status.get('is_monitoring', False)}",
            f"Alerts Processed: {pipeline_status.get('alerts_processed', 0)}",
            f"Modifications Detected: {pipeline_status.get('modifications', 0)}",
        ]
        content = "\n".join(report_lines)
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=attack_report.txt"},
        )
    except Exception as exc:
        logger.error(f"Report download error: {exc}")
        err("Report generation failed")


@router.post("/sync")
async def receive_sync(request: Request, _auth: str = Depends(verify_api_key)):
    """
    Receive a distributed sync event from a peer node.
    Accepts any JSON payload and broadcasts to local pipeline.
    """
    try:
        data = await request.json()
        logger.info(f"[Sync] Received event: {data.get('event_type', 'unknown')}")
        # Re-broadcast to other peers (this node acts as a relay)
        from backend.core.sync import sync_event
        sync_event(data)
        return ok({"synced": True, "event_type": data.get("event_type")})
    except Exception as exc:
        logger.error(f"Sync endpoint error: {exc}")
        err(f"Sync failed: {exc}")


@router.post("/node/register")
async def register_node(request: Request, db: Session = Depends(get_db), _auth: str = Depends(verify_api_key)):
    """Register a peer node for cluster sync."""
    try:
        data = await request.json()
        node_id = data.get("node_id", "")
        ip_address = data.get("ip_address", "")
        api_key = data.get("api_key", "")
        if not node_id:
            raise HTTPException(status_code=422, detail="node_id is required")
        existing = db.query(models.Node).filter(models.Node.node_id == node_id).first()
        if existing:
            existing.ip_address = ip_address
            existing.api_key = api_key
            existing.last_seen = datetime.utcnow()
            existing.status = "online"
        else:
            db.add(models.Node(
                node_id=node_id,
                ip_address=ip_address,
                api_key=api_key,
                status="online",
            ))
        db.commit()
        logger.info(f"Node registered: {node_id} @ {ip_address}")
        return ok({"registered": True, "node_id": node_id})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Node register error: {exc}")
        err(f"Registration failed: {exc}")
