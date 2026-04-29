"""
Production-grade versioned snapshot system for CyberShield.
Efficient file backups with deduplication and timestamp tracking.
"""
import os
import shutil
import hashlib
from datetime import datetime, timezone

SNAPSHOT_ROOT = os.environ.get("CYBERSHIELD_SNAPSHOT_ROOT", "./backup_snapshots")

_CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming hash


def file_hash(path):
    """Return SHA256 hash of entire file contents, read in chunks to avoid high memory use."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class SnapshotManager:
    def __init__(self, snapshot_root=SNAPSHOT_ROOT):
        self.snapshot_root = snapshot_root
        os.makedirs(self.snapshot_root, exist_ok=True)

    def create_snapshot(self, file_path):
        """
        Create a versioned snapshot of file_path if changed.
        Returns a dict with keys 'ok' (bool), 'detail' (str), and 'path' (str|None).
        """
        if not os.path.isfile(file_path):
            return {"ok": False, "detail": "Not a file", "path": None}
        fname = os.path.basename(file_path)
        fhash = file_hash(file_path)
        if not fhash:
            return {"ok": False, "detail": "Hash failed", "path": None}
        # Use timezone-aware UTC timestamp
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        snap_dir = os.path.join(self.snapshot_root, fname)
        os.makedirs(snap_dir, exist_ok=True)
        snap_path = os.path.join(snap_dir, f"{ts}_{fhash}")
        # Deduplication: skip if identical hash exists
        for existing in os.listdir(snap_dir):
            if existing.endswith(fhash):
                return {"ok": False, "detail": "No changes (duplicate hash)", "path": None}
        shutil.copy2(file_path, snap_path)
        return {"ok": True, "detail": "snapshot_created", "path": snap_path}

    def get_latest_snapshot(self, file_path):
        """
        Return the latest snapshot path for file_path.
        """
        fname = os.path.basename(file_path)
        snap_dir = os.path.join(self.snapshot_root, fname)
        if not os.path.isdir(snap_dir):
            return None
        snaps = sorted(os.listdir(snap_dir), reverse=True)
        if not snaps:
            return None
        return os.path.join(snap_dir, snaps[0])
