"""
Production-grade versioned snapshot system for CyberShield.
Efficient file backups with deduplication and timestamp tracking.
"""
import os
import shutil
import hashlib
from datetime import datetime

SNAPSHOT_ROOT = os.environ.get("CYBERSHIELD_SNAPSHOT_ROOT", "./backup_snapshots")

def file_hash(path):
    """Return SHA256 hash of file contents (first 1MB for speed)."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            h.update(f.read(1024*1024))
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
        """
        if not os.path.isfile(file_path):
            return False, "Not a file"
        fname = os.path.basename(file_path)
        fhash = file_hash(file_path)
        if not fhash:
            return False, "Hash failed"
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        snap_dir = os.path.join(self.snapshot_root, fname)
        os.makedirs(snap_dir, exist_ok=True)
        snap_path = os.path.join(snap_dir, f"{ts}_{fhash}")
        # Deduplication: skip if identical hash exists
        for existing in os.listdir(snap_dir):
            if existing.endswith(fhash):
                return False, "No changes (duplicate hash)"
        shutil.copy2(file_path, snap_path)
        return True, snap_path

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
