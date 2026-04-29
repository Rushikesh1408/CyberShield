"""
CyberShield pipeline: orchestrates monitoring, detection, snapshots, and recovery.
"""
import os
import logging
from backend.core.monitor import FileMonitor
from backend.core.detector import DetectionEngine
from backend.core.snapshot import SnapshotManager
from backend.core.recovery import RecoveryEngine

logger = logging.getLogger("cybershield.pipeline")

# broadcast_event is now provided by core/sync.py (lighter, no DB coupling)
try:
    from backend.core.sync import broadcast_event
except ImportError:
    def broadcast_event(event_type: str, data: dict) -> None:
        logger.debug(f"[Pipeline] broadcast_event stub: {event_type}")


class CyberShieldPipeline:
    def __init__(self):
        self.detector = DetectionEngine()
        self.snapshot_manager = SnapshotManager()
        self.recovery_engine = RecoveryEngine()
        self.is_running = False
        self.monitor = None

        self.stats = {
            "files_per_second": 0,
            "modifications": 0,
            "accesses": 0,
            "status": "SAFE",
            "alerts_processed": 0,
        }

    def process(self, event: dict) -> dict:
        """Process a single file-system event through the full pipeline."""
        self.stats["modifications"] += 1

        result = self.detector.analyze_event(event)
        if result.get("threat"):
            self.stats["status"] = "THREAT"
            self.stats["alerts_processed"] += 1
            logger.warning(
                f"[Pipeline] THREAT detected: {result.get('reason')} "
                f"severity={result.get('severity')} file={event.get('file_path')}"
            )

            # 1. Broadcast alert to peer nodes
            broadcast_event("alert", {
                "reason": result.get("reason"),
                "severity": result.get("severity"),
                "file_path": event.get("file_path"),
            })

            # 2. Generate & broadcast DNA signature
            import os as _os
            dna_sig = {
                "id": f"sig_{_os.path.basename(event.get('file_path', 'unknown'))}",
                "pattern": result.get("reason"),
            }
            broadcast_event("dna", dna_sig)

            # 3. Auto-recover: restore from snapshot
            try:
                self.recovery_engine.recover(event.get("file_path"))
            except Exception as exc:
                logger.error(f"[Pipeline] Recovery failed for {event.get('file_path')}: {exc}")

        return result

    def status(self) -> dict:
        """Return current pipeline status including is_monitoring flag."""
        return {
            "status": self.stats["status"],
            "is_monitoring": self.is_running,
            "files_per_second": self.stats["files_per_second"],
            "modifications": self.stats["modifications"],
            "accesses": self.stats["accesses"],
            "alerts_processed": self.stats["alerts_processed"],
        }

    def start(self) -> bool:
        """Start the file monitor. Returns True if started, False if already running."""
        if self.is_running:
            logger.info("[Pipeline] Already running.")
            return True
        try:
            os.makedirs("./protected_folder", exist_ok=True)
            self.monitor = FileMonitor(
                paths="./protected_folder",
                event_callback=self.process,
            )
            self.monitor.start()
            self.is_running = True
            logger.info("[Pipeline] File monitor started.")
            return True
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to start monitor: {exc}")
            self.is_running = False
            return False

    def stop(self) -> bool:
        """Stop the file monitor. Returns True on success."""
        if not self.is_running or self.monitor is None:
            self.is_running = False
            return True
        try:
            self.monitor.stop()
            self.is_running = False
            self.monitor = None
            logger.info("[Pipeline] File monitor stopped.")
            return True
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to stop monitor: {exc}")
            return False
