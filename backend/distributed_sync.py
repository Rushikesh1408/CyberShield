"""
Reliable, Secure, and Fault-Tolerant Distributed Sync for CyberShield Cluster.
"""
import os
import hashlib
import requests
import time
import threading
from datetime import datetime
from queue import Queue, Empty
from typing import List
from backend.logger import get_logger
from backend.db.database import SessionLocal
from backend.db import models

logger = get_logger("cybershield.cluster_sync")

# Config
_raw_timeout = os.environ.get("SYNC_TIMEOUT", "5")
try:
    SYNC_TIMEOUT = int(_raw_timeout)
    if SYNC_TIMEOUT <= 0:
        raise ValueError("must be positive")
except ValueError as _e:
    logger.warning(f"Invalid SYNC_TIMEOUT '{_raw_timeout}': {_e}. Using 5s.")
    SYNC_TIMEOUT = 5

MAX_RETRIES = 5
BACKOFF_FACTOR = 2
BATCH_WINDOW = 1.0  # seconds
MAX_BATCH_SIZE = 50

# Configurable node protocol (prefer HTTPS)
NODE_PROTOCOL = os.environ.get("CLUSTER_NODE_PROTOCOL", "https").strip().lower()
if NODE_PROTOCOL not in ("http", "https"):
    logger.warning(f"Invalid CLUSTER_NODE_PROTOCOL '{NODE_PROTOCOL}', defaulting to 'https'.")
    NODE_PROTOCOL = "https"


class ClusterManager:
    def __init__(self):
        self.broadcast_queue: Queue = Queue()
        self.dead_letter_queue: List[dict] = []  # persistent failed tasks
        self.stop_event = threading.Event()
        # Non-daemon so join() reliably waits for drain
        self.worker_thread = threading.Thread(
            target=self._process_queue, daemon=False, name="cybershield-cluster-worker"
        )
        self.worker_thread.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def queue_broadcast(self, event_type, data):
        """Adds a broadcast task to the reliable queue."""
        self.broadcast_queue.put({
            "type": event_type,
            "data": data,
            "attempts": 0,
            "failed_nodes": [],   # track which nodes failed per-attempt
            "next_retry": time.time(),
        })

    def shutdown(self, drain: bool = True) -> None:
        """
        Stop accepting new work and optionally wait for in-flight tasks to finish.
        Call from application teardown (e.g., atexit or SIGTERM handler).
        """
        self.stop_event.set()
        if drain:
            self.worker_thread.join(timeout=30)
            if self.worker_thread.is_alive():
                logger.warning("[ClusterManager] Worker did not drain within 30s shutdown timeout.")
        logger.info("[ClusterManager] Shutdown complete.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_active_nodes(self) -> List[models.Node]:
        """
        Return Node instances with ip_address and api_key_hash eagerly loaded
        so they can be used after the session closes (no DetachedInstanceError).
        """
        db = SessionLocal()
        try:
            nodes = db.query(models.Node).filter(models.Node.status != 'offline').all()
            # Force-load the attributes we need while the session is still open
            result = []
            for node in nodes:
                _ = node.ip_address    # access to ensure loaded
                _ = node.api_key_hash  # access to ensure loaded
                _ = node.node_id
                result.append(node)
            return result
        finally:
            db.close()

    def _update_node_status(self, node_id, status):
        db = SessionLocal()
        try:
            node = db.query(models.Node).filter(models.Node.node_id == node_id).first()
            if node:
                node.status = status
                node.last_seen = datetime.utcnow()
                db.commit()
        except Exception as e:
            logger.error(f"Failed to update node status {node_id}: {e}")
        finally:
            db.close()

    def _process_queue(self):
        """Worker loop — drains remaining tasks when stop_event is set."""
        while True:
            # Check stop_event but continue draining remaining items
            stop_requested = self.stop_event.is_set()
            try:
                task = self.broadcast_queue.get(timeout=1)
            except Empty:
                if stop_requested:
                    break  # Queue empty and stop requested — exit cleanly
                continue

            # Check backoff timing
            if time.time() < task["next_retry"]:
                self.broadcast_queue.put(task)
                time.sleep(0.5)
                continue

            nodes = self._get_active_nodes()
            if not nodes:
                if stop_requested:
                    logger.warning(f"[ClusterManager] Discarding task '{task['type']}' — no nodes and shutting down.")
                    continue
                time.sleep(2)
                self.broadcast_queue.put(task)
                continue

            # Only retry nodes that failed last time (or all nodes on first attempt)
            nodes_to_try = nodes if not task["failed_nodes"] else [
                n for n in nodes if n.node_id in task["failed_nodes"]
            ]

            newly_failed: List[str] = []
            for node in nodes_to_try:
                success = self._send_to_node(node, task["type"], task["data"])
                if not success:
                    newly_failed.append(node.node_id)

            task["failed_nodes"] = newly_failed

            if newly_failed:
                if task["attempts"] < MAX_RETRIES:
                    task["attempts"] += 1
                    task["next_retry"] = time.time() + (BACKOFF_FACTOR ** task["attempts"])
                    logger.warning(
                        f"Partial broadcast failure for task '{task['type']}'. "
                        f"Failed nodes: {newly_failed}. Retrying (attempt {task['attempts']})."
                    )
                    self.broadcast_queue.put(task)
                else:
                    # Max retries exhausted — move to dead-letter queue
                    logger.error(
                        f"[ClusterManager] Task '{task['type']}' exhausted {MAX_RETRIES} retries. "
                        f"Failed nodes: {newly_failed}. Moving to dead-letter queue."
                    )
                    task["dead_lettered_at"] = datetime.utcnow().isoformat()
                    self.dead_letter_queue.append(task)
            # else: all nodes succeeded — task is complete

        logger.info("[ClusterManager] Worker thread exiting.")

    def _send_to_node(self, node, event_type, data) -> bool:
        # Use configurable protocol (prefer HTTPS)
        protocol = NODE_PROTOCOL
        ip = str(node.ip_address or "").rstrip("/")
        url = f"{protocol}://{ip}/api/sync/{event_type}"
        headers = {"x-api-key": node.api_key_hash or ""}

        try:
            resp = requests.post(url, json=data, headers=headers, timeout=SYNC_TIMEOUT)
            if resp.status_code == 200:
                if node.status != 'online':
                    self._update_node_status(node.node_id, 'online')
                return True
            else:
                logger.error(f"Node {node.node_id} returned {resp.status_code}")
                self._update_node_status(node.node_id, 'degraded')
                return False
        except Exception as e:
            logger.error(f"Failed to reach node {node.node_id}: {e}")
            self._update_node_status(node.node_id, 'offline')
            return False


# Global instance
manager = ClusterManager()


def broadcast_event(event_type, data):
    """Production entry point for broadcasting."""
    logger.info(f"Queuing broadcast: {event_type}")
    manager.queue_broadcast(event_type, data)


def receive_event(event_type, data, db_session) -> bool:
    """
    Validated sync receiver.
    Checks for duplicates and logs health.
    """
    logger.info(f"Incoming sync [{event_type}]")

    if event_type == 'dna':
        # Validate dna_id before querying to avoid NULL comparisons
        dna_id = data.get("id")
        if not dna_id:
            logger.warning("[receive_event] Received DNA event with missing 'id' — ignoring.")
            return False
        existing = db_session.query(models.Fingerprint).filter(
            models.Fingerprint.id == dna_id
        ).first()
        if existing:
            logger.info(f"Duplicate DNA signature {dna_id} ignored.")
            return False

    logger.info(f"Sync validation passed for {event_type}")
    return True
