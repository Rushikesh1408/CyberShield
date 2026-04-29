"""
Reliable, Secure, and Fault-Tolerant Distributed Sync for CyberShield Cluster.
"""
import os
import requests
import time
import threading
from datetime import datetime
from queue import Queue, Empty
from backend.logger import get_logger
from backend.db.database import SessionLocal
from backend.db import models

logger = get_logger("cybershield.cluster_sync")

# Config
SYNC_TIMEOUT = int(os.environ.get("SYNC_TIMEOUT", 5))
MAX_RETRIES = 5
BACKOFF_FACTOR = 2
BATCH_WINDOW = 1.0 # seconds
MAX_BATCH_SIZE = 50

class ClusterManager:
    def __init__(self):
        self.broadcast_queue = Queue()
        self.stop_event = threading.Event()
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def _get_active_nodes(self):
        db = SessionLocal()
        try:
            return db.query(models.Node).filter(models.Node.status != 'offline').all()
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

    def queue_broadcast(self, event_type, data):
        """Adds a broadcast task to the reliable queue."""
        self.broadcast_queue.put({
            "type": event_type,
            "data": data,
            "attempts": 0,
            "next_retry": time.time()
        })

    def _process_queue(self):
        while not self.stop_event.is_set():
            try:
                task = self.broadcast_queue.get(timeout=1)
                
                # Check backoff timing
                if time.time() < task["next_retry"]:
                    self.broadcast_queue.put(task)
                    time.sleep(0.5)
                    continue

                nodes = self._get_active_nodes()
                if not nodes:
                    # No nodes, discard or wait? For now, we'll wait.
                    time.sleep(2)
                    self.broadcast_queue.put(task)
                    continue

                success_count = 0
                for node in nodes:
                    success = self._send_to_node(node, task["type"], task["data"])
                    if success:
                        success_count += 1
                
                if success_count < len(nodes) and task["attempts"] < MAX_RETRIES:
                    task["attempts"] += 1
                    task["next_retry"] = time.time() + (BACKOFF_FACTOR ** task["attempts"])
                    logger.warning(f"Partial broadcast failure. Retrying task {task['type']} (Attempt {task['attempts']})")
                    self.broadcast_queue.put(task)
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Worker thread error: {e}")

    def _send_to_node(self, node, event_type, data):
        url = f"http://{node.ip_address.rstrip('/')}/api/sync/{event_type}"
        headers = {"x-api-key": node.api_key}
        
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

def receive_event(event_type, data, db_session):
    """
    Validated sync receiver.
    Checks for duplicates and logs health.
    """
    logger.info(f"Incoming sync [{event_type}]")
    
    if event_type == 'dna':
        # Prevent duplicate DNA signatures
        dna_id = data.get("id")
        existing = db_session.query(models.Fingerprint).filter(models.Fingerprint.id == dna_id).first()
        if existing:
            logger.info(f"Duplicate DNA signature {dna_id} ignored.")
            return False
            
    # Success logging
    logger.info(f"Sync validation passed for {event_type}")
    return True
