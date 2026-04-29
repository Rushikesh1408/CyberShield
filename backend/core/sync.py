"""
Distributed sync module for CyberShield.
Broadcasts events to peer nodes using HTTP POST with API key authentication.
Failures are handled silently — no crash propagation.
"""
import os
import logging
import threading
import requests
from typing import Any, Dict, List

logger = logging.getLogger("cybershield.sync")

# Peer nodes can be configured via the SYNC_NODES env var (comma-separated URLs)
# Example: SYNC_NODES=http://node1:8000,http://node2:8000
_raw_nodes = os.environ.get("SYNC_NODES", "")
PEER_NODES: List[str] = [n.strip().rstrip("/") for n in _raw_nodes.split(",") if n.strip()]

SYNC_TIMEOUT = int(os.environ.get("SYNC_TIMEOUT", "5"))
API_KEY = os.environ.get("API_KEY", "")


def _broadcast_to_node(node_url: str, data: Dict[str, Any]) -> bool:
    """Send a sync event to a single peer node. Returns True on success."""
    try:
        response = requests.post(
            f"{node_url}/api/sync",
            json=data,
            headers={
                "x-api-key": API_KEY,
                "Content-Type": "application/json",
            },
            timeout=SYNC_TIMEOUT,
        )
        if response.status_code == 200:
            logger.debug(f"[Sync] Event delivered to {node_url}")
            return True
        else:
            logger.warning(f"[Sync] Node {node_url} returned HTTP {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        logger.warning(f"[Sync] Timeout reaching node {node_url}")
    except requests.exceptions.ConnectionError:
        logger.warning(f"[Sync] Cannot connect to node {node_url}")
    except Exception as exc:
        logger.warning(f"[Sync] Unexpected error for {node_url}: {exc}")
    return False


def sync_event(data: Dict[str, Any]) -> None:
    """
    Broadcast a sync event to all configured peer nodes.
    Runs each broadcast in a daemon thread so failures never block the caller.
    """
    if not PEER_NODES:
        logger.debug("[Sync] No peer nodes configured — skipping broadcast.")
        return

    for node_url in PEER_NODES:
        t = threading.Thread(
            target=_broadcast_to_node,
            args=(node_url, data),
            daemon=True,
            name=f"sync-{node_url}",
        )
        t.start()


def broadcast_event(event_type: str, data: Dict[str, Any]) -> None:
    """
    Convenience wrapper — adds event_type to the payload before broadcasting.
    """
    payload = {"event_type": event_type, **data}
    sync_event(payload)
