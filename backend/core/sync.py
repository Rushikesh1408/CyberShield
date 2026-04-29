"""
Distributed sync module for CyberShield.
Broadcasts events to peer nodes using HTTP POST with API key authentication.
Failures are handled gracefully — no crash propagation.
"""
import os
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

logger = logging.getLogger("cybershield.sync")

# Peer nodes can be configured via the SYNC_NODES env var (comma-separated URLs)
# Example: SYNC_NODES=http://node1:8000,http://node2:8000
_raw_nodes = os.environ.get("SYNC_NODES", "")
PEER_NODES: List[str] = [n.strip().rstrip("/") for n in _raw_nodes.split(",") if n.strip()]

# Safe SYNC_TIMEOUT parse — fall back to 5s on bad input
try:
    SYNC_TIMEOUT = int(os.environ.get("SYNC_TIMEOUT", "5"))
    if SYNC_TIMEOUT <= 0:
        raise ValueError("SYNC_TIMEOUT must be positive")
except ValueError as _e:
    logger.warning(f"[Sync] Invalid SYNC_TIMEOUT value: {_e}. Using default 5s.")
    SYNC_TIMEOUT = 5

# API_KEY must be set; empty string is not acceptable
_raw_api_key = os.environ.get("API_KEY", "")
if not _raw_api_key:
    logger.error(
        "[Sync] API_KEY environment variable is not set or is empty. "
        "Peer sync requests will be rejected by nodes requiring authentication."
    )
API_KEY: str = _raw_api_key

# Module-level executor — caller can call _executor.shutdown(wait=True) on teardown
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cybershield-sync")


def _broadcast_to_node(node_url: str, data: Dict[str, Any]) -> bool:
    """Send a sync event to a single peer node. Returns True on success."""
    import requests  # local import to keep module importable without requests at module level
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
    except Exception as exc:
        logger.warning(f"[Sync] Unexpected error for {node_url}: {exc}")
    return False


def sync_event(data: Dict[str, Any], wait: bool = False) -> None:
    """
    Broadcast a sync event to all configured peer nodes.
    Uses a ThreadPoolExecutor instead of daemon threads so broadcasts can
    be awaited on shutdown.  Pass wait=True to block until all futures complete.
    """
    if not PEER_NODES:
        logger.debug("[Sync] No peer nodes configured — skipping broadcast.")
        return

    futures = [
        _executor.submit(_broadcast_to_node, node_url, data)
        for node_url in PEER_NODES
    ]
    if wait:
        for future in futures:
            future.result()  # propagate exceptions to caller if needed


def broadcast_event(event_type: str, data: Dict[str, Any], wait: bool = False) -> None:
    """
    Convenience wrapper — adds event_type to the payload before broadcasting.
    """
    payload = {"event_type": event_type, **data}
    sync_event(payload, wait=wait)


def shutdown(wait: bool = True) -> None:
    """Gracefully shut down the sync executor. Call from application teardown."""
    _executor.shutdown(wait=wait)
